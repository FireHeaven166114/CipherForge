"""Response builders: normal values, and stored JSON that is missing, odd or corrupt."""

import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.detection.network_rules import ALL_RULES, NetworkRuleConfig, describe_rules
from app.models.network import CaptureSession, NetworkAlert, NetworkFlow
from app.network import views
from app.network.errors import ERRORS
from app.schemas.network import EnrichmentOut, SessionDetail
from tests.network_helpers import HOST, RESOLVER, SCANNER, SERVER, T0

BASE = datetime.fromtimestamp(T0, tz=UTC)
NOW = BASE + timedelta(seconds=90)
NAN = float("nan")
INF = float("inf")

STATES = (
    "pending",
    "completed",
    "failed",
    "unavailable",
    "disabled",
    "skipped_budget",
    "not_applicable",
    "not_looked_up",
)


def session_row(
    *,
    status: str = "completed",
    stats: Any = None,
    started: datetime = BASE,
    ended: datetime | None = None,
    error_code: str | None = None,
) -> CaptureSession:
    row = CaptureSession(
        id=uuid.uuid4(),
        owner="alice",
        source_kind="pcap",
        status=status,
        interface=None,
        source_label="scan.pcap",
        started_at=started,
        ended_at=ended,
        packets_total=10,
        bytes_total=1000,
        flows_total=3,
        alerts_total=1,
        packets_dropped=2,
        error_code=error_code,
        stats={},
    )
    # Assigned afterwards so a test can put in a value the column would never be given.
    row.stats = {} if stats is None else stats
    return row


def alert_row(**fields: Any) -> NetworkAlert:
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "session_id": uuid.uuid4(),
        "rule_id": "NET-001",
        "rule_name": "port_scan",
        "severity": "high",
        "explanation": "A scan.",
        "observed_value": 25.0,
        "threshold": 20.0,
        "window_seconds": 60,
        "src_ip": SCANNER,
        "dst_ip": SERVER,
        "dst_port": None,
        "protocol": "tcp",
        "first_observed": BASE,
        "last_observed": BASE,
        "created_at": BASE,
        "evidence": {},
        "enrichment": {},
    }
    values.update(fields)
    return NetworkAlert(**values)


def detail(
    row: CaptureSession,
    *,
    enabled: bool = True,
    pending: Callable[[str], bool] = lambda _address: False,
) -> SessionDetail:
    return views.session_detail(row, now=NOW, enrichment_enabled=enabled, is_pending=pending)


def peer(address: str, **fields: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "address": address,
        "first_seen": T0,
        "last_seen": T0 + 5,
        "packets": 3,
        "bytes": 300,
        "sent_to": True,
        "alerted": False,
        "peers": [HOST],
        "ports": [443],
        "protocols": ["tcp"],
    }
    entry.update(fields)
    return entry


def never_pending(_address: str) -> bool:
    return False


def as_json(model: Any) -> str:
    # Strict, as a response must be: no NaN, no Infinity.
    return json.dumps(model.model_dump(mode="json"), allow_nan=False)


# --- Small helpers -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("flags", "names"),
    [
        (None, []),
        (0, []),
        (0x01, ["FIN"]),
        (0x02, ["SYN"]),
        (0x04, ["RST"]),
        (0x08, ["PSH"]),
        (0x10, ["ACK"]),
        (0x20, ["URG"]),
        (0x40, ["ECE"]),
        (0x80, ["CWR"]),
        (0x12, ["SYN", "ACK"]),
        (0x14, ["RST", "ACK"]),
        (0x29, ["FIN", "PSH", "URG"]),
        (0xFF, ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]),
        (0x100, []),
        (0x1FF, ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]),
    ],
)
def test_tcp_flag_names(flags: int | None, names: list[str]) -> None:
    assert views.tcp_flag_names(flags) == names


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (5, 5),
        (0, 0),
        (-3, -3),
        (5.9, 5),
        (-5.9, -5),
        (True, 0),
        (False, 0),
        (None, 0),
        ("5", 0),
        ([], 0),
        ({}, 0),
        (NAN, 0),
        (INF, 0),
        (-INF, 0),
    ],
)
def test_integers_read_from_stored_json(value: Any, expected: int) -> None:
    assert views._int(value) == expected


def test_integers_take_the_given_default() -> None:
    assert views._int("x", 7) == 7
    assert views._int(NAN, 7) == 7


# --- parse_enrichment ----------------------------------------------------------------------


@pytest.mark.parametrize("raw", [None, {}, []])
def test_no_stored_lookup_means_nothing_to_look_up(raw: Any) -> None:
    result = views.parse_enrichment(raw)
    assert result.status == "not_applicable"
    assert result.message == (
        "The traffic involves no public address, so there is nothing to look up."
    )
    assert (result.address, result.risk_score, result.providers) == (None, None, [])


@pytest.mark.parametrize("status", STATES)
def test_every_known_status_is_kept(status: str) -> None:
    result = views.parse_enrichment({"status": status, "address": SCANNER})
    assert (result.status, result.address) == (status, SCANNER)


@pytest.mark.parametrize(
    ("status", "message"),
    [
        ("pending", "Waiting for the lookup."),
        ("disabled", "External enrichment is switched off."),
        ("skipped_budget", "Not looked up: the session reached its limit on lookups."),
        ("not_looked_up", "Not looked up."),
        ("completed", None),
        ("failed", None),
        ("unavailable", None),
    ],
)
def test_a_status_without_an_error_has_its_standard_message(
    status: str, message: str | None
) -> None:
    assert views.parse_enrichment({"status": status}).message == message


@pytest.mark.parametrize("code", sorted(views.ENRICHMENT_MESSAGES))
def test_each_error_code_has_its_message(code: str) -> None:
    result = views.parse_enrichment({"status": "failed", "error_code": code})
    assert result.error_code == code
    assert result.message == views.ENRICHMENT_MESSAGES[code]


def test_the_error_message_wins_over_the_status_message() -> None:
    result = views.parse_enrichment({"status": "pending", "error_code": "interrupted"})
    assert result.message == views.ENRICHMENT_MESSAGES["interrupted"]


def test_an_unknown_error_code_is_kept_without_a_message() -> None:
    result = views.parse_enrichment({"status": "failed", "error_code": "brand_new"})
    assert (result.error_code, result.message) == ("brand_new", None)


@pytest.mark.parametrize("raw", [{"address": SCANNER}, {"status": "bogus"}, {"status": None}])
def test_an_unreadable_status_becomes_unavailable(raw: dict[str, Any]) -> None:
    assert views.parse_enrichment(raw).status == "unavailable"


def test_a_completed_answer_without_evidence_says_so_and_carries_no_score() -> None:
    result = views.parse_enrichment(
        {
            "status": "completed",
            "assessed": False,
            "risk_score": 0,
            "classification": "informational",
        }
    )
    assert result.message is not None
    assert "does not mean it is safe" in result.message
    assert result.assessed is False
    assert (result.risk_score, result.classification) == (None, None)


def test_a_completed_answer_with_evidence_has_no_caveat() -> None:
    result = views.parse_enrichment(
        {"status": "completed", "assessed": True, "risk_score": 85, "classification": "malicious"}
    )
    assert (result.message, result.assessed) == (None, True)
    assert (result.risk_score, result.classification) == (85, "malicious")


@pytest.mark.parametrize("score", [True, False, 85.5, "85", [], {}, None])
def test_a_risk_score_must_be_a_whole_number(score: Any) -> None:
    assert views.parse_enrichment({"status": "completed", "risk_score": score}).risk_score is None


@pytest.mark.parametrize("assessed", ["yes", 1, 0, None, []])
def test_assessed_must_be_a_boolean(assessed: Any) -> None:
    assert views.parse_enrichment({"status": "completed", "assessed": assessed}).assessed is None


def test_an_indicator_id_and_completion_time_are_parsed() -> None:
    indicator = uuid.uuid4()
    result = views.parse_enrichment(
        {
            "status": "completed",
            "indicator_id": str(indicator),
            "completed_at": "2026-01-15T10:00:30Z",
        }
    )
    assert result.indicator_id == indicator
    assert result.completed_at == datetime(2026, 1, 15, 10, 0, 30, tzinfo=UTC)


@pytest.mark.parametrize("value", ["not-a-uuid", "", 5, [], {}, None, uuid.uuid4().int])
def test_an_unreadable_indicator_id_is_dropped(value: Any) -> None:
    assert (
        views.parse_enrichment({"status": "completed", "indicator_id": value}).indicator_id is None
    )


@pytest.mark.parametrize("value", ["yesterday", "", 1e300, NAN, INF, -1, [], {}, True])
def test_an_unreadable_completion_time_is_dropped(value: Any) -> None:
    assert (
        views.parse_enrichment({"status": "completed", "completed_at": value}).completed_at is None
    )


def test_providers_are_listed_with_fallbacks_and_a_limit() -> None:
    providers: list[Any] = [
        {"provider": "one", "display_name": "One", "status": "ok", "verdict": "malicious"},
        {"provider": "two"},
        {"provider": "three", "display_name": "", "status": "", "verdict": ""},
        {"provider": "", "display_name": "No id"},
        {"display_name": "No id either"},
        {"provider": ["list"], "display_name": "Wrong type"},
        "not a mapping",
        None,
        7,
    ]
    result = views.parse_enrichment({"status": "completed", "providers": providers})
    assert [
        (item.provider, item.display_name, item.status, item.verdict) for item in result.providers
    ] == [
        ("one", "One", "ok", "malicious"),
        ("two", "two", "unknown", None),
        ("three", "three", "unknown", None),
    ]


def test_at_most_ten_providers_are_listed() -> None:
    providers = [{"provider": f"p{index}"} for index in range(25)]
    result = views.parse_enrichment({"status": "completed", "providers": providers})
    assert [item.provider for item in result.providers] == [f"p{index}" for index in range(10)]


def test_the_enrichment_of_a_mapping_that_is_not_a_dict_is_read() -> None:
    from types import MappingProxyType

    result = views.parse_enrichment(MappingProxyType({"status": "completed", "address": RESOLVER}))
    assert (result.status, result.address) == ("completed", RESOLVER)


# --- parse_enrichment on corrupt values ----------------------------------------------------

CORRUPT_ENRICHMENTS: list[Any] = [
    [1],
    ["pending"],
    "completed",
    5,
    2.5,
    True,
    {"status": []},
    {"status": {}},
    {"status": ["completed"]},
    {"status": {"completed": 1}},
    {"status": 7},
    {"status": "completed", "providers": {"a": 1}},
    {"status": "completed", "providers": 5},
    {"status": "completed", "providers": True},
    {"status": "completed", "providers": 2.5},
    {"status": "completed", "providers": "abc"},
    {"status": "completed", "providers": [None, 1, "x", [], {"provider": ["x"]}]},
    {"status": "completed", "providers": [{"provider": "p", "status": 5, "verdict": []}]},
    {"status": "completed", "risk_score": NAN, "assessed": NAN},
    {"status": "completed", "risk_score": 10**30},
    {"status": "completed", "address": ["x"], "classification": {"a": 1}, "error_code": 5},
    {"status": "completed", "completed_at": [], "indicator_id": {}},
]


@pytest.mark.parametrize("raw", CORRUPT_ENRICHMENTS, ids=lambda raw: repr(raw)[:40])
def test_a_corrupt_enrichment_value_never_raises(raw: Any) -> None:
    result = views.parse_enrichment(raw)
    assert isinstance(result, EnrichmentOut)
    assert result.status in STATES
    as_json(result)


@pytest.mark.parametrize("raw", [[1], ["pending"], "completed", 5, 2.5, True])
def test_a_stored_value_that_is_not_an_object_reads_as_unavailable(raw: Any) -> None:
    result = views.parse_enrichment(raw)
    assert (result.status, result.address, result.providers) == ("unavailable", None, [])


@pytest.mark.parametrize("status", [[], {}, ["completed"], 7])
def test_a_status_that_is_not_text_reads_as_unavailable(status: Any) -> None:
    assert views.parse_enrichment({"status": status}).status == "unavailable"


@pytest.mark.parametrize("providers", [{"a": 1}, 5, True, 2.5, "abc"])
def test_providers_that_are_not_a_list_are_ignored(providers: Any) -> None:
    result = views.parse_enrichment({"status": "completed", "providers": providers})
    assert (result.status, result.providers) == ("completed", [])


# --- external_ips --------------------------------------------------------------------------


def addresses(items: list[Any]) -> list[str]:
    return [item.address for item in items]


def test_a_peer_entry_is_turned_into_an_external_address() -> None:
    stats = {
        "external_peers": [
            peer(
                SCANNER,
                first_seen="2026-01-15T10:00:00Z",
                last_seen=T0 + 10,
                packets=30,
                bytes=1800,
                sent_to=True,
                alerted=True,
                peers=[SERVER, HOST],
                ports=[22, 80, 443],
                protocols=["tcp", "udp"],
            )
        ]
    }
    (item,) = views.external_ips(stats, enabled=True, is_pending=never_pending)
    assert item.address == SCANNER
    assert item.first_seen == BASE
    assert item.last_seen == BASE + timedelta(seconds=10)
    assert (item.packets, item.bytes) == (30, 1800)
    assert (item.sent_to, item.alerted) == (True, True)
    assert (item.peers, item.ports, item.protocols) == (
        [SERVER, HOST],
        [22, 80, 443],
        ["tcp", "udp"],
    )
    assert item.enrichment.status == "not_looked_up"


def test_peer_lists_are_cleaned_and_limited() -> None:
    entry = peer(
        SCANNER,
        peers=[*(f"10.0.0.{index}" for index in range(1, 30)), None, 5],
        ports=[True, -1, 65536, 80, "443", 2.5, 0, 65535, *range(1000, 1020)],
        protocols=["tcp", 6, None, "udp"],
    )
    (item,) = views.external_ips(
        {"external_peers": [entry]}, enabled=True, is_pending=never_pending
    )
    assert item.peers == [f"10.0.0.{index}" for index in range(1, 11)]
    assert item.ports[:3] == [80, 0, 65535]
    assert len(item.ports) == 10
    assert item.protocols == ["tcp", "udp"]


def test_an_address_is_listed_once_and_entries_without_one_are_skipped() -> None:
    stats = {
        "external_peers": [
            peer(SCANNER, bytes=100),
            peer(SCANNER, bytes=999),
            peer("", bytes=5),
            {"packets": 1},
            peer(RESOLVER),
        ]
    }
    items = views.external_ips(stats, enabled=True, is_pending=never_pending)
    assert sorted(addresses(items)) == sorted([SCANNER, RESOLVER])
    assert next(item for item in items if item.address == SCANNER).bytes == 100


def test_addresses_are_sorted_alerted_first_then_by_volume_then_by_address() -> None:
    stats = {
        "external_peers": [
            peer("9.9.9.9", bytes=10),
            peer("8.8.4.4", bytes=500),
            peer("1.1.1.1", bytes=500),
            peer("45.33.32.156", bytes=1, alerted=True),
            peer("93.184.216.34", bytes=2, alerted=True),
        ]
    }
    items = views.external_ips(stats, enabled=True, is_pending=never_pending)
    assert addresses(items) == [
        "93.184.216.34",
        "45.33.32.156",
        "1.1.1.1",
        "8.8.4.4",
        "9.9.9.9",
    ]


def test_at_most_one_hundred_addresses_are_returned_and_alerted_ones_are_kept() -> None:
    peers = [peer(f"20.0.{index // 250}.{index % 250 + 1}", bytes=index) for index in range(150)]
    peers[3]["alerted"] = True
    peers[7]["alerted"] = True
    items = views.external_ips({"external_peers": peers}, enabled=True, is_pending=never_pending)
    assert len(items) == 100
    assert [item.alerted for item in items[:3]] == [True, True, False]
    assert peers[3]["address"] in addresses(items)
    assert peers[7]["address"] in addresses(items)


def test_the_lookup_state_comes_from_the_answer_or_the_queue_or_the_settings() -> None:
    answer = {"status": "completed", "address": SCANNER, "risk_score": 80, "assessed": True}
    stats = {
        "external_peers": [peer(SCANNER), peer(RESOLVER), peer("9.9.9.9"), peer("1.1.1.1")],
        "enrichment": {SCANNER: answer, "1.1.1.1": {}},
    }

    def pending(address: str) -> bool:
        return address == RESOLVER

    enabled = {
        item.address: item.enrichment.status
        for item in views.external_ips(stats, enabled=True, is_pending=pending)
    }
    assert enabled == {
        SCANNER: "completed",
        RESOLVER: "pending",
        "9.9.9.9": "not_looked_up",
        "1.1.1.1": "not_looked_up",
    }
    disabled = {
        item.address: item.enrichment.status
        for item in views.external_ips(stats, enabled=False, is_pending=pending)
    }
    # An answer that was already stored stays visible after the lookups are switched off.
    assert disabled == {
        SCANNER: "completed",
        RESOLVER: "disabled",
        "9.9.9.9": "disabled",
        "1.1.1.1": "disabled",
    }


def test_an_answer_without_traffic_details_is_still_listed() -> None:
    stats = {
        "external_peers": [peer(SCANNER)],
        "enrichment": {
            SCANNER: {"status": "completed"},
            RESOLVER: {"status": "failed", "error_code": "rate_limited"},
            "9.9.9.9": "garbage",
            "1.1.1.1": None,
        },
    }
    items = {
        item.address: item
        for item in views.external_ips(stats, enabled=True, is_pending=never_pending)
    }
    assert sorted(items) == sorted([SCANNER, RESOLVER])
    evicted = items[RESOLVER]
    assert (evicted.packets, evicted.bytes, evicted.first_seen, evicted.last_seen) == (
        None,
        None,
        None,
        None,
    )
    assert (evicted.sent_to, evicted.alerted, evicted.peers, evicted.ports) == (
        False,
        False,
        [],
        [],
    )
    assert evicted.enrichment.error_code == "rate_limited"


def test_no_stats_means_no_addresses() -> None:
    assert views.external_ips({}, enabled=True, is_pending=never_pending) == []


@pytest.mark.parametrize(
    "peers",
    [5, 2.5, True, "text", {"a": 1}, {"address": SCANNER}, [None, 1, "x", [], {"address": 5}]],
)
def test_peers_that_are_not_a_list_of_objects_are_ignored(peers: Any) -> None:
    assert (
        views.external_ips({"external_peers": peers}, enabled=True, is_pending=never_pending) == []
    )


@pytest.mark.parametrize("results", [[], "text", 5, True, None, ["x"]])
def test_results_that_are_not_an_object_are_ignored(results: Any) -> None:
    stats = {"external_peers": [peer(SCANNER)], "enrichment": results}
    (item,) = views.external_ips(stats, enabled=True, is_pending=never_pending)
    assert item.enrichment.status == "not_looked_up"


@pytest.mark.parametrize("number", [NAN, INF, -INF, "12", True, None, [], {}, 1e308])
def test_an_odd_traffic_counter_never_raises(number: Any) -> None:
    stats = {"external_peers": [peer(SCANNER, packets=number, bytes=number)]}
    (item,) = views.external_ips(stats, enabled=True, is_pending=never_pending)
    as_json(item)


@pytest.mark.parametrize("when", ["yesterday", "", NAN, INF, 1e300, -5, [], {}, True, None])
def test_an_odd_traffic_time_is_dropped(when: Any) -> None:
    stats = {"external_peers": [peer(SCANNER, first_seen=when, last_seen=when)]}
    (item,) = views.external_ips(stats, enabled=True, is_pending=never_pending)
    assert (item.first_seen, item.last_seen) == (None, None)


# --- summarize_enrichment ------------------------------------------------------------------


def test_the_summary_counts_each_state() -> None:
    stats = {
        "external_peers": [peer(f"20.0.0.{index}", bytes=index) for index in range(1, 9)],
        "enrichment": {
            "20.0.0.1": {"status": "completed"},
            "20.0.0.2": {"status": "completed"},
            "20.0.0.3": {"status": "failed", "error_code": "provider_error"},
            "20.0.0.4": {"status": "unavailable"},
            "20.0.0.5": {"status": "skipped_budget"},
        },
    }
    items = views.external_ips(stats, enabled=True, is_pending=lambda a: a == "20.0.0.6")
    summary = views.summarize_enrichment(items, enabled=True)
    assert summary.model_dump() == {
        "enabled": True,
        "total": 8,
        "completed": 2,
        "pending": 1,
        "failed": 1,
        "unavailable": 1,
        # skipped_budget, plus the two never looked up
        "skipped": 3,
    }


def test_the_summary_of_a_disabled_session_counts_everything_as_skipped() -> None:
    stats = {"external_peers": [peer(SCANNER), peer(RESOLVER)]}
    items = views.external_ips(stats, enabled=False, is_pending=never_pending)
    summary = views.summarize_enrichment(items, enabled=False)
    assert (summary.enabled, summary.total, summary.skipped, summary.completed) == (False, 2, 2, 0)


def test_the_summary_of_nothing_is_empty() -> None:
    assert views.summarize_enrichment([], enabled=True).model_dump() == {
        "enabled": True,
        "total": 0,
        "completed": 0,
        "pending": 0,
        "failed": 0,
        "unavailable": 0,
        "skipped": 0,
    }


# --- session_out ---------------------------------------------------------------------------


def test_a_finished_session_reports_its_stored_numbers() -> None:
    row = session_row(
        status="failed",
        started=BASE,
        ended=BASE + timedelta(seconds=42),
        error_code="capture_failed",
        stats={"active_flows": 17},
    )
    out = views.session_out(row, now=NOW)
    assert (out.id, out.source_kind, out.status) == (row.id, "pcap", "failed")
    assert (out.packets_total, out.bytes_total, out.flows_total) == (10, 1000, 3)
    assert (out.alerts_total, out.packets_dropped) == (1, 2)
    assert out.duration_seconds == 42.0
    assert out.error_code == "capture_failed"
    assert out.message == ERRORS["capture_failed"].message
    assert out.source_label == "scan.pcap"


@pytest.mark.parametrize("status", ["starting", "running", "stopping"])
def test_a_session_in_progress_counts_its_duration_up_to_now_and_shows_active_flows(
    status: str,
) -> None:
    out = views.session_out(session_row(status=status, stats={"active_flows": 17}), now=NOW)
    assert out.duration_seconds == 90.0
    assert out.active_flows == 17
    assert out.ended_at is None


@pytest.mark.parametrize("status", ["stopped", "completed", "failed", "permission_denied"])
def test_a_finished_session_has_no_active_flows(status: str) -> None:
    out = views.session_out(session_row(status=status, stats={"active_flows": 17}), now=NOW)
    assert out.active_flows == 0


def test_a_duration_is_never_negative() -> None:
    started = NOW + timedelta(hours=1)
    assert (
        views.session_out(session_row(status="running", started=started), now=NOW).duration_seconds
        == 0.0
    )
    ended_early = session_row(started=BASE, ended=BASE - timedelta(seconds=5))
    assert views.session_out(ended_early, now=NOW).duration_seconds == 0.0


@pytest.mark.parametrize(
    ("code", "message"),
    [
        (None, None),
        ("capture_permission_denied", ERRORS["capture_permission_denied"].message),
        ("not_a_known_code", "The session ended with an error."),
    ],
)
def test_the_session_message_follows_the_error_code(code: str | None, message: str | None) -> None:
    assert views.session_out(session_row(error_code=code), now=NOW).message == message


@pytest.mark.parametrize("stats", [None, [], "text", 5, True])
def test_a_session_whose_stats_are_not_an_object_still_reads(stats: Any) -> None:
    row = session_row(status="running")
    row.stats = stats
    assert views.session_out(row, now=NOW).active_flows == 0
    assert (
        views.session_detail(
            row, now=NOW, enrichment_enabled=True, is_pending=never_pending
        ).protocols
        == []
    )


@pytest.mark.parametrize("flows", [NAN, INF, -INF, "9", True, None, [], {}])
def test_an_odd_active_flow_count_reads_as_zero(flows: Any) -> None:
    out = views.session_out(session_row(status="running", stats={"active_flows": flows}), now=NOW)
    assert out.active_flows == 0


# --- session_detail ------------------------------------------------------------------------


def full_stats() -> dict[str, Any]:
    return {
        "first_packet_at": T0,
        "last_packet_at": "2026-01-15T10:01:00Z",
        "protocols": [
            {"protocol": "tcp", "packets": 100, "bytes": 6000},
            {"protocol": "udp", "packets": 5, "bytes": 500},
        ],
        "top_sources": [{"address": SCANNER, "packets": 90, "bytes": 5400}],
        "top_destinations": [{"address": SERVER, "packets": 95, "bytes": 5700}],
        "non_ip_packets": 4,
        "malformed_packets": 2,
        "flows_evicted": 1,
        "flows_stored": 30,
        "flows_not_stored": 3,
        "alerts_by_rule": {"NET-001": 2, "NET-006": 1},
        "alerts_suppressed": 7,
        "alerts_lost": 1,
        "talkers_truncated": True,
        "external_peers": [peer(SCANNER, alerted=True)],
        "enrichment": {SCANNER: {"status": "completed", "address": SCANNER, "risk_score": 90}},
    }


def test_the_detail_reads_every_statistic() -> None:
    row = session_row(stats=full_stats(), ended=BASE + timedelta(seconds=60))
    out = detail(row)
    assert out.first_packet_at == BASE
    assert out.last_packet_at == BASE + timedelta(seconds=60)
    assert [(item.protocol, item.packets, item.bytes) for item in out.protocols] == [
        ("tcp", 100, 6000),
        ("udp", 5, 500),
    ]
    assert [(item.address, item.packets, item.bytes) for item in out.top_sources] == [
        (SCANNER, 90, 5400)
    ]
    assert [item.address for item in out.top_destinations] == [SERVER]
    assert (out.non_ip_packets, out.malformed_packets) == (4, 2)
    assert (out.flows_evicted, out.flows_stored, out.flows_not_stored) == (1, 30, 3)
    assert out.alerts_by_rule == {"NET-001": 2, "NET-006": 1}
    assert (out.alerts_suppressed, out.alerts_lost, out.talkers_truncated) == (7, 1, True)
    assert [item.address for item in out.external_ips] == [SCANNER]
    assert out.external_ips[0].enrichment.risk_score == 90
    assert (out.enrichment.total, out.enrichment.completed) == (1, 1)
    # The detail carries everything the summary has.
    summary = views.session_out(row, now=NOW).model_dump()
    assert {key: getattr(out, key) for key in summary} == summary


def test_a_session_without_statistics_reads_as_empty() -> None:
    out = detail(session_row(stats={}))
    assert (out.first_packet_at, out.last_packet_at) == (None, None)
    assert (out.protocols, out.top_sources, out.top_destinations) == ([], [], [])
    assert (out.non_ip_packets, out.malformed_packets, out.flows_not_stored) == (0, 0, 0)
    assert (out.alerts_by_rule, out.external_ips, out.talkers_truncated) == ({}, [], False)
    assert out.enrichment.total == 0


def test_the_detail_passes_the_enrichment_setting_and_queue_to_the_addresses() -> None:
    stats = {"external_peers": [peer(SCANNER), peer(RESOLVER)]}
    out = detail(session_row(stats=stats), pending=lambda address: address == SCANNER)
    states = {item.address: item.enrichment.status for item in out.external_ips}
    assert states == {SCANNER: "pending", RESOLVER: "not_looked_up"}
    assert (out.enrichment.enabled, out.enrichment.pending) == (True, 1)
    off = detail(session_row(stats=stats), enabled=False)
    assert {item.enrichment.status for item in off.external_ips} == {"disabled"}
    assert (off.enrichment.enabled, off.enrichment.skipped) == (False, 2)


def test_protocol_and_talker_rows_without_a_name_are_skipped() -> None:
    stats = {
        "protocols": [
            {"protocol": "", "packets": 1},
            {"packets": 2},
            None,
            "tcp",
            {"protocol": "icmp", "packets": "many", "bytes": None},
        ],
        "top_sources": [{"address": "", "packets": 1}, {"packets": 1}, None, 7],
        "top_destinations": [{"address": SERVER}],
    }
    out = detail(session_row(stats=stats))
    assert [(item.protocol, item.packets, item.bytes) for item in out.protocols] == [("icmp", 0, 0)]
    assert out.top_sources == []
    assert [(item.address, item.packets) for item in out.top_destinations] == [(SERVER, 0)]


@pytest.mark.parametrize("value", [5, 2.5, True, "text", {"a": 1}, [], None, [None, 1, "x"]])
@pytest.mark.parametrize("field", ["protocols", "top_sources", "top_destinations"])
def test_a_list_statistic_that_is_not_a_list_reads_as_empty(field: str, value: Any) -> None:
    out = detail(session_row(stats={field: value}))
    assert getattr(out, field) == []


@pytest.mark.parametrize("field", ["alerts_by_rule", "enrichment_alerts"])
@pytest.mark.parametrize("value", [[], "text", 5, True, None, [("NET-001", 1)]])
def test_alerts_by_rule_that_is_not_an_object_reads_as_empty(field: str, value: Any) -> None:
    assert detail(session_row(stats={field: value})).alerts_by_rule == {}


def test_alerts_raised_by_enrichment_are_counted_with_the_monitors_own() -> None:
    stats = {"alerts_by_rule": {"NET-001": 2}, "enrichment_alerts": {"NET-001": 1, "NET-005": 1}}
    assert detail(session_row(stats=stats)).alerts_by_rule == {"NET-001": 3, "NET-005": 1}
    only_enrichment = {"enrichment_alerts": {"NET-005": 2}}
    assert detail(session_row(stats=only_enrichment)).alerts_by_rule == {"NET-005": 2}


def test_alerts_by_rule_counts_are_read_one_by_one() -> None:
    stats = {"alerts_by_rule": {"NET-001": 3, "NET-002": "x", "NET-003": NAN, "NET-004": True}}
    assert detail(session_row(stats=stats)).alerts_by_rule == {
        "NET-001": 3,
        "NET-002": 0,
        "NET-003": 0,
        "NET-004": 0,
    }


NASTY_STATS: list[tuple[str, Any]] = [
    ("protocols", 5),
    ("protocols", True),
    ("protocols", [{"protocol": "tcp", "packets": NAN, "bytes": INF}]),
    ("top_sources", 5),
    ("top_sources", [{"address": SCANNER, "packets": NAN, "bytes": -INF}]),
    ("top_destinations", 2.5),
    ("external_peers", 5),
    ("external_peers", True),
    ("external_peers", [peer(SCANNER, packets=NAN, bytes=INF)]),
    ("enrichment", [SCANNER]),
    ("enrichment", {SCANNER: [1]}),
    ("enrichment", {SCANNER: {"status": []}}),
    ("enrichment", {SCANNER: {"status": "completed", "providers": 5}}),
    ("alerts_by_rule", {"NET-001": NAN}),
    ("alerts_by_rule", [1]),
    ("enrichment_alerts", {"NET-005": NAN}),
    ("enrichment_alerts", [1]),
    ("non_ip_packets", NAN),
    ("malformed_packets", INF),
    ("flows_evicted", -INF),
    ("flows_stored", "3"),
    ("flows_not_stored", [3]),
    ("alerts_suppressed", {}),
    ("alerts_lost", None),
    ("talkers_truncated", [1]),
    ("first_packet_at", NAN),
    ("last_packet_at", [1]),
    ("active_flows", INF),
]


@pytest.mark.parametrize(("field", "value"), NASTY_STATS, ids=lambda item: repr(item)[:30])
@pytest.mark.parametrize("status", ["running", "completed"])
def test_a_corrupt_statistic_never_breaks_the_session_detail(
    status: str, field: str, value: Any
) -> None:
    stats = full_stats()
    stats[field] = value
    out = detail(session_row(status=status, stats=stats))
    assert isinstance(out, SessionDetail)
    as_json(out)
    # Everything the corrupt value did not touch is still read.
    assert (out.packets_total, out.alerts_total) == (10, 1)
    # ... and the page of sessions can still be built from the same row.
    as_json(views.session_out(session_row(status=status, stats=stats), now=NOW))


def test_a_row_with_every_statistic_corrupt_still_reads() -> None:
    stats = dict.fromkeys(full_stats(), 5)
    out = detail(session_row(status="running", stats=stats))
    assert (out.protocols, out.top_sources, out.external_ips) == ([], [], [])
    as_json(out)


# --- flows and alerts ----------------------------------------------------------------------


def test_a_flow_is_turned_into_its_response() -> None:
    row = NetworkFlow(
        id=7,
        session_id=uuid.uuid4(),
        protocol="tcp",
        src_ip=HOST,
        src_port=40000,
        dst_ip=SERVER,
        dst_port=443,
        first_seen=BASE,
        last_seen=BASE + timedelta(seconds=2.5),
        packets_out=4,
        packets_in=3,
        bytes_out=240,
        bytes_in=180,
        tcp_flags=0x12,
        close_reason="closed",
    )
    out = views.flow_out(row)
    assert (out.id, out.protocol, out.src_ip, out.src_port) == (7, "tcp", HOST, 40000)
    assert (out.dst_ip, out.dst_port, out.close_reason) == (SERVER, 443, "closed")
    assert out.duration_seconds == 2.5
    assert (out.packets_out, out.packets_in, out.bytes_out, out.bytes_in) == (4, 3, 240, 180)
    assert (out.tcp_flags, out.tcp_flag_names) == (0x12, ["SYN", "ACK"])


def test_a_flow_without_ports_or_flags_has_none() -> None:
    row = NetworkFlow(
        id=8,
        session_id=uuid.uuid4(),
        protocol="icmp",
        src_ip=HOST,
        src_port=None,
        dst_ip=RESOLVER,
        dst_port=None,
        first_seen=BASE,
        last_seen=BASE,
        packets_out=1,
        packets_in=0,
        bytes_out=84,
        bytes_in=0,
        tcp_flags=None,
        close_reason="idle",
    )
    out = views.flow_out(row)
    assert (out.src_port, out.dst_port, out.tcp_flags, out.tcp_flag_names) == (None, None, None, [])
    assert out.duration_seconds == 0.0


def test_a_known_rule_supplies_the_alert_title_and_unit() -> None:
    out = views.alert_out(alert_row(rule_id="NET-004", rule_name="high_volume"))
    assert (out.title, out.unit) == ("High traffic volume", "MB")
    assert (out.rule_id, out.rule_name, out.severity) == ("NET-004", "high_volume", "high")
    assert (out.observed_value, out.threshold, out.window_seconds) == (25.0, 20.0, 60)
    assert (out.src_ip, out.dst_ip, out.dst_port, out.protocol) == (SCANNER, SERVER, None, "tcp")


def test_an_alert_of_an_unknown_rule_falls_back_to_its_stored_name() -> None:
    out = views.alert_out(alert_row(rule_id="NET-099", rule_name="future_rule"))
    assert (out.title, out.unit) == ("future_rule", "")


def test_the_alert_carries_its_evidence_and_lookup() -> None:
    evidence = {"ports": [22, 80], "nested": {"a": 1}}
    enrichment = {"status": "completed", "address": SCANNER, "risk_score": 70, "assessed": True}
    out = views.alert_out(alert_row(evidence=evidence, enrichment=enrichment))
    assert out.evidence == evidence
    assert (out.enrichment.status, out.enrichment.risk_score) == ("completed", 70)


@pytest.mark.parametrize("evidence", [[1], "text", 5, True, None])
def test_alert_evidence_that_is_not_an_object_reads_as_empty(evidence: Any) -> None:
    assert views.alert_out(alert_row(evidence=evidence)).evidence == {}


@pytest.mark.parametrize("enrichment", CORRUPT_ENRICHMENTS, ids=lambda raw: repr(raw)[:40])
def test_an_alert_with_a_corrupt_lookup_still_reads(enrichment: Any) -> None:
    out = views.alert_out(alert_row(enrichment=enrichment))
    assert out.enrichment.status in STATES
    as_json(out)


def test_an_alert_without_a_lookup_has_nothing_to_look_up() -> None:
    assert views.alert_out(alert_row(enrichment={})).enrichment.status == "not_applicable"


# --- rules ---------------------------------------------------------------------------------


def test_every_rule_is_described_with_its_settings() -> None:
    settings = describe_rules(NetworkRuleConfig())
    outs = [views.rule_out(setting, enrichment_enabled=True) for setting in settings]
    assert [out.rule_id for out in outs] == [rule.rule_id for rule in ALL_RULES]
    by_id = {out.rule_id: out for out in outs}
    assert (by_id["NET-001"].threshold, by_id["NET-001"].window_seconds) == (20.0, 60)
    assert by_id["NET-001"].unit == "ports"
    assert by_id["NET-001"].severities == ["medium", "high", "critical"]
    assert by_id["NET-005"].window_seconds is None
    assert by_id["NET-005"].detail is not None
    assert all(out.active for out in outs)


def test_only_the_rule_that_needs_lookups_is_inactive_when_they_are_off() -> None:
    inactive = [
        views.rule_out(setting, enrichment_enabled=False).rule_id
        for setting in describe_rules(NetworkRuleConfig())
        if not views.rule_out(setting, enrichment_enabled=False).active
    ]
    assert inactive == ["NET-005"]
