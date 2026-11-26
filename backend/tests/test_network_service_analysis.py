"""NetworkService, capture files: from an upload in the spool to a finished, stored session.

The database, the analyzer, the recorder, the enrichment worker and the analysis thread are real.
The intelligence service is a double. Analyses are held at their start with a gate wherever a test
needs to look at the service while one is running.
"""

import logging
import threading
from collections import Counter
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.errors import ApiError
from app.database.session import build_engine, build_session_factory
from app.network import service as service_module
from tests.network_helpers import (
    ALICE,
    BOB,
    RESOLVER,
    SCAN_FLOWS,
    SCAN_FRAMES,
    SCANNER,
    SERVER,
    T0,
    AnalysisGate,
    Background,
    ServiceRig,
    StubIntel,
    assert_no_module_threads,
    assert_not_logged,
    hold_analyses,
    logged,
    provider_view,
    reply,
    rig_builder,
    scan_capture_files,
    scapy_arp,
    scapy_syn,
    wait_until,
    write_pcap,
)

SessionFactory = sessionmaker[Session]
NAME = "confidential-file-name.pcap"
SECOND_SCANNER = "93.184.216.34"


@pytest.fixture
def factory(make_settings: Callable[..., Settings], db_url: str) -> Iterator[SessionFactory]:
    engine = build_engine(make_settings(database_url=db_url))
    yield build_session_factory(engine)
    engine.dispose()


@pytest.fixture(autouse=True)
def _no_leaked_threads() -> Iterator[None]:
    yield
    assert_no_module_threads()


@pytest.fixture
def make_rig(
    factory: SessionFactory,
    make_settings: Callable[..., Settings],
    db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Callable[..., ServiceRig]]:
    yield from rig_builder(factory, make_settings, db_url, tmp_path / "spool", monkeypatch)


@pytest.fixture
def rig(make_rig: Callable[..., ServiceRig]) -> ServiceRig:
    return make_rig()


@pytest.fixture(scope="module")
def scan_files(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bytes]:
    return scan_capture_files(tmp_path_factory.mktemp("scan"))


@pytest.fixture
def hold_analysis(rig: ServiceRig, monkeypatch: pytest.MonkeyPatch) -> AnalysisGate:
    gate = hold_analyses(monkeypatch)
    rig.gates.append(gate.release)
    return gate


def target_of(session_id: Any) -> str:
    return f"network-session:{session_id}"


def idle(rig: ServiceRig) -> bool:
    return not rig.status().analysis.running


def seconds_apart(first: datetime | None, second: datetime) -> float:
    assert first is not None
    return abs((first - second).total_seconds())


# --- A file from upload to finished session -------------------------------------------------------


@pytest.mark.parametrize("kind", ["pcap", "pcapng"])
def test_an_uploaded_file_is_analysed_into_a_finished_session(
    rig: ServiceRig, scan_files: dict[str, bytes], kind: str, caplog: pytest.LogCaptureFixture
) -> None:
    data = scan_files[kind]

    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        accepted = rig.analyze(data, ALICE, name=NAME)
        row = rig.wait_for_end(accepted.id)
        wait_until(lambda: not rig.spool_files(), what="the upload to be removed")

    assert (row.status, row.error_code) == ("completed", None)
    assert (row.owner, row.source_kind, row.source_label, row.interface) == (
        "alice",
        "pcap",
        NAME,
        None,
    )
    assert (row.packets_total, row.flows_total, row.alerts_total) == (
        SCAN_FRAMES - 1,
        SCAN_FLOWS,
        1,
    )
    assert row.packets_dropped == 0
    assert row.stats["non_ip_packets"] == 1
    assert row.ended_at is not None and row.ended_at >= row.started_at
    assert len(rig.flows(accepted.id)) == SCAN_FLOWS
    (alert,) = rig.alerts(accepted.id)
    assert (alert.rule_id, alert.src_ip) == ("NET-001", SCANNER)
    # The file's own clock is the analysis clock, not the time of the upload.
    shown = rig.call("get_session", ALICE.actor, accepted.id)
    assert seconds_apart(shown.first_packet_at, datetime.fromtimestamp(T0, UTC)) < 0.001
    assert seconds_apart(shown.last_packet_at, datetime.fromtimestamp(T0 + 6, UTC)) < 0.001
    start = datetime.fromtimestamp(T0, UTC)
    assert start <= alert.first_observed <= alert.last_observed <= start + timedelta(seconds=7)
    # What was recorded about the action names the session and the file's shape, not its name.
    (entry,) = rig.audit("NETWORK_PCAP_ANALYZE")
    assert (entry.actor, entry.result, entry.target) == (
        "alice",
        "success",
        target_of(accepted.id),
    )
    assert entry.source_ip == ALICE.source_ip
    assert entry.details == {
        "size_bytes": len(data),
        "format": kind,
        "packets": SCAN_FRAMES,
        "truncated": False,
    }
    assert NAME not in str(entry.details) and NAME not in caplog.text


def test_the_session_returned_for_an_accepted_file_starts_from_nothing(
    rig: ServiceRig, scan_files: dict[str, bytes], hold_analysis: AnalysisGate
) -> None:
    accepted = rig.analyze(scan_files["pcap"], ALICE, name=NAME)

    wait_until(hold_analysis.entered.is_set, what="the analysis to begin")
    assert (accepted.status, accepted.source_kind, accepted.source_label) == (
        "running",
        "pcap",
        NAME,
    )
    assert (accepted.packets_total, accepted.bytes_total, accepted.flows_total) == (0, 0, 0)
    assert (accepted.alerts_total, accepted.packets_dropped, accepted.active_flows) == (0, 0, 0)
    assert accepted.ended_at is None and accepted.error_code is None
    assert accepted.protocols == [] and accepted.top_sources == []
    assert accepted.external_ips == [] and accepted.alerts_by_rule == {}
    assert (accepted.non_ip_packets, accepted.malformed_packets, accepted.flows_stored) == (0, 0, 0)
    # What the next request is told is the same.
    stored = rig.call("get_session", ALICE.actor, accepted.id)
    assert stored.model_dump(exclude={"duration_seconds"}) == accepted.model_dump(
        exclude={"duration_seconds"}
    )
    hold_analysis.release.set()
    assert rig.wait_for_end(accepted.id).status == "completed"


def test_a_file_without_ip_traffic_completes_with_nothing_to_show(
    rig: ServiceRig, tmp_path: Path
) -> None:
    path = write_pcap(tmp_path / "arp.pcap", [scapy_arp(T0), scapy_arp(T0 + 1)])

    accepted = rig.analyze(path.read_bytes())
    row = rig.wait_for_end(accepted.id)

    assert (row.status, row.error_code) == ("completed", None)
    assert (row.packets_total, row.flows_total, row.alerts_total) == (0, 0, 0)
    assert row.stats["non_ip_packets"] == 2
    assert rig.flows(accepted.id) == [] and rig.alerts(accepted.id) == []
    assert rig.intel.calls == []


def test_a_file_cut_short_is_analysed_as_far_as_it_goes(
    rig: ServiceRig, scan_files: dict[str, bytes]
) -> None:
    # The last record, the ARP frame, is cut in half. Everything before it is analysed.
    data = scan_files["pcap"][:-7]

    accepted = rig.analyze(data)
    row = rig.wait_for_end(accepted.id)

    assert (row.status, row.error_code) == ("completed", "capture_truncated")
    assert (row.packets_total, row.flows_total, row.alerts_total) == (
        SCAN_FRAMES - 1,
        SCAN_FLOWS,
        1,
    )
    assert row.stats["non_ip_packets"] == 0
    (entry,) = rig.audit("NETWORK_PCAP_ANALYZE")
    assert entry.details["truncated"] is True
    assert entry.details["packets"] == SCAN_FRAMES - 1
    shown = rig.call("get_session", ALICE.actor, accepted.id)
    assert (shown.status, shown.error_code) == ("completed", "capture_truncated")
    assert shown.message


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"this is not a capture file", id="text"),
        pytest.param(b"\xd4\xc3\xb2\xa1\x02\x00", id="header-cut-short"),
        pytest.param(b"\x00" * 64, id="zeros"),
    ],
)
def test_a_file_that_is_not_a_capture_is_refused_and_leaves_no_trace(
    rig: ServiceRig, data: bytes
) -> None:
    with pytest.raises(ApiError) as caught:
        rig.analyze(data, ALICE, name=NAME)

    assert (caught.value.status_code, caught.value.code) == (422, "invalid_capture_file")
    assert rig.sessions() == []
    assert rig.spool_files() == []
    (entry,) = rig.audit("NETWORK_PCAP_ANALYZE")
    assert (entry.actor, entry.result, entry.target) == ("alice", "rejected", None)
    assert entry.details == {"reason": "invalid_capture_file", "size_bytes": len(data)}
    assert NAME not in str(entry.details)
    assert idle(rig)


# --- One analysis at a time -----------------------------------------------------------------------


def test_a_second_file_is_refused_while_one_is_being_analysed(
    rig: ServiceRig, scan_files: dict[str, bytes], hold_analysis: AnalysisGate
) -> None:
    first = rig.analyze(scan_files["pcap"], ALICE)
    wait_until(hold_analysis.entered.is_set, what="the analysis to begin")

    with pytest.raises(ApiError) as early:
        rig.service.ensure_analysis_idle()
    with pytest.raises(ApiError) as refused:
        rig.analyze(scan_files["pcapng"], BOB, name="second.pcapng")

    for caught in (early, refused):
        assert (caught.value.status_code, caught.value.code) == (409, "analysis_already_running")
    # Only the first upload is still in the spool, and only the first session exists.
    assert len(rig.spool_files()) == 1
    assert [row.id for row in rig.sessions()] == [first.id]
    (rejection,) = [
        entry for entry in rig.audit("NETWORK_PCAP_ANALYZE") if entry.result != "success"
    ]
    assert (rejection.actor, rejection.result, rejection.target) == ("bob", "rejected", None)
    assert rejection.details == {"reason": "analysis_already_running"}

    hold_analysis.release.set()
    assert rig.wait_for_end(first.id).status == "completed"
    wait_until(lambda: idle(rig), what="the analysis slot to be released")
    rig.service.ensure_analysis_idle()
    second = rig.analyze(scan_files["pcapng"], BOB)
    assert rig.wait_for_end(second.id).status == "completed"


def test_of_simultaneous_uploads_exactly_one_is_analysed(
    rig: ServiceRig, scan_files: dict[str, bytes], hold_analysis: AnalysisGate
) -> None:
    calls = [Background(rig.analyze, scan_files["pcap"], ALICE, f"scan-{n}.pcap") for n in range(5)]
    for call in calls:
        call.join()

    winners = [call for call in calls if call.error is None]
    refusals = [call.error for call in calls if call.error is not None]
    assert len(winners) == 1
    assert [(e.status_code, e.code) for e in refusals if isinstance(e, ApiError)] == [
        (409, "analysis_already_running")
    ] * 4
    assert len(refusals) == 4
    assert len(rig.sessions()) == 1
    assert len(rig.spool_files()) == 1
    assert Counter(entry.result for entry in rig.audit("NETWORK_PCAP_ANALYZE")) == {
        "success": 1,
        "rejected": 4,
    }

    hold_analysis.release.set()
    assert rig.wait_for_end(winners[0].result.id).status == "completed"


def test_the_analysis_status_names_the_session_to_its_owner_only(
    rig: ServiceRig, scan_files: dict[str, bytes], hold_analysis: AnalysisGate
) -> None:
    accepted = rig.analyze(scan_files["pcap"], ALICE)
    wait_until(hold_analysis.entered.is_set, what="the analysis to begin")

    own, other = rig.status(ALICE).analysis, rig.status(BOB).analysis

    assert (own.running, own.session_id) == (True, accepted.id)
    assert (other.running, other.session_id) == (True, None)
    assert own.max_upload_mb == other.max_upload_mb == rig.settings.network_max_pcap_size_mb
    hold_analysis.release.set()
    rig.wait_for_end(accepted.id)
    wait_until(lambda: idle(rig), what="the analysis slot to be released")
    assert rig.status(ALICE).analysis.session_id is None


def test_a_file_can_be_analysed_while_a_capture_runs(
    rig: ServiceRig, scan_files: dict[str, bytes]
) -> None:
    capture = rig.start(ALICE)
    assert capture.session_id is not None

    accepted = rig.analyze(scan_files["pcap"], BOB)

    assert rig.wait_for_end(accepted.id).status == "completed"
    assert rig.status(ALICE).state == "running"
    assert rig.row(capture.session_id).packets_total == 0
    rig.stop(ALICE)


# --- What happens when something goes wrong -----------------------------------------------------


def test_a_file_is_not_kept_when_its_session_cannot_be_stored(
    rig: ServiceRig, scan_files: dict[str, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    upload = rig.upload(scan_files["pcap"])

    def broken() -> None:
        raise OperationalError("COMMIT", {}, Exception("the database is down"))

    with rig.factory() as db:
        monkeypatch.setattr(db, "commit", broken)
        with pytest.raises(OperationalError):
            rig.service.analyze_pcap(db, ALICE, upload=upload, name=NAME)

    assert rig.sessions() == [] and rig.audit() == []
    assert rig.spool_files() == []
    rig.service.ensure_analysis_idle()
    accepted = rig.analyze(scan_files["pcap"])
    assert rig.wait_for_end(accepted.id).status == "completed"


def test_a_file_whose_analysis_cannot_be_set_up_leaves_nothing_behind(
    rig: ServiceRig, scan_files: dict[str, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("cannot build")

    with monkeypatch.context() as patch:
        patch.setattr(service_module, "SessionMonitor", broken)
        with pytest.raises(RuntimeError):
            rig.analyze(scan_files["pcap"])

    # No session is left "running" for good, no upload is left behind and the slot is free.
    assert rig.sessions() == []
    assert rig.spool_files() == []
    rig.service.ensure_analysis_idle()
    accepted = rig.analyze(scan_files["pcap"])
    assert rig.wait_for_end(accepted.id).status == "completed"


def test_an_analysis_that_cannot_be_started_ends_its_session_as_failed(
    rig: ServiceRig,
    scan_files: dict[str, bytes],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def broken(self: Any, job: Callable[[], None]) -> None:
        raise RuntimeError("can't start new thread: details-that-must-not-be-logged")

    monkeypatch.setattr(service_module.PcapRunner, "launch", broken)

    with (
        caplog.at_level(logging.DEBUG, logger="cipherforge.network"),
        pytest.raises(ApiError) as caught,
    ):
        rig.analyze(scan_files["pcap"])

    assert (caught.value.status_code, caught.value.code) == (503, "analysis_failed")
    (row,) = rig.sessions()
    assert (row.status, row.error_code) == ("failed", "analysis_failed")
    assert row.ended_at is not None
    assert rig.spool_files() == []
    rig.service.ensure_analysis_idle()
    (record,) = logged(caplog, "pcap_launch_failed")
    assert record.error == "RuntimeError"
    assert_not_logged(caplog, "details-that-must-not-be-logged")


def test_an_analysis_that_crashes_ends_its_session_as_failed(
    rig: ServiceRig,
    scan_files: dict[str, bytes],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def crash(*_args: Any, **_kwargs: Any) -> None:
        raise ValueError("details-that-must-not-be-logged")

    monkeypatch.setattr(service_module, "analyze_file", crash)

    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        accepted = rig.analyze(scan_files["pcap"])
        row = rig.wait_for_end(accepted.id)
        wait_until(lambda: not rig.spool_files() and idle(rig), what="the analysis to be over")

    assert (row.status, row.error_code) == ("failed", "analysis_failed")
    assert row.ended_at is not None
    (record,) = logged(caplog, "pcap_analysis_failed")
    assert record.error == "ValueError"
    assert_not_logged(caplog, "details-that-must-not-be-logged")


def test_shutting_down_cancels_an_analysis_in_progress(
    rig: ServiceRig, scan_files: dict[str, bytes], hold_analysis: AnalysisGate
) -> None:
    accepted = rig.analyze(scan_files["pcap"])
    wait_until(hold_analysis.entered.is_set, what="the analysis to begin")

    rig.service.shutdown()

    row = rig.row(accepted.id)
    assert (row.status, row.error_code) == ("failed", "interrupted")
    assert row.ended_at is not None
    assert rig.spool_files() == []
    assert idle(rig)
    assert rig.flows(accepted.id) == []


# --- Looking up the addresses a file mentions -----------------------------------------------------


def test_only_public_addresses_of_a_file_are_looked_up_and_as_the_system(
    rig: ServiceRig, scan_files: dict[str, bytes]
) -> None:
    accepted = rig.analyze(scan_files["pcap"], ALICE)
    rig.wait_for_end(accepted.id)

    entries = rig.wait_for_lookups(accepted.id, {SCANNER, RESOLVER})

    assert set(entries) == {SCANNER, RESOLVER}
    assert {entry["status"] for entry in entries.values()} == {"completed"}
    # The private hosts and the documentation address are never sent to a provider.
    assert sorted(rig.intel.calls) == sorted([SCANNER, RESOLVER])
    assert {context.actor for context in rig.intel.contexts} == {"system:network-monitor"}
    assert rig.intel.refresh_flags == [False, False]
    shown = rig.call("get_session", ALICE.actor, accepted.id)
    assert (shown.enrichment.enabled, shown.enrichment.total, shown.enrichment.completed) == (
        True,
        2,
        2,
    )


def test_a_known_malicious_address_in_a_file_raises_one_more_alert(
    make_rig: Callable[..., ServiceRig], scan_files: dict[str, bytes]
) -> None:
    intel = StubIntel({SCANNER: reply(provider_view(), score=90, classification="critical")})
    rig = make_rig(intel=intel)

    accepted = rig.analyze(scan_files["pcap"])
    rig.wait_for_end(accepted.id)
    rig.wait_for_lookups(accepted.id, {SCANNER, RESOLVER})

    wait_until(
        lambda: (
            sorted(alert.rule_id for alert in rig.alerts(accepted.id)) == ["NET-001", "NET-005"]
        ),
        what="the known-malicious alert",
    )
    assert rig.row(accepted.id).alerts_total == 2
    assert rig.call("get_session", ALICE.actor, accepted.id).alerts_by_rule == {
        "NET-001": 1,
        "NET-005": 1,
    }
    assert rig.row(accepted.id).stats["enrichment"][SCANNER]["risk_score"] == 90
    assert sorted(intel.calls) == sorted([SCANNER, RESOLVER])


def test_nothing_is_looked_up_when_external_enrichment_is_off(
    make_rig: Callable[..., ServiceRig], scan_files: dict[str, bytes]
) -> None:
    rig = make_rig({"external_enrichment_enabled": False})

    accepted = rig.analyze(scan_files["pcap"])
    row = rig.wait_for_end(accepted.id)

    assert (row.status, row.packets_total) == ("completed", SCAN_FRAMES - 1)
    assert rig.intel.calls == []
    assert not row.stats.get("enrichment")
    shown = rig.call("get_session", ALICE.actor, accepted.id)
    assert shown.enrichment.enabled is False


def test_a_budget_of_one_looks_up_the_address_behind_the_alert_only(
    make_rig: Callable[..., ServiceRig], scan_files: dict[str, bytes]
) -> None:
    rig = make_rig({"network_enrichment_max_ips": 1})

    accepted = rig.analyze(scan_files["pcap"])
    rig.wait_for_end(accepted.id)
    entries = rig.wait_for_lookups(accepted.id, {SCANNER})

    assert set(entries) == {SCANNER}
    assert rig.intel.calls == [SCANNER]
    shown = rig.call("get_session", ALICE.actor, accepted.id)
    by_address = {ip.address: ip.enrichment.status for ip in shown.external_ips}
    assert by_address[SCANNER] == "completed"
    assert by_address[RESOLVER] == "not_looked_up"


def test_an_alert_for_an_address_beyond_the_budget_says_it_was_not_looked_up(
    make_rig: Callable[..., ServiceRig], tmp_path: Path
) -> None:
    frames = [
        scapy_syn(T0 + 0.1 * index, source, SERVER, 2000 + index)
        for index in range(25)
        for source in (SCANNER, SECOND_SCANNER)
    ]
    data = write_pcap(tmp_path / "two.pcap", frames).read_bytes()
    rig = make_rig({"network_enrichment_max_ips": 1})

    accepted = rig.analyze(data)
    rig.wait_for_end(accepted.id)

    def statuses() -> list[str]:
        return sorted(alert.enrichment.get("status", "") for alert in rig.alerts(accepted.id))

    wait_until(lambda: statuses() == ["completed", "skipped_budget"], what="the alerts' lookups")
    assert len(rig.intel.calls) == 1
    skipped = next(a for a in rig.alerts(accepted.id) if a.enrichment["status"] == "skipped_budget")
    assert skipped.src_ip != rig.intel.calls[0]
    assert {alert.rule_id for alert in rig.alerts(accepted.id)} == {"NET-001"}


def test_the_time_a_lookup_takes_does_not_hold_up_the_analysis(
    rig: ServiceRig, scan_files: dict[str, bytes]
) -> None:
    gate = threading.Event()
    rig.intel.gate = gate

    accepted = rig.analyze(scan_files["pcap"])
    row = rig.wait_for_end(accepted.id)

    # The session is finished while the answers are still awaited, and it says so.
    assert row.status == "completed"
    wait_until(rig.intel.entered.is_set, what="the first lookup to start")
    shown = rig.call("get_session", ALICE.actor, accepted.id)
    assert shown.status == "completed"
    assert (shown.enrichment.total, shown.enrichment.pending) == (2, 2)
    assert shown.enrichment.completed == 0
    (alert,) = rig.alerts(accepted.id)
    assert alert.enrichment["status"] == "pending"

    gate.set()
    rig.wait_for_lookups(accepted.id, {SCANNER, RESOLVER})
    settled = rig.call("get_session", ALICE.actor, accepted.id)
    assert (settled.enrichment.pending, settled.enrichment.completed) == (0, 2)
    wait_until(
        lambda: rig.alerts(accepted.id)[0].enrichment["status"] == "completed",
        what="the alert's lookup to be recorded",
    )
