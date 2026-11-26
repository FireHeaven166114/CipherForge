"""ThreatFox adapter against canned API responses (no network, no API key)."""

import base64
from datetime import UTC, datetime
from typing import Any

import httpx2
import pytest

from app.collectors.base import ProviderStatus, Reason
from app.collectors.threatfox import DEFAULT_BASE_URL, ThreatFoxCollector, request_body
from app.models.enums import IndicatorType
from tests.provider_helpers import (
    KEY,
    FakeTime,
    Script,
    Wire,
    assert_nothing_sensitive_logged,
    build,
    indicator,
)

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
IPV6 = "2606:4700:4700::1111"
MALPEDIA = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"
FIRST_SEEN = "2025-11-20 08:30:00 UTC"
LAST_SEEN = "2025-12-30 17:45:10 UTC"


def entry(ioc: str = "8.8.8.8:443", **overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": "12",
        "ioc": ioc,
        "threat_type": "botnet_cc",
        "threat_type_desc": "Indicator that identifies a botnet command&control server (C&C)",
        "ioc_type": "ip:port",
        "ioc_type_desc": "ip:port combination that is used for botnet Command&control (C&C)",
        "malware": "win.cobalt_strike",
        "malware_printable": "Cobalt Strike",
        "malware_alias": "Agentemis,BEACON,CobaltStrike",
        "malware_malpedia": MALPEDIA,
        "confidence_level": 75,
        "first_seen": FIRST_SEEN,
        "last_seen": None,
        "reference": None,
        "reporter": "abuse_ch",
        "tags": None,
        "malware_samples": [],
    }
    data.update(overrides)
    return data


def found(*entries: dict[str, Any]) -> dict[str, Any]:
    return {"query_status": "ok", "data": list(entries)}


def lookup(value: str, wire: Any, **options: Any) -> Any:
    return build(ThreatFoxCollector, wire, **options).lookup(indicator(value))


# --- The request -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.8.8.8", {"query": "search_ioc", "search_term": "8.8.8.8", "exact_match": False}),
        (IPV6, {"query": "search_ioc", "search_term": IPV6, "exact_match": False}),
        ("EXAMPLE.com", {"query": "search_ioc", "search_term": "example.com", "exact_match": True}),
        (
            "http://www.example.com/a?b=c",
            {
                "query": "search_ioc",
                "search_term": "http://www.example.com/a?b=c",
                "exact_match": True,
            },
        ),
        (MD5, {"query": "search_hash", "hash": MD5}),
        (SHA256, {"query": "search_hash", "hash": SHA256}),
    ],
)
def test_each_indicator_type_uses_its_documented_query(
    value: str, expected: dict[str, Any]
) -> None:
    wire = Wire(body={"query_status": "no_result", "data": "Your search did not yield any results"})

    lookup(value, wire)

    (request,) = wire.calls
    assert request.method == "POST"
    assert str(request.url) == "https://threatfox-api.abuse.ch/api/v1/"
    assert request.headers["auth-key"] == KEY
    assert request.headers["content-type"] == "application/json"
    assert request.headers["accept"] == "application/json"
    assert httpx2.Response(200, content=request.content).json() == expected
    assert KEY not in str(request.url) and KEY.encode() not in request.content


def test_request_body_is_built_only_from_the_normalized_indicator() -> None:
    assert request_body(indicator("8.8.4.4")) == {
        "query": "search_ioc",
        "search_term": "8.8.4.4",
        "exact_match": False,
    }


def test_sha1_is_unsupported_and_makes_no_request() -> None:
    wire = Wire(body=found(entry()))

    result = lookup(SHA1, wire)

    assert wire.calls == []
    assert result.status is ProviderStatus.UNSUPPORTED
    assert result.message == "ThreatFox does not accept sha1 indicators."
    assert ThreatFoxCollector.supported_types == frozenset(IndicatorType) - {IndicatorType.SHA1}


def test_no_key_means_no_request() -> None:
    wire = Wire(body=found(entry()))

    result = lookup("8.8.8.8", wire, key=None)

    assert wire.calls == []
    assert result.status is ProviderStatus.NOT_CONFIGURED
    assert result.reason is Reason.NOT_CONFIGURED
    assert result.message == "ThreatFox is not configured (no API key set)."


def test_a_custom_base_url_is_used() -> None:
    wire = Wire(body=found(entry()))

    lookup("8.8.8.8", wire, base_url="http://127.0.0.1:9/api/v1/")

    assert str(wire.calls[0].url) == "http://127.0.0.1:9/api/v1/"
    assert DEFAULT_BASE_URL == "https://threatfox-api.abuse.ch/api/v1"


# --- Mapping the answer ------------------------------------------------------------------


def test_a_reported_ip_is_mapped_with_the_reporters_confidence() -> None:
    body = found(
        entry(
            "8.8.8.8:443",
            confidence_level=90,
            last_seen=LAST_SEEN,
            reference="https://example.org/report",
            tags=["CobaltStrike", "c2"],
        )
    )

    result = lookup("8.8.8.8", Wire(body=body))

    summary = result.summary
    assert result.status is ProviderStatus.OK
    assert result.reason is None and result.message is None
    assert result.signal == 0.9
    assert result.evidence_at == datetime(2025, 12, 30, 17, 45, 10, tzinfo=UTC)
    assert result.first_evidence_at == datetime(2025, 11, 20, 8, 30, tzinfo=UTC)
    assert result.tags == ["cobaltstrike", "c2"]
    assert summary["verdict"] == "malicious"
    assert summary["match_count"] == 1
    assert summary["highest_confidence"] == 90
    assert summary["association"] == "indicator"
    assert summary["threat_types"] == ["botnet_cc"]
    assert summary["malware_families"] == ["Cobalt Strike"]
    assert summary["first_seen_at"] == "2025-11-20T08:30:00+00:00"
    assert summary["last_seen_at"] == "2025-12-30T17:45:10+00:00"
    (match,) = summary["matches"]
    assert match == {
        "id": "12",
        "ioc": "8.8.8.8:443",
        "ioc_type": "ip:port",
        "threat_type": "botnet_cc",
        "malware": "Cobalt Strike",
        "malware_aliases": ["Agentemis", "BEACON", "CobaltStrike"],
        "confidence_level": 90,
        "first_seen": "2025-11-20T08:30:00+00:00",
        "last_seen": "2025-12-30T17:45:10+00:00",
        "reporter": "abuse_ch",
        "reference": "https://example.org/report",
        "malpedia_url": MALPEDIA,
        "tags": ["CobaltStrike", "c2"],
    }


@pytest.mark.parametrize(
    ("confidence", "verdict", "signal"),
    [
        (100, "malicious", 1.0),
        (75, "malicious", 0.75),
        (74, "suspicious", 0.74),
        (50, "suspicious", 0.5),
        (0, "suspicious", 0.0),
    ],
)
def test_reporter_confidence_decides_the_label_and_the_signal(
    confidence: int, verdict: str, signal: float
) -> None:
    result = lookup("8.8.8.8", Wire(body=found(entry(confidence_level=confidence))))

    assert result.status is ProviderStatus.OK
    assert result.summary["verdict"] == verdict
    assert result.signal == signal


def test_an_ip_search_keeps_only_entries_for_exactly_that_address() -> None:
    body = found(
        entry("8.8.8.8:443", id="1", confidence_level=50),
        entry("18.8.8.88:80", id="2", confidence_level=100),  # contains the text, not the address
        entry("8.8.8.80:443", id="3", confidence_level=100),
        entry("8.8.8.8:8080", id="4", confidence_level=90),
        entry("8.8.8.8", id="5", confidence_level=30),
        entry("example.8.8.8.8:1", id="6", confidence_level=100),
    )

    result = lookup("8.8.8.8", Wire(body=body))

    summary = result.summary
    assert summary["match_count"] == 3
    assert [match["id"] for match in summary["matches"]] == ["4", "1", "5"], (
        "highest confidence first"
    )
    assert summary["highest_confidence"] == 90
    assert result.signal == 0.9


def test_an_ip_search_that_only_contains_the_text_is_not_a_match() -> None:
    body = found(entry("18.8.8.88:80", confidence_level=100), entry("8.8.8.80:443"))

    result = lookup("8.8.8.8", Wire(body=body))

    assert result.status is ProviderStatus.NO_DATA
    assert result.signal == 0.0
    assert result.summary["verdict"] == "not_found"


@pytest.mark.parametrize(
    ("ioc", "matches"),
    [
        (f"[{IPV6}]:443", True),
        (f"[{IPV6.upper()}]:443", True),
        (IPV6, True),
        (f"{IPV6}0", False),
        (f"[{IPV6}0]:443", False),
        ("[2606:4700:4700::1112]:443", False),
    ],
)
def test_ipv6_entries_are_matched_in_bracket_notation(ioc: str, matches: bool) -> None:
    result = lookup(IPV6, Wire(body=found(entry(ioc))))

    assert (result.status is ProviderStatus.OK) is matches


@pytest.mark.parametrize(
    ("stored", "matches"),
    [
        ("example.com", True),
        ("EXAMPLE.COM", True),
        ("sub.example.com", False),
        ("example.com.evil.net", False),
        ("notexample.com", False),
    ],
)
def test_domains_match_exactly_ignoring_case(stored: str, matches: bool) -> None:
    result = lookup("example.com", Wire(body=found(entry(stored, ioc_type="domain"))))

    assert (result.status is ProviderStatus.OK) is matches


@pytest.mark.parametrize(
    ("stored", "matches"),
    [
        ("http://www.example.com/a?b=c", True),
        ("http://www.example.com/a?b=c&d=e", False),
        ("http://www.example.com/a", False),
        ("http://www.example.com/", False),
        ("https://www.example.com/a?b=c", False),
    ],
)
def test_urls_match_exactly(stored: str, matches: bool) -> None:
    result = lookup("http://www.example.com/a?b=c", Wire(body=found(entry(stored, ioc_type="url"))))

    assert (result.status is ProviderStatus.OK) is matches


@pytest.mark.parametrize("value", [MD5, SHA256])
def test_hash_searches_return_the_iocs_associated_with_the_file(value: str) -> None:
    body = found(
        entry("http://harold.jetos.com:3606/is-ready", ioc_type="url", confidence_level=100),
        entry("203.0.113.9:443", confidence_level=50),
    )

    result = lookup(value, Wire(body=body))

    summary = result.summary
    assert result.status is ProviderStatus.OK
    assert summary["association"] == "file_hash"
    assert summary["match_count"] == 2
    assert result.signal == 1.0
    assert "does not rate the file" in summary["notes"][0]


def test_many_matches_are_summarised_and_the_rest_counted() -> None:
    entries = [
        entry(
            "8.8.8.8:443",
            id=str(100 + n),
            confidence_level=60 + n,
            malware_printable=f"Family {n}",
            tags=[f"Tag{n}", "shared"],
            threat_type=f"type{n}",
        )
        for n in range(8)
    ]

    result = lookup("8.8.8.8", Wire(body=found(*entries)))

    summary = result.summary
    assert summary["match_count"] == 8
    assert len(summary["matches"]) == 5
    assert [match["confidence_level"] for match in summary["matches"]] == [67, 66, 65, 64, 63]
    assert any("3 further matching records are not listed" in note for note in summary["notes"])
    assert len(summary["malware_families"]) == 5
    assert len(summary["threat_types"]) == 5
    assert len(result.tags) == 9 and result.tags.count("shared") == 1
    assert all(tag == tag.lower() for tag in result.tags)


def test_dates_cover_the_whole_set_of_matches() -> None:
    body = found(
        entry("8.8.8.8:443", id="1", first_seen="2025-10-01 00:00:00 UTC", last_seen=None),
        entry("8.8.8.8:80", id="2", first_seen="2025-11-01 00:00:00 UTC", last_seen=LAST_SEEN),
        entry("8.8.8.8:81", id="3", first_seen="not a date", last_seen=7),
    )

    result = lookup("8.8.8.8", Wire(body=body))

    assert result.first_evidence_at == datetime(2025, 10, 1, tzinfo=UTC)
    assert result.evidence_at == datetime(2025, 12, 30, 17, 45, 10, tzinfo=UTC)


def test_unreadable_dates_are_unknown_not_an_error() -> None:
    body = found(entry(first_seen="yesterday", last_seen="2999-01-01 00:00:00 UTC"))

    result = lookup("8.8.8.8", Wire(body=body))

    assert result.status is ProviderStatus.OK
    assert result.evidence_at is None and result.first_evidence_at is None
    assert result.summary["first_seen_at"] is None


def test_aliases_come_from_one_comma_separated_string() -> None:
    result = lookup("8.8.8.8", Wire(body=found(entry(malware_alias="A, B,, a ,C,D,E,F,G"))))

    assert result.summary["matches"][0]["malware_aliases"] == ["A", "B", "C", "D", "E"]


# --- No result and provider-reported errors ----------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        {"query_status": "no_result", "data": "Your search did not yield any results"},
        {"query_status": "no_result"},
        {"query_status": "ok", "data": []},
    ],
)
def test_no_result_is_an_answer_and_is_not_a_clean_bill(body: dict[str, Any]) -> None:
    result = lookup("8.8.8.8", Wire(body=body))

    assert result.status is ProviderStatus.NO_DATA
    assert result.is_answer and result.signal == 0.0
    assert result.summary["verdict"] == "not_found"
    assert result.summary["match_count"] == 0
    assert "older than six months" in result.summary["notes"][0]
    assert result.message is None and result.reason is None


@pytest.mark.parametrize("status", ["illegal_search_term", "illegal_hash", "illegal_id"])
def test_a_search_term_that_threatfox_refuses_is_invalid_input(status: str) -> None:
    result = lookup("8.8.8.8", Wire(body={"query_status": status, "data": "provider text"}))

    assert result.status is ProviderStatus.ERROR
    assert result.reason is Reason.INVALID_INPUT
    assert result.message == "ThreatFox rejected the search term as invalid."


@pytest.mark.parametrize("status", ["unauthorized", "Unauthorized", "forbidden", "403 Forbidden"])
def test_a_credentials_complaint_in_a_200_answer_is_an_auth_failure(status: str) -> None:
    result = lookup("8.8.8.8", Wire(body={"query_status": status}))

    assert result.reason is Reason.AUTH_FAILED
    assert result.message == "ThreatFox rejected the configured credentials."
    assert status not in result.message


def test_other_query_statuses_are_reported_without_the_providers_text() -> None:
    text = f"engine on fire, key {KEY}"

    result = lookup("8.8.8.8", Wire(body={"query_status": text, "data": text}))

    assert result.status is ProviderStatus.ERROR
    assert result.reason is Reason.UNAVAILABLE
    assert result.message == "ThreatFox returned an unexpected query status."
    assert KEY not in repr(result)


# --- Malformed answers -------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        [],
        "text",
        {},
        {"query_status": None},
        {"query_status": 1},
        {"query_status": "ok"},
        {"query_status": "ok", "data": None},
        {"query_status": "ok", "data": {"id": "1"}},
        {"query_status": "ok", "data": "text"},
        {"query_status": "ok", "data": ["text", 1, None]},
        {"query_status": "ok", "data": [{"ioc": "8.8.8.8:443"}]},
        {"query_status": "ok", "data": [{"confidence_level": 50}]},
        {"query_status": "ok", "data": [entry(confidence_level="75")]},
        {"query_status": "ok", "data": [entry(confidence_level=True)]},
        {"query_status": "ok", "data": [entry(confidence_level=101)]},
        {"query_status": "ok", "data": [entry(confidence_level=-1)]},
        {"query_status": "ok", "data": [entry(ioc=None)]},
    ],
)
def test_a_payload_that_is_not_what_was_asked_for_is_an_error(body: Any) -> None:
    result = lookup("8.8.8.8", Wire(body=body))

    assert result.status is ProviderStatus.ERROR
    assert result.reason is Reason.MALFORMED_RESPONSE
    assert result.message == "Unexpected response format from ThreatFox."
    assert not result.is_answer


def test_unreadable_entries_are_skipped_when_others_are_fine() -> None:
    body = found("junk", {"ioc": "8.8.8.8:1"}, entry("8.8.8.8:443", confidence_level=80), None)

    result = lookup("8.8.8.8", Wire(body=body))

    assert result.status is ProviderStatus.OK
    assert result.summary["match_count"] == 1


# --- Untrusted content -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("reference", "kept"),
    [
        ("https://example.org/report", True),
        ("http://example.org/report?id=1#frag", True),
        ("HTTPS://EXAMPLE.ORG/REPORT", True),
        ("javascript:alert(1)", False),
        ("data:text/html,<script>alert(1)</script>", False),
        ("//evil.example/x", False),
        ("ftp://example.org/x", False),
        ("file:///etc/passwd", False),
        ("https://user:pass@example.org/x", False),
        ("https://user@example.org/x", False),
        ("https:///nohost", False),
        ("https://example.org/a b", False),
        ("https://example.org/\nSet-Cookie: x=1", False),
        ("https://exämple.org/x", False),
        ("https://example.org/" + "a" * 600, False),
        ("  https://example.org/padded  ", True),
        ("", False),
        (None, False),
        (123, False),
        (["https://example.org/"], False),
    ],
)
def test_reporter_links_are_kept_only_when_they_are_plain_web_links(
    reference: Any, kept: bool
) -> None:
    result = lookup("8.8.8.8", Wire(body=found(entry(reference=reference))))

    link = result.summary["matches"][0]["reference"]
    assert (link is not None) is kept
    if kept:
        assert link == reference.strip()


@pytest.mark.parametrize(
    ("malpedia", "kept"),
    [
        (MALPEDIA, True),
        ("https://evil.example/details/win.cobalt_strike", False),
        ("https://malpedia.caad.fkie.fraunhofer.de.evil.example/x", False),
        ("http://malpedia.caad.fkie.fraunhofer.de/details/x", False),
        ("https://user@malpedia.caad.fkie.fraunhofer.de/details/x", False),
        ("javascript:alert(1)", False),
        (None, False),
    ],
)
def test_the_malpedia_link_must_point_at_malpedia(malpedia: Any, kept: bool) -> None:
    result = lookup("8.8.8.8", Wire(body=found(entry(malware_malpedia=malpedia))))

    assert (result.summary["matches"][0]["malpedia_url"] is not None) is kept


def test_text_from_reporters_is_cleaned_and_bounded() -> None:
    body = found(
        entry(
            "8.8.8.8:443",
            malware_printable="Evil\x00\u202e\u200bRAT " + "M" * 300,
            reporter="<script>alert(1)</script>" + "R" * 200,
            threat_type="T" * 100,
            ioc_type="x" * 100,
            tags=["Tag", "tag", "x" * 200, *map(str, range(30))],
            id="12; DROP TABLE",
        )
    )

    result = lookup("8.8.8.8", Wire(body=body))

    (match,) = result.summary["matches"]
    assert len(match["malware"]) <= 64 and not any(
        ord(c) < 32 or c in "\u202e\u200b" for c in match["malware"]
    )
    assert len(match["reporter"]) <= 64
    assert len(match["threat_type"]) <= 48 and len(match["ioc_type"]) <= 24
    assert match["id"] is None, "an id that is not digits is not shown"
    assert len(match["tags"]) <= 8
    assert len(result.tags) <= 10
    assert all(tag == tag.lower() and len(tag) <= 48 for tag in result.tags)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("77", "77"),
        (77, "77"),
        ("7" * 13, None),
        (-1, None),
        (True, None),
        (None, None),
        ("7a", None),
    ],
)
def test_record_ids_are_digits_only(raw: Any, expected: str | None) -> None:
    result = lookup("8.8.8.8", Wire(body=found(entry(id=raw))))

    assert result.summary["matches"][0]["id"] == expected


# --- Failures ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "provider_status", "reason", "message"),
    [
        (
            401,
            ProviderStatus.ERROR,
            Reason.AUTH_FAILED,
            "ThreatFox rejected the configured credentials.",
        ),
        (
            403,
            ProviderStatus.ERROR,
            Reason.AUTH_FAILED,
            "ThreatFox rejected the configured credentials.",
        ),
        (
            400,
            ProviderStatus.ERROR,
            Reason.INVALID_INPUT,
            "ThreatFox rejected the request as invalid (400).",
        ),
        (
            429,
            ProviderStatus.RATE_LIMITED,
            Reason.RATE_LIMITED,
            "ThreatFox rate limit reached; try again later.",
        ),
        (
            500,
            ProviderStatus.ERROR,
            Reason.UNAVAILABLE,
            "ThreatFox returned an unexpected HTTP status (500).",
        ),
        (
            302,
            ProviderStatus.ERROR,
            Reason.UNAVAILABLE,
            "ThreatFox returned an unexpected HTTP status (302).",
        ),
    ],
)
def test_failures_are_reported_with_a_reason_and_without_provider_text(
    status: int, provider_status: ProviderStatus, reason: Reason, message: str
) -> None:
    wire = Wire(
        status, body={"query_status": f"echo {KEY}"}, headers={"Location": "https://evil.example/"}
    )

    result = lookup("8.8.8.8", wire, timeout_seconds=15, max_retries=2)

    assert len(wire.calls) == 1, "none of these can be fixed by retrying"
    assert (result.status, result.reason, result.message) == (provider_status, reason, message)
    assert result.signal == 0.0 and not result.summary
    assert KEY not in repr(result)


def test_a_search_is_retried_with_the_same_body_and_key() -> None:
    clock = FakeTime()
    wire = Script(Wire(503), Wire(504), Wire(body=found(entry())))

    result = lookup("8.8.8.8", wire, timeout_seconds=15, max_retries=2, **clock.options)

    assert result.status is ProviderStatus.OK
    assert len(wire.calls) == 3
    assert {call.content for call in wire.calls} == {wire.calls[0].content}
    assert {call.headers["auth-key"] for call in wire.calls} == {KEY}
    assert clock.slept == [0.5, 1.0]


@pytest.mark.parametrize(
    ("error", "reason", "message"),
    [
        (httpx2.ReadTimeout("slow"), Reason.TIMEOUT, "ThreatFox did not respond in time."),
        (httpx2.ConnectError("down"), Reason.UNAVAILABLE, "Could not reach ThreatFox."),
    ],
)
def test_network_failures_are_reported_after_the_retries_run_out(
    error: Exception, reason: Reason, message: str
) -> None:
    clock = FakeTime()
    wire = Wire(error=error)

    result = lookup("8.8.8.8", wire, timeout_seconds=15, max_retries=2, **clock.options)

    assert len(wire.calls) == 3
    assert (result.status, result.reason, result.message) == (ProviderStatus.ERROR, reason, message)


def test_a_body_that_is_not_json_is_an_error() -> None:
    result = lookup("8.8.8.8", Wire(content=b"<html>Bad gateway</html>"))

    assert result.reason is Reason.MALFORMED_RESPONSE
    assert result.message == "ThreatFox returned invalid JSON."


# --- Logging -----------------------------------------------------------------------------

REMOTE_URL = "https://example.com/reset?token=s3cr3tT0ken"


@pytest.mark.usefixtures("production_logging")
@pytest.mark.parametrize(
    ("value", "secrets", "wire"),
    [
        ("8.8.4.4", ["8.8.4.4"], Wire(body=found(entry("8.8.4.4:443")))),
        (
            REMOTE_URL,
            ["s3cr3tT0ken", base64.b64encode(REMOTE_URL.encode()).decode()],
            Wire(body=found()),
        ),
        (SHA256, [SHA256], Wire(body={"query_status": "no_result"})),
        ("8.8.4.4", ["8.8.4.4"], Wire(401, body={})),
        ("8.8.4.4", ["8.8.4.4"], Wire(error=httpx2.ReadTimeout("slow"))),
    ],
)
def test_logs_never_contain_the_indicator_or_the_api_key(
    value: str, secrets: list[str], wire: Wire, caplog: pytest.LogCaptureFixture
) -> None:
    result = lookup(value, wire)

    assert KEY not in repr(result)
    assert any(record.getMessage() == "provider_lookup" for record in caplog.records)
    assert_nothing_sensitive_logged(caplog, *secrets)
