"""VirusTotal adapter against canned API v3 responses (no network, no API key)."""

import base64
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2
import pytest

from app.collectors.base import ProviderStatus, Reason
from app.collectors.virustotal import (
    DEFAULT_BASE_URL,
    VirusTotalCollector,
    detection_signal,
)
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
GUI = "https://www.virustotal.com/gui"
BAD_SHAPE = "Unexpected response format from VirusTotal."
STATS = {"malicious": 12, "suspicious": 3, "harmless": 55, "undetected": 5, "timeout": 1}


def epoch(days_ago: float) -> int:
    return int((datetime.now(UTC) - timedelta(days=days_ago)).timestamp())


def vt_payload(
    data_type: str = "ip_address", data_id: Any = "8.8.8.8", **attributes: Any
) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "last_analysis_stats": dict(STATS),
        "last_analysis_date": epoch(2),
        "first_submission_date": epoch(400),
        "reputation": -42,
        "tags": ["Phishing", "scanner"],
    }
    fields.update(attributes)
    return {"data": {"id": data_id, "type": data_type, "attributes": fields}}


def lookup(value: str, wire: Any, **options: Any) -> Any:
    return build(VirusTotalCollector, wire, **options).lookup(indicator(value))


# --- The request -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "path", "data_type"),
    [
        ("8.8.8.8", "/api/v3/ip_addresses/8.8.8.8", "ip_address"),
        (IPV6, f"/api/v3/ip_addresses/{IPV6}", "ip_address"),
        ("EXAMPLE.com", "/api/v3/domains/example.com", "domain"),
        (MD5, f"/api/v3/files/{MD5}", "file"),
        (SHA1, f"/api/v3/files/{SHA1}", "file"),
        (SHA256, f"/api/v3/files/{SHA256}", "file"),
        # The id of a URL is its URL-safe base64 form without padding.
        ("http://www.example.com/", "/api/v3/urls/aHR0cDovL3d3dy5leGFtcGxlLmNvbS8", "url"),
    ],
)
def test_each_indicator_type_uses_its_documented_endpoint(
    value: str, path: str, data_type: str
) -> None:
    wire = Wire(body=vt_payload(data_type, data_id=None))

    result = lookup(value, wire)

    (request,) = wire.calls
    assert result.status is ProviderStatus.OK
    assert (request.method, request.url.host, request.url.path) == (
        "GET",
        "www.virustotal.com",
        path,
    )
    assert request.headers["x-apikey"] == KEY
    assert request.headers["accept"] == "application/json"
    assert not request.url.query
    assert request.content == b""
    assert KEY not in str(request.url)


def test_a_url_is_addressed_by_the_base64_of_its_normalized_form() -> None:
    wire = Wire(body=vt_payload("url", data_id=None))

    lookup("https://Example.com/a?b=c#frag", wire)

    expected = base64.urlsafe_b64encode(b"https://example.com/a?b=c").decode().rstrip("=")
    assert wire.calls[0].url.path == f"/api/v3/urls/{expected}"
    assert "=" not in wire.calls[0].url.path


def test_every_indicator_type_is_supported() -> None:
    assert VirusTotalCollector.supported_types == frozenset(IndicatorType)


def test_a_custom_base_url_is_used_without_a_double_slash() -> None:
    wire = Wire(body=vt_payload())

    lookup("8.8.8.8", wire, base_url="http://127.0.0.1:9/api/v3/")

    assert str(wire.calls[0].url) == "http://127.0.0.1:9/api/v3/ip_addresses/8.8.8.8"
    assert DEFAULT_BASE_URL == "https://www.virustotal.com/api/v3"


def test_no_key_means_no_request() -> None:
    wire = Wire(body=vt_payload())

    result = lookup("8.8.8.8", wire, key=None)

    assert wire.calls == []
    assert result.status is ProviderStatus.NOT_CONFIGURED
    assert result.reason is Reason.NOT_CONFIGURED
    assert result.message == "VirusTotal is not configured (no API key set)."


# --- Mapping the answer ------------------------------------------------------------------


def test_a_flagged_ip_is_mapped_with_its_counts_and_dates() -> None:
    last_analysis, first_submission = epoch(2), epoch(400)
    body = vt_payload(
        last_analysis_date=last_analysis,
        first_submission_date=first_submission,
        country="us",
        asn=15169,
        as_owner="Example Networks",
        times_submitted=7,
    )

    result = lookup("8.8.8.8", Wire(body=body))

    summary = result.summary
    assert result.status is ProviderStatus.OK
    assert result.reason is None and result.message is None
    assert result.signal == 1.0
    assert result.evidence_at == datetime.fromtimestamp(last_analysis, UTC)
    assert result.first_evidence_at == datetime.fromtimestamp(first_submission, UTC)
    assert result.tags == ["phishing", "scanner"]
    assert summary["verdict"] == "malicious"
    assert summary["analysis_status"] == "completed"
    assert {key: summary[key] for key in STATS} == STATS
    assert summary["engines_total"] == 75, "timeouts did not reach a verdict"
    assert summary["reputation"] == -42
    assert summary["times_submitted"] == 7
    assert (summary["country_code"], summary["asn"]) == ("US", 15169)
    assert summary["as_owner"] == "Example Networks"
    assert summary["provider_id"] == "8.8.8.8"
    assert summary["provider_link"] == f"{GUI}/ip-address/8.8.8.8"
    assert summary["last_analysis_at"] == datetime.fromtimestamp(last_analysis, UTC).isoformat()
    assert summary["notes"] == []


@pytest.mark.parametrize(
    ("malicious", "suspicious", "expected"),
    [
        (0, 0, 0.0),
        (0, 1, 0.1),
        (1, 0, 0.25),
        (0, 3, 0.25),
        (2, 0, 0.5),
        (1, 2, 0.5),
        (3, 0, 0.7),
        (5, 0, 0.85),
        (0, 19, 0.85),
        (10, 0, 1.0),
        (0, 20, 1.0),
        (70, 5, 1.0),
    ],
)
def test_the_signal_weighs_malicious_engines_twice_a_suspicious_one(
    malicious: int, suspicious: int, expected: float
) -> None:
    assert detection_signal(malicious, suspicious) == expected


@pytest.mark.parametrize(
    ("stats", "verdict", "signal"),
    [
        ({"malicious": 2, "suspicious": 0, "harmless": 60, "undetected": 6}, "malicious", 0.5),
        ({"malicious": 0, "suspicious": 2, "harmless": 60, "undetected": 6}, "suspicious", 0.25),
        ({"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 6}, "harmless", 0.0),
        ({"harmless": 3}, "harmless", 0.0),
    ],
)
def test_the_verdict_names_the_strongest_category_any_engine_reported(
    stats: dict[str, int], verdict: str, signal: float
) -> None:
    body = vt_payload("domain", "example.com", last_analysis_stats=stats)

    result = lookup("example.com", Wire(body=body))

    assert result.status is ProviderStatus.OK
    assert result.summary["verdict"] == verdict
    assert result.signal == signal


def test_a_clean_result_is_not_called_safe() -> None:
    stats = {"harmless": 60, "undetected": 10}
    body = vt_payload("domain", "example.com", last_analysis_stats=stats)

    result = lookup("example.com", Wire(body=body))

    assert result.summary["verdict"] == "harmless"
    assert "not proof that it is safe" in result.summary["notes"][0]


def test_a_lone_detection_is_flagged_as_a_possible_false_positive() -> None:
    stats = {"malicious": 1, "harmless": 60, "undetected": 9}

    result = lookup("8.8.8.8", Wire(body=vt_payload(last_analysis_stats=stats)))

    assert result.summary["verdict"] == "malicious"
    assert result.signal == 0.25
    assert "Only 1 of 70 engines" in result.summary["notes"][0]
    assert "false positive" in result.summary["notes"][0]


@pytest.mark.parametrize(
    "attributes",
    [
        {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}},
        {"last_analysis_stats": {"timeout": 5}},
        {"last_analysis_stats": {}},
        {"last_analysis_stats": None},
        {"last_analysis_stats": None, "last_analysis_date": None},
    ],
)
def test_a_record_without_engine_results_is_no_data_not_a_clean_bill(
    attributes: dict[str, Any],
) -> None:
    result = lookup("8.8.8.8", Wire(body=vt_payload(**attributes)))

    assert result.status is ProviderStatus.NO_DATA
    assert result.is_answer
    assert result.signal == 0.0
    assert result.evidence_at is None, "no analysis happened, so there is no analysis date"
    assert result.summary["verdict"] == "unknown"
    assert result.summary["analysis_status"] == "no_analysis"
    assert result.summary["engines_total"] == 0
    assert "no engine results" in result.summary["notes"][0]


def test_a_missing_stats_field_is_also_no_data() -> None:
    body = vt_payload()
    del body["data"]["attributes"]["last_analysis_stats"]

    result = lookup("8.8.8.8", Wire(body=body))

    assert result.status is ProviderStatus.NO_DATA
    assert result.summary["verdict"] == "unknown"


def test_a_404_is_not_found_and_says_so_without_calling_it_safe() -> None:
    body = {"error": {"code": "NotFoundError", "message": "Resource not found."}}
    wire = Wire(404, body=body)

    result = lookup("8.8.8.8", wire)

    assert len(wire.calls) == 1, "a lookup must never fall back to submitting the indicator"
    assert result.status is ProviderStatus.NO_DATA
    assert result.signal == 0.0
    assert result.summary["verdict"] == "not_found"
    assert result.summary["analysis_status"] == "not_found"
    assert "does not mean it is safe" in result.summary["notes"][0]
    assert result.message is None and result.reason is None


def test_file_details_and_threat_names_are_ranked_by_how_often_they_were_reported() -> None:
    body = vt_payload(
        "file",
        SHA256,
        meaningful_name="invoice.exe",
        type_description="Win32 EXE",
        popular_threat_classification={
            "suggested_threat_label": "trojan.zbot/agent",
            "popular_threat_name": [
                {"value": "zbot", "count": 10},
                {"value": "agent", "count": 30},
                {"value": "Zbot", "count": 5},
                {"value": "extra", "count": 2},
                {"value": "more", "count": 1},
                "not-a-dict",
                {"value": None, "count": 4},
            ],
        },
    )

    result = lookup(SHA256, Wire(body=body))

    summary = result.summary
    assert summary["file_name"] == "invoice.exe"
    assert summary["file_type"] == "Win32 EXE"
    assert summary["threat_label"] == "trojan.zbot/agent"
    assert summary["threat_names"] == ["agent", "zbot", "extra", "more"]
    assert summary["malware_families"] == ["agent", "zbot", "extra"]
    assert summary["provider_link"] == f"{GUI}/file/{SHA256}"


def test_urls_and_domains_report_the_most_common_engine_categories() -> None:
    categories = {f"engine{n}": "phishing" for n in range(5)}
    categories |= {"a": "malicious", "b": "malicious", "c": "Parked", "d": "news"}
    categories |= {f"x{n}": f"rare{n}" for n in range(30)}
    body = vt_payload("domain", "example.com", categories=categories)

    result = lookup("example.com", Wire(body=body))

    assert len(result.summary["categories"]) == 5
    assert result.summary["categories"][:2] == ["phishing", "malicious"]


def test_threat_names_for_urls_come_from_the_url_report() -> None:
    sha = "ab" * 32
    body = vt_payload("url", sha, threat_names=["Phishing.Generic", "phishing.generic", "Evil"])

    result = lookup("http://www.example.com/", Wire(body=body))

    assert result.summary["threat_names"] == ["Phishing.Generic", "Evil"]
    assert result.summary["malware_families"] == []
    assert result.summary["provider_link"] == f"{GUI}/url/{sha}"


# --- Links and ids come from validated values, never from the response -------------------


@pytest.mark.parametrize(
    "data_id",
    [
        "javascript:alert(1)",
        "../../etc/passwd",
        "ab" * 31 + "/?",
        "G" * 64,
        "AB" * 32,
        "ab" * 33,
        12345,
        None,
        ["ab" * 32],
    ],
)
@pytest.mark.parametrize(
    ("value", "data_type"), [(SHA256, "file"), ("http://www.example.com/", "url")]
)
def test_files_and_urls_get_a_link_only_for_a_genuine_sha256_id(
    value: str, data_type: str, data_id: Any
) -> None:
    result = lookup(value, Wire(body=vt_payload(data_type, data_id)))

    assert result.summary["provider_id"] is None
    assert result.summary["provider_link"] is None


@pytest.mark.parametrize(
    ("value", "data_type", "data_id", "link"),
    [
        ("8.8.8.8", "ip_address", "8.8.8.8", f"{GUI}/ip-address/8.8.8.8"),
        ("8.8.8.8", "ip_address", None, f"{GUI}/ip-address/8.8.8.8"),
        (IPV6, "ip_address", "2606:4700:4700:0:0:0:0:1111", f"{GUI}/ip-address/{IPV6}"),
        ("example.com", "domain", "EXAMPLE.com", f"{GUI}/domain/example.com"),
        ("example.com", "domain", None, f"{GUI}/domain/example.com"),
    ],
)
def test_addresses_and_domains_link_to_the_validated_indicator(
    value: str, data_type: str, data_id: Any, link: str
) -> None:
    result = lookup(value, Wire(body=vt_payload(data_type, data_id)))

    assert result.summary["provider_link"] == link


@pytest.mark.parametrize(
    ("value", "data_type", "data_id"),
    [
        ("8.8.8.8", "ip_address", "1.1.1.1"),
        ("8.8.8.8", "ip_address", "not an ip"),
        ("example.com", "domain", "evil.example.org"),
        ("example.com", "domain", "javascript:alert(1)"),
    ],
)
def test_an_answer_for_a_different_indicator_gets_no_link(
    value: str, data_type: str, data_id: str
) -> None:
    result = lookup(value, Wire(body=vt_payload(data_type, data_id)))

    assert result.summary["provider_id"] is None
    assert result.summary["provider_link"] is None


def test_provider_links_never_leave_virustotal() -> None:
    for value, data_type, data_id in [
        ("8.8.8.8", "ip_address", "8.8.8.8"),
        ("example.com", "domain", "example.com"),
        (SHA256, "file", SHA256),
        (MD5, "file", SHA256),
    ]:
        result = lookup(value, Wire(body=vt_payload(data_type, data_id)))
        assert result.summary["provider_link"].startswith(f"{GUI}/")


# --- Untrusted content -------------------------------------------------------------------


def test_text_from_virustotal_is_cleaned_and_bounded() -> None:
    body = vt_payload(
        "file",
        SHA256,
        meaningful_name="evil\x00\u202e\u200b.exe  " + "A" * 500,
        type_description="<script>alert(1)</script>" + "B" * 200,
        tags=["Ransom", "ransom", "x" * 200, "<img src=x onerror=alert(1)>", *map(str, range(50))],
        popular_threat_classification={"suggested_threat_label": "L" * 300},
    )

    result = lookup(SHA256, Wire(body=body))

    summary = result.summary
    assert len(summary["file_name"]) <= 128
    assert not any(ord(char) < 32 or char in "\u202e\u200b" for char in summary["file_name"])
    assert len(summary["file_type"]) <= 64
    assert len(summary["threat_label"]) <= 64
    assert len(result.tags) == 10
    assert result.tags[0] == "ransom" and result.tags.count("ransom") == 1
    assert all(len(tag) <= 48 and tag == tag.lower() for tag in result.tags)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("de", "DE"),
        ("DE", "DE"),
        ("Germany", None),
        ("D", None),
        ("1E", None),
        (None, None),
        (49, None),
    ],
)
def test_country_codes_must_be_two_letters(raw: Any, expected: str | None) -> None:
    result = lookup("8.8.8.8", Wire(body=vt_payload(country=raw)))

    assert result.summary["country_code"] == expected


@pytest.mark.parametrize("raw", [None, True, "yesterday", 0, -1, 10**15, epoch(-30), 1.5e300])
def test_implausible_dates_are_treated_as_unknown(raw: Any) -> None:
    result = lookup(
        "8.8.8.8", Wire(body=vt_payload(last_analysis_date=raw, first_submission_date=raw))
    )

    assert result.status is ProviderStatus.OK
    assert result.evidence_at is None
    assert result.first_evidence_at is None


@pytest.mark.parametrize("raw", ["12", True, 1.5, -(10**10), 10**10, None])
def test_out_of_range_numbers_are_dropped(raw: Any) -> None:
    result = lookup("8.8.8.8", Wire(body=vt_payload(reputation=raw, asn=raw, times_submitted=raw)))

    assert result.summary["reputation"] is None
    assert result.summary["asn"] is None
    assert result.summary["times_submitted"] is None


# --- Malformed answers -------------------------------------------------------------------


def wrong(**changes: Any) -> dict[str, Any]:
    body = vt_payload()
    body["data"].update(changes)
    return body


@pytest.mark.parametrize(
    "body",
    [
        [],
        "text",
        {},
        {"data": []},
        {"data": None},
        wrong(type="domain"),
        wrong(type=None),
        wrong(attributes=None),
        wrong(attributes=[]),
        vt_payload(last_analysis_stats=[]),
        vt_payload(last_analysis_stats="12"),
        vt_payload(last_analysis_stats={"malicious": -1}),
        vt_payload(last_analysis_stats={"malicious": True}),
        vt_payload(last_analysis_stats={"malicious": "3"}),
        vt_payload(last_analysis_stats={"malicious": 1.5}),
        vt_payload(last_analysis_stats={"harmless": 10**9}),
    ],
)
def test_a_payload_that_is_not_what_was_asked_for_is_an_error(body: Any) -> None:
    result = lookup("8.8.8.8", Wire(body=body))

    assert result.status is ProviderStatus.ERROR
    assert result.reason is Reason.MALFORMED_RESPONSE
    assert result.message == BAD_SHAPE
    assert not result.is_answer


def test_a_domain_answer_for_an_ip_lookup_is_rejected() -> None:
    result = lookup("8.8.8.8", Wire(body=vt_payload("domain", "8.8.8.8")))

    assert result.reason is Reason.MALFORMED_RESPONSE


# --- Failures ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "provider_status", "reason", "message"),
    [
        (
            401,
            ProviderStatus.ERROR,
            Reason.AUTH_FAILED,
            "VirusTotal rejected the configured credentials.",
        ),
        (
            403,
            ProviderStatus.ERROR,
            Reason.AUTH_FAILED,
            "VirusTotal rejected the configured credentials.",
        ),
        (
            400,
            ProviderStatus.ERROR,
            Reason.INVALID_INPUT,
            "VirusTotal rejected the request as invalid (400).",
        ),
        (
            429,
            ProviderStatus.RATE_LIMITED,
            Reason.RATE_LIMITED,
            "VirusTotal rate limit reached; try again later.",
        ),
        (
            500,
            ProviderStatus.ERROR,
            Reason.UNAVAILABLE,
            "VirusTotal returned an unexpected HTTP status (500).",
        ),
        (
            302,
            ProviderStatus.ERROR,
            Reason.UNAVAILABLE,
            "VirusTotal returned an unexpected HTTP status (302).",
        ),
    ],
)
def test_failures_are_reported_with_a_reason_and_without_provider_text(
    status: int, provider_status: ProviderStatus, reason: Reason, message: str
) -> None:
    body = {"error": {"code": "Whatever", "message": f"provider text echoing {KEY}"}}
    wire = Wire(status, body=body, headers={"Location": "https://evil.example/"})

    result = lookup("8.8.8.8", wire, timeout_seconds=15, max_retries=2)

    assert len(wire.calls) == 1, "none of these can be fixed by retrying"
    assert (result.status, result.reason, result.message) == (provider_status, reason, message)
    assert result.signal == 0.0 and not result.summary
    assert KEY not in repr(result)


def test_a_transient_outage_is_retried_within_the_budget() -> None:
    clock = FakeTime()
    wire = Script(Wire(503), Wire(504), Wire(body=vt_payload()))

    result = lookup("8.8.8.8", wire, timeout_seconds=15, max_retries=2, **clock.options)

    assert result.status is ProviderStatus.OK
    assert len(wire.calls) == 3
    assert {call.headers["x-apikey"] for call in wire.calls} == {KEY}


def test_the_public_api_quota_wait_is_honoured_when_it_is_short() -> None:
    clock = FakeTime()
    wire = Script(Wire(429, headers={"Retry-After": "3"}), Wire(body=vt_payload()))

    result = lookup("8.8.8.8", wire, timeout_seconds=15, max_retries=2, **clock.options)

    assert result.status is ProviderStatus.OK
    assert clock.slept == [3.0]


def test_a_quota_reset_that_is_far_away_is_reported_not_waited_for() -> None:
    clock = FakeTime()
    wire = Wire(429, headers={"Retry-After": "55"})

    result = lookup("8.8.8.8", wire, timeout_seconds=15, max_retries=2, **clock.options)

    assert len(wire.calls) == 1 and clock.slept == []
    assert result.status is ProviderStatus.RATE_LIMITED
    assert result.message == "VirusTotal rate limit reached; try again in about 55 seconds."


@pytest.mark.parametrize(
    ("error", "reason", "message"),
    [
        (httpx2.ReadTimeout("slow"), Reason.TIMEOUT, "VirusTotal did not respond in time."),
        (httpx2.ConnectError("down"), Reason.UNAVAILABLE, "Could not reach VirusTotal."),
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
    assert result.message == "VirusTotal returned invalid JSON."


# --- Logging -----------------------------------------------------------------------------


REMOTE_URL = "https://example.com/reset?token=s3cr3tT0ken"
REMOTE_URL_ID = base64.urlsafe_b64encode(REMOTE_URL.encode()).decode().rstrip("=")


@pytest.mark.usefixtures("production_logging")
@pytest.mark.parametrize(
    ("value", "secrets", "wire"),
    [
        ("8.8.4.4", ["8.8.4.4"], Wire(body=vt_payload(data_id="8.8.4.4"))),
        (REMOTE_URL, ["s3cr3tT0ken", REMOTE_URL_ID], Wire(body=vt_payload("url", data_id=None))),
        (SHA256, [SHA256], Wire(404, body={})),
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
