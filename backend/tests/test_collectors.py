"""Provider adapters against canned HTTP responses (no network, no API keys)."""

import gzip
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2
import pytest

from app.collectors.abuseipdb import AbuseIPDBCollector, parse_abuseipdb
from app.collectors.base import (
    MAX_RESPONSE_BYTES,
    Collector,
    ProviderFailure,
    ProviderResult,
    ProviderStatus,
)
from app.collectors.otx import OTXCollector, parse_otx, pulse_signal
from app.collectors.registry import build_collectors, build_http_client
from app.core.config import Settings
from app.models.enums import IndicatorType
from app.services.normalization import NormalizedIndicator
from tests.provider_helpers import (
    KEY,
    Wire,
    assert_nothing_sensitive_logged,
    build,
    indicator,
    iso,
)

PULSE_ID = "5f1c" + "0" * 20


def abuse_payload(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "ipAddress": "8.8.8.8",
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 87,
        "countryCode": "DE",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example Hosting GmbH",
        "domain": "example.net",
        "hostnames": [],
        "isTor": False,
        "totalReports": 42,
        "numDistinctUsers": 17,
        "lastReportedAt": iso(2),
    }
    data.update(overrides)
    return {"data": data}


def otx_pulse(**overrides: Any) -> dict[str, Any]:
    pulse: dict[str, Any] = {
        "id": PULSE_ID,
        "name": "Example campaign",
        "created": iso(40),
        "modified": iso(3),
        "tags": ["Phishing", "banking"],
        "malware_families": [{"id": "Emotet", "display_name": "Emotet"}],
        "attack_ids": [{"id": "T1566", "name": "Phishing", "display_name": "T1566 - Phishing"}],
    }
    pulse.update(overrides)
    return pulse


def otx_payload(pulses: list[Any], **extra: Any) -> dict[str, Any]:
    return {"pulse_info": {"count": len(pulses), "pulses": pulses}, "validation": [], **extra}


# --- AbuseIPDB ---------------------------------------------------------------------------


def test_abuseipdb_request_and_mapping() -> None:
    wire = Wire(body=abuse_payload())

    result = build(AbuseIPDBCollector, wire).lookup(indicator("8.8.8.8"))

    (request,) = wire.calls
    assert request.method == "GET"
    assert request.url.host == "api.abuseipdb.com"
    assert request.url.path == "/api/v2/check"
    assert dict(request.url.params) == {"ipAddress": "8.8.8.8", "maxAgeInDays": "90"}
    assert request.headers["Key"] == KEY
    assert request.headers["Accept"] == "application/json"
    assert result.status is ProviderStatus.OK
    assert result.signal == pytest.approx(0.87)
    assert result.evidence_at is not None
    assert result.tags == []
    summary = result.summary
    assert summary["confidence_score"] == 87
    assert summary["total_reports"] == 42
    assert summary["distinct_reporters"] == 17
    assert summary["country_code"] == "DE"
    assert summary["window_days"] == 90
    assert summary["notes"] == []


def test_abuseipdb_accepts_ipv6() -> None:
    wire = Wire(body=abuse_payload(ipAddress="2606:4700:4700::1111", ipVersion=6))

    result = build(AbuseIPDBCollector, wire).lookup(indicator("2606:4700:4700::1111"))

    assert wire.calls[0].url.params["ipAddress"] == "2606:4700:4700::1111"
    assert result.status is ProviderStatus.OK


def test_abuseipdb_no_reports_is_no_data() -> None:
    payload = abuse_payload(abuseConfidenceScore=0, totalReports=0, lastReportedAt=None)

    result = build(AbuseIPDBCollector, Wire(body=payload)).lookup(indicator("8.8.8.8"))

    assert result.status is ProviderStatus.NO_DATA
    assert result.signal == 0
    assert result.evidence_at is None


def test_abuseipdb_whitelisted_address_contributes_nothing() -> None:
    result = parse_abuseipdb(abuse_payload(isWhitelisted=True))

    assert result.signal == 0
    assert result.summary["is_whitelisted"] is True
    assert "whitelisted" in result.summary["notes"][0]


def test_abuseipdb_null_whitelist_flag_is_not_treated_as_whitelisted() -> None:
    result = parse_abuseipdb(abuse_payload(isWhitelisted=None))

    assert result.signal == pytest.approx(0.87)
    assert result.summary["is_whitelisted"] is False


def test_abuseipdb_discounts_a_confident_score_built_on_few_reports() -> None:
    result = parse_abuseipdb(abuse_payload(abuseConfidenceScore=60, totalReports=2))

    assert result.signal == pytest.approx(0.3)
    assert "discounted" in result.summary["notes"][0]


def test_abuseipdb_tor_exit_is_tagged() -> None:
    assert parse_abuseipdb(abuse_payload(isTor=True)).tags == ["tor"]


def test_abuseipdb_cleans_untrusted_text_fields() -> None:
    result = parse_abuseipdb(
        abuse_payload(
            isp="Evil\u202e\x00 ISP\n" + "x" * 500,
            countryCode="<script>",
            usageType=["not", "a", "string"],
            lastReportedAt="not-a-date",
        )
    )

    assert "\u202e" not in result.summary["isp"]
    assert "\x00" not in result.summary["isp"]
    assert len(result.summary["isp"]) <= 96
    assert result.summary["country_code"] is None
    assert result.summary["usage_type"] is None
    assert result.evidence_at is None


@pytest.mark.parametrize("value", ["domain.example.com", "http://example.com/", "a" * 64])
def test_abuseipdb_makes_no_request_for_unsupported_types(value: str) -> None:
    wire = Wire(body=abuse_payload())

    result = build(AbuseIPDBCollector, wire).lookup(indicator(value))

    assert result.status is ProviderStatus.UNSUPPORTED
    assert wire.calls == []


@pytest.mark.parametrize("cls", [AbuseIPDBCollector, OTXCollector])
@pytest.mark.parametrize("key", [None, ""])
def test_unconfigured_providers_make_no_request(cls: type[Collector], key: str | None) -> None:
    wire = Wire(body={})

    collector = build(cls, wire, key=key)
    result = collector.lookup(indicator("8.8.8.8"))

    assert not collector.configured
    assert result.status is ProviderStatus.NOT_CONFIGURED
    assert wire.calls == []


@pytest.mark.parametrize(
    ("status", "expected", "fragment"),
    [
        (401, ProviderStatus.ERROR, "credentials"),
        (403, ProviderStatus.ERROR, "credentials"),
        (404, ProviderStatus.ERROR, "unexpected HTTP status"),
        (429, ProviderStatus.RATE_LIMITED, "rate limit"),
        (500, ProviderStatus.ERROR, "unexpected HTTP status"),
        (503, ProviderStatus.ERROR, "unexpected HTTP status"),
        (302, ProviderStatus.ERROR, "unexpected HTTP status"),
        (204, ProviderStatus.ERROR, "unexpected HTTP status"),
    ],
)
def test_http_statuses_map_to_provider_statuses(
    status: int, expected: ProviderStatus, fragment: str
) -> None:
    headers = {"Location": "https://evil.example/steal"} if status == 302 else None
    wire = Wire(status, body={"errors": []}, headers=headers)

    result = build(AbuseIPDBCollector, wire).lookup(indicator("8.8.8.8"))

    assert result.status is expected
    assert fragment in (result.message or "")
    assert len(wire.calls) == 1, "redirects must never be followed"


@pytest.mark.parametrize(
    ("error", "fragment"),
    [
        (httpx2.ReadTimeout("slow"), "in time"),
        (httpx2.ConnectTimeout("slow"), "in time"),
        (httpx2.ConnectError("refused"), "Could not reach"),
        (httpx2.ReadError("reset"), "Could not reach"),
    ],
)
def test_network_failures_become_provider_errors(error: Exception, fragment: str) -> None:
    result = build(AbuseIPDBCollector, Wire(error=error)).lookup(indicator("8.8.8.8"))

    assert result.status is ProviderStatus.ERROR
    assert fragment in (result.message or "")


@pytest.mark.parametrize(
    "content",
    [b"not json", b"", b"\xff\xfe\x00bad utf8", b"[" * 100_000, b"<html>blocked</html>"],
)
def test_invalid_json_becomes_a_provider_error(content: bytes) -> None:
    result = build(AbuseIPDBCollector, Wire(content=content)).lookup(indicator("8.8.8.8"))

    assert result.status is ProviderStatus.ERROR
    assert "invalid JSON" in (result.message or "")


@pytest.mark.parametrize(
    "payload",
    [
        [],
        "text",
        {},
        {"data": []},
        {"data": {}},
        {"data": {"abuseConfidenceScore": "high"}},
        {"data": {"abuseConfidenceScore": True}},
        {"data": {"abuseConfidenceScore": 101}},
        {"data": {"abuseConfidenceScore": -1}},
        {"errors": [{"detail": "Daily rate limit exceeded."}]},
    ],
)
def test_unexpected_abuseipdb_shapes_are_errors(payload: Any) -> None:
    with pytest.raises(ProviderFailure) as excinfo:
        parse_abuseipdb(payload)

    assert excinfo.value.status is ProviderStatus.ERROR


def test_oversized_responses_are_refused() -> None:
    wire = Wire(content=b"{" + b" " * MAX_RESPONSE_BYTES + b"}")

    result = build(AbuseIPDBCollector, wire).lookup(indicator("8.8.8.8"))

    assert result.status is ProviderStatus.ERROR
    assert "too large" in (result.message or "")


def test_decompression_bombs_are_refused() -> None:
    bomb = gzip.compress(b" " * (MAX_RESPONSE_BYTES + 1024))
    wire = Wire(content=bomb, headers={"Content-Encoding": "gzip"})

    result = build(AbuseIPDBCollector, wire).lookup(indicator("8.8.8.8"))

    assert len(bomb) < MAX_RESPONSE_BYTES // 100
    assert result.status is ProviderStatus.ERROR
    assert "too large" in (result.message or "")


# --- AlienVault OTX ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "section", "path_value"),
    [
        ("8.8.8.8", "IPv4", "8.8.8.8"),
        ("2606:4700:4700::1111", "IPv6", "2606:4700:4700::1111"),
        ("example.com", "domain", "example.com"),
        ("a" * 64, "file", "a" * 64),
        (
            "https://example.com/a/b?x=1&y=%2F",
            "url",
            "https%3A%2F%2Fexample.com%2Fa%2Fb%3Fx%3D1%26y%3D%252F",
        ),
    ],
)
def test_otx_builds_the_documented_path(value: str, section: str, path_value: str) -> None:
    wire = Wire(body=otx_payload([]))

    build(OTXCollector, wire).lookup(indicator(value))

    (request,) = wire.calls
    assert request.url.host == "otx.alienvault.com"
    assert request.url.raw_path.decode() == f"/api/v1/indicators/{section}/{path_value}/general"
    assert request.headers["X-OTX-API-KEY"] == KEY
    assert request.headers["Accept"] == "application/json"


def test_otx_maps_pulses_to_signal_and_context() -> None:
    older = otx_pulse(
        id="a" * 24,
        name="Older report",
        created="2022-01-01T10:00:00.123456",
        modified="2022-02-01T10:00:00",
        tags=["PHISHING", "emotet"],
        malware_families=["Emotet", {"display_name": "TrickBot"}],
        attack_ids=["T1566.001", "javascript:alert(1)", {"id": "T1059"}],
    )
    newer = otx_pulse(modified=iso(1), created=iso(10))
    wire = Wire(body=otx_payload([older, newer, otx_pulse(name="Third", modified=iso(5))]))

    result = build(OTXCollector, wire).lookup(indicator("8.8.8.8"))

    assert result.status is ProviderStatus.OK
    assert result.signal == pytest.approx(0.55)
    summary = result.summary
    assert summary["pulse_count"] == 3
    assert [pulse["name"] for pulse in summary["top_pulses"]] == [
        "Example campaign",
        "Third",
        "Older report",
    ]
    assert summary["top_pulses"][0]["id"] == PULSE_ID
    assert summary["malware_families"] == ["Emotet", "TrickBot"]
    assert summary["attack_ids"] == ["T1566", "T1059", "T1566.001"]
    assert result.tags[:2] == ["phishing", "banking"]
    assert result.first_evidence_at == datetime(2022, 1, 1, 10, 0, 0, 123456, tzinfo=UTC)
    assert result.evidence_at is not None
    assert result.evidence_at > datetime.now(UTC) - timedelta(days=2)
    assert any("community-submitted" in note for note in summary["notes"])


def test_otx_not_found_means_no_data() -> None:
    result = build(OTXCollector, Wire(404, body={"detail": "not found"})).lookup(
        indicator("a" * 64)
    )

    assert result.status is ProviderStatus.NO_DATA
    assert result.signal == 0


def test_otx_without_pulses_is_no_data() -> None:
    result = build(OTXCollector, Wire(body=otx_payload([]))).lookup(indicator("8.8.8.8"))

    assert result.status is ProviderStatus.NO_DATA
    assert result.signal == 0
    assert result.evidence_at is None


def test_otx_trusts_the_reported_pulse_count_over_the_truncated_list() -> None:
    payload = {"pulse_info": {"count": 30, "pulses": [otx_pulse()]}}

    result = parse_otx(payload)

    assert result.summary["pulse_count"] == 30
    assert result.summary["pulses_analyzed"] == 1
    assert result.signal == 1.0


def test_otx_validation_entries_reduce_the_signal() -> None:
    payload = otx_payload(
        [otx_pulse(), otx_pulse(id="b" * 24)],
        validation=[{"source": "whitelist", "message": "Whitelisted domain example.com"}],
    )

    result = parse_otx(payload)

    assert result.signal == pytest.approx(0.4 * 0.25)
    assert result.summary["validation"] == [
        {"source": "whitelist", "message": "Whitelisted domain example.com"}
    ]
    assert any("validation" in note for note in result.summary["notes"])


@pytest.mark.parametrize(
    ("pulse_count", "expected"),
    [
        (0, 0.0),
        (1, 0.25),
        (2, 0.4),
        (3, 0.55),
        (4, 0.55),
        (5, 0.7),
        (9, 0.7),
        (10, 0.85),
        (24, 0.85),
        (25, 1.0),
        (10_000, 1.0),
    ],
)
def test_pulse_signal_steps(pulse_count: int, expected: float) -> None:
    assert pulse_signal(pulse_count) == expected


def test_otx_treats_hostile_pulse_text_as_inert_bounded_data() -> None:
    hostile = otx_pulse(
        name="<script>alert(1)</script>\u202e\x00\n" + "A" * 400,
        tags=["<img src=x onerror=alert(1)>", "\x07bell", 5, None, {"x": 1}],
        malware_families=[{"display_name": "x" * 300}],
        id="../../etc/passwd",
    )

    result = parse_otx(otx_payload([hostile]))

    (pulse,) = result.summary["top_pulses"]
    assert pulse["name"].startswith("<script>alert(1)</script>")
    assert len(pulse["name"]) <= 160
    assert "\u202e" not in pulse["name"] and "\x00" not in pulse["name"]
    assert pulse["id"] is None, "only 24-character hex pulse ids are kept"
    assert result.tags == ["<img src=x onerror=alert(1)>", "bell"]
    assert len(result.summary["malware_families"][0]) <= 64


def test_otx_ignores_implausible_timestamps() -> None:
    future = (datetime.now(UTC) + timedelta(days=30)).isoformat()
    pulses = [
        otx_pulse(created="1970-01-01T00:00:00", modified=future),
        otx_pulse(created="garbage", modified=None),
    ]

    result = parse_otx(otx_payload(pulses))

    assert result.evidence_at is None
    assert result.first_evidence_at is None


@pytest.mark.parametrize(
    "payload",
    [
        [],
        "text",
        None,
        {},
        {"pulse_info": []},
        {"pulse_info": {"pulses": "nope"}},
        {"detail": "Authentication required"},
    ],
)
def test_unexpected_otx_shapes_are_errors(payload: Any) -> None:
    with pytest.raises(ProviderFailure) as excinfo:
        parse_otx(payload)

    assert excinfo.value.status is ProviderStatus.ERROR


def test_otx_rate_limit_is_reported_as_such() -> None:
    result = build(OTXCollector, Wire(429, body={})).lookup(indicator("example.com"))

    assert result.status is ProviderStatus.RATE_LIMITED


# --- Shared behaviour --------------------------------------------------------------------


class _ExplodingCollector(Collector):
    name = "exploding"
    display_name = "Exploding"
    supported_types = frozenset(IndicatorType)

    def _query(self, indicator: NormalizedIndicator, api_key: str) -> ProviderResult:
        raise KeyError(f"leaky {api_key} {indicator.indicator_value}")


@pytest.mark.usefixtures("production_logging")
def test_parser_bugs_degrade_one_provider_without_leaking(
    caplog: pytest.LogCaptureFixture,
) -> None:
    result = build(_ExplodingCollector, Wire()).lookup(indicator("8.8.8.8"))

    assert result.status is ProviderStatus.ERROR
    assert KEY not in (result.message or "")
    assert "8.8.8.8" not in (result.message or "")
    assert_nothing_sensitive_logged(caplog, "8.8.8.8")


@pytest.mark.usefixtures("production_logging")
@pytest.mark.parametrize(
    ("cls", "value", "secret", "wire"),
    [
        (AbuseIPDBCollector, "8.8.4.4", "8.8.4.4", Wire(body=abuse_payload())),
        (AbuseIPDBCollector, "8.8.4.4", "8.8.4.4", Wire(401, body={})),
        (AbuseIPDBCollector, "8.8.4.4", "8.8.4.4", Wire(error=httpx2.ReadTimeout("slow"))),
        (AbuseIPDBCollector, "8.8.4.4", "8.8.4.4", Wire(content=b"not json")),
        (
            OTXCollector,
            "https://example.com/reset?token=s3cr3tT0ken",
            "s3cr3tT0ken",
            Wire(body=otx_payload([otx_pulse()])),
        ),
        (OTXCollector, "example.com", "example.com", Wire(429, body={})),
    ],
)
def test_logs_never_contain_the_indicator_or_the_api_key(
    cls: type[Collector], value: str, secret: str, wire: Wire, caplog: pytest.LogCaptureFixture
) -> None:
    result = build(cls, wire).lookup(indicator(value))

    assert KEY not in repr(result)
    assert any(record.getMessage() == "provider_lookup" for record in caplog.records), (
        "each lookup should leave an operational log line"
    )
    assert_nothing_sensitive_logged(caplog, secret)


def test_registry_builds_providers_in_display_order(
    make_settings: Callable[..., Settings],
) -> None:
    settings = make_settings(
        abuseipdb_api_key=KEY,
        abuseipdb_cache_ttl_seconds=120,
        provider_timeout_seconds=7,
        threatfox_api_key=KEY,
        threatfox_cache_ttl_seconds=300,
        threatfox_timeout_seconds=12,
        threatfox_max_retries=1,
    )
    client = build_http_client(settings)

    abuse, otx, virustotal, threatfox = build_collectors(settings, client)

    assert [c.name for c in (abuse, otx, virustotal, threatfox)] == [
        "abuseipdb",
        "otx",
        "virustotal",
        "threatfox",
    ]
    assert [c.configured for c in (abuse, otx, virustotal, threatfox)] == [
        True,
        False,
        False,
        True,
    ]
    assert abuse.cache_ttl_seconds == 120
    assert (threatfox.cache_ttl_seconds, threatfox.timeout_seconds) == (300, 12)
    assert abuse.timeout_seconds is None, "the older adapters keep the shared client's timeouts"
    assert virustotal.timeout_seconds == settings.virustotal_timeout_seconds
    assert client.follow_redirects is False
    assert client.timeout.read == 7
    assert client.headers["User-Agent"].startswith("CipherForge/")
    client.close()
