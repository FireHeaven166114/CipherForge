"""Validation of the settings added for the VirusTotal, ThreatFox, network and file-sharing work."""

import base64
import secrets
from pathlib import Path
from typing import Any

import pytest

from app.core.config import BACKEND_ROOT, ConfigurationError, Settings, load_settings

SQLITE_URL = "sqlite+pysqlite:///unused.db"


def make(**overrides: Any) -> Settings:
    return load_settings(
        _env_file=None,
        environment="test",
        auth_mode="dev",
        database_url=SQLITE_URL,
        **overrides,
    )


def new_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def test_new_features_are_off_or_safe_by_default() -> None:
    settings = make()

    assert settings.virustotal_api_key is None
    assert settings.threatfox_api_key is None
    assert settings.cipherforge_master_key is None
    assert settings.master_key is None
    assert settings.app_timezone == "Asia/Kolkata"
    assert settings.external_enrichment_enabled is True
    assert settings.encrypted_file_storage_path == BACKEND_ROOT / "data" / "encrypted-files"


def test_documented_development_thresholds_are_the_defaults() -> None:
    settings = make()

    assert (settings.port_scan_threshold, settings.port_scan_window_seconds) == (20, 60)
    assert (settings.connection_rate_threshold, settings.connection_rate_window_seconds) == (
        100,
        60,
    )
    assert (settings.syn_rate_threshold, settings.syn_rate_window_seconds) == (200, 10)
    assert (settings.suspicious_port_threshold, settings.suspicious_port_window_seconds) == (
        25,
        60,
    )
    assert settings.flow_idle_timeout_seconds == 60
    assert settings.network_max_stored_flows == 20_000
    assert settings.network_enrichment_max_per_minute == 4
    assert settings.known_malicious_min_score == 61
    assert settings.expected_protocols == ["tcp", "udp", "icmp", "icmpv6", "igmp"]


@pytest.mark.parametrize("name", ["virustotal_api_key", "threatfox_api_key"])
def test_blank_provider_keys_mean_not_configured(name: str) -> None:
    assert getattr(make(**{name: "   "}), name) is None


@pytest.mark.parametrize("name", ["virustotal_api_key", "threatfox_api_key"])
def test_provider_keys_with_whitespace_are_rejected_without_echoing_them(name: str) -> None:
    with pytest.raises(ConfigurationError) as excinfo:
        make(**{name: "abc def"})

    assert name.upper() in str(excinfo.value)
    assert "abc def" not in str(excinfo.value)


def test_new_secrets_are_listed_for_log_redaction_and_hidden_from_repr() -> None:
    key = new_key()
    settings = make(
        virustotal_api_key="vt-secret-value",
        threatfox_api_key="tf-secret-value",
        cipherforge_master_key=key,
    )

    assert {"vt-secret-value", "tf-secret-value", key} <= set(settings.secret_values())
    for secret in ("vt-secret-value", "tf-secret-value", key):
        assert secret not in repr(settings)


@pytest.mark.parametrize(
    "name",
    [
        "virustotal_base_url",
        "threatfox_base_url",
    ],
)
@pytest.mark.parametrize(
    "url",
    [
        "http://www.virustotal.com/api/v3",
        "ftp://example.org/api",
        "https://user:pw@example.org/api",
        "https://example.org/api?key=1",
        "https://example.org/api#frag",
        "not a url",
        "https:///api",
    ],
)
def test_provider_urls_must_be_plain_https(name: str, url: str) -> None:
    with pytest.raises(ConfigurationError) as excinfo:
        make(**{name: url})

    assert name.upper() in str(excinfo.value)
    assert "pw@" not in str(excinfo.value)


def test_provider_urls_allow_loopback_http_and_strip_trailing_slash() -> None:
    settings = make(
        virustotal_base_url="http://127.0.0.1:9999/api/v3/",
        threatfox_base_url="https://example.org/api/v1/",
    )

    assert settings.virustotal_base_url == "http://127.0.0.1:9999/api/v3"
    assert settings.threatfox_base_url == "https://example.org/api/v1"


def test_master_key_accepts_base64url_with_or_without_padding() -> None:
    raw = secrets.token_bytes(32)
    padded = base64.urlsafe_b64encode(raw).decode()

    assert make(cipherforge_master_key=padded).master_key == raw
    assert make(cipherforge_master_key=padded.rstrip("=")).master_key == raw


@pytest.mark.parametrize(
    "value",
    [
        "short",
        base64.urlsafe_b64encode(secrets.token_bytes(16)).decode(),
        base64.urlsafe_b64encode(secrets.token_bytes(48)).decode(),
        "!" * 43,
        base64.b64encode(b"\xfb" * 32).decode(),  # standard base64 alphabet, not base64url
        base64.urlsafe_b64encode(b"\x00" * 32).decode(),
        base64.urlsafe_b64encode(b"ab" * 16).decode(),
    ],
)
def test_malformed_master_keys_stop_startup_without_echoing_the_value(value: str) -> None:
    with pytest.raises(ConfigurationError) as excinfo:
        make(cipherforge_master_key=value)

    assert "CIPHERFORGE_MASTER_KEY" in str(excinfo.value)
    assert value not in str(excinfo.value)


def test_blank_master_key_leaves_file_sharing_unconfigured() -> None:
    assert make(cipherforge_master_key="").master_key is None


def test_default_share_expiry_may_not_exceed_the_maximum() -> None:
    with pytest.raises(ConfigurationError, match="DEFAULT_SHARE_EXPIRY_HOURS"):
        make(default_share_expiry_hours=48, max_share_expiry_hours=24)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("virustotal_max_retries", 6),
        ("threatfox_max_retries", -1),
        ("virustotal_timeout_seconds", 0.5),
        ("threatfox_timeout_seconds", 31),
        ("max_active_flows", 10),
        ("monitoring_buffer_size", 10),
        ("max_encrypted_file_size_mb", 0),
        ("max_encrypted_file_size_mb", 101),
        ("max_share_downloads", 0),
        ("port_scan_threshold", 1),
        ("syn_rate_window_seconds", 0),
        ("network_retention_hours", 0),
        ("flow_idle_timeout_seconds", 1),
        ("network_max_stored_flows", 10),
        ("network_enrichment_max_per_minute", 0),
        ("known_malicious_min_score", 0),
        ("known_malicious_min_score", 101),
    ],
)
def test_numeric_settings_are_range_checked(name: str, value: float) -> None:
    with pytest.raises(ConfigurationError, match=name.upper()):
        make(**{name: value})


def test_only_the_ist_display_zone_is_supported() -> None:
    with pytest.raises(ConfigurationError, match="APP_TIMEZONE"):
        make(app_timezone="Europe/London")


def test_suspicious_ports_parse_from_a_comma_separated_list() -> None:
    assert make(suspicious_ports="445, 23,445,3389").suspicious_ports == [23, 445, 3389]


@pytest.mark.parametrize("value", ["0", "65536", "ssh", "22,,x"])
def test_suspicious_ports_reject_invalid_entries(value: str) -> None:
    with pytest.raises(ConfigurationError, match="SUSPICIOUS_PORTS"):
        make(suspicious_ports=value)


def test_expected_protocols_are_normalised_and_validated() -> None:
    assert make(expected_protocols="TCP, udp ,tcp").expected_protocols == ["tcp", "udp"]
    with pytest.raises(ConfigurationError, match="EXPECTED_PROTOCOLS"):
        make(expected_protocols="tcp;udp")
    with pytest.raises(ConfigurationError, match="EXPECTED_PROTOCOLS"):
        make(expected_protocols=" , ")


def test_storage_path_is_anchored_to_the_backend_folder_and_blank_means_default() -> None:
    assert make(encrypted_file_storage_path="var/files").encrypted_file_storage_path == (
        BACKEND_ROOT / "var" / "files"
    )
    assert make(encrypted_file_storage_path="").encrypted_file_storage_path == (
        BACKEND_ROOT / "data" / "encrypted-files"
    )


def test_absolute_storage_path_is_kept(tmp_path: Path) -> None:
    assert make(encrypted_file_storage_path=str(tmp_path)).encrypted_file_storage_path == tmp_path


def test_new_settings_load_from_environment_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", SQLITE_URL)
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("AUTH_MODE", "dev")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-from-env")
    monkeypatch.setenv("EXTERNAL_ENRICHMENT_ENABLED", "false")
    monkeypatch.setenv("SUSPICIOUS_PORTS", "8080,9001")
    monkeypatch.setenv("PORT_SCAN_THRESHOLD", "7")

    settings = load_settings(_env_file=None)

    assert settings.virustotal_api_key is not None
    assert settings.virustotal_api_key.get_secret_value() == "vt-from-env"
    assert settings.external_enrichment_enabled is False
    assert settings.suspicious_ports == [8080, 9001]
    assert settings.port_scan_threshold == 7
