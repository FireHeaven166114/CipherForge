"""Application settings.

Settings come from environment variables and, for local development, an
optional ``.env`` file at the repository root. Invalid settings stop the
application from starting (fail closed). Error messages name the offending
setting but never echo its value, so a typo cannot leak a secret into logs.
"""

import base64
import binascii
import re
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import (
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from app import __version__
from app.security.roles import Role

REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = Path(__file__).resolve().parents[2]

Environment = Literal["development", "test", "production"]
AuthMode = Literal["dev", "entra"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
LogFormat = Literal["json", "console"]

# Template files ship credentials such as CHANGE_ME_local_only; production must not accept them.
_PLACEHOLDER_MARKER = "CHANGE_ME"

# Hosts for which a plain-http provider URL is accepted (local mock servers in tests and demos).
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
MASTER_KEY_BYTES = 32

DEFAULT_SUSPICIOUS_PORTS = (23, 135, 139, 445, 1433, 3389, 4444, 5900, 6667, 31337)
DEFAULT_EXPECTED_PROTOCOLS = ("tcp", "udp", "icmp", "icmpv6", "igmp")
_PROTOCOL_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,15}$")


class ConfigurationError(RuntimeError):
    """Invalid configuration. The message lists setting names, never values."""


def _split_csv(value: Any) -> Any:
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return value


def _normalise_guid(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    try:
        return str(uuid.UUID(value.strip()))
    except ValueError:
        raise ValueError("must be a GUID") from None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=REPO_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "cipherforge-api"
    app_version: str = __version__
    environment: Environment = "production"
    log_level: LogLevel = "INFO"
    log_format: LogFormat = "json"

    database_url: SecretStr

    auth_mode: AuthMode = "entra"
    dev_auth_roles: Annotated[list[Role], NoDecode] = Field(
        default_factory=lambda: [Role.SECURITY_ANALYST]
    )
    entra_tenant_id: str | None = None
    entra_client_id: str | None = None
    entra_audience: str | None = None

    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # Threat-intelligence providers. A missing key disables that provider; it is reported
    # as "not configured" rather than failing the lookup.
    abuseipdb_api_key: SecretStr | None = None
    otx_api_key: SecretStr | None = None
    abuseipdb_cache_ttl_seconds: int = Field(default=6 * 3600, ge=60, le=30 * 86400)
    otx_cache_ttl_seconds: int = Field(default=12 * 3600, ge=60, le=30 * 86400)
    provider_timeout_seconds: float = Field(default=10.0, ge=1.0, le=30.0)
    investigate_rate_limit_per_minute: int = Field(default=30, ge=1, le=600)

    # VirusTotal API v3 and ThreatFox (abuse.ch). The timeout is the budget for one lookup,
    # retries included; retries cover only timeouts, connection failures and 5xx answers.
    virustotal_api_key: SecretStr | None = None
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"
    virustotal_timeout_seconds: float = Field(default=15.0, ge=1.0, le=30.0)
    virustotal_max_retries: int = Field(default=2, ge=0, le=5)
    virustotal_cache_ttl_seconds: int = Field(default=24 * 3600, ge=60, le=30 * 86400)
    threatfox_api_key: SecretStr | None = None
    threatfox_base_url: str = "https://threatfox-api.abuse.ch/api/v1"
    threatfox_timeout_seconds: float = Field(default=15.0, ge=1.0, le=30.0)
    threatfox_max_retries: int = Field(default=2, ge=0, le=5)
    threatfox_cache_ttl_seconds: int = Field(default=6 * 3600, ge=60, le=30 * 86400)

    # Every user-facing timestamp is shown in Indian Standard Time. Storage and API values stay
    # UTC, so the setting only names the display zone and accepts nothing else.
    app_timezone: Literal["Asia/Kolkata"] = "Asia/Kolkata"

    # Network monitoring. Thresholds are development starting points, not security standards:
    # tune them to the monitored network.
    external_enrichment_enabled: bool = True
    network_retention_hours: int = Field(default=72, ge=1, le=24 * 90)
    max_active_flows: int = Field(default=10_000, ge=100, le=1_000_000)
    monitoring_buffer_size: int = Field(default=10_000, ge=100, le=1_000_000)
    network_max_pcap_size_mb: int = Field(default=50, ge=1, le=500)
    network_enrichment_max_ips: int = Field(default=25, ge=1, le=200)
    # Enrichment looks addresses up one at a time at this pace. The default stays inside
    # VirusTotal's free public quota (4 requests per minute); raise it only with a higher quota.
    network_enrichment_max_per_minute: int = Field(default=4, ge=1, le=60)
    # A flow with no packets for this long is closed and written to the database.
    flow_idle_timeout_seconds: int = Field(default=60, ge=5, le=3600)
    # Flow rows kept per session; the oldest are dropped first once a session exceeds this.
    network_max_stored_flows: int = Field(default=20_000, ge=100, le=1_000_000)
    # A public address whose existing CipherForge risk score is at least this (61 is the "high"
    # band) raises a known-malicious-address alert.
    known_malicious_min_score: int = Field(default=61, ge=1, le=100)
    port_scan_threshold: int = Field(default=20, ge=2, le=65_535)
    port_scan_window_seconds: int = Field(default=60, ge=1, le=3600)
    connection_rate_threshold: int = Field(default=100, ge=2, le=1_000_000)
    connection_rate_window_seconds: int = Field(default=60, ge=1, le=3600)
    syn_rate_threshold: int = Field(default=200, ge=2, le=10_000_000)
    syn_rate_window_seconds: int = Field(default=10, ge=1, le=3600)
    suspicious_port_threshold: int = Field(default=25, ge=2, le=1_000_000)
    suspicious_port_window_seconds: int = Field(default=60, ge=1, le=3600)
    suspicious_ports: Annotated[list[int], NoDecode] = Field(
        default_factory=lambda: list(DEFAULT_SUSPICIOUS_PORTS)
    )
    high_volume_threshold_mb: int = Field(default=50, ge=1, le=1_000_000)
    high_volume_window_seconds: int = Field(default=60, ge=1, le=3600)
    expected_protocols: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: list(DEFAULT_EXPECTED_PROTOCOLS)
    )

    # Encrypted file sharing. Without a valid master key the feature reports itself as not
    # configured; a malformed key stops the application from starting.
    cipherforge_master_key: SecretStr | None = None
    encrypted_file_storage_path: Path = BACKEND_ROOT / "data" / "encrypted-files"
    max_encrypted_file_size_mb: int = Field(default=25, ge=1, le=100)
    default_share_expiry_hours: int = Field(default=24, ge=1, le=24 * 365)
    max_share_expiry_hours: int = Field(default=24 * 30, ge=1, le=24 * 365)
    max_share_downloads: int = Field(default=100, ge=1, le=10_000)
    file_upload_rate_limit_per_minute: int = Field(default=10, ge=1, le=600)
    share_create_rate_limit_per_minute: int = Field(default=10, ge=1, le=600)
    share_download_rate_limit_per_minute: int = Field(default=30, ge=1, le=600)
    share_password_attempt_limit: int = Field(default=5, ge=1, le=100)

    @field_validator(
        "abuseipdb_api_key",
        "otx_api_key",
        "virustotal_api_key",
        "threatfox_api_key",
        mode="after",
    )
    @classmethod
    def _clean_api_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        raw = value.get_secret_value().strip()
        if not raw:
            return None
        # Keys travel in HTTP headers: whitespace or control characters would corrupt them.
        if not raw.isascii() or any(ord(char) <= 32 or ord(char) == 127 for char in raw):
            raise ValueError("must not contain whitespace or control characters")
        return SecretStr(raw)

    @field_validator("virustotal_base_url", "threatfox_base_url", mode="after")
    @classmethod
    def _validate_provider_url(cls, value: str) -> str:
        cleaned = value.strip().rstrip("/")
        try:
            parsed = urlsplit(cleaned)
            host = parsed.hostname
        except ValueError:
            raise ValueError("is not a valid URL") from None
        if parsed.scheme not in {"https", "http"} or not host:
            raise ValueError("must be an http(s) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("must not contain credentials, a query string or a fragment")
        if parsed.scheme == "http" and host not in _LOOPBACK_HOSTS:
            # The API key is sent to this host, so it must not travel in clear text.
            raise ValueError("must use https (plain http is accepted only for loopback)")
        return cleaned

    @field_validator("cipherforge_master_key", mode="after")
    @classmethod
    def _validate_master_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        raw = value.get_secret_value().strip()
        if not raw:
            return None
        message = f"must be {MASTER_KEY_BYTES} random bytes encoded as base64url"
        if not _BASE64URL.fullmatch(raw):
            raise ValueError(message)
        try:
            decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except (binascii.Error, ValueError):
            raise ValueError(message) from None
        if len(decoded) != MASTER_KEY_BYTES:
            raise ValueError(message)
        if len(set(decoded)) < 8:
            raise ValueError("does not look random; generate a new key")
        return SecretStr(raw)

    @field_validator("encrypted_file_storage_path", mode="before")
    @classmethod
    def _default_blank_storage_path(cls, value: Any) -> Any:
        if value is None or (isinstance(value, str) and not value.strip()):
            return BACKEND_ROOT / "data" / "encrypted-files"
        return value

    @field_validator("encrypted_file_storage_path", mode="after")
    @classmethod
    def _absolute_storage_path(cls, value: Path) -> Path:
        # A relative path would move with the working directory; anchor it to the backend folder.
        return value if value.is_absolute() else BACKEND_ROOT / value

    @field_validator("suspicious_ports", mode="before")
    @classmethod
    def _parse_ports(cls, value: Any) -> Any:
        value = _split_csv(value)
        if not isinstance(value, list):
            return value
        try:
            return [int(item) for item in value]
        except (TypeError, ValueError):
            raise ValueError("must be a comma separated list of port numbers") from None

    @field_validator("suspicious_ports", mode="after")
    @classmethod
    def _check_ports(cls, value: list[int]) -> list[int]:
        if not all(1 <= port <= 65_535 for port in value):
            raise ValueError("ports must be between 1 and 65535")
        return sorted(set(value))

    @field_validator("expected_protocols", mode="before")
    @classmethod
    def _parse_protocols(cls, value: Any) -> Any:
        value = _split_csv(value)
        if isinstance(value, list):
            return [str(item).strip().lower() for item in value]
        return value

    @field_validator("expected_protocols", mode="after")
    @classmethod
    def _check_protocols(cls, value: list[str]) -> list[str]:
        if not value or not all(_PROTOCOL_NAME.fullmatch(name) for name in value):
            raise ValueError("must list protocol names such as tcp,udp,icmp")
        return list(dict.fromkeys(value))

    @field_validator("dev_auth_roles", mode="before")
    @classmethod
    def _parse_roles(cls, value: Any) -> Any:
        value = _split_csv(value)
        if not isinstance(value, list):
            return value
        roles: list[Role] = []
        for item in value:
            role = item if isinstance(item, Role) else Role.parse(str(item))
            if role is None:
                raise ValueError("contains an unknown role")
            roles.append(role)
        return roles

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_origins(cls, value: Any) -> Any:
        return _split_csv(value)

    @field_validator("cors_origins")
    @classmethod
    def _reject_wildcard_origin(cls, value: list[str]) -> list[str]:
        if "*" in value:
            raise ValueError("wildcard origins are not allowed")
        return [origin.rstrip("/") for origin in value]

    @field_validator("entra_tenant_id", "entra_client_id", mode="after")
    @classmethod
    def _validate_guid(cls, value: str | None) -> str | None:
        return _normalise_guid(value)

    @field_validator("entra_audience", mode="after")
    @classmethod
    def _blank_audience_is_unset(cls, value: str | None) -> str | None:
        return value.strip() or None if value else None

    @field_validator("database_url", mode="after")
    @classmethod
    def _validate_database_url(cls, value: SecretStr) -> SecretStr:
        try:
            backend = make_url(value.get_secret_value()).get_backend_name()
        except ArgumentError:
            raise ValueError("is not a valid SQLAlchemy URL") from None
        if backend not in {"postgresql", "sqlite"}:
            raise ValueError("uses an unsupported database backend")
        return value

    @model_validator(mode="after")
    def _enforce_safe_combinations(self) -> "Settings":
        if self.auth_mode == "dev" and self.environment == "production":
            raise ValueError("AUTH_MODE=dev is not permitted when ENVIRONMENT=production")
        if self.auth_mode == "entra" and not (self.entra_tenant_id and self.entra_client_id):
            raise ValueError("AUTH_MODE=entra requires ENTRA_TENANT_ID and ENTRA_CLIENT_ID")
        if self.environment == "production" and self.database_backend != "postgresql":
            raise ValueError("ENVIRONMENT=production requires a PostgreSQL DATABASE_URL")
        if (
            self.environment == "production"
            and _PLACEHOLDER_MARKER in self.database_url.get_secret_value().upper()
        ):
            raise ValueError("DATABASE_URL still contains a CHANGE_ME placeholder")
        if self.default_share_expiry_hours > self.max_share_expiry_hours:
            raise ValueError("DEFAULT_SHARE_EXPIRY_HOURS must not exceed MAX_SHARE_EXPIRY_HOURS")
        return self

    @property
    def database_backend(self) -> str:
        return make_url(self.database_url.get_secret_value()).get_backend_name()

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def entra_issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.entra_tenant_id}/v2.0"

    @property
    def entra_jwks_url(self) -> str:
        return f"https://login.microsoftonline.com/{self.entra_tenant_id}/discovery/v2.0/keys"

    @property
    def entra_expected_audience(self) -> str | None:
        return self.entra_audience or self.entra_client_id

    @property
    def master_key(self) -> bytes | None:
        """The raw 32-byte key-encryption key, or None when file sharing is not configured."""
        if self.cipherforge_master_key is None:
            return None
        raw = self.cipherforge_master_key.get_secret_value()
        return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))

    def secret_values(self) -> list[str]:
        """Plain-text secrets that must never appear in logs."""
        values: list[str] = []
        for name in type(self).model_fields:
            field_value = getattr(self, name)
            if isinstance(field_value, SecretStr) and field_value.get_secret_value():
                values.append(field_value.get_secret_value())
        password = make_url(self.database_url.get_secret_value()).password
        if password:
            values.append(password)
        return values


def load_settings(**overrides: Any) -> Settings:
    """Build settings, converting validation failures into a value-free error."""
    try:
        return Settings(**overrides)
    except ValidationError as exc:
        problems = []
        for error in exc.errors(include_input=False, include_url=False):
            location = ".".join(str(part).upper() for part in error["loc"]) or "SETTINGS"
            message = str(error["msg"]).removeprefix("Value error, ")
            problems.append(f"{location}: {message}")
        raise ConfigurationError("Invalid configuration - " + "; ".join(problems)) from None


@lru_cache
def get_settings() -> Settings:
    return load_settings()
