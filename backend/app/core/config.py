"""Application settings.

Settings come from environment variables and, for local development, an
optional ``.env`` file at the repository root. Invalid settings stop the
application from starting (fail closed). Error messages name the offending
setting but never echo its value, so a typo cannot leak a secret into logs.
"""

import uuid
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal

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

Environment = Literal["development", "test", "production"]
AuthMode = Literal["dev", "entra"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
LogFormat = Literal["json", "console"]

# Template files ship credentials such as CHANGE_ME_local_only; production must not accept them.
_PLACEHOLDER_MARKER = "CHANGE_ME"


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
