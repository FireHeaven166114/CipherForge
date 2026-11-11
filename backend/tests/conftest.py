"""Shared fixtures.

Tests never read the developer's real ``.env`` or environment: settings are
built with ``_env_file=None`` and the variables the app reads are cleared.
"""

import base64
import hashlib
import hmac
import json
import os
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import jwt
import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.core.logging_config import clear_registered_secrets
from app.main import create_app
from app.security.auth import EntraTokenValidator

BACKEND_DIR = Path(__file__).resolve().parents[1]
TENANT_ID = "11111111-2222-3333-4444-555555555555"
CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"

_ENV_VARS = (
    "ENVIRONMENT",
    "LOG_LEVEL",
    "LOG_FORMAT",
    "DATABASE_URL",
    "AUTH_MODE",
    "DEV_AUTH_ROLES",
    "ENTRA_TENANT_ID",
    "ENTRA_CLIENT_ID",
    "ENTRA_AUDIENCE",
    "CORS_ORIGINS",
    "ABUSEIPDB_API_KEY",
    "OTX_API_KEY",
    "ABUSEIPDB_CACHE_TTL_SECONDS",
    "OTX_CACHE_TTL_SECONDS",
    "PROVIDER_TIMEOUT_SECONDS",
    "INVESTIGATE_RATE_LIMIT_PER_MINUTE",
)


@pytest.fixture(autouse=True)
def _isolated_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    clear_registered_secrets()
    yield
    clear_registered_secrets()


@pytest.fixture
def make_settings(tmp_path: Any) -> Callable[..., Settings]:
    def factory(**overrides: Any) -> Settings:
        values: dict[str, Any] = {
            "environment": "test",
            "auth_mode": "dev",
            "log_format": "json",
            "database_url": f"sqlite+pysqlite:///{(tmp_path / 'test.db').as_posix()}",
        }
        values.update(overrides)
        return Settings(_env_file=None, **values)

    return factory


@pytest.fixture
def client(make_settings: Callable[..., Settings]) -> Iterator[TestClient]:
    with TestClient(create_app(make_settings())) as test_client:
        yield test_client


# --- Migrated database --------------------------------------------------------


def _migrate(url: str, *, down: bool = False) -> None:
    """Run the real Alembic migrations, so tests exercise the schema and triggers we ship."""
    engine = create_engine(url, poolclass=NullPool)
    try:
        with engine.begin() as connection:
            config = Config(str(BACKEND_DIR / "alembic.ini"))
            config.attributes["connection"] = connection
            if down:
                command.downgrade(config, "base")
            else:
                command.upgrade(config, "head")
    finally:
        engine.dispose()


@pytest.fixture(params=["sqlite", "postgresql"])
def db_url(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[str]:
    """A freshly migrated database. PostgreSQL runs only when TEST_DATABASE_URL is set."""
    if request.param == "sqlite":
        url = f"sqlite+pysqlite:///{(tmp_path / 'migrated.db').as_posix()}"
        _migrate(url)
        yield url
        return

    url = os.getenv("TEST_DATABASE_URL", "")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set")
    _migrate(url)
    try:
        yield url
    finally:
        # audit_logs rejects TRUNCATE by design, so reset by dropping the schema.
        _migrate(url, down=True)


# --- Entra token helpers ------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class TokenFactory:
    """Builds signed (and deliberately malformed) Entra-style access tokens."""

    def __init__(self) -> None:
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.public_pem = self.public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def claims(
        overrides: dict[str, Any] | None = None, remove: tuple[str, ...] = ()
    ) -> dict[str, Any]:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "sub-123",
            "oid": "oid-456",
            "tid": TENANT_ID,
            "name": "Ada Analyst",
            "iat": now,
            "nbf": now - 5,
            "exp": now + 3600,
            "roles": ["SecurityAnalyst"],
        }
        claims.update(overrides or {})
        for name in remove:
            claims.pop(name, None)
        return claims

    def make(
        self,
        overrides: dict[str, Any] | None = None,
        remove: tuple[str, ...] = (),
        signing_key: Any = None,
    ) -> str:
        return jwt.encode(
            self.claims(overrides, remove),
            signing_key or self.private_key,
            algorithm="RS256",
            headers={"kid": "test-key"},
        )

    def forge_hs256_with_public_key(self) -> str:
        """Classic algorithm-confusion attack: HMAC-sign using the public key as the secret."""
        header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        payload = _b64url(json.dumps(self.claims()).encode())
        signing_input = f"{header}.{payload}".encode()
        signature = hmac.new(self.public_pem, signing_input, hashlib.sha256).digest()
        return f"{header}.{payload}.{_b64url(signature)}"

    def forge_alg_none(self) -> str:
        header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        payload = _b64url(json.dumps(self.claims()).encode())
        return f"{header}.{payload}."


@pytest.fixture(scope="session")
def tokens() -> TokenFactory:
    return TokenFactory()


@pytest.fixture
def entra_validator(tokens: TokenFactory) -> EntraTokenValidator:
    return EntraTokenValidator(
        tenant_id=TENANT_ID,
        issuer=ISSUER,
        audience=CLIENT_ID,
        key_resolver=lambda _token: tokens.public_key,
    )


@pytest.fixture
def entra_settings(make_settings: Callable[..., Settings]) -> Settings:
    return make_settings(
        auth_mode="entra",
        entra_tenant_id=TENANT_ID,
        entra_client_id=CLIENT_ID,
    )
