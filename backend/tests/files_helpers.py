"""Harness shared by the encrypted-file tests.

``api_factory`` builds a real application (Entra auth with per-user tokens, a migrated SQLite
database, a master key, a blob directory under ``tmp_path``) whose file service has a cheap
Argon2id cost and controllable clocks, plus helpers to drive the API and to look at what ended
up in the database, the audit trail and the blob directory.
"""

import base64
import logging
import secrets
import uuid
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.files.crypto import KdfParams
from app.files.service import Caller, FileService
from app.main import create_app
from app.models.audit import AuditLog
from app.models.files import EncryptedFile, FileShare
from app.services.intel_service import IntelService
from tests.conftest import CLIENT_ID, TENANT_ID, TokenFactory

# Far below the production cost so the suite stays fast; one test uses the real defaults.
FAST_KDF = KdfParams(time_cost=1, memory_kib=64, parallelism=1)

USER = "User"
ANALYST = "SecurityAnalyst"
ADMIN = "Admin"

CLIENT_ADDRESS = "203.0.113.7"
OCTET_STREAM = "application/octet-stream"
API = "/api/v1"

# Markers that must never appear in the database, the blobs, logs, errors or audit rows.
CONTENT_MARKER = b"CF-PLAINTEXT-MARKER-7f3c1a9e"
NAME_MARKER = "Quarterly-Plan-9a1c"
CONTENT = CONTENT_MARKER + bytes(range(256)) * 3
FILE_NAME = f"{NAME_MARKER}.txt"
PASSWORD = "correct horse staple"
WRONG_PASSWORD = "incorrect horse staple"

_GENERATE = object()


def random_key() -> str:
    """A fresh master key in the format the setting expects (base64url of 32 random bytes)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def assert_error(response: Response, status: int, code: str) -> dict[str, Any]:
    """Check the status and the stable error code of an error envelope; return the error."""
    assert response.status_code == status, response.text
    error: dict[str, Any] = response.json()["error"]
    assert error["code"] == code, error
    return error


def rendered_logs(caplog: pytest.LogCaptureFixture) -> str:
    """Everything the captured log records carry: message, every attribute and any traceback."""
    formatter = logging.Formatter()
    parts = [caplog.text]
    for record in caplog.records:
        parts.append(f"{record.getMessage()} {vars(record)}")
        if record.exc_info:
            parts.append(formatter.formatException(record.exc_info))
    return "\n".join(parts)


class Clock:
    """A controllable wall clock for share expiry and audit timestamps."""

    def __init__(self) -> None:
        self.now = datetime.now(UTC).replace(microsecond=0)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta: float) -> None:
        self.now += timedelta(**delta)


class Ticker:
    """A controllable monotonic clock for the rate limiters."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass(frozen=True)
class Link:
    file_id: str
    share_id: str
    token: str


@dataclass
class FileApi:
    app: FastAPI
    client: TestClient
    clock: Clock
    ticks: Ticker
    tokens: TokenFactory
    make_settings: Callable[..., Settings]
    options: dict[str, Any]
    kdf: KdfParams
    db_url: str
    storage_root: Path
    service: FileService

    # --- Identities and requests --------------------------------------------------------------

    def headers(self, user: str = "alice", roles: Sequence[str] = (USER,)) -> dict[str, str]:
        token = self.tokens.make({"oid": user, "roles": list(roles)})
        return {"Authorization": f"Bearer {token}"}

    def request(
        self,
        method: str,
        path: str,
        *,
        user: str | None = "alice",
        roles: Sequence[str] = (USER,),
        headers: dict[str, str] | None = None,
        client: TestClient | None = None,
        **kwargs: Any,
    ) -> Response:
        """Send a request as ``user`` (``None`` is anonymous)."""
        merged = {**(self.headers(user, roles) if user else {}), **(headers or {})}
        return (client or self.client).request(method, f"{API}{path}", headers=merged, **kwargs)

    def from_address(self, address: str) -> TestClient:
        return TestClient(self.app, client=(address, 50000))

    def upload(
        self,
        content: bytes | Iterable[bytes] = CONTENT,
        *,
        name: str | None = FILE_NAME,
        encoded_name: str | None = None,
        content_type: str | None = OCTET_STREAM,
        user: str | None = "alice",
        roles: Sequence[str] = (USER,),
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> Response:
        merged: dict[str, str] = {}
        if content_type is not None:
            merged["Content-Type"] = content_type
        if encoded_name is not None:
            merged["X-File-Name"] = encoded_name
        elif name is not None:
            merged["X-File-Name"] = quote(name, safe="")
        merged.update(headers or {})
        return self.request(
            "POST", "/files", content=content, user=user, roles=roles, headers=merged, **kwargs
        )

    def new_file(self, content: bytes = CONTENT, **kwargs: Any) -> str:
        response = self.upload(content, **kwargs)
        assert response.status_code == 201, response.text
        return str(response.json()["id"])

    def share(
        self,
        file_id: str,
        *,
        user: str | None = "alice",
        roles: Sequence[str] = (USER,),
        **body: Any,
    ) -> Response:
        return self.request("POST", f"/files/{file_id}/shares", json=body, user=user, roles=roles)

    def new_link(self, file_id: str | None = None, **body: Any) -> Link:
        file_id = file_id or self.new_file()
        response = self.share(file_id, **body)
        assert response.status_code == 201, response.text
        data = response.json()
        return Link(file_id, data["share"]["id"], data["token"])

    def revoke(self, link: Link, **kwargs: Any) -> Response:
        return self.request(
            "POST", f"/files/{link.file_id}/shares/{link.share_id}/revoke", **kwargs
        )

    def info(self, token: str, *, client: TestClient | None = None) -> Response:
        return (client or self.client).get(f"{API}/shares/{token}")

    def fetch(self, token: str, *, client: TestClient | None = None) -> Response:
        """The GET download, which cannot carry a password."""
        return (client or self.client).get(f"{API}/shares/{token}/download")

    def fetch_with(
        self, token: str, password: str | None, *, client: TestClient | None = None
    ) -> Response:
        return (client or self.client).post(
            f"{API}/shares/{token}/download", json={"password": password}
        )

    # --- What is stored -----------------------------------------------------------------------

    def session(self) -> Session:
        return self.app.state.session_factory()

    def rows(self, statement: Any) -> list[Any]:
        with self.session() as session:
            return list(session.scalars(statement))

    def audit(self, file_id: str | None = None) -> list[AuditLog]:
        statement = select(AuditLog).order_by(AuditLog.id)
        if file_id is not None:
            statement = statement.where(AuditLog.target == f"file:{file_id}")
        return self.rows(statement)

    def actions(self, file_id: str | None = None) -> list[tuple[str, str]]:
        return [(row.action, row.result) for row in self.audit(file_id)]

    def file_row(self, file_id: str) -> EncryptedFile:
        return self.rows(select(EncryptedFile).where(EncryptedFile.id == uuid.UUID(file_id)))[0]

    def share_row(self, share_id: str) -> FileShare:
        return self.rows(select(FileShare).where(FileShare.id == uuid.UUID(share_id)))[0]

    def blob_path(self, file_id: str) -> Path:
        return self.storage_root / self.file_row(file_id).storage_name

    def blobs(self) -> list[Path]:
        return sorted(self.storage_root.iterdir()) if self.storage_root.exists() else []

    def corrupt_blob(self, file_id: str, *, position: int = 0) -> None:
        """Flip one bit of the stored ciphertext, as bit rot or an attacker with disk access."""
        path = self.blob_path(file_id)
        data = bytearray(path.read_bytes())
        data[position] ^= 0x01
        path.write_bytes(bytes(data))

    @property
    def database_file(self) -> Path:
        return Path(self.db_url.removeprefix("sqlite+pysqlite:///"))

    def caller(self, user: str = "alice") -> Caller:
        return Caller(user, CLIENT_ADDRESS)

    @contextmanager
    def statements(self) -> Iterator[list[str]]:
        """Every SQL statement the application's engine runs inside the block."""
        seen: list[str] = []

        def record(*args: Any) -> None:
            seen.append(args[2])

        engine = self.app.state.engine
        event.listen(engine, "before_cursor_execute", record)
        try:
            yield seen
        finally:
            event.remove(engine, "before_cursor_execute", record)

    def reconfigure(self, **overrides: Any) -> FileService:
        """Swap in a service built from changed settings, over the same database and blobs."""
        self.options = {**self.options, **overrides}
        self.service = FileService(
            self.make_settings(**self.options),
            clock=self.clock,
            kdf_params=self.kdf,
            limiter_clock=self.ticks,
        )
        self.app.state.file_service = self.service
        return self.service


ApiFactory = Callable[..., FileApi]


def api_factory(
    make_settings: Callable[..., Settings],
    entra_validator: Any,
    tokens: TokenFactory,
    db_url: str,
    tmp_path: Path,
) -> Iterator[ApiFactory]:
    """The body of the ``make_api`` fixture, shared by the test modules."""
    with ExitStack() as stack:

        def build(
            *,
            master_key: Any = _GENERATE,
            kdf: KdfParams = FAST_KDF,
            client_address: str = CLIENT_ADDRESS,
            **settings: Any,
        ) -> FileApi:
            options: dict[str, Any] = {
                "auth_mode": "entra",
                "entra_tenant_id": TENANT_ID,
                "entra_client_id": CLIENT_ID,
                "database_url": db_url,
                "cipherforge_master_key": random_key() if master_key is _GENERATE else master_key,
                "encrypted_file_storage_path": tmp_path / "blobs",
                # Keep unrelated tests clear of the budgets; the rate-limit tests set their own.
                "file_upload_rate_limit_per_minute": 600,
                "share_create_rate_limit_per_minute": 600,
                "share_download_rate_limit_per_minute": 600,
                **settings,
            }
            clock, ticks = Clock(), Ticker()
            app_settings = make_settings(**options)
            app = create_app(
                app_settings, token_validator=entra_validator, intel_service=IntelService([])
            )
            service = FileService(app_settings, clock=clock, kdf_params=kdf, limiter_clock=ticks)
            app.state.file_service = service
            client = stack.enter_context(TestClient(app, client=(client_address, 50000)))
            return FileApi(
                app=app,
                client=client,
                clock=clock,
                ticks=ticks,
                tokens=tokens,
                make_settings=make_settings,
                options=options,
                kdf=kdf,
                db_url=db_url,
                storage_root=app_settings.encrypted_file_storage_path,
                service=service,
            )

        yield build
