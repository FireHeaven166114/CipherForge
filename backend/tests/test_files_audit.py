"""The audit trail of the encrypted-file module, and proof that secrets stay out of every place
they must not be: logs, error bodies, audit rows, the database file and the stored blobs."""

import base64
import hashlib
import json
import logging
import secrets
import uuid
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from httpx2 import Response
from sqlalchemy import select

from app.core.config import Settings
from app.files import crypto
from app.files.logsafe import (
    REDACTED,
    ShareTokenFilter,
    install_share_token_filter,
    mask_share_tokens,
)
from app.files.storage import BlobStorage
from app.models.files import EncryptedFile
from tests.conftest import TokenFactory
from tests.files_helpers import (
    API,
    CLIENT_ADDRESS,
    CONTENT,
    CONTENT_MARKER,
    NAME_MARKER,
    PASSWORD,
    WRONG_PASSWORD,
    ApiFactory,
    FileApi,
    api_factory,
    assert_error,
    random_key,
    rendered_logs,
)

# Below the 8-character minimum, so a request carrying it is refused with a validation error.
SHORT_PASSWORD = "Zq9-pW7"
# The only keys an audit row's details may ever carry: nothing that could hold a secret.
DETAIL_KEYS = {
    "size_bytes",
    "share_id",
    "expires_at",
    "max_downloads",
    "password_protected",
    "reason",
    "shares_removed",
}


@pytest.fixture
def make_api(
    make_settings: Callable[..., Settings],
    entra_validator: Any,
    tokens: TokenFactory,
    db_url: str,
    tmp_path: Path,
) -> Iterator[ApiFactory]:
    yield from api_factory(make_settings, entra_validator, tokens, db_url, tmp_path)


def master_key_of(api: FileApi) -> bytes:
    key = api.make_settings(**api.options).master_key
    assert key is not None
    return key


def file_key_of(api: FileApi, file_id: str) -> bytes:
    """A file's data key, recovered the way the server does it."""
    row = api.file_row(file_id)
    return crypto.open_file_dek(master_key_of(api), row.id, row.key_id, row.wrapped_dek)


def audit_dump(api: FileApi) -> str:
    return json.dumps(
        [
            {
                "actor": row.actor,
                "action": row.action,
                "target": row.target,
                "result": row.result,
                "source_ip": row.source_ip,
                "correlation_id": row.correlation_id,
                "details": row.details,
            }
            for row in api.audit()
        ],
        default=str,
        sort_keys=True,
    )


def leaks(text: str, needles: dict[str, str]) -> list[str]:
    """The labels of the needles that appear in ``text``."""
    return sorted(label for label, needle in needles.items() if needle in text)


def database_bytes(api: FileApi) -> bytes:
    """The raw SQLite file plus whatever journal sits next to it."""
    if not api.db_url.startswith("sqlite"):
        pytest.skip("reads the SQLite database file")
    base = api.database_file
    parts = [base, *(base.with_name(base.name + suffix) for suffix in ("-wal", "-journal"))]
    return b"".join(path.read_bytes() for path in parts if path.exists())


# --- The audit trail ------------------------------------------------------------------------------


def test_every_audited_action_is_recorded_with_its_actor_result_target_and_reason(
    make_api: ApiFactory,
) -> None:
    api = make_api()
    original_key = api.options["cipherforge_master_key"]

    healthy = api.new_file()
    plain = api.new_link(healthy, max_downloads=1)
    locked = api.new_link(healthy, max_downloads=3, password=PASSWORD)
    assert_error(api.fetch(locked.token), 403, "password_required")
    assert_error(api.fetch_with(locked.token, WRONG_PASSWORD), 403, "invalid_password")
    assert api.fetch_with(locked.token, PASSWORD).status_code == 200
    assert api.fetch(plain.token).status_code == 200
    assert_error(api.fetch(plain.token), 410, "share_limit_reached")
    revoked = api.new_link(healthy)
    assert api.revoke(revoked).json()["status"] == "revoked"
    assert api.revoke(revoked).json()["status"] == "revoked"  # idempotent: no second row
    revoked_error = assert_error(api.fetch(revoked.token), 410, "share_revoked")
    expiring = api.new_link(healthy, expires_in_hours=1)
    api.clock.advance(hours=2)
    assert_error(api.info(expiring.token), 410, "share_expired")
    mismatch = api.new_link(healthy)
    api.reconfigure(cipherforge_master_key=random_key())
    assert_error(api.fetch(mismatch.token), 503, "encryption_key_mismatch")
    api.reconfigure(cipherforge_master_key=original_key)
    damaged = api.new_link()
    api.corrupt_blob(damaged.file_id)
    assert_error(api.fetch(damaged.token), 409, "file_unavailable")
    assert_error(api.fetch(damaged.token), 409, "file_unavailable")
    assert api.request("DELETE", f"/files/{damaged.file_id}").status_code == 204

    def entry(
        actor: str, action: str, result: str, file_id: str, share: str | None, reason: str | None
    ) -> tuple[str, str, str, str, str | None, str | None]:
        return (actor, action, result, f"file:{file_id}", share, reason)

    owner, anyone = "alice", "anonymous"
    expected = [
        entry(owner, "FILE_CREATE", "success", healthy, None, None),
        entry(owner, "SHARE_CREATE", "success", healthy, plain.share_id, None),
        entry(owner, "SHARE_CREATE", "success", healthy, locked.share_id, None),
        entry(
            anyone,
            "SHARE_DOWNLOAD_REJECTED",
            "rejected",
            healthy,
            locked.share_id,
            "password_required",
        ),
        entry(
            anyone,
            "SHARE_PASSWORD_FAILED",
            "rejected",
            healthy,
            locked.share_id,
            "invalid_password",
        ),
        entry(anyone, "SHARE_DOWNLOAD", "success", healthy, locked.share_id, None),
        entry(anyone, "SHARE_DOWNLOAD", "success", healthy, plain.share_id, None),
        entry(anyone, "SHARE_LIMIT_REACHED", "rejected", healthy, plain.share_id, "limit_reached"),
        entry(owner, "SHARE_CREATE", "success", healthy, revoked.share_id, None),
        entry(owner, "SHARE_REVOKE", "success", healthy, revoked.share_id, None),
        entry(anyone, "SHARE_DOWNLOAD_REJECTED", "rejected", healthy, revoked.share_id, "revoked"),
        entry(owner, "SHARE_CREATE", "success", healthy, expiring.share_id, None),
        entry(anyone, "SHARE_EXPIRED", "rejected", healthy, expiring.share_id, "expired"),
        entry(owner, "SHARE_CREATE", "success", healthy, mismatch.share_id, None),
        entry(
            anyone,
            "SHARE_DOWNLOAD_REJECTED",
            "rejected",
            healthy,
            mismatch.share_id,
            "key_mismatch",
        ),
        entry(owner, "FILE_CREATE", "success", damaged.file_id, None, None),
        entry(owner, "SHARE_CREATE", "success", damaged.file_id, damaged.share_id, None),
        entry(
            anyone,
            "FILE_INTEGRITY_FAILED",
            "failed",
            damaged.file_id,
            damaged.share_id,
            "authentication_failed",
        ),
        entry(
            anyone,
            "SHARE_DOWNLOAD_REJECTED",
            "rejected",
            damaged.file_id,
            damaged.share_id,
            "file_unavailable",
        ),
        entry(owner, "FILE_DELETE", "success", damaged.file_id, None, None),
    ]
    rows = api.audit()
    assert [
        (
            row.actor,
            row.action,
            row.result,
            row.target,
            (row.details or {}).get("share_id"),
            (row.details or {}).get("reason"),
        )
        for row in rows
    ] == expected

    assert {row.source_ip for row in rows} == {CLIENT_ADDRESS}
    assert all(row.correlation_id for row in rows)
    assert all(set(row.details or {}) <= DETAIL_KEYS for row in rows)
    assert [row.timestamp for row in rows] == sorted(row.timestamp for row in rows)
    assert rows[0].details == {"size_bytes": len(CONTENT)}
    created = rows[2].details
    assert created is not None
    assert (created["max_downloads"], created["password_protected"]) == (3, True)
    assert datetime.fromisoformat(created["expires_at"]).tzinfo is not None
    # The error a link holder was shown carries the id that finds its audit row.
    rejected = next(r for r in rows if (r.details or {}).get("reason") == "revoked")
    assert rejected.correlation_id == revoked_error["correlation_id"]
    # Deleting a file removes the file and its links but never the history.
    assert (
        api.rows(select(EncryptedFile).where(EncryptedFile.id == uuid.UUID(damaged.file_id))) == []
    )
    assert len(api.audit(damaged.file_id)) == 5


def test_the_activity_feed_shows_what_the_owner_may_see_and_nothing_else(
    make_api: ApiFactory,
) -> None:
    api = make_api()
    link = api.new_link()
    stranger = api.from_address("198.51.100.77")
    api.revoke(link)
    assert_error(api.fetch(link.token, client=stranger), 410, "share_revoked")

    rows = api.audit(link.file_id)
    feed = api.request("GET", f"/files/{link.file_id}/activity")

    assert [row.source_ip for row in rows] == [CLIENT_ADDRESS] * 3 + ["198.51.100.77"]
    assert "198.51.100.77" not in feed.text
    assert CLIENT_ADDRESS not in feed.text
    items = feed.json()["items"]
    assert [(i["action"], i["result"]) for i in items] == [
        ("SHARE_DOWNLOAD_REJECTED", "rejected"),
        ("SHARE_REVOKE", "success"),
        ("SHARE_CREATE", "success"),
        ("FILE_CREATE", "success"),
    ]
    assert all(
        set(item) == {"timestamp", "action", "result", "share_id", "reason"} for item in items
    )
    assert items[0]["reason"] == "revoked"


def test_unknown_links_throttling_and_a_missing_key_are_not_audited(
    make_api: ApiFactory,
) -> None:
    api = make_api(share_download_rate_limit_per_minute=8, share_password_attempt_limit=1)
    link = api.new_link(max_downloads=5, password=PASSWORD)
    baseline = api.actions()

    assert api.info(link.token).status_code == 200
    for token in (crypto.new_share_token(), "short"):
        assert_error(api.info(token), 404, "share_not_found")
        assert_error(api.fetch(token), 404, "share_not_found")
    assert api.actions() == baseline

    assert_error(api.fetch_with(link.token, WRONG_PASSWORD), 403, "invalid_password")
    assert_error(api.fetch_with(link.token, PASSWORD), 429, "too_many_attempts")
    throttled = [api.info(link.token).status_code for _ in range(4)]
    assert throttled == [200, 429, 429, 429]
    assert api.actions() == [*baseline, ("SHARE_PASSWORD_FAILED", "rejected")]

    api.reconfigure(cipherforge_master_key=None)
    assert_error(api.fetch(link.token), 503, "feature_not_configured")
    assert_error(api.info(link.token), 503, "feature_not_configured")
    assert_error(api.upload(), 503, "feature_not_configured")
    assert api.actions() == [*baseline, ("SHARE_PASSWORD_FAILED", "rejected")]


# --- Nothing secret in logs, errors or audit rows -------------------------------------------------


def test_no_secret_reaches_logs_error_bodies_management_responses_or_audit_rows(
    make_api: ApiFactory, production_logging: None, caplog: pytest.LogCaptureFixture
) -> None:
    api = make_api(log_level="DEBUG")
    original_key = api.options["cipherforge_master_key"]
    other_key = random_key()
    sent: list[Response] = []

    def keep(*responses: Response) -> None:
        sent.extend(responses)

    file_id = api.new_file()
    plain = api.new_link(file_id, max_downloads=5)
    locked = api.new_link(file_id, max_downloads=5, password=PASSWORD)
    spent = api.new_link(file_id)
    revoked = api.new_link(file_id)
    expiring = api.new_link(file_id, expires_in_hours=1)
    mismatch = api.new_link(file_id)
    damaged = api.new_link()
    unknown = [crypto.new_share_token(), crypto.new_share_token()]
    malformed = "not-a-link-" + "x" * 40
    keep(
        api.info(plain.token),
        api.fetch(plain.token),
        api.fetch_with(plain.token, None),
        api.info(locked.token),
        api.fetch(locked.token),
        api.fetch_with(locked.token, WRONG_PASSWORD),
        api.fetch_with(locked.token, PASSWORD),
        api.fetch(spent.token),
        api.fetch(spent.token),
        api.revoke(revoked),
        api.revoke(revoked),
        api.fetch(revoked.token),
        api.fetch_with(revoked.token, PASSWORD),
    )
    for token in (*unknown, malformed):
        keep(api.info(token), api.fetch(token), api.fetch_with(token, PASSWORD))
    api.clock.advance(hours=2)
    keep(api.info(expiring.token))
    # Refused requests that carried a secret must not echo it back.
    keep(
        api.share(file_id, password=SHORT_PASSWORD),
        api.share(file_id, password="p" * 200),
        api.upload(content_type="text/plain"),
        api.upload(encoded_name="%ff"),
        api.upload(b""),
        api.request("GET", f"/files/{file_id}", user="bob"),
        api.request("DELETE", f"/files/{file_id}", user="bob"),
        api.share(file_id, user="bob", password=PASSWORD),
    )
    api.corrupt_blob(damaged.file_id)
    keep(api.fetch(damaged.token), api.fetch(damaged.token))
    api.reconfigure(cipherforge_master_key=other_key)
    keep(api.fetch(mismatch.token), api.info(mismatch.token), api.share(file_id))
    api.reconfigure(cipherforge_master_key=original_key)
    keep(
        api.request("GET", "/files/status"),
        api.request("GET", "/files"),
        api.request("GET", f"/files/{file_id}"),
        api.request("GET", f"/files/{file_id}/activity"),
        api.request("GET", f"/files/{damaged.file_id}/activity"),
        api.request("DELETE", f"/files/{damaged.file_id}"),
    )

    master = master_key_of(api)
    key = file_key_of(api, file_id)
    row = api.file_row(file_id)
    links = [plain, locked, spent, revoked, expiring, mismatch, damaged]
    needles: dict[str, str] = {}
    for index, token in enumerate([link.token for link in links] + unknown + [malformed]):
        needles[f"token {index}"] = token
        needles[f"token hash {index}"] = crypto.hash_share_token(token)
    needles |= {
        "password": PASSWORD,
        "wrong password": WRONG_PASSWORD,
        "short password": SHORT_PASSWORD,
        "overlong password": "p" * 200,
        "master key": original_key,
        "other master key": other_key,
        "master key (hex)": master.hex(),
        "data key (hex)": key.hex(),
        "data key (base64)": base64.b64encode(key).decode(),
        "data key (urlsafe)": base64.urlsafe_b64encode(key).decode(),
        "wrapped key (hex)": row.wrapped_dek.hex(),
        "content nonce (hex)": row.nonce.hex(),
    }
    assert all(len(needle) >= len(SHORT_PASSWORD) for needle in needles.values())
    plaintext = {"content": CONTENT_MARKER.decode(), "file name": NAME_MARKER}
    storage_names = {
        f"blob {i}": r.storage_name for i, r in enumerate(api.rows(select(EncryptedFile)))
    }
    assert not [r for r in sent if r.status_code >= 500 and r.status_code != 503]

    errors = "\n".join(r.text for r in sent if r.status_code >= 400)
    owner_views = "\n".join(
        r.text
        for r in sent
        if r.status_code < 400
        and r.request.url.path.startswith(f"{API}/files")
        and (r.request.method == "GET" or r.request.url.path.endswith("/revoke"))
    )
    logs = rendered_logs(caplog)
    audit = audit_dump(api)
    # The scan must be able to see a leak at all, and each place scanned must hold real content.
    assert leaks(f"GET /api/v1/shares/{plain.token}", needles) == ["token 0"]
    for code in (
        "share_not_found",
        "share_revoked",
        "share_expired",
        "password_required",
        "invalid_password",
        "file_unavailable",
        "encryption_key_mismatch",
        "file_not_found",
        "unsupported_media_type",
        "invalid_filename",
        "empty_file",
    ):
        assert code in errors, code
    for action in (
        "FILE_CREATE",
        "SHARE_CREATE",
        "SHARE_DOWNLOAD",
        "SHARE_PASSWORD_FAILED",
        "SHARE_REVOKE",
        "FILE_INTEGRITY_FAILED",
        "FILE_DELETE",
    ):
        assert action in audit, action
    for place, text in {"logs": logs, "errors": errors, "audit": audit}.items():
        assert leaks(text, needles | plaintext) == [], place
    # An owner's own views show their file name, but never tokens, keys, blobs or content.
    assert NAME_MARKER in owner_views
    assert leaks(owner_views, needles | storage_names | {"content": plaintext["content"]}) == []

    logged = {
        record.getMessage() for record in caplog.records if record.name == "cipherforge.files"
    }
    assert {
        "file_created",
        "share_created",
        "share_downloaded",
        "share_rejected",
        "share_revoked",
        "file_integrity_failed",
        "file_deleted",
    } <= logged
    paths = [
        record.path
        for record in caplog.records
        if record.name == "cipherforge.http" and "/shares/" in getattr(record, "path", "")
    ]
    assert paths
    assert all(REDACTED in path for path in paths)


def test_the_token_filter_masks_link_tokens_wherever_a_path_is_logged() -> None:
    token = "A" * 43

    assert mask_share_tokens(f"/api/v1/shares/{token}") == f"/api/v1/shares/{REDACTED}"
    assert mask_share_tokens(f"/share/{token}") == f"/share/{REDACTED}"
    assert (
        mask_share_tokens(f'"GET /api/v1/shares/{token}/download?x=1 HTTP/1.1" 200')
        == f'"GET /api/v1/shares/{REDACTED}/download?x=1 HTTP/1.1" 200'
    )
    for untouched in ("/api/v1/files/status", "/api/v1/shares", "/api/v1/shares/", "plain text"):
        assert mask_share_tokens(untouched) == untouched

    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:1", "GET", f"/api/v1/shares/{token}/download", "1.1", 200),
        None,
    )
    record.path = f"/api/v1/shares/{token}"
    assert ShareTokenFilter().filter(record) is True
    assert token not in record.getMessage()
    assert token not in record.path
    assert record.args is not None
    assert record.args[-1] == 200


def test_the_token_filter_is_installed_once_on_the_request_loggers() -> None:
    install_share_token_filter()
    install_share_token_filter()

    for name in ("cipherforge.http", "uvicorn.access"):
        installed = [f for f in logging.getLogger(name).filters if isinstance(f, ShareTokenFilter)]
        assert len(installed) == 1, name


# --- Nothing secret at rest -----------------------------------------------------------------------


def test_the_database_and_the_blobs_hold_no_plaintext_name_password_token_or_key(
    make_api: ApiFactory,
) -> None:
    api = make_api()
    protected = api.new_link(max_downloads=3, password=PASSWORD)
    open_link = api.new_link(protected.file_id)
    assert api.fetch_with(protected.token, PASSWORD).status_code == 200
    assert_error(api.fetch_with(protected.token, WRONG_PASSWORD), 403, "invalid_password")
    assert api.fetch(open_link.token).status_code == 200
    master = master_key_of(api)
    key = file_key_of(api, protected.file_id)
    row = api.file_row(protected.file_id)

    database = database_bytes(api)
    blobs = b"".join(path.read_bytes() for path in api.blobs())
    needles = {
        "content": CONTENT_MARKER,
        "file name": NAME_MARKER.encode(),
        "file name (utf-16)": NAME_MARKER.encode("utf-16-le"),
        "password": PASSWORD.encode(),
        "wrong password": WRONG_PASSWORD.encode(),
        "token": protected.token.encode(),
        "other token": open_link.token.encode(),
        "master key": master,
        "master key (text)": api.options["cipherforge_master_key"].encode(),
        "data key": key,
        "data key (hex)": key.hex().encode(),
        "data key (base64)": base64.b64encode(key),
    }
    for label, needle in needles.items():
        assert needle not in database, label
        assert needle not in blobs, label
    # The scan can see what is there: hashes, audit rows and blob names are stored.
    assert hashlib.sha256(protected.token.encode()).hexdigest().encode() in database
    assert b"SHARE_DOWNLOAD" in database
    assert row.storage_name.encode() in database
    assert [path.name for path in api.blobs()] == [row.storage_name]
    assert NAME_MARKER not in row.storage_name
    assert len(blobs) == len(CONTENT) + crypto.TAG_SIZE


def test_only_ciphertext_ever_reaches_the_storage_layer(
    make_api: ApiFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = make_api()
    written: list[bytes] = []
    original = BlobStorage.write

    def recording(self: BlobStorage, name: str, data: bytes) -> None:
        written.append(bytes(data))
        original(self, name, data)

    monkeypatch.setattr(BlobStorage, "write", recording)

    file_id = api.new_file()

    assert len(written) == 1
    assert CONTENT_MARKER not in written[0]
    assert len(written[0]) == len(CONTENT) + crypto.TAG_SIZE
    assert written[0] == api.blob_path(file_id).read_bytes()


def test_the_database_alone_cannot_check_a_password_guess(make_api: ApiFactory) -> None:
    api = make_api()
    link = api.new_link(password=PASSWORD)
    share, file = api.share_row(link.share_id), api.file_row(link.file_id)
    params = crypto.KdfParams(share.kdf_time_cost, share.kdf_memory_kib, share.kdf_parallelism)

    def unwrap(master: bytes, password: str) -> bytes:
        assert share.kdf_salt is not None
        assert share.password_wrapped_dek is not None
        return crypto.unwrap_dek_with_password(
            master,
            share.id,
            file.id,
            password,
            salt=share.kdf_salt,
            params=params,
            wrapped_dek=share.password_wrapped_dek,
        )

    master = master_key_of(api)
    assert unwrap(master, PASSWORD) == file_key_of(api, link.file_id)
    with pytest.raises(crypto.WrongPassword):
        unwrap(master, WRONG_PASSWORD)
    # Everything in the database plus the right password still verifies nothing without the key.
    for guessed_key in (secrets.token_bytes(32), bytes(32)):
        with pytest.raises(crypto.WrongPassword):
            unwrap(guessed_key, PASSWORD)
