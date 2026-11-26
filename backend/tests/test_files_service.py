"""The file service without HTTP: races, integrity failures, key handling and clean-up."""

import os
import threading
import uuid
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from app.core.config import Settings
from app.core.errors import ApiError
from app.files import crypto
from app.files import service as service_module
from app.files.service import Caller, DownloadResult, FileService
from app.models.files import EncryptedFile, FileShare
from app.schemas.files import ShareCreateRequest
from tests.conftest import TokenFactory
from tests.files_helpers import (
    CONTENT,
    PASSWORD,
    WRONG_PASSWORD,
    ApiFactory,
    FileApi,
    api_factory,
    assert_error,
    random_key,
)

LINK_HOLDER = "198.51.100.9"


@pytest.fixture
def make_api(
    make_settings: Callable[..., Settings],
    entra_validator: Any,
    tokens: TokenFactory,
    db_url: str,
    tmp_path: Path,
) -> Iterator[ApiFactory]:
    yield from api_factory(make_settings, entra_validator, tokens, db_url, tmp_path)


def download(
    api: FileApi, token: str, password: str | None = None, *, address: str = LINK_HOLDER
) -> DownloadResult:
    """One download through the service, in a session of its own like a real request."""
    with api.session() as session:
        return api.service.download(session, Caller.anonymous(address), token, password)


def refusal(api: FileApi, token: str, password: str | None = None) -> str:
    """The error code a download is refused with."""
    with pytest.raises(ApiError) as refused:
        download(api, token, password)
    return refused.value.code


def outcome(result: object) -> str:
    if isinstance(result, DownloadResult):
        return "ok"
    if isinstance(result, ApiError):
        return result.code
    return repr(result)


def run_together(count: int, work: Callable[[int], object]) -> list[object]:
    """Run ``work`` in ``count`` threads released at the same instant; collect what each gave."""
    barrier = threading.Barrier(count)
    results: list[object] = [None] * count

    def target(index: int) -> None:
        barrier.wait(timeout=10)
        try:
            results[index] = work(index)
        except BaseException as exc:
            results[index] = exc

    threads = [threading.Thread(target=target, args=(index,)) for index in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not any(thread.is_alive() for thread in threads)
    return results


# --- Concurrent downloads -------------------------------------------------------------------------


def test_concurrent_downloads_never_exceed_max_downloads(make_api: ApiFactory) -> None:
    api = make_api()
    link = api.new_link(max_downloads=3)

    results = run_together(12, lambda _: download(api, link.token))

    assert Counter(map(outcome, results)) == {"ok": 3, "share_limit_reached": 9}
    assert all(r.content == CONTENT for r in results if isinstance(r, DownloadResult))
    assert api.share_row(link.share_id).download_count == 3
    assert api.actions(link.file_id).count(("SHARE_DOWNLOAD", "success")) == 3
    assert api.actions(link.file_id).count(("SHARE_LIMIT_REACHED", "rejected")) == 9


def test_concurrent_downloads_of_a_password_share_never_exceed_max_downloads(
    make_api: ApiFactory,
) -> None:
    # In-flight requests count against the wrong-password budget, so give it room.
    api = make_api(share_password_attempt_limit=100)
    link = api.new_link(max_downloads=2, password=PASSWORD)

    results = run_together(8, lambda _: download(api, link.token, PASSWORD))

    assert Counter(map(outcome, results)) == {"ok": 2, "share_limit_reached": 6}
    assert api.share_row(link.share_id).download_count == 2


def test_parallel_wrong_passwords_never_run_more_derivations_than_the_budget(
    make_api: ApiFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = make_api()  # five wrong passwords per share and per network
    link = api.new_link(max_downloads=5, password=PASSWORD)
    derivations: list[int] = []
    original = crypto.unwrap_dek_with_password

    def counting(*args: Any, **kwargs: Any) -> bytes:
        derivations.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(crypto, "unwrap_dek_with_password", counting)

    results = run_together(12, lambda _: download(api, link.token, WRONG_PASSWORD))

    assert Counter(map(outcome, results)) == {"invalid_password": 5, "too_many_attempts": 7}
    assert len(derivations) == 5
    assert api.share_row(link.share_id).download_count == 0
    assert api.actions(link.file_id).count(("SHARE_PASSWORD_FAILED", "rejected")) == 5


# --- A request that loses a race while it is decrypting -------------------------------------------


def race_during_decryption(monkeypatch: pytest.MonkeyPatch, event: Callable[[], None]) -> None:
    """Run ``event`` once, right after the first decryption, i.e. while a request is in flight."""
    original = crypto.decrypt_content

    def decrypt_then_race(*args: Any, **kwargs: Any) -> bytes:
        content = original(*args, **kwargs)
        monkeypatch.setattr(crypto, "decrypt_content", original)
        event()
        return content

    monkeypatch.setattr(crypto, "decrypt_content", decrypt_then_race)


def test_the_request_that_loses_the_last_slot_gets_no_data(
    make_api: ApiFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = make_api()
    link = api.new_link(max_downloads=1)
    winners: list[DownloadResult] = []
    race_during_decryption(monkeypatch, lambda: winners.append(download(api, link.token)))

    assert refusal(api, link.token) == "share_limit_reached"

    assert [winner.content for winner in winners] == [CONTENT]
    assert api.share_row(link.share_id).download_count == 1
    assert api.actions(link.file_id) == [
        ("FILE_CREATE", "success"),
        ("SHARE_CREATE", "success"),
        ("SHARE_DOWNLOAD", "success"),
        ("SHARE_LIMIT_REACHED", "rejected"),
    ]


def test_a_link_revoked_mid_request_returns_no_data_and_uses_no_download(
    make_api: ApiFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = make_api()
    link = api.new_link(max_downloads=3)
    race_during_decryption(monkeypatch, lambda: api.revoke(link))

    assert refusal(api, link.token) == "share_revoked"

    share = api.share_row(link.share_id)
    assert (share.download_count, share.last_downloaded_at) == (0, None)
    assert api.actions(link.file_id)[-2:] == [
        ("SHARE_REVOKE", "success"),
        ("SHARE_DOWNLOAD_REJECTED", "rejected"),
    ]


def test_a_link_that_expires_mid_request_returns_no_data_and_uses_no_download(
    make_api: ApiFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = make_api()
    link = api.new_link(expires_in_hours=1, max_downloads=3)
    race_during_decryption(monkeypatch, lambda: api.clock.advance(hours=1))

    assert refusal(api, link.token) == "share_expired"

    assert api.share_row(link.share_id).download_count == 0
    assert api.actions(link.file_id)[-1] == ("SHARE_EXPIRED", "rejected")


# --- Integrity ------------------------------------------------------------------------------------


def flip_first_byte(path: Path) -> None:
    data = path.read_bytes()
    path.write_bytes(bytes([data[0] ^ 0x01]) + data[1:])


def flip_last_byte(path: Path) -> None:
    data = path.read_bytes()
    path.write_bytes(data[:-1] + bytes([data[-1] ^ 0x01]))


def truncate(path: Path) -> None:
    path.write_bytes(path.read_bytes()[:-1])


def extend(path: Path) -> None:
    path.write_bytes(path.read_bytes() + b"\x00")


def empty(path: Path) -> None:
    path.write_bytes(b"")


def remove(path: Path) -> None:
    path.unlink()


@pytest.mark.parametrize(
    ("damage", "reason"),
    [
        (flip_first_byte, "authentication_failed"),
        (flip_last_byte, "authentication_failed"),
        (truncate, "blob_invalid"),
        (extend, "blob_invalid"),
        (empty, "blob_invalid"),
        (remove, "blob_invalid"),
    ],
)
def test_damaged_ciphertext_is_never_returned_and_quarantines_the_file(
    make_api: ApiFactory, damage: Callable[[Path], None], reason: str
) -> None:
    api = make_api()
    link = api.new_link(max_downloads=2)
    damage(api.blob_path(link.file_id))

    assert refusal(api, link.token) == "file_unavailable"

    assert api.file_row(link.file_id).status == "corrupt"
    assert api.share_row(link.share_id).download_count == 0
    audit = api.audit(link.file_id)[-1]
    assert (audit.action, audit.result) == ("FILE_INTEGRITY_FAILED", "failed")
    assert audit.details == {"reason": reason, "share_id": link.share_id}

    # Every later request is refused the same way, and is recorded as a rejection.
    assert refusal(api, link.token) == "file_unavailable"
    assert_error(api.info(link.token), 409, "file_unavailable")
    assert_error(api.share(link.file_id), 409, "file_unavailable")
    assert api.actions(link.file_id).count(("FILE_INTEGRITY_FAILED", "failed")) == 1
    assert api.audit(link.file_id)[-1].action == "SHARE_DOWNLOAD_REJECTED"
    assert api.audit(link.file_id)[-1].details == {
        "reason": "file_unavailable",
        "share_id": link.share_id,
    }
    detail = api.request("GET", f"/files/{link.file_id}").json()
    assert detail["status"] == "corrupt"


def test_quarantine_is_not_undone_by_putting_the_data_back(make_api: ApiFactory) -> None:
    api = make_api()
    link = api.new_link(max_downloads=2)
    path = api.blob_path(link.file_id)
    good = path.read_bytes()
    flip_first_byte(path)
    assert refusal(api, link.token) == "file_unavailable"

    path.write_bytes(good)

    assert refusal(api, link.token) == "file_unavailable"


def test_a_password_share_hides_the_damage_from_someone_without_the_password(
    make_api: ApiFactory,
) -> None:
    api = make_api()
    link = api.new_link(max_downloads=2, password=PASSWORD)
    flip_first_byte(api.blob_path(link.file_id))

    assert refusal(api, link.token, WRONG_PASSWORD) == "invalid_password"
    assert refusal(api, link.token, None) == "password_required"
    assert api.file_row(link.file_id).status == "active"

    assert refusal(api, link.token, PASSWORD) == "file_unavailable"
    assert api.file_row(link.file_id).status == "corrupt"
    assert api.share_row(link.share_id).download_count == 0


def test_swapped_ciphertext_between_two_files_is_detected(make_api: ApiFactory) -> None:
    api = make_api()
    first = api.new_link(api.new_file(b"A" * 100, name="one.txt"))
    second = api.new_link(api.new_file(b"B" * 100, name="two.txt"))
    one, two = api.blob_path(first.file_id), api.blob_path(second.file_id)
    spare = one.with_name("swap.tmp")
    os.replace(one, spare)
    os.replace(two, one)
    os.replace(spare, two)

    assert refusal(api, first.token) == "file_unavailable"
    assert refusal(api, second.token) == "file_unavailable"
    assert api.file_row(first.file_id).status == "corrupt"
    assert api.file_row(second.file_id).status == "corrupt"


def test_swapped_key_records_between_two_files_are_detected(make_api: ApiFactory) -> None:
    api = make_api()
    first = api.new_link(api.new_file(b"A" * 100, name="one.txt"))
    second = api.new_link(api.new_file(b"B" * 100, name="two.txt"))
    with api.session() as session:
        one = session.get(EncryptedFile, uuid.UUID(first.file_id))
        two = session.get(EncryptedFile, uuid.UUID(second.file_id))
        assert one is not None
        assert two is not None
        one.wrapped_dek, two.wrapped_dek = two.wrapped_dek, one.wrapped_dek
        session.commit()

    assert refusal(api, first.token) == "file_unavailable"

    assert api.file_row(first.file_id).status == "corrupt"
    audit = api.audit(first.file_id)[-1]
    assert audit.action == "FILE_INTEGRITY_FAILED"
    assert audit.details["reason"] == "wrapped_key_invalid"
    assert_error(api.share(first.file_id), 409, "file_unavailable")


def test_a_tampered_stored_name_cannot_be_shown_and_quarantines_the_file(
    make_api: ApiFactory,
) -> None:
    api = make_api()
    link = api.new_link(max_downloads=2)
    with api.session() as session:
        row = session.get(EncryptedFile, uuid.UUID(link.file_id))
        assert row is not None
        row.name_ciphertext = bytes([row.name_ciphertext[0] ^ 0x01]) + row.name_ciphertext[1:]
        session.commit()

    listing = api.request("GET", "/files").json()
    assert [item["name"] for item in listing["items"]] == ["(unreadable name)"]

    assert refusal(api, link.token) == "file_unavailable"
    assert api.file_row(link.file_id).status == "corrupt"
    assert api.share_row(link.share_id).download_count == 0


# --- Master key -----------------------------------------------------------------------------------


def test_a_different_master_key_is_reported_and_quarantines_nothing(make_api: ApiFactory) -> None:
    api = make_api()
    link = api.new_link(max_downloads=2)
    original_key = api.options["cipherforge_master_key"]
    api.reconfigure(cipherforge_master_key=random_key())

    assert refusal(api, link.token) == "encryption_key_mismatch"
    assert_error(api.info(link.token), 503, "encryption_key_mismatch")
    assert_error(api.share(link.file_id), 503, "encryption_key_mismatch")

    assert api.file_row(link.file_id).status == "active"
    assert api.share_row(link.share_id).download_count == 0
    names = [item["name"] for item in api.request("GET", "/files").json()["items"]]
    assert names == ["(unreadable name)"]
    audit = api.audit(link.file_id)[-1]
    assert (audit.action, audit.result) == ("SHARE_DOWNLOAD_REJECTED", "rejected")
    assert audit.details == {"reason": "key_mismatch", "share_id": link.share_id}
    assert "FILE_INTEGRITY_FAILED" not in [row.action for row in api.audit()]

    # Putting the right key back makes the very same link work again.
    api.reconfigure(cipherforge_master_key=original_key)
    assert download(api, link.token).content == CONTENT


def test_without_a_master_key_owners_can_still_manage_but_nothing_is_encrypted_or_decrypted(
    make_api: ApiFactory,
) -> None:
    api = make_api()
    link = api.new_link(max_downloads=5)
    spare = api.new_link()
    before = len(api.audit())
    api.reconfigure(cipherforge_master_key=None)

    assert api.service.configured is False
    assert refusal(api, link.token) == "feature_not_configured"
    assert_error(api.info(link.token), 503, "feature_not_configured")
    assert_error(api.share(link.file_id), 503, "feature_not_configured")
    assert_error(api.upload(), 503, "feature_not_configured")
    assert len(api.audit()) == before  # a missing key is not a per-share event

    assert api.request("GET", "/files").json()["items"][0]["name"] == "(unreadable name)"
    assert api.revoke(spare).status_code == 200
    assert api.request("GET", f"/files/{link.file_id}/activity").status_code == 200
    assert api.request("DELETE", f"/files/{link.file_id}").status_code == 204
    assert api.request("GET", "/files/status").json()["configured"] is False


def test_the_service_can_be_built_without_a_master_key_or_a_storage_directory(
    make_settings: Callable[..., Settings], tmp_path: Path
) -> None:
    root = tmp_path / "never-created"

    service = FileService(
        make_settings(cipherforge_master_key=None, encrypted_file_storage_path=root)
    )

    assert service.configured is False
    assert service.status().configured is False
    assert not root.exists()


# --- Unknown tokens and rate limits never reach the database --------------------------------------


@pytest.mark.parametrize(
    "token",
    [
        "",
        "short",
        "A" * 42,
        "A" * 44,
        "A" * 42 + "!",
        "A" * 42 + "=",
        "A" * 42 + "+",
        "A" * 21 + "/" + "A" * 21,
        "../../etc/passwd",
        "%2e%2e%2f" * 5,
        "é" * 43,
        "A" * 42 + "\n",
        "A" * 4096,
        "a b" * 15,
    ],
)
def test_a_malformed_token_is_unknown_without_a_database_query(
    make_api: ApiFactory, token: str
) -> None:
    api = make_api()
    with api.statements() as statements, api.session() as session:
        with pytest.raises(ApiError) as info:
            api.service.share_info(session, Caller.anonymous(LINK_HOLDER), token)
        with pytest.raises(ApiError) as fetched:
            api.service.download(session, Caller.anonymous(LINK_HOLDER), token, PASSWORD)

    assert (info.value.status_code, info.value.code) == (404, "share_not_found")
    assert (fetched.value.status_code, fetched.value.code) == (404, "share_not_found")
    assert statements == []
    assert api.audit() == []


def test_an_unknown_but_well_formed_token_costs_one_read_and_leaves_no_audit_row(
    make_api: ApiFactory,
) -> None:
    api = make_api()
    with api.statements() as statements:
        assert_error(api.info(crypto.new_share_token()), 404, "share_not_found")
        assert_error(api.fetch(crypto.new_share_token()), 404, "share_not_found")
        assert_error(api.fetch_with(crypto.new_share_token(), PASSWORD), 404, "share_not_found")

    assert len(statements) == 3
    assert all(statement.lstrip().upper().startswith("SELECT") for statement in statements)
    assert api.audit() == []


def test_a_request_over_the_rate_limit_never_reaches_the_database(make_api: ApiFactory) -> None:
    api = make_api(share_download_rate_limit_per_minute=1)
    link = api.new_link()
    assert api.info(link.token).status_code == 200

    with api.statements() as statements:
        error = assert_error(api.info(link.token), 429, "rate_limited")

    assert error["message"]
    assert statements == []


# --- The password key derivation ------------------------------------------------------------------


def test_a_busy_key_derivation_makes_share_creation_fail_cleanly(
    make_api: ApiFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = make_api()
    file_id = api.new_file()
    monkeypatch.setattr(crypto, "_kdf_slots", threading.BoundedSemaphore(0))
    monkeypatch.setattr(crypto, "KDF_WAIT_SECONDS", 0.01)

    response = api.share(file_id, password=PASSWORD)

    assert_error(response, 503, "service_busy")
    assert response.headers["Retry-After"] == "2"
    assert api.rows(select(FileShare)) == []
    assert api.actions(file_id) == [("FILE_CREATE", "success")]


def test_a_busy_key_derivation_does_not_use_up_password_attempts(
    make_api: ApiFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = make_api(share_password_attempt_limit=2)
    link = api.new_link(max_downloads=3, password=PASSWORD)
    with monkeypatch.context() as busy:
        busy.setattr(crypto, "_kdf_slots", threading.BoundedSemaphore(0))
        busy.setattr(crypto, "KDF_WAIT_SECONDS", 0.01)
        for _ in range(5):
            assert refusal(api, link.token, PASSWORD) == "service_busy"

    assert refusal(api, link.token, WRONG_PASSWORD) == "invalid_password"
    assert download(api, link.token, PASSWORD).content == CONTENT
    assert api.share_row(link.share_id).download_count == 1


@pytest.mark.parametrize(
    "tampering",
    [
        {"kdf_memory_kib": 10_000_000},
        {"kdf_time_cost": 1000},
        {"kdf_parallelism": 64},
        {"kdf_memory_kib": 0},
        {"kdf_salt": b"short"},
        {"password_wrapped_dek": b"\x00" * 10},
    ],
)
def test_tampered_key_derivation_data_is_refused_without_running_it(
    make_api: ApiFactory, tampering: dict[str, Any]
) -> None:
    api = make_api(share_password_attempt_limit=2)
    link = api.new_link(max_downloads=3, password=PASSWORD)
    with api.session() as session:
        share = session.get(FileShare, uuid.UUID(link.share_id))
        assert share is not None
        for column, value in tampering.items():
            setattr(share, column, value)
        session.commit()

    for _ in range(4):  # more than the attempt budget: nothing is counted against it
        assert refusal(api, link.token, PASSWORD) == "file_unavailable"

    assert api.file_row(link.file_id).status == "active"
    assert api.share_row(link.share_id).download_count == 0
    assert "FILE_INTEGRITY_FAILED" not in [row.action for row in api.audit()]


# --- Clean-up after failures ----------------------------------------------------------------------


def test_a_failed_database_insert_removes_the_blob_it_had_written(
    make_api: ApiFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = make_api()

    def database_down(*_: Any, **__: Any) -> None:
        raise OperationalError("INSERT", {}, Exception("connection lost"))

    monkeypatch.setattr(service_module, "record_audit", database_down)

    error = assert_error(api.upload(), 500, "internal_error")

    assert "connection lost" not in str(error)
    assert api.blobs() == []
    assert api.rows(select(EncryptedFile)) == []


def test_an_unexpected_error_after_the_blob_is_written_removes_it_too(
    make_api: ApiFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = make_api()

    def explode(*_: Any, **__: Any) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(service_module, "record_audit", explode)

    with api.session() as session, pytest.raises(RuntimeError, match="boom"):
        api.service.create_file(session, api.caller(), name="a.txt", content=CONTENT)

    assert api.blobs() == []
    assert api.rows(select(EncryptedFile)) == []


@pytest.mark.parametrize("failing_call", ["replace", "fsync"])
def test_a_failed_blob_write_leaves_no_row_no_blob_and_no_temp_file(
    make_api: ApiFactory, monkeypatch: pytest.MonkeyPatch, failing_call: str
) -> None:
    api = make_api()

    def disk_full(*_: Any, **__: Any) -> None:
        raise OSError("no space left on device")

    monkeypatch.setattr(os, failing_call, disk_full)

    assert_error(api.upload(), 503, "storage_unavailable")

    assert api.blobs() == []
    assert api.rows(select(EncryptedFile)) == []
    assert api.audit() == []


def test_a_share_for_a_file_deleted_in_the_meantime_is_a_plain_not_found(
    make_api: ApiFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = make_api()
    file_id = api.new_file()
    original = crypto.new_share_token

    def delete_the_file_first() -> str:
        assert api.request("DELETE", f"/files/{file_id}").status_code == 204
        return original()

    monkeypatch.setattr(crypto, "new_share_token", delete_the_file_first)

    with api.session() as session, pytest.raises(ApiError) as lost:
        api.service.create_share(session, api.caller(), file_id, ShareCreateRequest())

    assert (lost.value.status_code, lost.value.code) == (404, "file_not_found")
    assert api.rows(select(FileShare)) == []
    assert "SHARE_CREATE" not in [row.action for row in api.audit()]


# --- Deleting -------------------------------------------------------------------------------------


def test_deleting_removes_blob_and_links_but_keeps_the_history(make_api: ApiFactory) -> None:
    api = make_api()
    file_id = api.new_file()
    first = api.new_link(file_id)
    api.new_link(file_id, password=PASSWORD)
    assert download(api, first.token).content == CONTENT
    assert len(api.blobs()) == 1

    assert api.request("DELETE", f"/files/{file_id}").status_code == 204

    assert api.blobs() == []
    assert api.rows(select(EncryptedFile)) == []
    assert api.rows(select(FileShare)) == []
    assert api.actions(file_id) == [
        ("FILE_CREATE", "success"),
        ("SHARE_CREATE", "success"),
        ("SHARE_CREATE", "success"),
        ("SHARE_DOWNLOAD", "success"),
        ("FILE_DELETE", "success"),
    ]
    assert api.audit(file_id)[-1].details == {"shares_removed": 2}
    assert refusal(api, first.token) == "share_not_found"
    assert_error(api.request("DELETE", f"/files/{file_id}"), 404, "file_not_found")


def test_deleting_a_file_whose_blob_is_already_gone_still_succeeds(make_api: ApiFactory) -> None:
    api = make_api()
    file_id = api.new_file()
    api.blob_path(file_id).unlink()

    assert api.request("DELETE", f"/files/{file_id}").status_code == 204

    assert api.rows(select(EncryptedFile)) == []


def test_a_blob_that_cannot_be_removed_keeps_the_file_so_the_delete_can_be_retried(
    make_api: ApiFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = make_api()
    link = api.new_link(max_downloads=2)

    def busy(*_: Any) -> None:
        raise PermissionError("busy")

    with monkeypatch.context() as locked:
        locked.setattr(os, "unlink", busy)
        assert_error(api.request("DELETE", f"/files/{link.file_id}"), 503, "storage_unavailable")

    assert len(api.rows(select(EncryptedFile))) == 1
    assert len(api.rows(select(FileShare))) == 1
    assert download(api, link.token).content == CONTENT
    assert api.request("DELETE", f"/files/{link.file_id}").status_code == 204
    assert api.blobs() == []


# --- Expiry and status ----------------------------------------------------------------------------


def test_a_link_works_until_the_very_moment_it_expires(make_api: ApiFactory) -> None:
    api = make_api()
    link = api.new_link(expires_in_hours=2, max_downloads=5)
    api.clock.advance(hours=1, minutes=59, seconds=59)
    assert download(api, link.token).content == CONTENT

    api.clock.advance(seconds=1)

    assert refusal(api, link.token) == "share_expired"
    assert api.share_row(link.share_id).download_count == 1


def test_share_status_follows_revoked_then_expired_then_exhausted_then_active(
    make_api: ApiFactory,
) -> None:
    api = make_api()
    file_id = api.new_file()
    link = api.new_link(file_id, expires_in_hours=1, max_downloads=1)

    def status() -> str:
        return str(api.request("GET", f"/files/{file_id}").json()["shares"][0]["status"])

    assert status() == "active"
    download(api, link.token)
    assert status() == "exhausted"
    api.clock.advance(hours=1)
    assert status() == "expired"
    assert api.revoke(link).json()["status"] == "revoked"
    assert status() == "revoked"
    assert refusal(api, link.token) == "share_revoked"


def test_a_revoked_link_is_reported_as_revoked_even_when_it_is_also_expired(
    make_api: ApiFactory,
) -> None:
    api = make_api()
    link = api.new_link(expires_in_hours=1)
    api.revoke(link)
    api.clock.advance(hours=2)

    assert refusal(api, link.token) == "share_revoked"


def test_an_expired_link_is_reported_as_expired_even_when_it_is_also_used_up(
    make_api: ApiFactory,
) -> None:
    api = make_api()
    link = api.new_link(expires_in_hours=1, max_downloads=1)
    download(api, link.token)
    api.clock.advance(hours=2)

    assert refusal(api, link.token) == "share_expired"


# --- Names ----------------------------------------------------------------------------------------


def test_the_stored_name_round_trips_through_the_listing_and_the_link(
    make_api: ApiFactory,
) -> None:
    api = make_api()
    link = api.new_link(api.new_file(name="résumé 日本語.txt"))

    assert download(api, link.token).name == "résumé 日本語.txt"
    assert api.request("GET", "/files").json()["items"][0]["name"] == "résumé 日本語.txt"
    assert "résumé".encode() not in api.file_row(link.file_id).name_ciphertext
