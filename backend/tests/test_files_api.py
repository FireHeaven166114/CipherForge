"""The encrypted-file HTTP contract: shapes, validation, headers, and the owner and link flows."""

import asyncio
import hashlib
import os
import re
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from starlette.requests import ClientDisconnect

from app.api.v1 import files as files_api
from app.core.config import Settings
from app.core.errors import ApiError
from app.files import crypto
from app.files.names import content_disposition
from app.models.files import EncryptedFile, FileShare
from app.services.audit import record_audit
from tests.conftest import TokenFactory
from tests.files_helpers import (
    API,
    CLIENT_ADDRESS,
    CONTENT,
    CONTENT_MARKER,
    FILE_NAME,
    NAME_MARKER,
    OCTET_STREAM,
    PASSWORD,
    WRONG_PASSWORD,
    ApiFactory,
    FileApi,
    api_factory,
    assert_error,
    random_key,
)

FILE_FIELDS = {
    "id",
    "name",
    "size_bytes",
    "status",
    "algorithm",
    "created_at",
    "share_count",
    "active_share_count",
}
SHARE_FIELDS = {
    "id",
    "file_id",
    "created_at",
    "expires_at",
    "max_downloads",
    "download_count",
    "downloads_remaining",
    "last_downloaded_at",
    "revoked_at",
    "password_protected",
    "status",
}
INFO_FIELDS = {
    "state",
    "file_name",
    "size_bytes",
    "password_required",
    "expires_at",
    "downloads_remaining",
}
TOKEN_FORMAT = re.compile(r"[A-Za-z0-9_-]{43}")
BLOB_NAME = re.compile(r"[0-9a-f]{32}\.bin")
MULTIPART_BODY = (
    b"--cf-boundary\r\n"
    b'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n\r\n'
    b"data\r\n--cf-boundary--\r\n"
)


@pytest.fixture
def make_api(
    make_settings: Callable[..., Settings],
    entra_validator: Any,
    tokens: TokenFactory,
    db_url: str,
    tmp_path: Path,
) -> Iterator[ApiFactory]:
    yield from api_factory(make_settings, entra_validator, tokens, db_url, tmp_path)


def when(value: str) -> datetime:
    """Parse an API timestamp, insisting on the UTC ``Z`` form the contract promises."""
    assert value.endswith("Z"), value
    return datetime.fromisoformat(value)


def assert_nothing_stored(api: FileApi) -> None:
    assert api.blobs() == []
    assert api.rows(select(EncryptedFile)) == []
    assert api.audit() == []


# --- Feature status -------------------------------------------------------------------------------


def test_status_reports_whether_the_feature_is_configured_and_its_limits(
    make_api: ApiFactory,
) -> None:
    api = make_api(
        max_encrypted_file_size_mb=2,
        default_share_expiry_hours=12,
        max_share_expiry_hours=48,
        max_share_downloads=7,
    )

    response = api.request("GET", "/files/status")

    assert response.status_code == 200
    assert response.json() == {
        "configured": True,
        "max_file_size_bytes": 2 * 1024 * 1024,
        "default_share_expiry_hours": 12,
        "max_share_expiry_hours": 48,
        "max_share_downloads": 7,
        "min_password_length": 8,
        "max_password_length": 128,
    }


def test_status_without_a_master_key_is_an_answer_not_an_error(make_api: ApiFactory) -> None:
    api = make_api(master_key=None)

    response = api.request("GET", "/files/status")

    assert response.status_code == 200
    assert response.json()["configured"] is False


# --- Uploading ------------------------------------------------------------------------------------


def test_an_upload_returns_the_new_file_record(make_api: ApiFactory) -> None:
    api = make_api()

    response = api.upload()

    assert response.status_code == 201
    body = response.json()
    assert set(body) == FILE_FIELDS
    assert uuid.UUID(body["id"]).version == 4
    assert body["name"] == FILE_NAME
    assert body["size_bytes"] == len(CONTENT)
    assert body["status"] == "active"
    assert body["algorithm"] == "AES-256-GCM"
    assert when(body["created_at"]) == api.clock.now
    assert (body["share_count"], body["active_share_count"]) == (0, 0)


def test_the_listing_and_the_detail_show_the_record_the_upload_returned(
    make_api: ApiFactory,
) -> None:
    api = make_api()
    created = api.upload().json()

    listed = api.request("GET", "/files").json()
    detail = api.request("GET", f"/files/{created['id']}").json()

    assert listed == {"items": [created], "total": 1}
    assert detail == {**created, "shares": []}


def test_only_ciphertext_is_stored_under_a_random_server_chosen_name(make_api: ApiFactory) -> None:
    api = make_api()
    file_id = api.new_file()

    [blob] = api.blobs()

    assert BLOB_NAME.fullmatch(blob.name)
    assert blob.name == api.file_row(file_id).storage_name
    stored = blob.read_bytes()
    assert len(stored) == len(CONTENT) + crypto.TAG_SIZE
    assert CONTENT_MARKER not in stored
    assert api.file_row(file_id).size_bytes == len(CONTENT)


def test_uploading_the_same_name_and_content_twice_makes_two_independent_files(
    make_api: ApiFactory,
) -> None:
    api = make_api()
    first, second = api.new_file(), api.new_file()
    one, two = api.file_row(first), api.file_row(second)

    assert first != second
    assert one.storage_name != two.storage_name
    assert one.nonce != two.nonce
    assert one.wrapped_dek != two.wrapped_dek
    assert one.name_nonce != two.name_nonce
    assert api.blob_path(first).read_bytes() != api.blob_path(second).read_bytes()
    listing = api.request("GET", "/files").json()
    assert listing["total"] == 2
    assert [item["name"] for item in listing["items"]] == [FILE_NAME, FILE_NAME]
    # Neither upload replaced the other: each still opens with its own link.
    for file_id in (first, second):
        assert api.fetch(api.new_link(file_id).token).content == CONTENT


def test_files_round_trip_byte_for_byte(make_api: ApiFactory) -> None:
    api = make_api(max_encrypted_file_size_mb=2)
    samples = {
        "one byte": b"\x00",
        "every byte value": bytes(range(256)),
        "a megabyte and a half of noise": os.urandom(1_500_000),
    }

    for label, original in samples.items():
        link = api.new_link(api.new_file(original, name=f"{len(original)}.bin"))
        response = api.fetch(link.token)

        assert response.status_code == 200, label
        assert len(response.content) == len(original), label
        assert hashlib.sha256(response.content).digest() == hashlib.sha256(original).digest(), label


SANITISED_NAMES = [
    ("../../etc/passwd", "passwd"),
    ("..\\..\\windows\\win.ini", "win.ini"),
    ("C:\\Users\\victim\\report.docx", "report.docx"),
    ("report\x00.exe", "report.exe"),
    ("\u202egpj.exe", "gpj.exe"),
    ("CON", "_CON"),
    ("nul.txt", "_nul.txt"),
    ('a"; filename="b.exe', "a_; filename=_b.exe"),
    ("first\r\nSet-Cookie: x=1", "firstSet-Cookie_ x=1"),
    ("  ..hidden..  ", "hidden"),
    ("résumé 日本語.pdf", "résumé 日本語.pdf"),
]


def test_names_are_sanitised_and_cannot_break_out_of_the_download_header(
    make_api: ApiFactory,
) -> None:
    api = make_api()

    for raw, expected in SANITISED_NAMES:
        created = api.upload(name=raw)
        assert created.status_code == 201, raw
        assert created.json()["name"] == expected, raw

        response = api.fetch(api.new_link(created.json()["id"]).token)

        disposition = response.headers["content-disposition"]
        assert disposition == content_disposition(expected), raw
        assert "\r" not in disposition
        assert "\n" not in disposition
        # Only the pair of quotes and the two separators the format itself uses.
        assert disposition.count('"') == 2, disposition
        assert disposition.count(";") == 2, disposition
        assert "set-cookie" not in response.headers
    listed = {item["name"] for item in api.request("GET", "/files?limit=200").json()["items"]}
    assert listed == {expected for _, expected in SANITISED_NAMES}


def test_a_percent_encoded_traversal_is_decoded_once_and_then_neutralised(
    make_api: ApiFactory,
) -> None:
    api = make_api()

    created = api.upload(encoded_name="..%2f..%2fx.txt")

    assert created.status_code == 201
    assert created.json()["name"] == "x.txt"
    # Nothing was written outside the blob directory, and the name is not a file anywhere.
    assert [path.name for path in api.blobs()] == [api.file_row(created.json()["id"]).storage_name]


def test_a_very_long_name_is_shortened_but_keeps_its_extension(make_api: ApiFactory) -> None:
    api = make_api()

    long_name = api.upload(name="x" * 400 + ".pdf").json()["name"]
    longest_header = api.upload(encoded_name="a" * 1024)

    assert len(long_name) == 255
    assert long_name.endswith(".pdf")
    assert longest_header.status_code == 201
    assert len(longest_header.json()["name"]) == 255


UNUSABLE_NAMES = {
    "empty": "",
    "a separator": "%2f",
    "a traversal": "%2e%2e%2f",
    "dots": "%2e%2e",
    "a NUL": "%00",
    "spaces": "%20%20",
    "a bidi override": "%e2%80%ae",
    "invalid UTF-8": "%ff%fe",
    "an overlong UTF-8 slash": "%c0%af",
    "too long a header": "a" * 1025,
}


def test_unusable_names_are_refused_and_nothing_is_stored(make_api: ApiFactory) -> None:
    api = make_api()

    for label, encoded in UNUSABLE_NAMES.items():
        response = api.upload(encoded_name=encoded)
        assert response.status_code == 422, label
        assert response.json()["error"]["code"] == "invalid_filename", label

    missing = api.upload(name=None)
    assert_error(missing, 422, "invalid_filename")
    unencoded = api.upload(name=None, headers={"X-File-Name": "é.txt".encode()})
    assert_error(unencoded, 422, "invalid_filename")
    assert_nothing_stored(api)


def test_a_repeated_name_header_is_refused(make_api: ApiFactory) -> None:
    api = make_api()

    response = api.client.post(
        f"{API}/files",
        content=CONTENT,
        headers=[
            *api.headers().items(),
            ("Content-Type", OCTET_STREAM),
            ("X-File-Name", "first.txt"),
            ("X-File-Name", "second.txt"),
        ],
    )

    assert_error(response, 422, "invalid_filename")
    assert_nothing_stored(api)


def test_only_raw_octet_stream_uploads_are_accepted(make_api: ApiFactory) -> None:
    api = make_api()
    unsupported = {
        "no content type": None,
        "an empty content type": "",
        "json": "application/json",
        "a form": "application/x-www-form-urlencoded",
        "text": "text/plain",
        "multipart": "multipart/form-data; boundary=cf-boundary",
        "a look-alike": "application/octet-streams",
    }

    for label, content_type in unsupported.items():
        response = api.upload(MULTIPART_BODY, content_type=content_type)
        assert response.status_code == 415, label
        assert response.json()["error"]["code"] == "unsupported_media_type", label
    assert_nothing_stored(api)

    # Parameters and letter case do not matter for the media type itself.
    for content_type in ("application/octet-stream; charset=binary", "Application/Octet-Stream"):
        assert api.upload(content_type=content_type).status_code == 201, content_type


def test_the_size_limit_is_exact(make_api: ApiFactory) -> None:
    api = make_api(max_encrypted_file_size_mb=1)
    limit = 1024 * 1024

    assert api.upload(b"x" * limit).status_code == 201
    over = api.upload(b"x" * (limit + 1))

    assert_error(over, 413, "file_too_large")
    assert len(api.blobs()) == 1
    assert api.request("GET", "/files").json()["total"] == 1


def test_a_chunked_upload_cannot_exceed_the_limit(make_api: ApiFactory) -> None:
    api = make_api(max_encrypted_file_size_mb=1)

    def chunks() -> Iterator[bytes]:
        for _ in range(3):
            yield b"x" * 500_000

    response = api.upload(chunks())

    # No length was declared, so only the running total can have refused it.
    assert "content-length" not in response.request.headers
    assert_error(response, 413, "file_too_large")
    assert_nothing_stored(api)


def test_an_empty_file_is_refused(make_api: ApiFactory) -> None:
    api = make_api()

    response = api.upload(b"")

    assert_error(response, 422, "empty_file")
    assert_nothing_stored(api)


def test_cheap_refusals_happen_before_the_body_is_read(
    make_api: ApiFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def forbidden(*_: Any, **__: Any) -> bytearray:
        raise AssertionError("the body must not be read")

    monkeypatch.setattr(files_api, "_read_body", forbidden)
    api = make_api(master_key=None)

    assert_error(api.upload(), 503, "feature_not_configured")

    api.reconfigure(cipherforge_master_key=random_key())
    assert_error(api.upload(content_type="text/plain"), 415, "unsupported_media_type")
    assert_error(api.upload(name=None), 422, "invalid_filename")
    assert_nothing_stored(api)


# --- Listing and inspecting -----------------------------------------------------------------------


def test_files_are_listed_newest_first_with_paging(make_api: ApiFactory) -> None:
    api = make_api()
    for number in range(5):
        api.new_file(name=f"file-{number}.txt")
        api.clock.advance(seconds=1)

    def names(**params: int) -> list[str]:
        return [
            item["name"] for item in api.request("GET", "/files", params=params).json()["items"]
        ]

    assert names() == [f"file-{number}.txt" for number in (4, 3, 2, 1, 0)]
    assert names(limit=2) == ["file-4.txt", "file-3.txt"]
    assert names(limit=2, offset=2) == ["file-2.txt", "file-1.txt"]
    assert names(limit=2, offset=4) == ["file-0.txt"]
    assert api.request("GET", "/files", params={"limit": 2, "offset": 99}).json() == {
        "items": [],
        "total": 5,
    }


@pytest.mark.parametrize(
    "params",
    [{"limit": 0}, {"limit": 201}, {"limit": "many"}, {"offset": -1}, {"offset": "x"}],
)
def test_paging_parameters_are_validated(make_api: ApiFactory, params: dict[str, Any]) -> None:
    api = make_api()

    response = api.request("GET", "/files", params=params)

    assert_error(response, 422, "validation_error")


def test_a_file_shows_its_links_newest_first_with_their_state(make_api: ApiFactory) -> None:
    api = make_api()
    file_id = api.new_file()
    expired = api.new_link(file_id, expires_in_hours=1)
    api.clock.advance(hours=2)
    active = api.new_link(file_id, max_downloads=3)
    api.clock.advance(seconds=1)
    revoked = api.new_link(file_id)
    assert api.revoke(revoked).status_code == 200
    api.clock.advance(seconds=1)
    used = api.new_link(file_id)
    assert api.fetch(used.token).status_code == 200
    downloaded_at = api.clock.now
    api.clock.advance(seconds=1)
    protected = api.new_link(file_id, password=PASSWORD)

    detail = api.request("GET", f"/files/{file_id}").json()

    assert [(share["id"], share["status"]) for share in detail["shares"]] == [
        (protected.share_id, "active"),
        (used.share_id, "exhausted"),
        (revoked.share_id, "revoked"),
        (active.share_id, "active"),
        (expired.share_id, "expired"),
    ]
    assert all(set(share) == SHARE_FIELDS for share in detail["shares"])
    assert (detail["share_count"], detail["active_share_count"]) == (5, 2)
    by_id = {share["id"]: share for share in detail["shares"]}
    assert by_id[used.share_id]["downloads_remaining"] == 0
    assert when(by_id[used.share_id]["last_downloaded_at"]) == downloaded_at
    assert by_id[protected.share_id]["password_protected"] is True
    assert by_id[active.share_id]["password_protected"] is False
    summary = api.request("GET", "/files").json()["items"][0]
    assert (summary["share_count"], summary["active_share_count"]) == (5, 2)


# --- Creating links -------------------------------------------------------------------------------


def test_a_new_link_has_the_documented_shape_and_defaults(make_api: ApiFactory) -> None:
    api = make_api()
    file_id = api.new_file()

    response = api.request("POST", f"/files/{file_id}/shares")  # no body at all

    assert response.status_code == 201
    body = response.json()
    assert set(body) == {"share", "token", "path"}
    assert TOKEN_FORMAT.fullmatch(body["token"])
    assert body["path"] == f"/share/{body['token']}"
    share = body["share"]
    assert set(share) == SHARE_FIELDS
    assert share["file_id"] == file_id
    assert uuid.UUID(share["id"]).version == 4
    assert (share["max_downloads"], share["download_count"], share["downloads_remaining"]) == (
        1,
        0,
        1,
    )
    assert (share["status"], share["password_protected"]) == ("active", False)
    assert share["last_downloaded_at"] is None
    assert share["revoked_at"] is None
    assert when(share["created_at"]) == api.clock.now
    assert when(share["expires_at"]) == api.clock.now + timedelta(hours=24)
    # An explicit null means "the default" too.
    explicit = api.share(file_id, expires_in_hours=None, max_downloads=None, password=None)
    assert explicit.status_code == 201
    assert explicit.json()["share"]["max_downloads"] == 1


def test_link_limits_are_honoured_at_their_bounds(make_api: ApiFactory) -> None:
    api = make_api(max_share_expiry_hours=720, max_share_downloads=100)
    file_id = api.new_file()

    for hours, downloads in [(1, 1), (720, 100), (48, 5)]:
        share = api.share(file_id, expires_in_hours=hours, max_downloads=downloads).json()["share"]
        assert when(share["expires_at"]) == api.clock.now + timedelta(hours=hours)
        assert (share["max_downloads"], share["downloads_remaining"]) == (downloads, downloads)


BAD_LIMITS: list[dict[str, Any]] = [
    {"expires_in_hours": 0},
    {"expires_in_hours": -1},
    {"expires_in_hours": 721},
    {"max_downloads": 0},
    {"max_downloads": -1},
    {"max_downloads": 101},
    {"expires_in_hours": "5"},
    {"expires_in_hours": 1.5},
    {"max_downloads": True},
    {"max_downloads": [1]},
    {"something_else": 1},
]


def test_link_limits_outside_the_policy_are_refused(make_api: ApiFactory) -> None:
    api = make_api(max_share_expiry_hours=720, max_share_downloads=100)
    file_id = api.new_file()

    for body in BAD_LIMITS:
        response = api.share(file_id, **body)
        assert response.status_code == 422, body
        assert response.json()["error"]["code"] == "validation_error", body

    assert api.rows(select(FileShare)) == []
    assert api.actions(file_id) == [("FILE_CREATE", "success")]


def test_the_password_policy_is_enforced_and_a_refused_password_is_not_echoed(
    make_api: ApiFactory,
) -> None:
    api = make_api()
    file_id = api.new_file()
    too_short, too_long = "Zq9!xyz", "Zq9!" * 33  # 7 and 132 characters
    refused: dict[str, Any] = {
        "empty": "",
        "seven characters": too_short,
        "more than 128": too_long,
        "a number": 12345678,
        "a list": ["Zq9!xyzw"],
        "a boolean": True,
    }

    for label, password in refused.items():
        response = api.share(file_id, password=password)
        assert response.status_code == 422, label
        assert response.json()["error"]["code"] == "validation_error", label
        assert too_short not in response.text, label
        assert too_long not in response.text, label

    lone_surrogates = b'{"password": "' + b"\\ud800" * 8 + b'"}'
    response = api.request(
        "POST",
        f"/files/{file_id}/shares",
        content=lone_surrogates,
        headers={"Content-Type": "application/json"},
    )
    assert_error(response, 422, "validation_error")
    assert api.rows(select(FileShare)) == []

    for label, password in {
        "eight characters": "Zq9!xyz1",
        "128 characters": "Zq9!" * 32,
        "unicode": "пароль-密码-🔑!!",
    }.items():
        link = api.new_link(file_id, password=password)
        assert api.share_row(link.share_id).password_protected, label
        assert api.fetch_with(link.token, password).content == CONTENT, label


def test_tokens_are_random_url_safe_and_only_their_hash_is_stored(make_api: ApiFactory) -> None:
    api = make_api()
    file_id = api.new_file()
    links = [api.new_link(file_id) for _ in range(25)]

    assert len({link.token for link in links}) == 25
    stored = {str(row.id): row for row in api.rows(select(FileShare))}
    for link in links:
        assert TOKEN_FORMAT.fullmatch(link.token)
        assert stored[link.share_id].token_hash == hashlib.sha256(link.token.encode()).hexdigest()
    # The token is shown once, when the link is made, and never again.
    for path in (f"/files/{file_id}", "/files", f"/files/{file_id}/activity"):
        text = api.request("GET", path, params={"limit": 200} if path == "/files" else None).text
        assert not any(link.token in text for link in links), path


# --- Opening links --------------------------------------------------------------------------------


def test_info_describes_a_link_without_using_it_up(make_api: ApiFactory) -> None:
    api = make_api()
    link = api.new_link(max_downloads=2, expires_in_hours=5)

    for _ in range(3):
        response = api.info(link.token)

        assert response.status_code == 200
        body = response.json()
        assert set(body) == INFO_FIELDS
        assert body["state"] == "available"
        assert body["file_name"] == FILE_NAME
        assert body["size_bytes"] == len(CONTENT)
        assert body["password_required"] is False
        assert body["downloads_remaining"] == 2
        assert when(body["expires_at"]) == api.clock.now + timedelta(hours=5)
    assert api.share_row(link.share_id).download_count == 0
    assert api.actions(link.file_id) == [("FILE_CREATE", "success"), ("SHARE_CREATE", "success")]


def test_a_password_link_keeps_the_file_name_back_until_it_is_opened(make_api: ApiFactory) -> None:
    api = make_api()
    link = api.new_link(password=PASSWORD)

    response = api.info(link.token)

    body = response.json()
    assert (body["password_required"], body["file_name"]) == (True, None)
    assert body["size_bytes"] == len(CONTENT)
    assert NAME_MARKER not in response.text
    opened = api.fetch_with(link.token, PASSWORD)
    assert opened.headers["content-disposition"] == content_disposition(FILE_NAME)


def test_a_download_is_the_exact_file_with_hardened_headers(make_api: ApiFactory) -> None:
    api = make_api()
    link = api.new_link()

    response = api.fetch(link.token)

    assert response.status_code == 200
    assert response.content == CONTENT
    headers = response.headers
    assert headers["content-type"] == OCTET_STREAM
    assert headers["content-disposition"] == content_disposition(FILE_NAME)
    assert headers["content-length"] == str(len(CONTENT))
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["cache-control"] == "no-store"
    assert headers["content-security-policy"] == "default-src 'none'; sandbox"
    assert headers["referrer-policy"] == "no-referrer"
    assert "set-cookie" not in headers
    assert "www-authenticate" not in headers


def test_a_link_works_exactly_as_often_as_it_allows(make_api: ApiFactory) -> None:
    api = make_api()
    link = api.new_link(max_downloads=3)

    for used in range(1, 4):
        api.clock.advance(seconds=1)
        assert api.fetch(link.token).content == CONTENT
        share = api.request("GET", f"/files/{link.file_id}").json()["shares"][0]
        assert share["download_count"] == used
        assert share["downloads_remaining"] == 3 - used
        assert when(share["last_downloaded_at"]) == api.clock.now

    assert share["status"] == "exhausted"
    assert_error(api.fetch(link.token), 410, "share_limit_reached")
    assert_error(api.info(link.token), 410, "share_limit_reached")
    assert_error(api.fetch_with(link.token, None), 410, "share_limit_reached")
    assert api.share_row(link.share_id).download_count == 3


def test_the_post_form_also_serves_links_that_have_no_password(make_api: ApiFactory) -> None:
    api = make_api()
    link = api.new_link(max_downloads=4)
    url = f"{API}/shares/{link.token}/download"

    responses = [
        api.client.post(url),
        api.client.post(url, json={}),
        api.client.post(url, json={"password": None}),
        api.fetch_with(link.token, None),
    ]

    assert [response.status_code for response in responses] == [200, 200, 200, 200]
    assert all(response.content == CONTENT for response in responses)
    assert api.share_row(link.share_id).download_count == 4


def test_a_password_link_needs_its_password_in_the_body_of_a_post(make_api: ApiFactory) -> None:
    api = make_api()
    link = api.new_link(max_downloads=2, password=PASSWORD)
    url = f"{API}/shares/{link.token}/download"

    assert_error(api.fetch(link.token), 403, "password_required")
    assert_error(api.fetch_with(link.token, None), 403, "password_required")
    assert_error(api.fetch_with(link.token, ""), 403, "password_required")
    # A password in the URL or in a header is not looked at.
    assert_error(api.client.get(url, params={"password": PASSWORD}), 403, "password_required")
    assert_error(api.client.get(url, headers={"X-Password": PASSWORD}), 403, "password_required")
    assert_error(api.fetch_with(link.token, WRONG_PASSWORD), 403, "invalid_password")
    assert api.share_row(link.share_id).download_count == 0

    opened = api.fetch_with(link.token, PASSWORD)

    assert opened.status_code == 200
    assert opened.content == CONTENT
    assert api.share_row(link.share_id).download_count == 1


def test_a_password_may_be_typed_in_another_unicode_form(make_api: ApiFactory) -> None:
    api = make_api()
    composed = "Caf\u00e9-Passw\u00f6rt-1"
    decomposed = "Cafe\u0301-Passwo\u0308rt-1"
    link = api.new_link(max_downloads=2, password=composed)

    assert api.fetch_with(link.token, decomposed).content == CONTENT


def test_a_malformed_download_body_is_refused_without_echoing_it_or_costing_anything(
    make_api: ApiFactory,
) -> None:
    api = make_api()
    link = api.new_link(max_downloads=2, password=PASSWORD)
    url = f"{API}/shares/{link.token}/download"
    as_json = {"Content-Type": "application/json"}
    long_password = "Y" * 129
    cases: dict[str, tuple[dict[str, Any], int, str]] = {
        "not json": ({"content": b"{nope", "headers": as_json}, 422, "validation_error"),
        "a list": ({"content": b'["x"]', "headers": as_json}, 422, "validation_error"),
        "a number": ({"json": {"password": 12345678}}, 422, "validation_error"),
        "an extra field": ({"json": {"password": PASSWORD, "extra": 1}}, 422, "validation_error"),
        "129 characters": ({"json": {"password": long_password}}, 422, "validation_error"),
        "a form": (
            {
                "content": f"password={PASSWORD}".encode(),
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            },
            415,
            "unsupported_media_type",
        ),
        "far too big": (
            {"content": b'{"password": "' + b"x" * 5000 + b'"}', "headers": as_json},
            413,
            "request_too_large",
        ),
    }

    for label, (kwargs, status, code) in cases.items():
        response = api.client.post(url, **kwargs)
        assert response.status_code == status, label
        assert response.json()["error"]["code"] == code, label
        assert PASSWORD not in response.text, label
        assert long_password not in response.text, label

    # None of that used a download or a password guess.
    assert api.share_row(link.share_id).download_count == 0
    assert api.fetch_with(link.token, PASSWORD).content == CONTENT


def test_unknown_and_malformed_tokens_all_look_alike(make_api: ApiFactory) -> None:
    api = make_api()
    candidates = [
        crypto.new_share_token(),  # well formed, but nobody's
        "a" * 42,
        "a" * 44,
        "a" * 42 + "=",
        "a" * 42 + "+",
        "a" * 42 + ".",
        "0" * 43,
    ]
    answers = set()

    for token in candidates:
        for response in (api.info(token), api.fetch(token), api.fetch_with(token, PASSWORD)):
            assert response.status_code == 404, token
            error = response.json()["error"]
            answers.add((error["code"], error["message"]))

    assert len(answers) == 1
    assert {code for code, _ in answers} == {"share_not_found"}
    assert api.audit() == []  # an anonymous caller cannot write to the audit trail by guessing


# --- Revoking, activity and deleting --------------------------------------------------------------


def test_revoking_stops_the_link_and_is_idempotent(make_api: ApiFactory) -> None:
    api = make_api()
    link = api.new_link(max_downloads=5)
    api.clock.advance(seconds=1)

    first = api.revoke(link)

    assert first.status_code == 200
    share = first.json()
    assert set(share) == SHARE_FIELDS
    assert share["status"] == "revoked"
    assert when(share["revoked_at"]) == api.clock.now
    assert_error(api.fetch(link.token), 410, "share_revoked")
    assert_error(api.info(link.token), 410, "share_revoked")
    assert_error(api.fetch_with(link.token, PASSWORD), 410, "share_revoked")

    api.clock.advance(seconds=5)
    second = api.revoke(link)

    assert second.status_code == 200
    assert second.json() == share  # unchanged, keeping the original revocation time
    assert api.actions(link.file_id).count(("SHARE_REVOKE", "success")) == 1
    assert api.share_row(link.share_id).download_count == 0


def test_activity_tells_the_owner_what_happened_to_a_file(make_api: ApiFactory) -> None:
    api = make_api()
    file_id = api.new_file()
    api.clock.advance(seconds=1)
    link = api.new_link(file_id, max_downloads=2, password=PASSWORD)
    api.clock.advance(seconds=1)
    api.fetch_with(link.token, WRONG_PASSWORD)
    api.clock.advance(seconds=1)
    api.fetch_with(link.token, PASSWORD)
    api.clock.advance(seconds=1)
    api.revoke(link)
    api.clock.advance(seconds=1)
    api.fetch_with(link.token, PASSWORD)

    response = api.request("GET", f"/files/{file_id}/activity")

    assert response.status_code == 200
    items = response.json()["items"]
    assert all(
        set(item) == {"timestamp", "action", "result", "share_id", "reason"} for item in items
    )
    assert [(i["action"], i["result"], i["share_id"], i["reason"]) for i in items] == [
        ("SHARE_DOWNLOAD_REJECTED", "rejected", link.share_id, "revoked"),
        ("SHARE_REVOKE", "success", link.share_id, None),
        ("SHARE_DOWNLOAD", "success", link.share_id, None),
        ("SHARE_PASSWORD_FAILED", "rejected", link.share_id, "invalid_password"),
        ("SHARE_CREATE", "success", link.share_id, None),
        ("FILE_CREATE", "success", None, None),
    ]
    stamps = [when(item["timestamp"]) for item in items]
    assert stamps == sorted(stamps, reverse=True)
    assert stamps[0] == api.clock.now
    assert CLIENT_ADDRESS not in response.text  # source addresses stay in the audit store


def test_activity_shows_at_most_the_latest_hundred_events(make_api: ApiFactory) -> None:
    api = make_api()
    file_id = api.new_file()
    with api.session() as session:
        for number in range(1, 121):
            record_audit(
                session,
                actor="anonymous",
                action="SHARE_DOWNLOAD_REJECTED",
                result="rejected",
                target=f"file:{file_id}",
                details={"share_id": str(uuid.uuid4()), "reason": "revoked"},
                timestamp=api.clock.now + timedelta(seconds=number),
            )
        session.commit()

    items = api.request("GET", f"/files/{file_id}/activity").json()["items"]

    assert len(items) == 100
    assert when(items[0]["timestamp"]) == api.clock.now + timedelta(seconds=120)
    assert when(items[-1]["timestamp"]) == api.clock.now + timedelta(seconds=21)


def test_activity_never_mixes_up_two_files(make_api: ApiFactory) -> None:
    api = make_api()
    first = api.new_link(max_downloads=2)
    second = api.new_link(max_downloads=2)
    api.fetch(first.token)

    one = api.request("GET", f"/files/{first.file_id}/activity").json()["items"]
    two = api.request("GET", f"/files/{second.file_id}/activity").json()["items"]

    assert [item["action"] for item in one] == ["SHARE_DOWNLOAD", "SHARE_CREATE", "FILE_CREATE"]
    assert [item["action"] for item in two] == ["SHARE_CREATE", "FILE_CREATE"]
    assert {item["share_id"] for item in one} == {first.share_id, None}
    assert {item["share_id"] for item in two} == {second.share_id, None}


def test_deleting_a_file_removes_it_its_blob_and_its_links(make_api: ApiFactory) -> None:
    api = make_api()
    link = api.new_link()

    response = api.request("DELETE", f"/files/{link.file_id}")

    assert response.status_code == 204
    assert response.content == b""
    assert api.blobs() == []
    assert api.request("GET", "/files").json() == {"items": [], "total": 0}
    assert_error(api.info(link.token), 404, "share_not_found")
    for method, path in [
        ("GET", f"/files/{link.file_id}"),
        ("DELETE", f"/files/{link.file_id}"),
        ("GET", f"/files/{link.file_id}/activity"),
        ("POST", f"/files/{link.file_id}/shares"),
        ("POST", f"/files/{link.file_id}/shares/{link.share_id}/revoke"),
    ]:
        assert_error(api.request(method, path), 404, "file_not_found")


# --- Reading the request body ---------------------------------------------------------------------


class FakeRequest:
    """Just enough of a request for ``_read_body``: its headers and a stream of chunks."""

    def __init__(
        self, chunks: list[bytes], *, length: str | None = None, disconnect_at: int | None = None
    ) -> None:
        self.headers = {} if length is None else {"content-length": length}
        self.chunks_read = 0
        self._chunks = chunks
        self._disconnect_at = disconnect_at

    async def stream(self) -> AsyncIterator[bytes]:
        for index, chunk in enumerate(self._chunks):
            if index == self._disconnect_at:
                raise ClientDisconnect
            self.chunks_read += 1
            yield chunk


def read_body(
    request: FakeRequest,
    limit: int,
    too_large: Callable[[], ApiError] = files_api._file_too_large,
) -> bytearray:
    return asyncio.run(files_api._read_body(request, limit, too_large))  # type: ignore[arg-type]


def refused_with(request: FakeRequest, limit: int, **kwargs: Any) -> ApiError:
    with pytest.raises(ApiError) as refused:
        read_body(request, limit, **kwargs)
    return refused.value


def test_a_declared_length_over_the_limit_is_refused_without_reading_anything() -> None:
    request = FakeRequest([b"x" * 10], length="11")

    error = refused_with(request, 10)

    assert (error.status_code, error.code) == (413, "file_too_large")
    assert request.chunks_read == 0


def test_a_stream_is_cut_off_as_soon_as_it_passes_the_limit() -> None:
    request = FakeRequest([b"x" * 10] * 50)  # chunked: nothing declared up front

    error = refused_with(request, 25)

    assert (error.status_code, error.code) == (413, "file_too_large")
    assert request.chunks_read == 3  # two chunks fit; the third showed it was too much


def test_a_lying_content_length_does_not_widen_the_limit() -> None:
    request = FakeRequest([b"x" * 30], length="5")

    assert refused_with(request, 25).code == "file_too_large"


def test_a_body_exactly_at_the_limit_is_accepted() -> None:
    request = FakeRequest([b"x" * 10, b"y" * 15], length="25")

    assert bytes(read_body(request, 25)) == b"x" * 10 + b"y" * 15


@pytest.mark.parametrize(
    "declared", ["abc", "-1", "1e3", "", " 5", "5 ", "0x10", "+5", "\uff11\uff12"]
)
def test_an_invalid_content_length_is_a_bad_request(declared: str) -> None:
    request = FakeRequest([b"x"], length=declared)

    error = refused_with(request, 100)

    assert (error.status_code, error.code) == (400, "invalid_content_length")
    assert request.chunks_read == 0


@pytest.mark.parametrize("declared", ["9" * 16, "9" * 5000])
def test_an_absurd_content_length_is_too_large_without_being_parsed(declared: str) -> None:
    error = refused_with(FakeRequest([b"x"], length=declared), 100)

    assert (error.status_code, error.code) == (413, "file_too_large")


def test_a_connection_dropped_mid_upload_is_a_bad_request() -> None:
    error = refused_with(FakeRequest([b"x", b"y"], disconnect_at=1), 100)

    assert (error.status_code, error.code) == (400, "upload_interrupted")


def test_the_download_body_has_its_own_small_limit_and_error() -> None:
    cap = files_api.MAX_DOWNLOAD_BODY_BYTES

    error = refused_with(
        FakeRequest([b"x" * (cap + 1)]), cap, too_large=files_api._request_too_large
    )

    assert (error.status_code, error.code) == (413, "request_too_large")
