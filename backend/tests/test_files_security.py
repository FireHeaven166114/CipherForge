"""Access control and abuse limits of the encrypted-file module.

Who may call what, how one owner is kept away from another owner's files, and how guessing
(link tokens, passwords) and flooding (uploads, link requests) are throttled.
"""

import hashlib
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from httpx2 import Response
from sqlalchemy import select

from app.api.v1 import files as files_api
from app.core.config import Settings
from app.files import crypto
from app.models.files import EncryptedFile, FileShare
from tests.conftest import TokenFactory
from tests.files_helpers import (
    ADMIN,
    ANALYST,
    API,
    CONTENT,
    OCTET_STREAM,
    PASSWORD,
    USER,
    WRONG_PASSWORD,
    ApiFactory,
    FileApi,
    Link,
    api_factory,
    assert_error,
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


# Every owner-facing endpoint: name -> (method, path with {file}/{share} placeholders, options).
MANAGEMENT: dict[str, tuple[str, str, dict[str, Any]]] = {
    "status": ("GET", "/files/status", {}),
    "upload": (
        "POST",
        "/files",
        {"content": b"data", "headers": {"Content-Type": OCTET_STREAM, "X-File-Name": "a.txt"}},
    ),
    "list": ("GET", "/files", {}),
    "detail": ("GET", "/files/{file}", {}),
    "delete": ("DELETE", "/files/{file}", {}),
    "share": ("POST", "/files/{file}/shares", {"json": {"max_downloads": 2}}),
    "revoke": ("POST", "/files/{file}/shares/{share}/revoke", {}),
    "activity": ("GET", "/files/{file}/activity", {}),
}
# The endpoints addressed by a file id: what one owner must not reach in another's name.
BY_FILE = ["detail", "delete", "share", "revoke", "activity"]
STRANGERS = [("bob", USER), ("carol", ADMIN), ("dan", ANALYST)]
NOT_AUTHORISED = [[], ["Guest"], ["Auditor"], ["Administrator"], ["Users"]]


def send(api: FileApi, endpoint: str, link: Link, **identity: Any) -> Response:
    """Call one management endpoint for ``link``'s file and share as the given identity."""
    method, template, options = MANAGEMENT[endpoint]
    headers = {**options.get("headers", {}), **identity.pop("headers", {})}
    rest = {key: value for key, value in options.items() if key != "headers"}
    path = template.format(file=link.file_id, share=link.share_id)
    return api.request(method, path, headers=headers, **rest, **identity)


def shape(response: Response) -> tuple[int, dict[str, Any]]:
    """What a client can learn from an error: the status and the envelope minus the request id."""
    error = dict(response.json()["error"])
    error.pop("correlation_id")
    return response.status_code, error


def snapshot(api: FileApi) -> dict[str, Any]:
    """Everything the module stores, to prove that a refused request changed nothing."""
    return {
        "blobs": [(p.name, hashlib.sha256(p.read_bytes()).hexdigest()) for p in api.blobs()],
        "files": [(r.id, r.status, r.storage_name) for r in api.rows(select(EncryptedFile))],
        "shares": [(r.id, r.revoked_at, r.download_count) for r in api.rows(select(FileShare))],
        "audit": [row.id for row in api.audit()],
    }


def invalid_credentials(tokens: TokenFactory) -> dict[str, dict[str, str]]:
    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    valid = tokens.make({"oid": "alice", "roles": [USER]})
    return {
        "no credentials": {},
        "garbage token": bearer("not-a-token"),
        "wrong scheme": {"Authorization": f"Basic {valid}"},
        "no scheme": {"Authorization": valid},
        "expired": bearer(tokens.make({"oid": "alice", "roles": [USER], "exp": 1_000_000_000})),
        "wrong audience": bearer(tokens.make({"oid": "alice", "roles": [USER], "aud": "other"})),
        "unsigned": bearer(tokens.forge_alg_none()),
        "key confusion": bearer(tokens.forge_hs256_with_public_key()),
    }


@pytest.fixture
def derivations(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """One entry per Argon2id password derivation that actually ran."""
    ran: list[int] = []
    original = crypto.unwrap_dek_with_password

    def counting(*args: Any, **kwargs: Any) -> bytes:
        ran.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(crypto, "unwrap_dek_with_password", counting)
    return ran


# --- Authentication -------------------------------------------------------------------------------


@pytest.mark.parametrize("endpoint", MANAGEMENT)
def test_every_management_endpoint_refuses_missing_or_invalid_credentials(
    make_api: ApiFactory, tokens: TokenFactory, endpoint: str
) -> None:
    api = make_api()
    link = api.new_link()
    before = snapshot(api)

    for label, headers in invalid_credentials(tokens).items():
        response = send(api, endpoint, link, user=None, headers=headers)
        assert response.status_code == 401, label
        assert response.json()["error"]["code"] == "unauthorized", label

    assert snapshot(api) == before


def test_authorisation_runs_before_the_limiter_the_body_or_any_file_work(
    make_api: ApiFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = make_api(file_upload_rate_limit_per_minute=1)
    reached: list[str] = []

    async def read_body(*_: Any, **__: Any) -> bytearray:
        reached.append("body")
        raise AssertionError("an unauthorised upload was read")

    monkeypatch.setattr(files_api, "_read_body", read_body)
    monkeypatch.setattr(api.service, "enforce_upload_rate", lambda owner: reached.append(owner))

    for _ in range(3):
        assert_error(api.upload(user=None), 401, "unauthorized")
        assert_error(api.upload(user="mallory", roles=[]), 403, "forbidden")

    assert reached == []
    assert api.blobs() == []
    assert api.audit() == []


# --- Roles ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("endpoint", MANAGEMENT)
def test_a_principal_without_a_known_role_is_forbidden_on_every_endpoint(
    make_api: ApiFactory, endpoint: str
) -> None:
    api = make_api()
    link = api.new_link()
    before = snapshot(api)

    for roles in NOT_AUTHORISED:
        response = send(api, endpoint, link, user="mallory", roles=roles)
        assert response.status_code == 403, roles
        assert response.json()["error"]["code"] == "forbidden", roles

    assert snapshot(api) == before


@pytest.mark.parametrize("role", [USER, ANALYST, ADMIN])
def test_every_role_can_manage_its_own_files(make_api: ApiFactory, role: str) -> None:
    api = make_api()
    me: dict[str, Any] = {"user": f"{role.lower()}-owner", "roles": [role]}

    file_id = api.new_file(**me)
    created = api.share(file_id, **me)
    assert created.status_code == 201
    share_id = created.json()["share"]["id"]

    assert api.request("GET", "/files/status", **me).status_code == 200
    assert api.request("GET", "/files", **me).json()["total"] == 1
    assert api.request("GET", f"/files/{file_id}", **me).status_code == 200
    revoked = api.request("POST", f"/files/{file_id}/shares/{share_id}/revoke", **me)
    assert (revoked.status_code, revoked.json()["status"]) == (200, "revoked")
    activity = api.request("GET", f"/files/{file_id}/activity", **me).json()["items"]
    assert [item["action"] for item in activity] == ["SHARE_REVOKE", "SHARE_CREATE", "FILE_CREATE"]
    assert api.request("DELETE", f"/files/{file_id}", **me).status_code == 204
    assert api.request("GET", f"/files/{file_id}", **me).status_code == 404


# --- One owner cannot reach another owner's files -------------------------------------------------


def test_other_owners_cannot_see_or_change_a_file_even_as_admin(make_api: ApiFactory) -> None:
    api = make_api()
    link = api.new_link(password=PASSWORD)
    unknown = api.request("GET", f"/files/{uuid.uuid4()}")
    reference = shape(unknown)
    assert reference[0] == 404
    assert reference[1]["code"] == "file_not_found"
    before = snapshot(api)

    for name, role in STRANGERS:
        for endpoint in BY_FILE:
            response = send(api, endpoint, link, user=name, roles=[role])
            assert shape(response) == reference, (name, endpoint)
        listing = api.request("GET", "/files?limit=200", user=name, roles=[role])
        assert listing.json() == {"items": [], "total": 0}

    assert snapshot(api) == before
    assert api.request("GET", f"/files/{link.file_id}").status_code == 200
    assert api.fetch_with(link.token, PASSWORD).content == CONTENT


@pytest.mark.parametrize("endpoint", BY_FILE)
def test_a_missing_file_a_malformed_id_and_a_foreign_file_look_the_same(
    make_api: ApiFactory, endpoint: str
) -> None:
    api = make_api()
    link = api.new_link()
    foreign = shape(send(api, endpoint, link, user="bob"))

    for file_id, share_id in [
        (str(uuid.uuid4()), str(uuid.uuid4())),
        ("not-a-uuid", "not-a-uuid"),
        ("%2e%2e", "%00"),
        ("0" * 36, "0" * 36),
        (link.file_id.upper() + "x", link.share_id),
    ]:
        missing = Link(file_id, share_id, link.token)
        assert shape(send(api, endpoint, missing, user="alice")) == foreign, (file_id, share_id)


def test_a_share_id_only_works_through_the_file_it_belongs_to(make_api: ApiFactory) -> None:
    api = make_api()
    first, second = api.new_link(), api.new_link()
    bobs_file = api.new_file(user="bob")
    reference = shape(api.request("GET", f"/files/{uuid.uuid4()}"))

    attempts = [
        api.request("POST", f"/files/{second.file_id}/shares/{first.share_id}/revoke"),
        api.request("POST", f"/files/{bobs_file}/shares/{first.share_id}/revoke", user="bob"),
        api.request("POST", f"/files/{first.file_id}/shares/{uuid.uuid4()}/revoke"),
        api.request("POST", f"/files/{first.file_id}/shares/not-a-uuid/revoke"),
    ]

    assert [shape(attempt) for attempt in attempts] == [reference] * 4
    assert api.share_row(first.share_id).revoked_at is None
    assert api.info(first.token).status_code == 200


# --- The route inventory --------------------------------------------------------------------------


def test_the_routes_are_exactly_the_documented_ones_and_only_link_routes_are_public(
    make_api: ApiFactory,
) -> None:
    api = make_api()
    expected = {
        ("GET", "/api/v1/files/status"),
        ("POST", "/api/v1/files"),
        ("GET", "/api/v1/files"),
        ("GET", "/api/v1/files/{file_id}"),
        ("DELETE", "/api/v1/files/{file_id}"),
        ("POST", "/api/v1/files/{file_id}/shares"),
        ("POST", "/api/v1/files/{file_id}/shares/{share_id}/revoke"),
        ("GET", "/api/v1/files/{file_id}/activity"),
        ("GET", "/api/v1/shares/{token}"),
        ("GET", "/api/v1/shares/{token}/download"),
        ("POST", "/api/v1/shares/{token}/download"),
    }

    operations = api.app.openapi()["paths"]
    found = {
        (method.upper(), path)
        for path, item in operations.items()
        if path.startswith((f"{API}/files", f"{API}/shares"))
        for method in item
    }

    assert found == expected
    for method, path in expected:
        operation = operations[path][method.lower()]
        if path.startswith(f"{API}/files"):
            assert operation["security"] == [{"EntraBearer": []}], (method, path)
        else:
            assert "security" not in operation, (method, path)
    upload = operations[f"{API}/files"]["post"]
    assert list(upload["requestBody"]["content"]) == [OCTET_STREAM]


# --- What link holders get ------------------------------------------------------------------------


def test_link_routes_need_no_credentials_and_never_set_cookies(make_api: ApiFactory) -> None:
    api = make_api()
    link = api.new_link(max_downloads=10)
    base = f"{API}/shares/{link.token}"

    for headers in (
        {},
        {"Authorization": "Bearer garbage"},
        {"Authorization": f"Bearer {api.tokens.make({'oid': 'bob', 'roles': [USER]})}"},
        {"Cookie": "session=abc"},
    ):
        for response in (
            api.client.get(base, headers=headers),
            api.client.get(f"{base}/download", headers=headers),
            api.client.post(f"{base}/download", json={"password": None}, headers=headers),
        ):
            assert response.status_code == 200, headers
            assert "set-cookie" not in response.headers


def test_link_errors_are_never_cacheable_or_sniffable(make_api: ApiFactory) -> None:
    api = make_api()
    revoked = api.new_link()
    api.revoke(revoked)

    for response in (
        api.info(crypto.new_share_token()),
        api.info("short"),
        api.fetch(revoked.token),
        api.fetch_with(revoked.token, PASSWORD),
    ):
        assert response.status_code in {404, 410}
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Content-Type-Options"] == "nosniff"


# --- Upload rate limit ----------------------------------------------------------------------------


def test_uploads_are_rate_limited_per_user_and_recover(make_api: ApiFactory) -> None:
    api = make_api(file_upload_rate_limit_per_minute=3)
    for _ in range(3):
        api.new_file()
    before = snapshot(api)

    refused = api.upload()

    assert_error(refused, 429, "rate_limited")
    assert 1 <= int(refused.headers["Retry-After"]) <= 60
    assert snapshot(api) == before
    assert api.upload(user="bob").status_code == 201

    api.ticks.advance(61)
    assert api.upload().status_code == 201


def test_a_rate_limited_upload_is_refused_before_its_body_is_read(
    make_api: ApiFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = make_api(file_upload_rate_limit_per_minute=1)
    api.new_file()

    async def read_body(*_: Any, **__: Any) -> bytearray:
        raise AssertionError("the body was read")

    monkeypatch.setattr(files_api, "_read_body", read_body)

    assert_error(api.upload(), 429, "rate_limited")


def test_share_links_are_rate_limited_per_user_and_recover(make_api: ApiFactory) -> None:
    api = make_api(share_create_rate_limit_per_minute=2)
    file_id = api.new_file()
    bobs_file = api.new_file(user="bob")
    for _ in range(2):
        api.new_link(file_id)
    before = snapshot(api)

    refused = api.share(file_id, password=PASSWORD)

    assert_error(refused, 429, "rate_limited")
    assert 1 <= int(refused.headers["Retry-After"]) <= 60
    assert snapshot(api) == before
    assert api.share(bobs_file, user="bob").status_code == 201

    api.ticks.advance(61)
    assert api.share(file_id).status_code == 201


def test_a_refused_share_request_does_not_spend_the_link_budget(make_api: ApiFactory) -> None:
    api = make_api(share_create_rate_limit_per_minute=1)
    file_id = api.new_file()

    assert api.share(file_id, expires_in_hours=0).status_code == 422
    assert api.share(str(uuid.uuid4())).status_code == 404

    assert api.share(file_id).status_code == 201


# --- Link request rate limit ----------------------------------------------------------------------


def test_link_requests_are_rate_limited_per_client_address(make_api: ApiFactory) -> None:
    api = make_api(share_download_rate_limit_per_minute=4)
    link = api.new_link(max_downloads=10)
    elsewhere = api.from_address("198.51.100.77")

    allowed = [call(link.token) for call in (api.info, api.fetch, api.info, api.fetch)]
    assert [response.status_code for response in allowed] == [200] * 4
    audited = api.actions(link.file_id)

    for refused in (api.info(link.token), api.fetch(link.token), api.fetch_with(link.token, None)):
        assert_error(refused, 429, "rate_limited")
        assert 1 <= int(refused.headers["Retry-After"]) <= 60
    assert api.info(link.token, client=elsewhere).status_code == 200
    assert api.actions(link.file_id) == audited

    api.ticks.advance(61)
    assert api.info(link.token).status_code == 200


def test_guessing_links_burns_the_clients_request_budget(make_api: ApiFactory) -> None:
    api = make_api(share_download_rate_limit_per_minute=3)

    for token in (crypto.new_share_token(), "short", crypto.new_share_token()):
        assert_error(api.info(token), 404, "share_not_found")
    assert_error(api.info(crypto.new_share_token()), 429, "rate_limited")
    assert_error(api.fetch(crypto.new_share_token()), 429, "rate_limited")

    assert api.audit() == []


# --- Wrong-password lockout -----------------------------------------------------------------------


def test_wrong_passwords_lock_a_link_for_everyone_before_any_key_derivation(
    make_api: ApiFactory, derivations: list[int]
) -> None:
    api = make_api(share_password_attempt_limit=3)
    link = api.new_link(max_downloads=5, password=PASSWORD)
    elsewhere = api.from_address("198.51.100.77")
    for _ in range(3):
        assert_error(api.fetch_with(link.token, WRONG_PASSWORD), 403, "invalid_password")
    assert len(derivations) == 3

    wrong = api.fetch_with(link.token, WRONG_PASSWORD)
    right = api.fetch_with(link.token, PASSWORD)
    right_elsewhere = api.fetch_with(link.token, PASSWORD, client=elsewhere)

    for locked in (wrong, right, right_elsewhere):
        assert_error(locked, 429, "too_many_attempts")
        assert locked.headers["Retry-After"] == "900"
    # A locked link says nothing about whether the password was right.
    assert shape(wrong) == shape(right) == shape(right_elsewhere)
    assert len(derivations) == 3
    assert api.info(link.token).status_code == 200

    api.ticks.advance(300)
    assert api.fetch_with(link.token, PASSWORD).headers["Retry-After"] == "600"

    api.ticks.advance(601)
    unlocked = api.fetch_with(link.token, PASSWORD)
    assert unlocked.status_code == 200
    assert unlocked.content == CONTENT
    assert len(derivations) == 4
    assert api.actions(link.file_id) == [
        ("FILE_CREATE", "success"),
        ("SHARE_CREATE", "success"),
        *[("SHARE_PASSWORD_FAILED", "rejected")] * 3,
        ("SHARE_DOWNLOAD", "success"),
    ]


def test_wrong_passwords_against_different_links_lock_the_client_not_the_links(
    make_api: ApiFactory, derivations: list[int]
) -> None:
    api = make_api(share_password_attempt_limit=3)
    links = [api.new_link(password=PASSWORD) for _ in range(4)]
    attacker = api.from_address("198.51.100.77")
    honest = api.from_address("192.0.2.55")

    for link in links[:3]:
        guess = api.fetch_with(link.token, WRONG_PASSWORD, client=attacker)
        assert_error(guess, 403, "invalid_password")
    locked = api.fetch_with(links[3].token, PASSWORD, client=attacker)

    assert_error(locked, 429, "too_many_attempts")
    assert len(derivations) == 3
    served = api.fetch_with(links[3].token, PASSWORD, client=honest)
    assert served.status_code == 200
    assert served.content == CONTENT


def test_ipv6_clients_are_limited_by_their_64_bit_network(
    make_api: ApiFactory, derivations: list[int]
) -> None:
    api = make_api(share_password_attempt_limit=2)
    first, second = api.new_link(password=PASSWORD), api.new_link(password=PASSWORD)
    here = api.from_address("2001:db8:1:2::1")
    same_network = api.from_address("2001:db8:1:2:ffff:ffff:ffff:ffff")
    other_network = api.from_address("2001:db8:1:3::1")

    assert_error(api.fetch_with(first.token, WRONG_PASSWORD, client=here), 403, "invalid_password")
    guess = api.fetch_with(second.token, WRONG_PASSWORD, client=same_network)
    assert_error(guess, 403, "invalid_password")

    assert_error(api.fetch_with(second.token, PASSWORD, client=here), 429, "too_many_attempts")
    assert len(derivations) == 2
    assert api.fetch_with(second.token, PASSWORD, client=other_network).status_code == 200


def test_a_correct_password_does_not_refill_the_attempt_budget(
    make_api: ApiFactory, derivations: list[int]
) -> None:
    api = make_api(share_password_attempt_limit=3)
    link = api.new_link(max_downloads=5, password=PASSWORD)

    assert_error(api.fetch_with(link.token, WRONG_PASSWORD), 403, "invalid_password")
    assert_error(api.fetch_with(link.token, WRONG_PASSWORD), 403, "invalid_password")
    assert api.fetch_with(link.token, PASSWORD).status_code == 200
    assert_error(api.fetch_with(link.token, WRONG_PASSWORD), 403, "invalid_password")

    assert_error(api.fetch_with(link.token, WRONG_PASSWORD), 429, "too_many_attempts")
    assert len(derivations) == 4


def test_requests_without_a_password_do_not_use_up_the_attempt_budget(
    make_api: ApiFactory, derivations: list[int]
) -> None:
    api = make_api(share_password_attempt_limit=2)
    link = api.new_link(max_downloads=2, password=PASSWORD)

    for _ in range(4):
        assert_error(api.fetch(link.token), 403, "password_required")
        assert_error(api.fetch_with(link.token, None), 403, "password_required")
        assert_error(api.fetch_with(link.token, ""), 403, "password_required")

    assert derivations == []
    assert api.fetch_with(link.token, PASSWORD).status_code == 200


# --- Development mode -----------------------------------------------------------------------------


def test_in_development_mode_every_request_is_the_single_dev_user(make_api: ApiFactory) -> None:
    api = make_api(auth_mode="dev")

    created = api.upload(user=None)
    assert created.status_code == 201
    file_id = created.json()["id"]

    assert api.request("GET", f"/files/{file_id}", user=None).status_code == 200
    assert api.request("GET", f"/files/{file_id}", user="bob").status_code == 200
    assert {row.actor for row in api.audit()} == {"dev-user"}
