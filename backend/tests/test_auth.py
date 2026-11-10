"""Authentication and authorization behaviour, including token attack cases."""

from collections.abc import Callable
from typing import Annotated

import jwt
import pytest
from fastapi import Depends
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.security.auth import EntraTokenValidator, Principal, require_roles
from app.security.roles import Role
from tests.conftest import CLIENT_ID, TENANT_ID, TokenFactory

ME = "/api/v1/me"

AnalystPrincipal = Annotated[Principal, Depends(require_roles(Role.SECURITY_ANALYST, Role.ADMIN))]


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def entra_client(entra_settings: Settings, entra_validator: EntraTokenValidator) -> TestClient:
    app = create_app(entra_settings, token_validator=entra_validator)

    @app.get("/_test/analyst")
    def analyst_only(principal: AnalystPrincipal) -> dict[str, str]:
        return {"subject": principal.subject}

    with TestClient(app) as client:
        yield client


# --- dev mode -----------------------------------------------------------------


def test_dev_mode_returns_the_configured_local_principal(client: TestClient) -> None:
    response = client.get(ME)

    assert response.status_code == 200
    assert response.json() == {
        "subject": "dev-user",
        "name": "Local Developer",
        "roles": ["SecurityAnalyst"],
        "auth_mode": "dev",
    }


def test_dev_mode_roles_are_enforced(make_settings: Callable[..., Settings]) -> None:
    app = create_app(make_settings(dev_auth_roles="User"))

    @app.get("/_test/analyst")
    def analyst_only(_: AnalystPrincipal) -> dict[str, str]:
        return {"ok": "yes"}

    with TestClient(app) as client:
        assert client.get("/_test/analyst").status_code == 403


# --- Entra token validation ---------------------------------------------------


def test_missing_token_is_rejected(entra_client: TestClient) -> None:
    response = entra_client.get(ME)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json()["error"]["code"] == "unauthorized"


def test_valid_token_is_accepted(entra_client: TestClient, tokens: TokenFactory) -> None:
    response = entra_client.get(ME, headers=bearer(tokens.make()))

    assert response.status_code == 200
    assert response.json() == {
        "subject": "oid-456",
        "name": "Ada Analyst",
        "roles": ["SecurityAnalyst"],
        "auth_mode": "entra",
    }


@pytest.mark.parametrize(
    ("label", "overrides", "remove"),
    [
        ("expired", {"exp": 1_000_000_000}, ()),
        ("not yet valid", {"nbf": 4_000_000_000}, ()),
        ("wrong audience", {"aud": "someone-else"}, ()),
        ("wrong issuer", {"iss": "https://login.microsoftonline.com/other/v2.0"}, ()),
        ("wrong tenant", {"tid": "99999999-9999-9999-9999-999999999999"}, ()),
        ("missing tenant", {}, ("tid",)),
        ("missing expiry", {}, ("exp",)),
        ("missing subject", {}, ("sub",)),
        ("missing audience", {}, ("aud",)),
    ],
)
def test_bad_claims_are_rejected(
    entra_client: TestClient,
    tokens: TokenFactory,
    label: str,
    overrides: dict,
    remove: tuple[str, ...],
) -> None:
    token = tokens.make(overrides, remove)

    response = entra_client.get(ME, headers=bearer(token))

    assert response.status_code == 401, label
    assert response.json()["error"]["message"] == "Invalid or expired token."


def test_token_signed_with_another_key_is_rejected(
    entra_client: TestClient, tokens: TokenFactory
) -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa

    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    response = entra_client.get(ME, headers=bearer(tokens.make(signing_key=attacker_key)))

    assert response.status_code == 401


def test_algorithm_confusion_attack_is_rejected(
    entra_client: TestClient, tokens: TokenFactory
) -> None:
    response = entra_client.get(ME, headers=bearer(tokens.forge_hs256_with_public_key()))

    assert response.status_code == 401


def test_unsigned_alg_none_token_is_rejected(
    entra_client: TestClient, tokens: TokenFactory
) -> None:
    response = entra_client.get(ME, headers=bearer(tokens.forge_alg_none()))

    assert response.status_code == 401


@pytest.mark.parametrize("garbage", ["not-a-jwt", "a.b.c", "....", "x" * 9000])
def test_malformed_or_oversized_tokens_are_rejected(entra_client: TestClient, garbage: str) -> None:
    assert entra_client.get(ME, headers=bearer(garbage)).status_code == 401


def test_wrong_authorization_scheme_is_rejected(
    entra_client: TestClient, tokens: TokenFactory
) -> None:
    response = entra_client.get(ME, headers={"Authorization": f"Basic {tokens.make()}"})

    assert response.status_code == 401


def test_unknown_roles_are_ignored(entra_client: TestClient, tokens: TokenFactory) -> None:
    token = tokens.make({"roles": ["Hacker", "user", 42, None]})

    response = entra_client.get(ME, headers=bearer(token))

    assert response.json()["roles"] == ["User"]


def test_non_list_roles_claim_yields_no_roles(
    entra_client: TestClient, tokens: TokenFactory
) -> None:
    response = entra_client.get(ME, headers=bearer(tokens.make({"roles": {"Admin": True}})))

    assert response.status_code == 200
    assert response.json()["roles"] == []


# --- authorization ------------------------------------------------------------


def test_role_protected_route_allows_matching_role(
    entra_client: TestClient, tokens: TokenFactory
) -> None:
    response = entra_client.get("/_test/analyst", headers=bearer(tokens.make()))

    assert response.status_code == 200
    assert response.json() == {"subject": "oid-456"}


@pytest.mark.parametrize("roles", [["User"], [], ["Hacker"]])
def test_role_protected_route_denies_insufficient_roles(
    entra_client: TestClient, tokens: TokenFactory, roles: list[str]
) -> None:
    response = entra_client.get("/_test/analyst", headers=bearer(tokens.make({"roles": roles})))

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


def test_role_protected_route_requires_authentication(entra_client: TestClient) -> None:
    assert entra_client.get("/_test/analyst").status_code == 401


def test_admin_role_is_accepted_where_listed(
    entra_client: TestClient, tokens: TokenFactory
) -> None:
    token = tokens.make({"roles": ["Admin"]})

    assert entra_client.get("/_test/analyst", headers=bearer(token)).status_code == 200


# --- key service failures -------------------------------------------------------


def test_unreachable_key_service_fails_closed_with_503(
    entra_settings: Settings, tokens: TokenFactory
) -> None:
    def resolver(_token: str) -> object:
        raise jwt.PyJWKClientConnectionError("jwks endpoint down")

    validator = EntraTokenValidator(
        tenant_id=TENANT_ID,
        issuer=f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
        audience=CLIENT_ID,
        key_resolver=resolver,
    )
    with TestClient(create_app(entra_settings, token_validator=validator)) as client:
        response = client.get(ME, headers=bearer(tokens.make()))

    assert response.status_code == 503
    assert "jwks" not in response.text.lower()


def test_unknown_signing_key_is_a_401(entra_settings: Settings, tokens: TokenFactory) -> None:
    def resolver(_token: str) -> object:
        raise jwt.PyJWKClientError("Unable to find a signing key that matches")

    validator = EntraTokenValidator(
        tenant_id=TENANT_ID,
        issuer=f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
        audience=CLIENT_ID,
        key_resolver=resolver,
    )
    with TestClient(create_app(entra_settings, token_validator=validator)) as client:
        assert client.get(ME, headers=bearer(tokens.make())).status_code == 401


def test_failed_authentication_is_logged_without_the_token(
    entra_client: TestClient, tokens: TokenFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    token = tokens.make({"exp": 1_000_000_000})

    entra_client.get(ME, headers=bearer(token))

    output = capsys.readouterr().out
    assert "authentication_failed" in output
    assert '"reason": "expired"' in output
    assert token not in output
