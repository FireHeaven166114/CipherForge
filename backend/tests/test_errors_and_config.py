from collections.abc import Callable

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.core.config import ConfigurationError, Settings, load_settings
from app.main import create_app
from app.security.auth import require_roles
from app.security.roles import Role

GUID_A = "11111111-2222-3333-4444-555555555555"
GUID_B = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
PG_URL = "postgresql+psycopg://cipherforge:TopSecretPw@localhost:5432/cipherforge"


def test_unknown_route_uses_the_error_envelope(client: TestClient) -> None:
    response = client.get("/does-not-exist")

    assert response.status_code == 404
    body = response.json()["error"]
    assert body["code"] == "not_found"
    assert body["correlation_id"] == response.headers["X-Correlation-ID"]


def test_validation_errors_do_not_echo_submitted_values(
    make_settings: Callable[..., Settings],
) -> None:
    class Payload(BaseModel):
        count: int

    app = create_app(make_settings())

    @app.post("/_test/echo")
    def echo(payload: Payload) -> Payload:
        return payload

    with TestClient(app) as client:
        response = client.post("/_test/echo", json={"count": "SUBMITTED-SECRET-VALUE"})

    assert response.status_code == 422
    assert "SUBMITTED-SECRET-VALUE" not in response.text
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"][0]["loc"] == ["body", "count"]


def test_unhandled_exceptions_become_a_generic_500(
    make_settings: Callable[..., Settings],
) -> None:
    app = create_app(make_settings())

    @app.get("/_test/boom")
    def boom() -> None:
        raise RuntimeError("db connection failed password=hunter2hunter2")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/_test/boom")

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert "hunter2" not in response.text
    assert "RuntimeError" not in response.text
    assert response.headers["X-Correlation-ID"] == response.json()["error"]["correlation_id"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_forbidden_uses_the_error_envelope(make_settings: Callable[..., Settings]) -> None:
    app = create_app(make_settings(dev_auth_roles="User"))

    @app.get("/_test/protected")
    def protected(_: object = Depends(require_roles(Role.ADMIN))) -> dict[str, str]:
        return {"ok": "yes"}

    with TestClient(app) as client:
        response = client.get("/_test/protected")

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


# --- configuration guards ----------------------------------------------------


def test_dev_auth_is_refused_in_production() -> None:
    with pytest.raises(ConfigurationError, match="AUTH_MODE=dev is not permitted"):
        load_settings(
            _env_file=None, environment="production", auth_mode="dev", database_url=PG_URL
        )


def test_entra_mode_requires_tenant_and_client() -> None:
    with pytest.raises(ConfigurationError, match="ENTRA_TENANT_ID"):
        load_settings(_env_file=None, environment="test", auth_mode="entra", database_url=PG_URL)


def test_entra_ids_must_be_guids() -> None:
    with pytest.raises(ConfigurationError, match="ENTRA_TENANT_ID: must be a GUID"):
        load_settings(
            _env_file=None,
            environment="test",
            auth_mode="entra",
            entra_tenant_id="not-a-guid",
            entra_client_id=GUID_B,
            database_url=PG_URL,
        )


def test_production_requires_postgresql() -> None:
    with pytest.raises(ConfigurationError, match="requires a PostgreSQL"):
        load_settings(
            _env_file=None,
            environment="production",
            auth_mode="entra",
            entra_tenant_id=GUID_A,
            entra_client_id=GUID_B,
            database_url="sqlite+pysqlite:///x.db",
        )


def test_production_refuses_the_template_database_password() -> None:
    with pytest.raises(ConfigurationError, match="CHANGE_ME placeholder") as excinfo:
        load_settings(
            _env_file=None,
            environment="production",
            auth_mode="entra",
            entra_tenant_id=GUID_A,
            entra_client_id=GUID_B,
            database_url="postgresql+psycopg://cipherforge:change_me_local_only@db:5432/cipherforge",
        )

    assert "change_me_local_only" not in str(excinfo.value)


def test_template_database_password_is_allowed_outside_production() -> None:
    settings = load_settings(
        _env_file=None,
        environment="development",
        auth_mode="dev",
        database_url="postgresql+psycopg://cipherforge:CHANGE_ME_local_only@localhost:5432/cipherforge",
    )

    assert settings.environment == "development"


def test_missing_database_url_is_reported_by_name() -> None:
    with pytest.raises(ConfigurationError, match="DATABASE_URL"):
        load_settings(_env_file=None, environment="test", auth_mode="dev")


def test_wildcard_cors_origin_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="CORS_ORIGINS"):
        load_settings(
            _env_file=None,
            environment="test",
            auth_mode="dev",
            database_url=PG_URL,
            cors_origins="*",
        )


def test_invalid_configuration_never_echoes_values() -> None:
    with pytest.raises(ConfigurationError) as excinfo:
        load_settings(
            _env_file=None,
            environment="staging-not-valid",
            auth_mode="dev",
            database_url="postgresql+psycopg://cipherforge:TopSecretPw@localhost/db",
        )

    assert "TopSecretPw" not in str(excinfo.value)
    assert "staging-not-valid" not in str(excinfo.value)
    assert "ENVIRONMENT" in str(excinfo.value)


def test_secrets_are_not_exposed_by_repr(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(database_url=PG_URL)

    assert "TopSecretPw" not in repr(settings)
    assert "TopSecretPw" not in str(settings)
    assert "TopSecretPw" in settings.secret_values()


def test_settings_load_from_environment_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", PG_URL)
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("AUTH_MODE", "dev")
    monkeypatch.setenv("DEV_AUTH_ROLES", "Admin, security analyst")
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5173/, http://localhost:3000")

    settings = load_settings(_env_file=None)

    assert settings.dev_auth_roles == [Role.ADMIN, Role.SECURITY_ANALYST]
    assert settings.cors_origins == ["http://localhost:5173", "http://localhost:3000"]
    assert settings.environment == "development"


def test_unknown_dev_role_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="DEV_AUTH_ROLES"):
        load_settings(
            _env_file=None,
            environment="test",
            auth_mode="dev",
            database_url=PG_URL,
            dev_auth_roles="Admin,Wizard",
        )
