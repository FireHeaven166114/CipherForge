import re
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from app import __version__
from app.core.config import Settings
from app.main import create_app

GUID_A = "11111111-2222-3333-4444-555555555555"
GUID_B = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def test_health_returns_stable_payload(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "cipherforge-api", "version": __version__}


def test_health_does_not_depend_on_the_database(
    make_settings: Callable[..., Settings], tmp_path
) -> None:
    unreachable = f"sqlite+pysqlite:///{(tmp_path / 'missing-dir' / 'x.db').as_posix()}"
    with TestClient(create_app(make_settings(database_url=unreachable))) as client:
        assert client.get("/health").status_code == 200


def test_ready_reports_ok_when_database_is_reachable(client: TestClient) -> None:
    response = client.get("/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "checks": {"database": "ok"}}


def test_ready_returns_503_without_leaking_details(
    make_settings: Callable[..., Settings], tmp_path
) -> None:
    unreachable = f"sqlite+pysqlite:///{(tmp_path / 'missing-dir' / 'x.db').as_posix()}"
    with TestClient(create_app(make_settings(database_url=unreachable))) as client:
        response = client.get("/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready", "checks": {"database": "unavailable"}}
    assert "missing-dir" not in response.text
    assert "sqlite" not in response.text.lower()


def test_correlation_id_is_generated_when_absent(client: TestClient) -> None:
    correlation_id = client.get("/health").headers["X-Correlation-ID"]

    assert re.fullmatch(r"[0-9a-f]{32}", correlation_id)


def test_valid_incoming_correlation_id_is_echoed(client: TestClient) -> None:
    response = client.get("/health", headers={"X-Correlation-ID": "trace-abc_123.def"})

    assert response.headers["X-Correlation-ID"] == "trace-abc_123.def"


def test_untrusted_correlation_ids_are_replaced(client: TestClient) -> None:
    for bad in ("short", "x" * 100, "has spaces in it", "semi;colon;injection"):
        response = client.get("/health", headers={"X-Correlation-ID": bad})
        assert response.headers["X-Correlation-ID"] != bad


def test_security_headers_are_set(client: TestClient) -> None:
    headers = client.get("/health").headers

    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Cache-Control"] == "no-store"


def test_interactive_docs_are_available_outside_production(client: TestClient) -> None:
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_interactive_docs_are_disabled_in_production(
    make_settings: Callable[..., Settings],
) -> None:
    settings = make_settings(
        environment="production",
        auth_mode="entra",
        entra_tenant_id=GUID_A,
        entra_client_id=GUID_B,
        database_url="postgresql+psycopg://user:pw@localhost:5432/db",
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404
        assert client.get("/health").status_code == 200


def test_cors_allows_only_configured_origins(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(cors_origins="http://localhost:5173")
    with TestClient(create_app(settings)) as client:
        allowed = client.get("/health", headers={"Origin": "http://localhost:5173"})
        denied = client.get("/health", headers={"Origin": "https://evil.example"})

    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-origin" not in denied.headers


@pytest.mark.parametrize("method", ["GET", "POST", "DELETE"])
def test_cors_preflight_allows_the_methods_the_dashboard_uses(
    make_settings: Callable[..., Settings], method: str
) -> None:
    settings = make_settings(cors_origins="http://localhost:5173")
    with TestClient(create_app(settings)) as client:
        preflight = client.options(
            "/api/v1/intel/indicators/anything",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": method,
                "Access-Control-Request-Headers": "authorization",
            },
        )

    assert preflight.status_code == 200
    assert method in preflight.headers["access-control-allow-methods"]
