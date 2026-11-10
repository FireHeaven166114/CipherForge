import io
import json
import logging
from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.context import correlation_id_var
from app.core.logging_config import (
    REDACTED,
    JsonFormatter,
    configure_logging,
    redact,
    redact_value,
    register_secrets,
)
from app.main import create_app

JWT = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
    "c2lnbmF0dXJlLXNpZ25hdHVyZS1zaWduYXR1cmU"
)


@pytest.mark.parametrize(
    ("raw", "must_not_contain"),
    [
        ("calling provider api_key=abc123SECRETvalue now", "abc123SECRETvalue"),
        ("ABUSEIPDB_API_KEY=abc123SECRETvalue", "abc123SECRETvalue"),
        ("headers: X-OTX-API-KEY: abc123SECRETvalue", "abc123SECRETvalue"),
        ("Authorization: Bearer abc.def-ghi_jkl", "abc.def-ghi_jkl"),
        (f"token was {JWT}", JWT),
        ("postgresql+psycopg://cipherforge:p%40ssw0rd@db:5432/app", "p%40ssw0rd"),
        ("postgresql+psycopg://cipherforge:p@ss@db:5432/app", "p@ss"),
        ('{"password": "my secret pass phrase"}', "secret pass phrase"),
        ("client_secret='top secret value'", "top secret value"),
        ("cookie=session-id-1234567890", "session-id-1234567890"),
    ],
)
def test_redact_masks_secrets(raw: str, must_not_contain: str) -> None:
    redacted = redact(raw)

    assert must_not_contain not in redacted
    assert REDACTED in redacted


def test_redact_leaves_ordinary_text_alone() -> None:
    line = "request completed: GET /health 200 in 3.2ms for 8.8.8.8"

    assert redact(line) == line


def test_registered_secret_values_are_masked_anywhere() -> None:
    register_secrets(["super-secret-value-123", "short"])

    assert "super-secret-value-123" not in redact("it appeared as super-secret-value-123 here")
    # Very short values are ignored so ordinary words are not blanked out.
    assert redact("a short string") == "a short string"


def test_configure_logging_registers_settings_secrets(
    make_settings: Callable[..., Settings],
) -> None:
    settings = make_settings(database_url="postgresql+psycopg://u:Zx9-Very-Secret-Pw@db:5432/app")

    configure_logging(settings)

    assert "Zx9-Very-Secret-Pw" not in redact("connect failed using Zx9-Very-Secret-Pw")


def test_redact_value_uses_field_names() -> None:
    assert redact_value("api_key", "anything") == REDACTED
    assert redact_value("authorization", "anything") == REDACTED
    assert redact_value("path", "/health") == "/health"
    assert redact_value("details", {"password": "x", "ok": "y"}) == {
        "password": REDACTED,
        "ok": "y",
    }


@pytest.fixture
def json_logger() -> Iterator[tuple[logging.Logger, io.StringIO]]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("test.json_logger")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    yield logger, stream
    logger.handlers = []


def test_json_formatter_emits_valid_redacted_json(
    json_logger: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = json_logger
    token = correlation_id_var.set("corr-12345678")
    try:
        try:
            raise RuntimeError("failed with api_key=abc123SECRETvalue")
        except RuntimeError:
            logger.exception(
                "lookup failed for api_key=%s",
                "abc123SECRETvalue",
                extra={"api_key": "zzz", "ioc": "1.2.3.4"},
            )
    finally:
        correlation_id_var.reset(token)

    record = json.loads(stream.getvalue())
    assert record["level"] == "ERROR"
    assert record["correlation_id"] == "corr-12345678"
    assert record["ioc"] == "1.2.3.4"
    assert record["api_key"] == REDACTED
    assert "abc123SECRETvalue" not in stream.getvalue()
    assert "Traceback" in record["exception"]


def _json_lines(text: str) -> list[dict]:
    records = []
    for line in text.splitlines():
        if line.startswith("{"):
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def test_requests_are_logged_without_query_strings(
    make_settings: Callable[..., Settings], capsys: pytest.CaptureFixture[str]
) -> None:
    with TestClient(create_app(make_settings())) as client:
        response = client.get("/health?api_key=QUERYSTRINGSECRET1234")

    output = capsys.readouterr().out
    assert "QUERYSTRINGSECRET1234" not in output
    requests = [r for r in _json_lines(output) if r.get("message") == "request"]
    assert requests, "expected a structured request log line"
    entry = requests[-1]
    assert entry["path"] == "/health"
    assert entry["status_code"] == 200
    assert entry["correlation_id"] == response.headers["X-Correlation-ID"]
    assert "duration_ms" in entry


def test_database_password_never_reaches_logs_or_responses(
    make_settings: Callable[..., Settings], capsys: pytest.CaptureFixture[str]
) -> None:
    password = "Sup3rS3cretDbPassw0rd"
    # Port 1 on loopback refuses immediately, which drives /ready down its failure path.
    url = f"postgresql+psycopg://cipherforge:{password}@127.0.0.1:1/cipherforge"
    settings = make_settings(database_url=url)

    with TestClient(create_app(settings)) as client:
        response = client.get("/ready")

    output = capsys.readouterr().out
    assert response.status_code == 503
    assert "database_unavailable" in output
    assert password not in output
    assert password not in response.text
    assert password not in repr(settings)
