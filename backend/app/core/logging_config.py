"""Structured logging with correlation IDs and secret redaction.

Every log line is passed through :func:`redact` before it is written, so a
secret that ends up in a message, an exception, or an ``extra`` field is masked
even when the calling code forgot to be careful. Redaction is a safety net, not
a licence to log secrets.
"""

import json
import logging
import re
import sys
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from app.core.config import Settings
from app.core.context import correlation_id_var

REDACTED = "[REDACTED]"

_SENSITIVE_WORDS = (
    r"(?:api[_-]?key|token|secret|password|passwd|pwd|authorization|cookie|credential)"
)
_SENSITIVE_NAME = re.compile(_SENSITIVE_WORDS, re.IGNORECASE)

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # JSON Web Tokens.
    (re.compile(r"\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*"), REDACTED),
    # "Bearer <token>" and "Basic <credentials>".
    (re.compile(r"\b(Bearer|Basic)\s+[\w\-.~+/]+=*", re.IGNORECASE), rf"\1 {REDACTED}"),
    # scheme://user:password@host - the password may contain '@'.
    (re.compile(r"(?<=://)([^\s/:@]+):[^\s/]*@"), rf"\1:{REDACTED}@"),
    # name=value, name: value or "name": "value" where the name looks sensitive.
    (
        re.compile(
            rf"""([\w\-]*{_SENSITIVE_WORDS}[\w\-]*["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&}}\]"']+)""",
            re.IGNORECASE,
        ),
        rf"\1{REDACTED}",
    ),
)

_MIN_SECRET_LENGTH = 8
_known_secrets: set[str] = set()
_known_secrets_lock = threading.Lock()


def register_secrets(values: Iterable[str]) -> None:
    """Remember exact secret values so they are masked wherever they appear."""
    with _known_secrets_lock:
        _known_secrets.update(v for v in values if len(v) >= _MIN_SECRET_LENGTH)


def clear_registered_secrets() -> None:
    with _known_secrets_lock:
        _known_secrets.clear()


def redact(text: str) -> str:
    with _known_secrets_lock:
        secrets = sorted(_known_secrets, key=len, reverse=True)
    for secret in secrets:
        text = text.replace(secret, REDACTED)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_value(name: str, value: Any) -> Any:
    """Redact a structured log field using both its name and its content."""
    if _SENSITIVE_NAME.search(name):
        return REDACTED
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {str(k): redact_value(str(k), v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [redact_value(name, item) for item in value]
    return value


_STANDARD_RECORD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {
    "message",
    "asctime",
    "color_message",  # uvicorn adds an ANSI-coloured duplicate of the message
}


def _extra_fields(record: logging.LogRecord) -> dict[str, Any]:
    return {
        key: value
        for key, value in record.__dict__.items()
        if key not in _STANDARD_RECORD_ATTRS and not key.startswith("_")
    }


class JsonFormatter(logging.Formatter):
    """One JSON object per line, suitable for log pipelines."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "message": redact(record.getMessage()),
        }
        correlation_id = correlation_id_var.get()
        if correlation_id:
            payload["correlation_id"] = correlation_id
        for key, value in _extra_fields(record).items():
            payload[key] = redact_value(key, value)
        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, default=str, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    """Human-friendly output for local development."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = self.formatTime(record, "%H:%M:%S")
        parts = [f"{timestamp} {record.levelname:<8} {record.name}: {redact(record.getMessage())}"]
        correlation_id = correlation_id_var.get()
        if correlation_id:
            parts.append(f"correlation_id={correlation_id}")
        for key, value in _extra_fields(record).items():
            parts.append(f"{key}={redact_value(key, value)}")
        line = " ".join(parts)
        if record.exc_info:
            line += "\n" + redact(self.formatException(record.exc_info))
        return line


class StdoutHandler(logging.StreamHandler):
    """Writes to whatever ``sys.stdout`` currently is (robust to test capture)."""

    def __init__(self) -> None:
        logging.Handler.__init__(self)

    @property
    def stream(self) -> Any:
        return sys.stdout


_HANDLER_MARKER = "_cipherforge_handler"


def configure_logging(settings: Settings) -> None:
    """Install the redacting handler on the root logger (idempotent)."""
    register_secrets(settings.secret_values())

    handler = StdoutHandler()
    handler.setFormatter(JsonFormatter() if settings.log_format == "json" else ConsoleFormatter())
    setattr(handler, _HANDLER_MARKER, True)

    root = logging.getLogger()
    for existing in list(root.handlers):
        if getattr(existing, _HANDLER_MARKER, False):
            root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(settings.log_level)

    # Route uvicorn's own records through our handler; requests are logged by
    # RequestLoggingMiddleware, so uvicorn's access log would only duplicate them.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
    logging.getLogger("uvicorn.access").disabled = True
    # HTTP client libraries log full request URLs at INFO. That would copy analyst-submitted
    # indicators (and any token embedded in a URL indicator) into the general application log,
    # where redaction cannot know to hide them. The audit trail is the record of lookups.
    for name in ("httpx", "httpx2", "httpcore", "httpcore2"):
        logging.getLogger(name).setLevel(logging.WARNING)
