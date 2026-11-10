"""Pure-ASGI middleware.

These are written against the raw ASGI interface instead of
``BaseHTTPMiddleware`` so that context variables (the correlation ID) reach
synchronous endpoints running in the thread pool.

Order matters. ``create_app`` stacks them, outermost first, as::

    CorrelationId -> SecurityHeaders -> RequestLogging -> CORS -> UnhandledException -> app

so that even an unexpected 500 carries a correlation ID and security headers.
"""

import logging
import re
import time
import uuid

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.context import correlation_id_var
from app.core.errors import error_response

logger = logging.getLogger("cipherforge.http")

CORRELATION_HEADER = "X-Correlation-ID"
# Incoming IDs are only trusted if they look harmless; this prevents log injection.
_VALID_CORRELATION_ID = re.compile(r"[A-Za-z0-9._-]{8,64}")

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class CorrelationIdMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = Headers(scope=scope).get(CORRELATION_HEADER)
        if incoming and _VALID_CORRELATION_ID.fullmatch(incoming):
            correlation_id = incoming
        else:
            correlation_id = uuid.uuid4().hex
        scope.setdefault("state", {})["correlation_id"] = correlation_id
        token = correlation_id_var.set(correlation_id)

        async def send_with_header(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)[CORRELATION_HEADER] = correlation_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_header)
        finally:
            correlation_id_var.reset(token)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in _SECURITY_HEADERS.items():
                    headers.setdefault(name, value)
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RequestLoggingMiddleware:
    """One structured log line per request. Query strings are never logged."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        status_code = 500

        async def send_capturing_status(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_capturing_status)
        finally:
            level = logging.ERROR if status_code >= 500 else logging.INFO
            logger.log(
                level,
                "request",
                extra={
                    "method": scope["method"],
                    "path": scope["path"],
                    "status_code": status_code,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                },
            )


class UnhandledExceptionMiddleware:
    """Turns unexpected exceptions into a generic 500 without leaking details."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def send_tracking_start(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, send_tracking_start)
        except Exception:
            logger.exception(
                "unhandled_exception",
                extra={"method": scope["method"], "path": scope["path"]},
            )
            if response_started:
                raise
            response = error_response(500, "internal_error", "An internal error occurred.")
            await response(scope, receive, send)
