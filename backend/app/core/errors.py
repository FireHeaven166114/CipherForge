"""Uniform JSON error envelope.

Every error the API returns has the shape::

    {"error": {"code": "...", "message": "...", "correlation_id": "...", "details": [...]}}

Messages are deliberately generic: no stack traces, SQL, file paths or
connection details are ever returned to the caller.
"""

import http
import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.context import correlation_id_var

logger = logging.getLogger("cipherforge.errors")

_ERROR_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    503: "service_unavailable",
}


def error_response(
    status_code: int,
    code: str,
    message: str,
    *,
    details: list[dict[str, Any]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    error: dict[str, Any] = {
        "code": code,
        "message": message,
        "correlation_id": correlation_id_var.get(),
    }
    if details:
        error["details"] = details
    return JSONResponse({"error": error}, status_code=status_code, headers=headers)


async def http_exception_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = _ERROR_CODES.get(exc.status_code, "http_error")
    message = exc.detail if isinstance(exc.detail, str) else http.HTTPStatus(exc.status_code).phrase
    return error_response(exc.status_code, code, message, headers=exc.headers)


async def validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    # Only location, message and type are returned; the submitted value is not echoed back.
    details = [
        {"loc": [str(part) for part in error["loc"]], "msg": error["msg"], "type": error["type"]}
        for error in exc.errors()
    ]
    return error_response(422, "validation_error", "Request validation failed.", details=details)


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_exception_handler)  # type: ignore[arg-type]
