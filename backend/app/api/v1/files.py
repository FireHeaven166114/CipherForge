"""Encrypted file sharing endpoints.

Two routers are exported:

* ``router`` -- management for the signed-in owner: upload, list, inspect, share, revoke,
  activity and delete. Every role may use it, and every query is scoped to the caller's own
  files (another owner's file is indistinguishable from one that does not exist).
* ``public_router`` -- link holders. No authentication and no cookies: possession of the 256-bit
  link token is the credential. A password, when the link has one, travels only in the body of a
  POST, never in a URL.

Uploads are the raw bytes of the file (``Content-Type: application/octet-stream``) with the name
percent-encoded in ``X-File-Name``. ``multipart/form-data`` is intentionally unsupported (415):
its parser spools larger parts to temporary files, which would put plaintext on disk before it is
encrypted, and the module's guarantee is that plaintext never touches the disk.
"""

import logging
from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from starlette.requests import ClientDisconnect

from app.api.deps import DbSession, FileServiceDep
from app.api.v1.intel import client_address
from app.core.errors import ApiError
from app.files.names import InvalidFilename, content_disposition, filename_from_header
from app.files.service import Caller, DownloadResult
from app.schemas.files import (
    ActivityList,
    DownloadRequest,
    FileDetail,
    FileFeatureStatus,
    FileList,
    FileOut,
    PublicShareInfo,
    ShareCreated,
    ShareCreateRequest,
    ShareOut,
)
from app.security.auth import Principal, require_roles
from app.security.roles import Role

logger = logging.getLogger("cipherforge.files")

OCTET_STREAM = "application/octet-stream"
JSON_MEDIA_TYPE = "application/json"
FILE_NAME_HEADER = "x-file-name"
# A download body is {"password": "..."} with a password of at most 128 characters.
MAX_DOWNLOAD_BODY_BYTES = 4096
_MAX_DIGITS_IN_CONTENT_LENGTH = 15

# Every role may keep and share files. Authorization is a router dependency, so it runs before
# anything else: an anonymous or unauthorized caller never reaches the upload limiter or the body.
require_file_user = require_roles(Role.USER, Role.SECURITY_ANALYST, Role.ADMIN)
FileUser = Annotated[Principal, Depends(require_file_user)]

router = APIRouter(
    prefix="/files",
    tags=["encrypted-files"],
    dependencies=[Depends(require_file_user)],
)
public_router = APIRouter(prefix="/shares", tags=["file-share-links"])

_ERROR_NOTE = "Error envelope with a stable `error.code`."
_OWNER_NOT_FOUND = {404: {"description": f"`file_not_found`. {_ERROR_NOTE}"}}
_DOWNLOAD_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; sandbox",
    "Referrer-Policy": "no-referrer",
}
_LINK_ERRORS: dict[int | str, dict[str, Any]] = {
    403: {"description": "`password_required` or `invalid_password`."},
    404: {"description": "`share_not_found`: unknown or malformed link."},
    409: {"description": "`file_unavailable`: the stored file failed verification or is missing."},
    410: {"description": "`share_revoked`, `share_expired` or `share_limit_reached`."},
    429: {"description": "`rate_limited` or `too_many_attempts`; see `Retry-After`."},
    503: {"description": "`feature_not_configured` or `encryption_key_mismatch`."},
}
_DOWNLOAD_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {
        "description": "The decrypted file.",
        "content": {OCTET_STREAM: {"schema": {"type": "string", "format": "binary"}}},
    },
    **_LINK_ERRORS,
}
_UPLOAD_OPENAPI: dict[str, Any] = {
    "parameters": [
        {
            "name": "X-File-Name",
            "in": "header",
            "required": True,
            "description": "The file name, percent-encoded UTF-8 (at most 1024 characters).",
            "schema": {"type": "string", "maxLength": 1024},
        }
    ],
    "requestBody": {
        "required": True,
        "description": "The raw bytes of the file. multipart/form-data is not supported.",
        "content": {OCTET_STREAM: {"schema": {"type": "string", "format": "binary"}}},
    },
}
_DOWNLOAD_OPENAPI: dict[str, Any] = {
    "requestBody": {
        "required": False,
        "content": {JSON_MEDIA_TYPE: {"schema": DownloadRequest.model_json_schema()}},
    }
}


def _media_type(request: Request) -> str:
    return request.headers.get("content-type", "").split(";", 1)[0].strip().lower()


def _file_too_large() -> ApiError:
    return ApiError(413, "file_too_large", "The file is larger than the allowed size.")


def _request_too_large() -> ApiError:
    return ApiError(413, "request_too_large", "The request body is too large.")


async def _read_body(request: Request, limit: int, too_large: Callable[[], ApiError]) -> bytearray:
    """Read the body without ever holding more than ``limit`` bytes.

    A declared ``Content-Length`` over the limit is refused before reading anything, and the
    running total is checked chunk by chunk, so a chunked body (which declares no length) cannot
    exceed the limit either.
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        if not (declared.isascii() and declared.isdigit()):
            raise ApiError(400, "invalid_content_length", "The Content-Length header is invalid.")
        if len(declared) > _MAX_DIGITS_IN_CONTENT_LENGTH or int(declared) > limit:
            raise too_large()
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > limit:
                raise too_large()
            body.extend(chunk)
    except ClientDisconnect:
        raise ApiError(
            400, "upload_interrupted", "The request body was not received completely."
        ) from None
    return body


async def read_download_request(request: Request) -> DownloadRequest:
    """The optional JSON body of a download, ``{"password": str | null}``.

    FastAPI's own body parsing would buffer a body of any size before the endpoint runs; this is
    an unauthenticated endpoint, so the body is read here under a small cap instead.
    """
    body = await _read_body(request, MAX_DOWNLOAD_BODY_BYTES, _request_too_large)
    if not body.strip():
        return DownloadRequest()
    if _media_type(request) != JSON_MEDIA_TYPE:
        raise ApiError(415, "unsupported_media_type", "Send the request body as application/json.")
    try:
        return DownloadRequest.model_validate_json(body)
    except ValidationError as exc:
        # Location, message and type only: the submitted value (a password) is never echoed.
        raise RequestValidationError(
            [
                {"loc": ("body", *error["loc"]), "msg": error["msg"], "type": error["type"]}
                for error in exc.errors(
                    include_url=False, include_context=False, include_input=False
                )
            ]
        ) from None


DownloadBody = Annotated[DownloadRequest, Depends(read_download_request)]


def _owner(request: Request, principal: Principal) -> Caller:
    return Caller(principal.subject, client_address(request))


def _link_holder(request: Request) -> Caller:
    return Caller.anonymous(client_address(request))


def _file_response(result: DownloadResult) -> Response:
    return Response(
        content=result.content,
        media_type=OCTET_STREAM,
        headers={"Content-Disposition": content_disposition(result.name), **_DOWNLOAD_HEADERS},
    )


# --- Owner management ---------------------------------------------------------------------------


@router.get("/status", response_model=FileFeatureStatus, summary="Feature status and limits")
def file_status(service: FileServiceDep) -> FileFeatureStatus:
    """Whether encrypted file sharing is configured on this server, and its limits."""
    return service.status()


@router.post(
    "",
    response_model=FileOut,
    status_code=201,
    summary="Encrypt and store a file",
    responses={
        413: {"description": "`file_too_large`."},
        415: {"description": "`unsupported_media_type`: send application/octet-stream."},
        422: {"description": "`empty_file` or `invalid_filename`."},
        429: {"description": "`rate_limited`; see `Retry-After`."},
        503: {"description": "`feature_not_configured`."},
    },
    openapi_extra=_UPLOAD_OPENAPI,
)
async def upload_file(
    request: Request, principal: FileUser, service: FileServiceDep, session: DbSession
) -> FileOut:
    """Encrypt the request body with a fresh key and store only the ciphertext.

    The body is the raw file (``Content-Type: application/octet-stream``) and the name travels in
    ``X-File-Name``. It is read as a stream under the size limit, encrypted in memory and written
    once; nothing is ever overwritten, so uploading the same name twice makes two files.

    This endpoint is ``async`` only to read the stream; encryption and the database work run in
    the thread pool.
    """
    service.require_configured()  # before reading a single byte of the body
    service.enforce_upload_rate(principal.subject)
    if _media_type(request) != OCTET_STREAM:
        raise ApiError(
            415,
            "unsupported_media_type",
            "Upload the raw file bytes as application/octet-stream.",
        )
    try:
        name = filename_from_header(request.headers.getlist(FILE_NAME_HEADER))
    except InvalidFilename:
        raise ApiError(
            422, "invalid_filename", "The X-File-Name header is missing or not a usable name."
        ) from None
    content = await _read_body(request, service.max_file_size_bytes, _file_too_large)
    return await run_in_threadpool(
        service.create_file, session, _owner(request, principal), name=name, content=content
    )


@router.get("", response_model=FileList, summary="List your files, newest first")
def list_files(
    principal: FileUser,
    service: FileServiceDep,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
) -> FileList:
    return service.list_files(session, principal.subject, limit=limit, offset=offset)


@router.get(
    "/{file_id}",
    response_model=FileDetail,
    summary="One of your files, with its links",
    responses=_OWNER_NOT_FOUND,
)
def get_file(
    file_id: str, principal: FileUser, service: FileServiceDep, session: DbSession
) -> FileDetail:
    return service.get_file(session, principal.subject, file_id)


@router.delete(
    "/{file_id}",
    status_code=204,
    summary="Delete a file, its stored ciphertext and its links",
    responses=_OWNER_NOT_FOUND,
)
def delete_file(
    file_id: str,
    request: Request,
    principal: FileUser,
    service: FileServiceDep,
    session: DbSession,
) -> Response:
    """The audit trail keeps its record of the file and gains one of this deletion."""
    service.delete_file(session, _owner(request, principal), file_id)
    return Response(status_code=204)


@router.post(
    "/{file_id}/shares",
    response_model=ShareCreated,
    status_code=201,
    summary="Create a share link",
    responses={
        **_OWNER_NOT_FOUND,
        409: {"description": "`file_unavailable`."},
        429: {"description": "`rate_limited`; see `Retry-After`."},
    },
)
def create_share(
    file_id: str,
    request: Request,
    principal: FileUser,
    service: FileServiceDep,
    session: DbSession,
    payload: ShareCreateRequest | None = None,
) -> ShareCreated:
    """Create a link. The response carries the token once and it can never be shown again: only
    its hash is stored. The link holds neither a key nor the optional password."""
    return service.create_share(
        session, _owner(request, principal), file_id, payload or ShareCreateRequest()
    )


@router.post(
    "/{file_id}/shares/{share_id}/revoke",
    response_model=ShareOut,
    summary="Revoke a share link",
    responses=_OWNER_NOT_FOUND,
)
def revoke_share(
    file_id: str,
    share_id: str,
    request: Request,
    principal: FileUser,
    service: FileServiceDep,
    session: DbSession,
) -> ShareOut:
    """Idempotent: revoking a revoked link returns it unchanged and records nothing new."""
    return service.revoke_share(session, _owner(request, principal), file_id, share_id)


@router.get(
    "/{file_id}/activity",
    response_model=ActivityList,
    summary="Recent audit events for one of your files",
    responses=_OWNER_NOT_FOUND,
)
def file_activity(
    file_id: str, principal: FileUser, service: FileServiceDep, session: DbSession
) -> ActivityList:
    """Newest first, at most 100 events. Source addresses are never included."""
    return service.activity(session, principal.subject, file_id)


# --- Link holders (public) ----------------------------------------------------------------------


@public_router.get(
    "/{token}",
    response_model=PublicShareInfo,
    summary="What a link offers, without downloading it",
    responses=_LINK_ERRORS,
)
def share_info(
    token: str, request: Request, service: FileServiceDep, session: DbSession
) -> PublicShareInfo:
    """Consumes no download. The file name is withheld while a password is still required."""
    return service.share_info(session, _link_holder(request), token)


@public_router.get(
    "/{token}/download",
    response_class=Response,
    response_model=None,
    summary="Download through a link that has no password",
    responses=_DOWNLOAD_RESPONSES,
)
def download_share(
    token: str, request: Request, service: FileServiceDep, session: DbSession
) -> Response:
    """A password-protected link answers 403 ``password_required``: passwords are never accepted
    in a URL, so use the POST form."""
    return _file_response(service.download(session, _link_holder(request), token, None))


@public_router.post(
    "/{token}/download",
    response_class=Response,
    response_model=None,
    summary="Download through a link, optionally with its password",
    responses=_DOWNLOAD_RESPONSES,
    openapi_extra=_DOWNLOAD_OPENAPI,
)
def download_share_with_password(
    token: str,
    request: Request,
    service: FileServiceDep,
    session: DbSession,
    body: DownloadBody,
) -> Response:
    """The file is decrypted and verified completely before the download is counted, so a
    failed integrity check or a wrong password never uses one up. A body is optional for links
    without a password."""
    password = body.password.get_secret_value() if body.password is not None else None
    return _file_response(service.download(session, _link_holder(request), token, password))
