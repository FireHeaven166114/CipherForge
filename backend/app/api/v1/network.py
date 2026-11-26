"""Network-monitoring endpoints. Security Analysts and Admins only.

Every session, flow and alert belongs to the user who started the capture or uploaded the file.
Other users, administrators included, get the same ``404`` as for something that does not exist.
"""

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from app.api.deps import DbSession, NetworkServiceDep, SettingsDep
from app.api.v1.intel import (
    AnalystPrincipal,
    RateLimitedAnalyst,
    client_address,
    enforce_investigation_rate_limit,
    require_analyst,
)
from app.core.errors import ApiError
from app.network.pcap import display_name, receive_upload
from app.schemas.network import (
    AlertOut,
    AlertPage,
    FlowPage,
    InterfaceList,
    NetworkStatus,
    RuleOut,
    SessionDetail,
    SessionPage,
    Severity,
    StartCaptureRequest,
)
from app.security.auth import Principal
from app.services.intel_service import RequestContext

OCTET_STREAM = "application/octet-stream"
FILE_NAME_HEADER = "x-file-name"
_MAX_DIGITS_IN_CONTENT_LENGTH = 15
_MEGABYTE = 1024 * 1024

router = APIRouter(
    prefix="/network",
    tags=["network-monitoring"],
    dependencies=[Depends(require_analyst)],
)

_NOT_FOUND_SESSION = {404: {"description": "`session_not_found`."}}
_UPLOAD_OPENAPI: dict[str, Any] = {
    "parameters": [
        {
            "name": "X-File-Name",
            "in": "header",
            "required": True,
            "description": "The file name, percent-encoded UTF-8. Must end in .pcap, .pcapng "
            "or .cap. It is shown in the session list and never used as a path.",
            "schema": {"type": "string", "maxLength": 1024},
        }
    ],
    "requestBody": {
        "required": True,
        "description": "The raw bytes of the capture file. multipart/form-data is not supported.",
        "content": {OCTET_STREAM: {"schema": {"type": "string", "format": "binary"}}},
    },
}


def _context(request: Request, principal: Principal) -> RequestContext:
    return RequestContext(actor=principal.subject, source_ip=client_address(request))


def _check_declared_length(request: Request, limit: int) -> None:
    """Refuse an upload whose declared size is over the limit before reading any of it."""
    declared = request.headers.get("content-length")
    if declared is None:
        return
    if not (declared.isascii() and declared.isdigit()):
        raise ApiError(400, "invalid_content_length", "The Content-Length header is invalid.")
    if len(declared) > _MAX_DIGITS_IN_CONTENT_LENGTH or int(declared) > limit:
        raise ApiError(
            413,
            "file_too_large",
            f"The capture file is larger than the {limit // _MEGABYTE} MB limit.",
        )


# --- Status ------------------------------------------------------------------------------------


@router.get("/status", response_model=NetworkStatus, summary="Capture status for the caller")
def network_status(
    principal: AnalystPrincipal, service: NetworkServiceDep, session: DbSession
) -> NetworkStatus:
    """The state of the caller's live capture (or the last one), and whether capture is possible
    at all on this server."""
    return service.status(session, principal.subject)


@router.get(
    "/interfaces",
    response_model=InterfaceList,
    summary="Network interfaces a capture can be started on",
    responses={429: {"description": "`rate_limited` when `refresh` is set; see `Retry-After`."}},
)
def list_interfaces(
    request: Request,
    principal: AnalystPrincipal,
    service: NetworkServiceDep,
    refresh: Annotated[bool, Query(description="Look at the system again (rate limited).")] = False,
) -> InterfaceList:
    if refresh:
        enforce_investigation_rate_limit(request, principal)
    return service.interfaces(refresh=refresh)


@router.get("/rules", response_model=list[RuleOut], summary="The detection rules and thresholds")
def list_rules(service: NetworkServiceDep) -> list[RuleOut]:
    """The rules that judge captured traffic, with the thresholds this server is configured with."""
    return service.rules()


# --- Live capture ------------------------------------------------------------------------------


@router.post(
    "/capture/start",
    response_model=NetworkStatus,
    summary="Start a live capture",
    responses={
        404: {"description": "`interface_not_found`."},
        409: {"description": "`capture_already_running`."},
        503: {
            "description": "`capture_permission_denied`, `capture_backend_missing`, "
            "`interface_unavailable` or `capture_failed`."
        },
    },
)
def start_capture(
    payload: StartCaptureRequest,
    request: Request,
    principal: AnalystPrincipal,
    service: NetworkServiceDep,
    session: DbSession,
) -> NetworkStatus:
    """Start capturing packet metadata on one interface. Only one capture can run at a time.

    Packet payloads are never kept: only addresses, ports, protocol, size, TCP flags and time.
    """
    return service.start_live(session, _context(request, principal), payload.interface)


@router.post(
    "/capture/stop",
    response_model=NetworkStatus,
    summary="Stop your live capture",
    responses={409: {"description": "`capture_not_running`."}},
)
def stop_capture(
    request: Request,
    principal: AnalystPrincipal,
    service: NetworkServiceDep,
    session: DbSession,
) -> NetworkStatus:
    return service.stop_live(session, _context(request, principal))


# --- Capture files -----------------------------------------------------------------------------


@router.post(
    "/pcap",
    response_model=SessionDetail,
    status_code=202,
    summary="Analyse an uploaded PCAP or PCAPNG file",
    responses={
        400: {"description": "`invalid_content_length` or `upload_interrupted`."},
        409: {"description": "`analysis_already_running`."},
        413: {"description": "`file_too_large`."},
        415: {"description": "`unsupported_media_type`: send application/octet-stream."},
        422: {"description": "`invalid_filename` or `invalid_capture_file`."},
        429: {"description": "`rate_limited`; see `Retry-After`."},
    },
    openapi_extra=_UPLOAD_OPENAPI,
)
async def analyze_pcap(
    request: Request,
    principal: RateLimitedAnalyst,
    settings: SettingsDep,
    service: NetworkServiceDep,
    session: DbSession,
) -> SessionDetail:
    """Check the capture file, then analyse it in the background and return the new session.

    The body is the raw file (``Content-Type: application/octet-stream``) and its name travels in
    ``X-File-Name``. Poll ``GET /network/sessions/{id}`` until its status is no longer
    ``running``. The upload is kept in a private temporary folder only while it is analysed.
    """
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != OCTET_STREAM:
        raise ApiError(
            415,
            "unsupported_media_type",
            "Upload the raw capture file as application/octet-stream.",
        )
    names = request.headers.getlist(FILE_NAME_HEADER)
    name = display_name(names[0] if len(names) == 1 else None)
    limit = settings.network_max_pcap_size_mb * _MEGABYTE
    _check_declared_length(request, limit)
    service.ensure_analysis_idle()
    try:
        upload = await receive_upload(request.stream(), spool=service.spool, max_bytes=limit)
    except ClientDisconnect:
        raise ApiError(
            400, "upload_interrupted", "The request body was not received completely."
        ) from None
    return await run_in_threadpool(
        service.analyze_pcap, session, _context(request, principal), upload=upload, name=name
    )


# --- Sessions ----------------------------------------------------------------------------------


@router.get("/sessions", response_model=SessionPage, summary="Your monitoring sessions")
def list_sessions(
    principal: AnalystPrincipal,
    service: NetworkServiceDep,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
) -> SessionPage:
    """Live captures and analysed files, newest first."""
    return service.list_sessions(session, principal.subject, limit=limit, offset=offset)


@router.get(
    "/sessions/{session_id}",
    response_model=SessionDetail,
    summary="One session with its totals, top talkers and external addresses",
    responses=_NOT_FOUND_SESSION,
)
def get_session(
    session_id: uuid.UUID,
    principal: AnalystPrincipal,
    service: NetworkServiceDep,
    session: DbSession,
) -> SessionDetail:
    return service.get_session(session, principal.subject, session_id)


@router.get(
    "/sessions/{session_id}/flows",
    response_model=FlowPage,
    summary="The network flows of a session, newest first",
    responses=_NOT_FOUND_SESSION,
)
def list_flows(
    session_id: uuid.UUID,
    principal: AnalystPrincipal,
    service: NetworkServiceDep,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
) -> FlowPage:
    return service.list_flows(session, principal.subject, session_id, limit=limit, offset=offset)


@router.get(
    "/sessions/{session_id}/alerts",
    response_model=AlertPage,
    summary="The alerts of a session, newest first",
    responses=_NOT_FOUND_SESSION,
)
def list_alerts(
    session_id: uuid.UUID,
    principal: AnalystPrincipal,
    service: NetworkServiceDep,
    session: DbSession,
    severity: Annotated[list[Severity] | None, Query(description="Only these severities.")] = None,
    rule: Annotated[
        str | None, Query(pattern=r"^NET-[0-9]{3}$", description="Only this rule, e.g. NET-001.")
    ] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
) -> AlertPage:
    return service.list_alerts(
        session,
        principal.subject,
        session_id,
        severities=severity or (),
        rule_id=rule,
        limit=limit,
        offset=offset,
    )


@router.delete(
    "/sessions/{session_id}",
    status_code=204,
    summary="Delete a finished session with its flows and alerts",
    responses={
        404: {"description": "`session_not_found`."},
        409: {"description": "`session_running`: stop it first."},
    },
)
def delete_session(
    session_id: uuid.UUID,
    request: Request,
    principal: AnalystPrincipal,
    service: NetworkServiceDep,
    session: DbSession,
) -> Response:
    service.delete_session(session, _context(request, principal), session_id)
    return Response(status_code=204)


# --- Alerts ------------------------------------------------------------------------------------


@router.post(
    "/alerts/{alert_id}/enrich",
    response_model=AlertOut,
    summary="Look up an alert's public address with the threat-intelligence providers",
    responses={
        404: {"description": "`alert_not_found`."},
        409: {"description": "`enrichment_disabled`."},
        422: {"description": "`address_not_public`."},
        429: {"description": "`rate_limited`; see `Retry-After`."},
    },
)
def enrich_alert(
    alert_id: uuid.UUID,
    request: Request,
    principal: RateLimitedAnalyst,
    service: NetworkServiceDep,
    session: DbSession,
) -> AlertOut:
    """Providers reuse their fresh answers, so asking again does not spend their quota."""
    return service.enrich_alert(session, _context(request, principal), alert_id)
