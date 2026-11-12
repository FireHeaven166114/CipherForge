"""Threat-intelligence endpoints. Security Analysts and Admins only."""

import ipaddress
import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.deps import DbSession, IntelServiceDep
from app.correlation.scoring import Classification
from app.models.enums import IndicatorType
from app.schemas.intel import (
    IndicatorPage,
    InvestigateRequest,
    InvestigationResponse,
    OverviewResponse,
    StatsResponse,
)
from app.security.auth import Principal, require_roles
from app.security.roles import Role
from app.services.intel_service import RequestContext, SortOrder
from app.services.normalization import InvalidIndicatorError

logger = logging.getLogger("cipherforge.intel")

HTTP_NOT_FOUND = 404
HTTP_UNPROCESSABLE = 422
HTTP_TOO_MANY_REQUESTS = 429

# Authorization runs first (it is a dependency of the rate limiter below), so an anonymous or
# unauthorized caller never consumes, or learns about, anyone's rate-limit budget.
require_analyst = require_roles(Role.SECURITY_ANALYST, Role.ADMIN)
AnalystPrincipal = Annotated[Principal, Depends(require_analyst)]

router = APIRouter(
    prefix="/intel",
    tags=["threat-intelligence"],
    dependencies=[Depends(require_analyst)],
)


def enforce_investigation_rate_limit(request: Request, principal: AnalystPrincipal) -> Principal:
    retry_after = request.app.state.rate_limiter.check(principal.subject)
    if retry_after is not None:
        logger.warning(
            "rate_limited",
            extra={"subject": principal.subject, "retry_after_seconds": retry_after},
        )
        raise HTTPException(
            status_code=HTTP_TOO_MANY_REQUESTS,
            detail="Too many investigations. Try again shortly.",
            headers={"Retry-After": str(retry_after)},
        )
    return principal


RateLimitedAnalyst = Annotated[Principal, Depends(enforce_investigation_rate_limit)]


def client_address(request: Request) -> str | None:
    """The caller's address for the audit trail, or None if it is not a valid IP address.

    Behind a trusted proxy, uvicorn takes this from X-Forwarded-For without validating it, so a
    value that is not an address is dropped rather than stored.
    """
    if request.client is None:
        return None
    try:
        return str(ipaddress.ip_address(request.client.host))
    except ValueError:
        return None


@router.post(
    "/investigate",
    response_model=InvestigationResponse,
    summary="Investigate an indicator of compromise",
)
def investigate(
    payload: InvestigateRequest,
    request: Request,
    principal: RateLimitedAnalyst,
    service: IntelServiceDep,
    session: DbSession,
) -> InvestigationResponse:
    """Normalize the indicator, query the configured providers (or reuse fresh cached answers),
    store each answer, rescore, and return every provider's answer next to the CipherForge score.
    """
    context = RequestContext(actor=principal.subject, source_ip=client_address(request))
    try:
        return service.investigate(session, context, payload.indicator, refresh=payload.refresh)
    except InvalidIndicatorError as exc:
        # The message never echoes the input.
        raise HTTPException(status_code=HTTP_UNPROCESSABLE, detail=str(exc)) from None


@router.get(
    "/indicators/{indicator_id}",
    response_model=InvestigationResponse,
    summary="A stored indicator with its provider answers and score",
)
def get_indicator(
    indicator_id: uuid.UUID, service: IntelServiceDep, session: DbSession
) -> InvestigationResponse:
    """Read-only: serves stored evidence and the score snapshot; never calls a provider."""
    response = service.get_investigation(session, indicator_id)
    if response is None:
        raise HTTPException(status_code=HTTP_NOT_FOUND, detail="Indicator not found.")
    return response


@router.get(
    "/indicators",
    response_model=IndicatorPage,
    summary="Search stored indicators",
)
def list_indicators(
    service: IntelServiceDep,
    session: DbSession,
    indicator_type: Annotated[IndicatorType | None, Query(alias="type")] = None,
    classification: Annotated[
        list[Classification] | None,
        Query(
            max_length=len(Classification),
            description="Score band. Repeat it to match several, such as high and critical.",
        ),
    ] = None,
    assessed: Annotated[
        bool | None,
        Query(
            description=(
                "true keeps indicators at least one provider answered for; false keeps those no "
                "provider answered for, whose score of 0 says nothing about them."
            )
        ),
    ] = None,
    q: Annotated[
        str | None, Query(max_length=256, description="Case-insensitive substring of the value.")
    ] = None,
    sort: Annotated[SortOrder, Query()] = "recent",
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> IndicatorPage:
    return service.list_indicators(
        session,
        indicator_type=indicator_type,
        classifications=classification or (),
        assessed=assessed,
        query=q,
        sort=sort,
        limit=limit,
        offset=offset,
    )


@router.get("/stats", response_model=StatsResponse, summary="Counts for the overview dashboard")
def stats(service: IntelServiceDep, session: DbSession) -> StatsResponse:
    return service.stats(session)


@router.get(
    "/overview",
    response_model=OverviewResponse,
    summary="Aggregates for the command-deck dashboard",
)
def overview(service: IntelServiceDep, session: DbSession) -> OverviewResponse:
    """Read-only: figures computed from stored indicators, provider answers and the lookup trail."""
    return service.overview(session)
