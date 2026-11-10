"""Liveness and readiness probes (unauthenticated, no sensitive data)."""

from fastapi import APIRouter, Request, Response, status

from app.api.deps import SettingsDep
from app.database.session import check_database
from app.schemas.health import HealthResponse, ReadinessResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse, summary="Liveness probe")
def health(settings: SettingsDep) -> HealthResponse:
    """The process is up. Does not touch any dependency."""
    return HealthResponse(status="ok", service=settings.app_name, version=settings.app_version)


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    responses={503: {"model": ReadinessResponse}},
    summary="Readiness probe",
)
def ready(request: Request, response: Response) -> ReadinessResponse:
    """The service can reach the database. Returns 503 otherwise, without details."""
    database_ok = check_database(request.app.state.engine)
    if not database_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(
        status="ready" if database_ok else "not_ready",
        checks={"database": "ok" if database_ok else "unavailable"},
    )
