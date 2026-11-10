from fastapi import APIRouter

from app.api.deps import SettingsDep
from app.schemas.identity import MeResponse
from app.security.auth import CurrentPrincipal

router = APIRouter(tags=["identity"])


@router.get("/me", response_model=MeResponse, summary="Current caller identity")
def me(principal: CurrentPrincipal, settings: SettingsDep) -> MeResponse:
    return MeResponse(
        subject=principal.subject,
        name=principal.name,
        roles=sorted(role.value for role in principal.roles),
        auth_mode=settings.auth_mode,
    )
