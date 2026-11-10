"""Authentication and role-based authorization.

Two modes, selected by ``AUTH_MODE``:

* ``entra`` - validate a Microsoft Entra ID (v2.0) access token and read the
  caller's roles from its ``roles`` claim.
* ``dev``   - no sign-in; every request is a fixed local principal. Settings
  validation refuses to start the API in this mode when ``ENVIRONMENT=production``.

Authorization is deny-by-default: protected routes declare the roles that may
call them with :func:`require_roles`.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any, Literal

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import ConfigurationError, Settings
from app.security.roles import Role

logger = logging.getLogger("cipherforge.auth")

MAX_TOKEN_LENGTH = 8192
# Only asymmetric RS256 is accepted. Never accept "none" or symmetric algorithms:
# that is what blocks algorithm-confusion attacks.
ALLOWED_ALGORITHMS = ("RS256",)
REQUIRED_CLAIMS = ("exp", "iss", "aud", "sub")

KeyResolver = Callable[[str], Any]


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    name: str | None
    roles: frozenset[Role]
    auth_method: Literal["dev", "entra"]


class TokenValidationError(Exception):
    """The presented token is not acceptable.

    ``reason`` is a coarse, safe category suitable for logs. It is never
    returned to the caller.
    """

    def __init__(self, reason: str, *, service_unavailable: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.service_unavailable = service_unavailable


class EntraTokenValidator:
    def __init__(
        self,
        *,
        tenant_id: str,
        issuer: str,
        audience: str,
        key_resolver: KeyResolver,
        leeway_seconds: int = 60,
    ) -> None:
        self._tenant_id = tenant_id.lower()
        self._issuer = issuer
        self._audience = audience
        self._key_resolver = key_resolver
        self._leeway_seconds = leeway_seconds

    @classmethod
    def from_settings(cls, settings: Settings) -> "EntraTokenValidator":
        jwks_client = jwt.PyJWKClient(
            settings.entra_jwks_url, cache_jwk_set=True, lifespan=3600, timeout=5
        )

        def resolve_key(token: str) -> Any:
            return jwks_client.get_signing_key_from_jwt(token).key

        audience = settings.entra_expected_audience
        if audience is None or settings.entra_tenant_id is None:
            raise ConfigurationError("Entra authentication requires a tenant and a client ID.")
        return cls(
            tenant_id=settings.entra_tenant_id,
            issuer=settings.entra_issuer,
            audience=audience,
            key_resolver=resolve_key,
        )

    def validate(self, token: str) -> Principal:
        if len(token) > MAX_TOKEN_LENGTH:
            raise TokenValidationError("token_too_large")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise TokenValidationError("malformed") from None
        if header.get("alg") not in ALLOWED_ALGORITHMS:
            raise TokenValidationError("disallowed_algorithm")

        try:
            key = self._key_resolver(token)
        except jwt.PyJWKClientConnectionError:
            raise TokenValidationError(
                "key_service_unavailable", service_unavailable=True
            ) from None
        except jwt.PyJWKClientError:
            raise TokenValidationError("unknown_signing_key") from None

        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=list(ALLOWED_ALGORITHMS),
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway_seconds,
                options={"require": list(REQUIRED_CLAIMS)},
            )
        except jwt.ExpiredSignatureError:
            raise TokenValidationError("expired") from None
        except jwt.ImmatureSignatureError:
            raise TokenValidationError("not_yet_valid") from None
        except jwt.InvalidAudienceError:
            raise TokenValidationError("wrong_audience") from None
        except jwt.InvalidIssuerError:
            raise TokenValidationError("wrong_issuer") from None
        except jwt.InvalidSignatureError:
            raise TokenValidationError("bad_signature") from None
        except jwt.MissingRequiredClaimError:
            raise TokenValidationError("missing_claim") from None
        except jwt.PyJWTError:
            raise TokenValidationError("invalid") from None

        tenant = claims.get("tid")
        if not isinstance(tenant, str) or tenant.lower() != self._tenant_id:
            raise TokenValidationError("wrong_tenant")

        return Principal(
            subject=str(claims.get("oid") or claims["sub"]),
            name=_optional_str(claims.get("name") or claims.get("preferred_username")),
            roles=_extract_roles(claims.get("roles")),
            auth_method="entra",
        )


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _extract_roles(raw: Any) -> frozenset[Role]:
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return frozenset()
    parsed = (Role.parse(item) for item in raw if isinstance(item, str))
    return frozenset(role for role in parsed if role is not None)


def dev_principal(settings: Settings) -> Principal:
    return Principal(
        subject="dev-user",
        name="Local Developer",
        roles=frozenset(settings.dev_auth_roles),
        auth_method="dev",
    )


_bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="EntraBearer",
    description="Microsoft Entra ID access token (v2.0).",
)


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
) -> Principal:
    settings: Settings = request.app.state.settings
    if settings.auth_mode == "dev":
        return dev_principal(settings)

    if credentials is None or not credentials.credentials:
        logger.warning(
            "authentication_failed",
            extra={"reason": "missing_credentials", "path": request.url.path},
        )
        raise _unauthorized("Authentication required.")

    validator: EntraTokenValidator = request.app.state.token_validator
    try:
        return validator.validate(credentials.credentials)
    except TokenValidationError as exc:
        logger.warning(
            "authentication_failed", extra={"reason": exc.reason, "path": request.url.path}
        )
        if exc.service_unavailable:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unavailable.",
            ) from None
        raise _unauthorized("Invalid or expired token.") from None


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


def require_roles(*allowed: Role) -> Callable[..., Principal]:
    """Dependency factory: the caller must hold at least one of ``allowed``."""
    allowed_roles = frozenset(allowed)

    def dependency(principal: CurrentPrincipal, request: Request) -> Principal:
        if not principal.roles & allowed_roles:
            logger.warning(
                "authorization_denied",
                extra={
                    "subject": principal.subject,
                    "path": request.url.path,
                    "required_roles": sorted(role.value for role in allowed_roles),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions."
            )
        return principal

    return dependency
