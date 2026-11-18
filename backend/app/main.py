"""FastAPI application factory.

Run with::

    uvicorn app.main:create_app --factory

A factory (rather than a module-level ``app``) keeps importing this module free
of side effects, so tests can build an app with explicit settings.
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.health import router as health_router
from app.api.v1.router import api_router
from app.collectors.registry import build_collectors, build_http_client
from app.core.config import Settings, get_settings
from app.core.errors import register_exception_handlers
from app.core.logging_config import configure_logging
from app.core.middleware import (
    CorrelationIdMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
    UnhandledExceptionMiddleware,
)
from app.database.session import build_engine, build_session_factory
from app.security.auth import EntraTokenValidator
from app.security.rate_limit import SlidingWindowRateLimiter
from app.services.intel_service import IntelService

logger = logging.getLogger("cipherforge.app")


def build_intel_service(settings: Settings) -> IntelService:
    http_client = build_http_client(settings)
    return IntelService(
        build_collectors(settings, http_client),
        http_client=http_client,
        provider_timeout_seconds=settings.provider_timeout_seconds,
    )


def create_app(
    settings: Settings | None = None,
    *,
    token_validator: EntraTokenValidator | None = None,
    intel_service: IntelService | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)

    engine = build_engine(settings)
    if token_validator is None and settings.auth_mode == "entra":
        token_validator = EntraTokenValidator.from_settings(settings)
    if intel_service is None:
        intel_service = build_intel_service(settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        logger.info(
            "startup",
            extra={
                "version": settings.app_version,
                "environment": settings.environment,
                "auth_mode": settings.auth_mode,
            },
        )
        yield
        intel_service.close()
        engine.dispose()
        logger.info("shutdown")

    # Interactive API docs are a development convenience, not a production surface.
    docs_enabled = not settings.is_production
    app = FastAPI(
        title="CipherForge API",
        version=settings.app_version,
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = build_session_factory(engine)
    app.state.token_validator = token_validator
    app.state.intel_service = intel_service
    app.state.rate_limiter = SlidingWindowRateLimiter(settings.investigate_rate_limit_per_minute)

    register_exception_handlers(app)

    # Starlette wraps the most recently added middleware outermost.
    app.add_middleware(UnhandledExceptionMiddleware)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "X-Correlation-ID"],
            expose_headers=["X-Correlation-ID"],
            allow_credentials=False,
        )
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(CorrelationIdMiddleware)

    app.include_router(health_router)
    app.include_router(api_router)
    return app
