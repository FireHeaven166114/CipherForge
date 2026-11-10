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

logger = logging.getLogger("cipherforge.app")


def create_app(
    settings: Settings | None = None,
    *,
    token_validator: EntraTokenValidator | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)

    engine = build_engine(settings)
    if token_validator is None and settings.auth_mode == "entra":
        token_validator = EntraTokenValidator.from_settings(settings)

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

    register_exception_handlers(app)

    # Starlette wraps the most recently added middleware outermost.
    app.add_middleware(UnhandledExceptionMiddleware)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST"],
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
