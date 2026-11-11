"""Database engine, session factory and connectivity check."""

import logging
from typing import Any

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import Settings

logger = logging.getLogger("cipherforge.database")

CONNECT_TIMEOUT_SECONDS = 5


def _enable_sqlite_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def build_engine(settings: Settings) -> Engine:
    url = make_url(settings.database_url.get_secret_value())
    kwargs: dict[str, Any] = {"pool_pre_ping": True}
    is_sqlite = url.get_backend_name() == "sqlite"
    if is_sqlite:
        # SQLite is supported for unit tests only; PostgreSQL is the real target.
        kwargs["connect_args"] = {"check_same_thread": False}
        if url.database in (None, "", ":memory:"):
            kwargs["poolclass"] = StaticPool
    else:
        # Fail fast so /ready answers quickly when the database is unreachable.
        kwargs["connect_args"] = {"connect_timeout": CONNECT_TIMEOUT_SECONDS}
        kwargs["pool_recycle"] = 1800
    engine = create_engine(url, **kwargs)
    if is_sqlite:
        # SQLite ignores foreign keys unless asked; tests should enforce them like PostgreSQL.
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    return engine


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def check_database(engine: Engine) -> bool:
    """Return True if a trivial query succeeds. Never raises, never exposes details."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        first_line = str(exc).splitlines()[0][:300] if str(exc) else ""
        logger.warning(
            "database_unavailable", extra={"error_type": type(exc).__name__, "error": first_line}
        )
        return False
    return True
