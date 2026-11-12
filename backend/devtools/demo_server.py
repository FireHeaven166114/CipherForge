"""Demo API: the real application with simulated providers and a seeded two-week history.

Run it from ``backend/``::

    python -m uvicorn devtools.demo_server:create_demo_app --factory --port 8000

Everything is synthetic. The database is a throwaway SQLite file directly inside
``backend/.demo/`` (any other location is refused, so it can never touch a real database), the
providers are simulated and development sign-in is on. The first start seeds about two weeks of
lookups through the real service; a database whose newest lookup is more than a day old is
rebuilt. ``CIPHERFORGE_DEMO_RESET=1`` forces a rebuild and ``CIPHERFORGE_DEMO_DB`` picks another
``.db`` file inside ``backend/.demo/``.
"""

import logging
import os
from datetime import datetime, timedelta
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.main import create_app
from app.models.audit import AuditLog
from app.models.types import utcnow
from app.services.intel_service import IntelService
from devtools.demo_data import DemoClock, build_catalogue, seed_demo, tiers_of
from devtools.simulated_providers import build_simulated_collectors

BACKEND_DIR = Path(__file__).resolve().parents[1]
DEMO_DIR = BACKEND_DIR / ".demo"
DEFAULT_DATABASE_NAME = "demo.db"
STALE_AFTER = timedelta(hours=24)
# High enough that automated browser tests never trip the limiter; the real default is 30.
DEMO_RATE_LIMIT_PER_MINUTE = 600

logger = logging.getLogger("cipherforge.demo")


def demo_database_path() -> Path:
    configured = os.environ.get("CIPHERFORGE_DEMO_DB")
    path = Path(configured).resolve() if configured else DEMO_DIR / DEFAULT_DATABASE_NAME
    if path.parent != DEMO_DIR.resolve() or path.suffix != ".db":
        raise RuntimeError("CIPHERFORGE_DEMO_DB must be a .db file directly inside backend/.demo/")
    return path


def sqlite_url(path: Path) -> str:
    return f"sqlite+pysqlite:///{path.as_posix()}"


def demo_settings(path: Path) -> Settings:
    return Settings(
        _env_file=None,
        environment="development",
        auth_mode="dev",
        dev_auth_roles=os.environ.get("CIPHERFORGE_DEMO_ROLES", "SecurityAnalyst"),
        log_format="console",
        database_url=sqlite_url(path),
        investigate_rate_limit_per_minute=DEMO_RATE_LIMIT_PER_MINUTE,
    )


def _migrate(url: str) -> None:
    """Apply the real migrations, so the demo database has the schema and triggers we ship."""
    engine = create_engine(url, poolclass=NullPool)
    try:
        with engine.begin() as connection:
            config = Config(str(BACKEND_DIR / "alembic.ini"))
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
    finally:
        engine.dispose()


def _latest_lookup(url: str) -> datetime | None:
    engine = create_engine(url, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            return connection.execute(select(func.max(AuditLog.timestamp))).scalar()
    except SQLAlchemyError:
        return None
    finally:
        engine.dispose()


def _remove_database(path: Path) -> None:
    for suffix in ("", "-wal", "-shm", "-journal"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)


def prepare_database(path: Path, *, reset: bool, now: datetime) -> bool:
    """Create or refresh the demo database. Returns True when it needs seeding."""
    url = sqlite_url(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        latest = _latest_lookup(url)
        if reset or latest is None or now - latest > STALE_AFTER:
            _remove_database(path)
    _migrate(url)
    return _latest_lookup(url) is None


def create_demo_app() -> FastAPI:
    path = demo_database_path()
    now = utcnow()
    needs_seed = prepare_database(
        path, reset=os.environ.get("CIPHERFORGE_DEMO_RESET") == "1", now=now
    )

    catalogue = build_catalogue()
    clock = DemoClock()
    collectors, client = build_simulated_collectors(clock, tiers=tiers_of(catalogue))
    service = IntelService(collectors, http_client=client, clock=clock)
    app = create_app(demo_settings(path), intel_service=service)

    logger.warning("demo_mode", extra={"providers": "simulated", "data": "synthetic"})
    if needs_seed:
        summary = seed_demo(service, app.state.session_factory, clock, catalogue=catalogue, now=now)
        logger.info(
            "demo_seeded",
            extra={
                "lookups": summary.lookups,
                "rejected": summary.rejected,
                "indicators": summary.indicators,
            },
        )
    return app
