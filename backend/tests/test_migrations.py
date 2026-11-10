"""Alembic wiring.

The SQLite run executes everywhere; the PostgreSQL run needs a real server and
is enabled by setting ``TEST_DATABASE_URL`` (CI provides one).
"""

import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text

from app.core.config import Settings
from app.main import create_app

BACKEND_DIR = Path(__file__).resolve().parents[1]


def _alembic_config(connection) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.attributes["connection"] = connection
    return config


def _head_revision() -> str:
    head = ScriptDirectory.from_config(Config(str(BACKEND_DIR / "alembic.ini"))).get_current_head()
    assert head is not None
    return head


def test_migrations_have_a_single_linear_head() -> None:
    script = ScriptDirectory.from_config(Config(str(BACKEND_DIR / "alembic.ini")))

    assert len(script.get_heads()) == 1


def test_upgrade_and_downgrade_on_sqlite(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite+pysqlite:///{(tmp_path / 'migrate.db').as_posix()}")

    with engine.begin() as connection:
        command.upgrade(_alembic_config(connection), "head")
        version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    assert version == _head_revision()

    with engine.begin() as connection:
        command.downgrade(_alembic_config(connection), "base")
        assert "alembic_version" in inspect(connection).get_table_names()
        assert connection.execute(text("SELECT COUNT(*) FROM alembic_version")).scalar_one() == 0


@pytest.mark.integration
@pytest.mark.skipif(not os.getenv("TEST_DATABASE_URL"), reason="TEST_DATABASE_URL not set")
def test_upgrade_downgrade_and_readiness_on_postgresql() -> None:
    url = os.environ["TEST_DATABASE_URL"]
    engine = create_engine(url)

    with engine.begin() as connection:
        command.upgrade(_alembic_config(connection), "head")
        command.downgrade(_alembic_config(connection), "base")
        command.upgrade(_alembic_config(connection), "head")
        version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    assert version == _head_revision()

    try:
        settings = Settings(
            _env_file=None, environment="test", auth_mode="dev", log_format="json", database_url=url
        )
        with TestClient(create_app(settings)) as client:
            response = client.get("/ready")
        assert response.status_code == 200
        assert response.json()["checks"] == {"database": "ok"}
    finally:
        # Leave the shared test database empty for whichever suite runs next.
        with engine.begin() as connection:
            command.downgrade(_alembic_config(connection), "base")
        engine.dispose()
