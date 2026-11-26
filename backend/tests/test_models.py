"""Schema behaviour the application relies on: constraints, cascades and the append-only audit log.

Each test runs against a database built by the real migrations: SQLite always, PostgreSQL when
``TEST_DATABASE_URL`` is set.
"""

import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, delete, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError, StatementError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.database.session import build_engine, build_session_factory
from app.models import AuditLog, Base, ThreatIndicator, ThreatObservation, ThreatSource


@pytest.fixture
def session(db_url: str, make_settings: Callable[..., Settings]) -> Iterator[Session]:
    engine = build_engine(make_settings(database_url=db_url))
    with build_session_factory(engine)() as db_session:
        yield db_session
    engine.dispose()


def _indicator(**overrides: Any) -> ThreatIndicator:
    values: dict[str, Any] = {"indicator_type": "ipv4", "indicator_value": "8.8.8.8"}
    values.update(overrides)
    return ThreatIndicator(**values)


def _source(name: str = "abuseipdb") -> ThreatSource:
    return ThreatSource(name=name, display_name=name.title())


def _observation(indicator_id: uuid.UUID, source_id: int, **overrides: Any) -> ThreatObservation:
    values: dict[str, Any] = {
        "indicator_id": indicator_id,
        "source_id": source_id,
        "status": "ok",
        "signal": 0.5,
    }
    values.update(overrides)
    return ThreatObservation(**values)


def test_models_match_the_migrations(db_url: str) -> None:
    engine = create_engine(db_url, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(connection, opts={"compare_type": True})
            differences = compare_metadata(context, Base.metadata)
    finally:
        engine.dispose()

    assert differences == []


def test_indicator_defaults_round_trip(session: Session) -> None:
    session.add(_indicator())
    session.commit()
    session.expire_all()

    stored = session.scalars(select(ThreatIndicator)).one()

    assert isinstance(stored.id, uuid.UUID)
    assert (stored.risk_score, stored.confidence, stored.source_count) == (0, 0, 0)
    assert stored.tags == []
    assert stored.status == "stale"
    assert stored.created_at.utcoffset() == timedelta(0)
    assert stored.first_seen is None


def test_type_and_value_are_unique_together(session: Session) -> None:
    session.add_all([_indicator(), _indicator(indicator_type="domain")])
    session.commit()

    session.add(_indicator())
    with pytest.raises(IntegrityError):
        session.commit()


@pytest.mark.parametrize("hash_type", ["md5", "sha1", "sha256"])
def test_every_supported_hash_type_can_be_stored(session: Session, hash_type: str) -> None:
    session.add(_indicator(indicator_type=hash_type, indicator_value="a" * 32))
    session.commit()

    assert session.scalars(select(ThreatIndicator.indicator_type)).one() == hash_type


@pytest.mark.parametrize(
    "bad_values",
    [
        {"indicator_type": "sha512"},
        {"status": "unknown"},
        {"risk_score": 101},
        {"risk_score": -1},
        {"confidence": 101},
        {"source_count": -1},
    ],
)
def test_indicator_check_constraints(session: Session, bad_values: dict[str, Any]) -> None:
    session.add(_indicator(**bad_values))

    with pytest.raises(IntegrityError):
        session.commit()


@pytest.mark.parametrize("bad_values", [{"status": "error"}, {"signal": 1.5}, {"signal": -0.1}])
def test_observation_check_constraints(session: Session, bad_values: dict[str, Any]) -> None:
    indicator, source = _indicator(), _source()
    session.add_all([indicator, source])
    session.commit()

    session.add(_observation(indicator.id, source.id, **bad_values))
    with pytest.raises(IntegrityError):
        session.commit()


def test_observation_needs_an_existing_indicator_and_source(session: Session) -> None:
    source = _source()
    session.add(source)
    session.commit()

    session.add(_observation(uuid.uuid4(), source.id))
    with pytest.raises(IntegrityError):
        session.commit()


def test_deleting_an_indicator_removes_its_observations(session: Session) -> None:
    indicator, other, source = _indicator(), _indicator(indicator_value="1.1.1.1"), _source()
    session.add_all([indicator, other, source])
    session.commit()
    session.add_all([_observation(indicator.id, source.id), _observation(other.id, source.id)])
    session.commit()

    session.execute(delete(ThreatIndicator).where(ThreatIndicator.id == indicator.id))
    session.commit()

    remaining = session.scalars(select(ThreatObservation)).all()
    assert [row.indicator_id for row in remaining] == [other.id]


@pytest.mark.parametrize(
    ("override", "left_behind"),
    [(None, False), ("OFF", True)],
    ids=["as-configured", "control-with-the-setting-off"],
)
def test_sqlite_overwrites_deleted_rows_instead_of_leaving_them_in_the_file(
    tmp_path: Path, make_settings: Callable[..., Settings], override: str | None, left_behind: bool
) -> None:
    marker = "DELETED-INDICATOR-MARKER-8f3a1c"
    path = tmp_path / "scratch.db"
    engine = build_engine(make_settings(database_url=f"sqlite+pysqlite:///{path.as_posix()}"))
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE scratch (id INTEGER PRIMARY KEY, value TEXT)"))
            connection.execute(text("INSERT INTO scratch (value) VALUES (:v)"), {"v": marker})
        assert marker.encode() in path.read_bytes()

        with engine.begin() as connection:
            if override is not None:  # proves that the check below can fail
                connection.exec_driver_sql(f"PRAGMA secure_delete={override}")
            connection.execute(text("DELETE FROM scratch"))
        with engine.connect() as connection:
            assert connection.execute(text("SELECT count(*) FROM scratch")).scalar() == 0
    finally:
        engine.dispose()

    assert (marker.encode() in path.read_bytes()) is left_behind


def test_a_source_in_use_cannot_be_deleted(session: Session) -> None:
    indicator, source = _indicator(), _source()
    session.add_all([indicator, source])
    session.commit()
    session.add(_observation(indicator.id, source.id))
    session.commit()

    with pytest.raises(IntegrityError):
        session.execute(delete(ThreatSource).where(ThreatSource.id == source.id))


def test_datetimes_come_back_as_utc(session: Session) -> None:
    plus_five = timezone(timedelta(hours=5))
    session.add(_indicator(last_seen=datetime(2025, 1, 1, 12, 0, tzinfo=plus_five)))
    session.commit()
    session.expire_all()

    stored = session.scalars(select(ThreatIndicator)).one()

    assert stored.last_seen == datetime(2025, 1, 1, 7, 0, tzinfo=UTC)
    assert stored.last_seen is not None
    assert stored.last_seen.utcoffset() == timedelta(0)


def test_naive_datetimes_are_rejected(session: Session) -> None:
    session.add(_indicator(last_seen=datetime(2025, 1, 1, 12, 0)))

    with pytest.raises(StatementError, match="naive datetimes"):
        session.commit()


def test_audit_rows_can_be_inserted_but_not_changed(session: Session) -> None:
    session.add(AuditLog(actor="analyst-1", action="IOC_LOOKUP", result="success"))
    session.commit()

    with pytest.raises(DBAPIError, match="append-only"):
        session.execute(update(AuditLog).values(result="tampered"))
    session.rollback()
    with pytest.raises(DBAPIError, match="append-only"):
        session.execute(delete(AuditLog))
    session.rollback()

    rows = session.scalars(select(AuditLog)).all()
    assert [(row.actor, row.result) for row in rows] == [("analyst-1", "success")]
    assert rows[0].timestamp.utcoffset() == timedelta(0)


def test_audit_log_rejects_truncate_on_postgresql(session: Session) -> None:
    if session.get_bind().dialect.name != "postgresql":
        pytest.skip("SQLite has no TRUNCATE statement")
    session.add(AuditLog(actor="analyst-1", action="IOC_LOOKUP", result="success"))
    session.commit()

    with pytest.raises(DBAPIError, match="append-only"):
        session.execute(text("TRUNCATE audit_logs"))
    session.rollback()

    assert session.scalars(select(AuditLog)).one().actor == "analyst-1"
