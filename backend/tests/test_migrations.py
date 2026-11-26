"""Alembic wiring.

The SQLite run executes everywhere; the PostgreSQL run needs a real server and
is enabled by setting ``TEST_DATABASE_URL`` (CI provides one).
"""

import os
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.exc import IntegrityError

from app.core.config import Settings
from app.main import create_app
from app.models import Base

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


def _seed_revision_2_rows(connection) -> str:
    """One indicator with one provider observation, written as the 0002 schema stores them."""
    indicator_id = uuid.uuid4().hex
    stamp = "2025-01-01 00:00:00.000000"
    connection.execute(
        text(
            "INSERT INTO threat_sources (name, display_name, created_at) "
            "VALUES ('otx', 'OTX', :stamp)"
        ),
        {"stamp": stamp},
    )
    connection.execute(
        text(
            "INSERT INTO threat_indicators (id, indicator_type, indicator_value, risk_score, "
            "confidence, source_count, tags, status, created_at, updated_at) "
            "VALUES (:id, 'ipv4', '8.8.8.8', 10, 20, 1, '[]', 'active', :stamp, :stamp)"
        ),
        {"id": indicator_id, "stamp": stamp},
    )
    connection.execute(
        text(
            "INSERT INTO threat_observations (id, indicator_id, source_id, status, signal, "
            "fetched_at, summary, tags) "
            "VALUES (:id, :indicator, 1, 'ok', 0.5, :stamp, '{}', '[]')"
        ),
        {"id": uuid.uuid4().hex, "indicator": indicator_id, "stamp": stamp},
    )
    return indicator_id


def _count(connection, table: str) -> int:
    return connection.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one()  # noqa: S608


def _insert_hash_indicator(connection, kind: str) -> None:
    connection.execute(
        text(
            "INSERT INTO threat_indicators (id, indicator_type, indicator_value, risk_score, "
            "confidence, source_count, tags, status, created_at, updated_at) "
            "VALUES (:id, :kind, :value, 0, 0, 0, '[]', 'stale', "
            "'2025-01-01 00:00:00.000000', '2025-01-01 00:00:00.000000')"
        ),
        {"id": uuid.uuid4().hex, "kind": kind, "value": "ab" * 16},
    )


def test_hash_migration_keeps_existing_rows_and_widens_the_type_check(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite+pysqlite:///{(tmp_path / 'hashes.db').as_posix()}")
    with engine.begin() as connection:
        command.upgrade(_alembic_config(connection), "0002_threat_intel")
        _seed_revision_2_rows(connection)

    with pytest.raises(IntegrityError), engine.begin() as connection:
        _insert_hash_indicator(connection, "md5")

    with engine.begin() as connection:
        command.upgrade(_alembic_config(connection), "0003_hash_indicators")

    with engine.begin() as connection:
        assert _count(connection, "threat_indicators") == 1
        assert _count(connection, "threat_observations") == 1
        for kind in ("md5", "sha1"):
            _insert_hash_indicator(connection, kind)
    with pytest.raises(IntegrityError), engine.begin() as connection:
        _insert_hash_indicator(connection, "sha512")


def test_hash_migration_downgrade_refuses_to_drop_stored_hashes(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite+pysqlite:///{(tmp_path / 'downgrade.db').as_posix()}")
    with engine.begin() as connection:
        command.upgrade(_alembic_config(connection), "0003_hash_indicators")
        _seed_revision_2_rows(connection)
        _insert_hash_indicator(connection, "md5")

    with pytest.raises(RuntimeError, match="MD5 or SHA-1"), engine.begin() as connection:
        command.downgrade(_alembic_config(connection), "0002_threat_intel")

    with engine.begin() as connection:
        assert _count(connection, "threat_indicators") == 2
        connection.execute(text("DELETE FROM threat_indicators WHERE indicator_type = 'md5'"))
        command.downgrade(_alembic_config(connection), "0002_threat_intel")

    with engine.begin() as connection:
        assert _count(connection, "threat_indicators") == 1
        assert _count(connection, "threat_observations") == 1
        with pytest.raises(IntegrityError):
            _insert_hash_indicator(connection, "md5")


def test_hash_migration_will_not_rebuild_a_table_while_foreign_keys_are_enforced(
    tmp_path: Path,
) -> None:
    # Rebuilding threat_indicators drops the table, and with enforcement on SQLite would delete
    # every provider observation through the ON DELETE CASCADE.
    engine = create_engine(f"sqlite+pysqlite:///{(tmp_path / 'fk.db').as_posix()}")
    with engine.begin() as connection:
        command.upgrade(_alembic_config(connection), "0002_threat_intel")
        _seed_revision_2_rows(connection)

    strict = create_engine(f"sqlite+pysqlite:///{(tmp_path / 'fk.db').as_posix()}")
    event.listen(strict, "connect", lambda dbapi, _: dbapi.execute("PRAGMA foreign_keys=ON"))
    with pytest.raises(RuntimeError, match="foreign key enforcement"), strict.begin() as connection:
        command.upgrade(_alembic_config(connection), "0003_hash_indicators")

    with engine.begin() as connection:
        assert _count(connection, "threat_indicators") == 1
        assert _count(connection, "threat_observations") == 1
        revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        assert revision == "0002_threat_intel"


STAMP = "2025-01-01 00:00:00.000000"
LATER = "2025-01-01 00:05:00.000000"
NEW_TABLES = {
    "capture_sessions",
    "network_flows",
    "network_alerts",
    "encrypted_files",
    "file_shares",
}


def _sqlite_engine(path: Path, *, enforce_foreign_keys: bool = False):
    engine = create_engine(f"sqlite+pysqlite:///{path.as_posix()}")
    if enforce_foreign_keys:
        event.listen(engine, "connect", lambda dbapi, _: dbapi.execute("PRAGMA foreign_keys=ON"))
    return engine


def _migrate(engine, revision: str, *, down: bool = False) -> None:
    with engine.begin() as connection:
        (command.downgrade if down else command.upgrade)(_alembic_config(connection), revision)


def test_migrated_schema_matches_the_models(tmp_path: Path) -> None:
    engine = _sqlite_engine(tmp_path / "drift.db")
    _migrate(engine, "head")

    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        differences = compare_metadata(context, Base.metadata)

    assert differences == []


def test_network_and_file_migrations_leave_existing_data_alone(tmp_path: Path) -> None:
    engine = _sqlite_engine(tmp_path / "keep.db")
    _migrate(engine, "0003_hash_indicators")
    with engine.begin() as connection:
        _seed_revision_2_rows(connection)
        connection.execute(
            text(
                "INSERT INTO audit_logs (timestamp, actor, action, result) "
                "VALUES (:stamp, 'analyst', 'IOC_LOOKUP', 'success')"
            ),
            {"stamp": STAMP},
        )

    def existing_rows() -> list[int]:
        with engine.begin() as connection:
            return [
                _count(connection, table)
                for table in ("threat_indicators", "threat_observations", "audit_logs")
            ]

    _migrate(engine, "head")
    assert existing_rows() == [1, 1, 1]
    with engine.begin() as connection:
        assert set(inspect(connection).get_table_names()) >= NEW_TABLES
        assert [_count(connection, table) for table in sorted(NEW_TABLES)] == [0] * len(NEW_TABLES)

    _migrate(engine, "0003_hash_indicators", down=True)
    assert existing_rows() == [1, 1, 1]
    with engine.begin() as connection:
        assert NEW_TABLES.isdisjoint(inspect(connection).get_table_names())

    _migrate(engine, "head")
    assert existing_rows() == [1, 1, 1]


@pytest.fixture(scope="module")
def strict_engine(tmp_path_factory: pytest.TempPathFactory):
    """A migrated SQLite database that enforces foreign keys, as the application does."""
    path = tmp_path_factory.mktemp("schema") / "schema.db"
    _migrate(_sqlite_engine(path), "head")
    engine = _sqlite_engine(path, enforce_foreign_keys=True)
    yield engine
    engine.dispose()


@pytest.fixture
def connection(strict_engine):
    """A connection whose writes are rolled back, so each test starts from an empty database."""
    with strict_engine.connect() as conn:
        transaction = conn.begin()
        yield conn
        transaction.rollback()


def _insert_session(connection) -> str:
    session_id = uuid.uuid4().hex
    connection.execute(
        text(
            "INSERT INTO capture_sessions (id, owner, source_kind, status, started_at, "
            "packets_total, bytes_total, flows_total, alerts_total, packets_dropped, stats) "
            "VALUES (:id, 'analyst', 'pcap', 'completed', :stamp, 0, 0, 0, 0, 0, '{}')"
        ),
        {"id": session_id, "stamp": STAMP},
    )
    return session_id


def _insert_flow(connection, session_id: str, **overrides) -> None:
    values = {
        "session": session_id,
        "src_port": 40000,
        "dst_port": 443,
        "first": STAMP,
        "last": LATER,
        "packets_out": 1,
        "reason": "ended",
        **overrides,
    }
    connection.execute(
        text(
            "INSERT INTO network_flows (session_id, protocol, src_ip, src_port, dst_ip, dst_port, "
            "first_seen, last_seen, packets_out, packets_in, bytes_out, bytes_in, close_reason) "
            "VALUES (:session, 'tcp', '10.0.0.1', :src_port, '10.0.0.2', :dst_port, :first, "
            ":last, :packets_out, 0, 0, 0, :reason)"
        ),
        values,
    )


def _insert_alert(connection, session_id: str, **overrides) -> None:
    values = {
        "id": uuid.uuid4().hex,
        "session": session_id,
        "severity": "high",
        "observed": 30.0,
        "threshold": 20.0,
        "window": 60,
        "dst_port": 22,
        "first": STAMP,
        "last": LATER,
        **overrides,
    }
    connection.execute(
        text(
            "INSERT INTO network_alerts (id, session_id, rule_id, rule_name, severity, "
            "explanation, observed_value, threshold, window_seconds, dst_port, first_observed, "
            "last_observed, created_at, evidence, enrichment) "
            "VALUES (:id, :session, 'NET-001', 'port_scan', :severity, 'x', :observed, "
            ":threshold, :window, :dst_port, :first, :last, :first, '{}', '{}')"
        ),
        values,
    )


def test_valid_network_rows_are_accepted_and_removed_with_their_session(connection) -> None:
    session_id = _insert_session(connection)
    _insert_flow(connection, session_id)
    _insert_flow(connection, session_id, src_port=None, dst_port=None)
    _insert_alert(connection, session_id)
    _insert_alert(connection, session_id, window=None, dst_port=None)
    assert _count(connection, "network_flows") == 2
    assert _count(connection, "network_alerts") == 2

    connection.execute(text("DELETE FROM capture_sessions WHERE id = :id"), {"id": session_id})

    assert _count(connection, "network_flows") == 0
    assert _count(connection, "network_alerts") == 0


@pytest.mark.parametrize(
    "overrides",
    [
        {"dst_port": 65536},
        {"src_port": -1},
        {"packets_out": -1},
        {"reason": "vanished"},
        {"first": LATER, "last": STAMP},
    ],
)
def test_flow_constraints_reject_impossible_rows(connection, overrides: dict) -> None:
    session_id = _insert_session(connection)

    with pytest.raises(IntegrityError):
        _insert_flow(connection, session_id, **overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        {"severity": "urgent"},
        {"observed": -1.0},
        {"threshold": -1.0},
        {"window": 0},
        {"dst_port": 70000},
        {"first": LATER, "last": STAMP},
    ],
)
def test_alert_constraints_reject_impossible_rows(connection, overrides: dict) -> None:
    session_id = _insert_session(connection)

    with pytest.raises(IntegrityError):
        _insert_alert(connection, session_id, **overrides)


def test_a_flow_cannot_reference_a_missing_session(connection) -> None:
    with pytest.raises(IntegrityError):
        _insert_flow(connection, uuid.uuid4().hex)


@pytest.mark.parametrize(
    "overrides",
    [
        {"status": "paused"},
        {"source_kind": "radio"},
        {"packets_total": -1},
        {"ended_at": "2024-12-31 00:00:00.000000"},
    ],
)
def test_session_constraints_reject_impossible_rows(connection, overrides: dict) -> None:
    values = {"status": "completed", "source_kind": "pcap", "packets_total": 0, "ended_at": None}
    values.update(overrides)

    with pytest.raises(IntegrityError):
        connection.execute(
            text(
                "INSERT INTO capture_sessions (id, owner, source_kind, status, started_at, "
                "ended_at, packets_total, bytes_total, flows_total, alerts_total, "
                "packets_dropped, stats) VALUES (:id, 'analyst', :source_kind, :status, :stamp, "
                ":ended_at, :packets_total, 0, 0, 0, 0, '{}')"
            ),
            {"id": uuid.uuid4().hex, "stamp": STAMP, **values},
        )


def _insert_file(connection, **overrides) -> str:
    values = {
        "id": uuid.uuid4().hex,
        "storage": uuid.uuid4().hex,
        "status": "active",
        "algorithm": "AES-256-GCM",
        "size": 10,
        **overrides,
    }
    connection.execute(
        text(
            "INSERT INTO encrypted_files (id, owner, status, storage_name, size_bytes, algorithm, "
            "nonce, wrapped_dek, key_id, name_nonce, name_ciphertext, created_at) "
            "VALUES (:id, 'analyst', :status, :storage, :size, :algorithm, :blob12, :blob, "
            "'key', :blob12, :blob, :stamp)"
        ),
        {**values, "blob12": b"\x00" * 12, "blob": b"\x01" * 48, "stamp": STAMP},
    )
    return values["id"]


def _insert_share(connection, file_id: str, **overrides) -> None:
    values = {
        "id": uuid.uuid4().hex,
        "file": file_id,
        "token": uuid.uuid4().hex * 2,
        "created": STAMP,
        "expires": LATER,
        "max": 3,
        "count": 0,
        "kdf": None,
        "salt": None,
        "time": None,
        "memory": None,
        "lanes": None,
        "wrapped": None,
        **overrides,
    }
    connection.execute(
        text(
            "INSERT INTO file_shares (id, file_id, token_hash, created_at, expires_at, "
            "max_downloads, download_count, kdf_algorithm, kdf_salt, kdf_time_cost, "
            "kdf_memory_kib, kdf_parallelism, password_wrapped_dek) "
            "VALUES (:id, :file, :token, :created, :expires, :max, :count, :kdf, :salt, :time, "
            ":memory, :lanes, :wrapped)"
        ),
        values,
    )


PASSWORD_SHARE = {
    "kdf": "argon2id",
    "salt": b"\x02" * 16,
    "time": 3,
    "memory": 65536,
    "lanes": 1,
    "wrapped": b"\x03" * 60,
}


def test_valid_file_rows_are_accepted_and_removed_with_their_file(connection) -> None:
    file_id = _insert_file(connection)
    _insert_share(connection, file_id)
    _insert_share(connection, file_id, **PASSWORD_SHARE)
    assert _count(connection, "file_shares") == 2

    connection.execute(text("DELETE FROM encrypted_files WHERE id = :id"), {"id": file_id})

    assert _count(connection, "file_shares") == 0


@pytest.mark.parametrize(
    "overrides",
    [
        {"status": "deleted"},
        {"algorithm": "AES-128-CBC"},
        {"size": -1},
    ],
)
def test_file_constraints_reject_impossible_rows(connection, overrides: dict) -> None:
    with pytest.raises(IntegrityError):
        _insert_file(connection, **overrides)


def test_two_files_cannot_share_a_storage_name(connection) -> None:
    _insert_file(connection, storage="same-blob")

    with pytest.raises(IntegrityError):
        _insert_file(connection, storage="same-blob")


@pytest.mark.parametrize(
    "overrides",
    [
        {"expires": STAMP},
        {"expires": "2024-12-31 00:00:00.000000"},
        {"max": 0},
        {"count": 4},
        {"count": -1},
        # A password share needs every key-derivation column; a half-filled one is refused.
        {"kdf": "argon2id"},
        {**PASSWORD_SHARE, "wrapped": None},
        {**PASSWORD_SHARE, "kdf": "scrypt"},
        {"salt": b"\x02" * 16},
    ],
)
def test_share_constraints_reject_impossible_rows(connection, overrides: dict) -> None:
    file_id = _insert_file(connection)

    with pytest.raises(IntegrityError):
        _insert_share(connection, file_id, **overrides)


def test_two_shares_cannot_have_the_same_token_hash(connection) -> None:
    file_id = _insert_file(connection)
    _insert_share(connection, file_id, token="a" * 64)

    with pytest.raises(IntegrityError):
        _insert_share(connection, file_id, token="a" * 64)


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
