"""Threat intelligence: sources, indicators, provider observations and the audit log.

``audit_logs`` is append-only. Triggers reject UPDATE, DELETE (and TRUNCATE on PostgreSQL)
so an application bug or injected SQL statement cannot rewrite history. They do not stop
a database superuser, who can drop the trigger.

Revision ID: 0002_threat_intel
Revises: 0001_baseline
Create Date: 2025-01-02 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_threat_intel"
down_revision: str | None = "0001_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
AUDIT_ID_TYPE = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def _timestamp() -> sa.DateTime:
    return sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "threat_sources",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=32), nullable=False),
        sa.Column("display_name", sa.String(length=64), nullable=False),
        sa.Column("created_at", _timestamp(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_sources")),
        sa.UniqueConstraint("name", name=op.f("uq_threat_sources_name")),
    )

    op.create_table(
        "threat_indicators",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("indicator_type", sa.String(length=16), nullable=False),
        sa.Column("indicator_value", sa.String(length=2048), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("first_seen", _timestamp(), nullable=True),
        sa.Column("last_seen", _timestamp(), nullable=True),
        sa.Column("source_count", sa.Integer(), nullable=False),
        sa.Column("tags", JSON_TYPE, nullable=False),
        sa.Column("score_detail", JSON_TYPE, nullable=True),
        sa.Column("scored_at", _timestamp(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", _timestamp(), nullable=False),
        sa.Column("updated_at", _timestamp(), nullable=False),
        sa.Column("last_checked_at", _timestamp(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_indicators")),
        sa.UniqueConstraint(
            "indicator_type", "indicator_value", name=op.f("uq_threat_indicators_type_value")
        ),
        sa.CheckConstraint(
            "indicator_type IN ('ipv4', 'ipv6', 'domain', 'url', 'sha256')",
            name=op.f("ck_threat_indicators_indicator_type"),
        ),
        sa.CheckConstraint(
            "status IN ('active', 'stale')", name=op.f("ck_threat_indicators_status")
        ),
        sa.CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100",
            name=op.f("ck_threat_indicators_risk_score_range"),
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 100",
            name=op.f("ck_threat_indicators_confidence_range"),
        ),
        sa.CheckConstraint(
            "source_count >= 0", name=op.f("ck_threat_indicators_source_count_non_negative")
        ),
    )

    op.create_table(
        "threat_observations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("indicator_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("signal", sa.Float(), nullable=False),
        sa.Column("fetched_at", _timestamp(), nullable=False),
        sa.Column("evidence_at", _timestamp(), nullable=True),
        sa.Column("first_evidence_at", _timestamp(), nullable=True),
        sa.Column("summary", JSON_TYPE, nullable=False),
        sa.Column("tags", JSON_TYPE, nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_observations")),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["threat_indicators.id"],
            name=op.f("fk_threat_observations_indicator_id_threat_indicators"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["threat_sources.id"],
            name=op.f("fk_threat_observations_source_id_threat_sources"),
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "status IN ('ok', 'no_data')", name=op.f("ck_threat_observations_status")
        ),
        sa.CheckConstraint(
            "signal >= 0 AND signal <= 1", name=op.f("ck_threat_observations_signal_range")
        ),
    )
    op.create_index(
        op.f("ix_threat_observations_lookup"),
        "threat_observations",
        ["indicator_id", "source_id", "fetched_at"],
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", AUDIT_ID_TYPE, autoincrement=True, nullable=False),
        sa.Column("timestamp", _timestamp(), nullable=False),
        sa.Column("actor", sa.String(length=256), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=2100), nullable=True),
        sa.Column("result", sa.String(length=32), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.Column("details", JSON_TYPE, nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_logs")),
    )
    op.create_index(op.f("ix_audit_logs_timestamp"), "audit_logs", ["timestamp"])
    op.create_index(op.f("ix_audit_logs_action_timestamp"), "audit_logs", ["action", "timestamp"])
    _create_append_only_triggers()


def downgrade() -> None:
    # Dropping the table also drops its indexes and triggers.
    op.drop_table("audit_logs")
    if op.get_context().dialect.name == "postgresql":
        op.execute("DROP FUNCTION audit_logs_reject_change()")
    op.drop_table("threat_observations")
    op.drop_table("threat_indicators")
    op.drop_table("threat_sources")


def _create_append_only_triggers() -> None:
    dialect = op.get_context().dialect.name
    if dialect == "postgresql":
        op.execute(
            "CREATE FUNCTION audit_logs_reject_change() RETURNS trigger LANGUAGE plpgsql AS "
            "$$ BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END; $$"
        )
        op.execute(
            "CREATE TRIGGER audit_logs_reject_row_change BEFORE UPDATE OR DELETE ON audit_logs "
            "FOR EACH ROW EXECUTE FUNCTION audit_logs_reject_change()"
        )
        op.execute(
            "CREATE TRIGGER audit_logs_reject_truncate BEFORE TRUNCATE ON audit_logs "
            "FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_reject_change()"
        )
    elif dialect == "sqlite":
        for action in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER audit_logs_reject_{action.lower()} BEFORE {action} ON audit_logs "
                "BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END"
            )
    else:
        raise NotImplementedError(f"append-only audit triggers are not defined for {dialect}")
