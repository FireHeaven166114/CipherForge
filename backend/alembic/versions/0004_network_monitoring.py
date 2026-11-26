"""Network monitoring: capture sessions, flows and alerts.

Adds three new tables and touches nothing that already exists, so the upgrade cannot affect
stored threat-intelligence or audit data. Flows and alerts reference their session with
``ON DELETE CASCADE``: deleting a session removes the data that only made sense inside it.

Downgrading drops the three tables and the monitoring data in them.

Revision ID: 0004_network_monitoring
Revises: 0003_hash_indicators
Create Date: 2025-01-04 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_network_monitoring"
down_revision: str | None = "0003_hash_indicators"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
BIG_ID_TYPE = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def _timestamp() -> sa.DateTime:
    return sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "capture_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner", sa.String(length=256), nullable=False),
        sa.Column("source_kind", sa.String(length=8), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("interface", sa.String(length=256), nullable=True),
        sa.Column("source_label", sa.String(length=128), nullable=True),
        sa.Column("started_at", _timestamp(), nullable=False),
        sa.Column("ended_at", _timestamp(), nullable=True),
        sa.Column("packets_total", sa.BigInteger(), nullable=False),
        sa.Column("bytes_total", sa.BigInteger(), nullable=False),
        sa.Column("flows_total", sa.Integer(), nullable=False),
        sa.Column("alerts_total", sa.Integer(), nullable=False),
        sa.Column("packets_dropped", sa.BigInteger(), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("stats", JSON_TYPE, nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_capture_sessions")),
        sa.CheckConstraint(
            "source_kind IN ('live', 'pcap')", name=op.f("ck_capture_sessions_source_kind")
        ),
        sa.CheckConstraint(
            "status IN ('starting', 'running', 'stopping', 'stopped', 'completed', 'failed', "
            "'permission_denied')",
            name=op.f("ck_capture_sessions_status"),
        ),
        sa.CheckConstraint(
            "packets_total >= 0", name=op.f("ck_capture_sessions_packets_total_non_negative")
        ),
        sa.CheckConstraint(
            "bytes_total >= 0", name=op.f("ck_capture_sessions_bytes_total_non_negative")
        ),
        sa.CheckConstraint(
            "flows_total >= 0", name=op.f("ck_capture_sessions_flows_total_non_negative")
        ),
        sa.CheckConstraint(
            "alerts_total >= 0", name=op.f("ck_capture_sessions_alerts_total_non_negative")
        ),
        sa.CheckConstraint(
            "packets_dropped >= 0", name=op.f("ck_capture_sessions_packets_dropped_non_negative")
        ),
        sa.CheckConstraint(
            "ended_at IS NULL OR ended_at >= started_at",
            name=op.f("ck_capture_sessions_ended_after_started"),
        ),
    )
    op.create_index(
        op.f("ix_capture_sessions_owner_started"), "capture_sessions", ["owner", "started_at"]
    )
    op.create_index(op.f("ix_capture_sessions_status"), "capture_sessions", ["status"])

    op.create_table(
        "network_flows",
        sa.Column("id", BIG_ID_TYPE, autoincrement=True, nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("src_ip", sa.String(length=45), nullable=False),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_ip", sa.String(length=45), nullable=False),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("first_seen", _timestamp(), nullable=False),
        sa.Column("last_seen", _timestamp(), nullable=False),
        sa.Column("packets_out", sa.BigInteger(), nullable=False),
        sa.Column("packets_in", sa.BigInteger(), nullable=False),
        sa.Column("bytes_out", sa.BigInteger(), nullable=False),
        sa.Column("bytes_in", sa.BigInteger(), nullable=False),
        sa.Column("tcp_flags", sa.Integer(), nullable=True),
        sa.Column("close_reason", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_network_flows")),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["capture_sessions.id"],
            name=op.f("fk_network_flows_session_id_capture_sessions"),
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "close_reason IN ('idle', 'evicted', 'closed', 'ended')",
            name=op.f("ck_network_flows_close_reason"),
        ),
        sa.CheckConstraint(
            "src_port IS NULL OR (src_port >= 0 AND src_port <= 65535)",
            name=op.f("ck_network_flows_src_port"),
        ),
        sa.CheckConstraint(
            "dst_port IS NULL OR (dst_port >= 0 AND dst_port <= 65535)",
            name=op.f("ck_network_flows_dst_port"),
        ),
        sa.CheckConstraint(
            "packets_out >= 0 AND packets_in >= 0 AND bytes_out >= 0 AND bytes_in >= 0",
            name=op.f("ck_network_flows_counters_non_negative"),
        ),
        sa.CheckConstraint(
            "last_seen >= first_seen", name=op.f("ck_network_flows_last_after_first")
        ),
    )
    op.create_index(
        op.f("ix_network_flows_session_first_seen"),
        "network_flows",
        ["session_id", "first_seen"],
    )
    op.create_index(op.f("ix_network_flows_last_seen"), "network_flows", ["last_seen"])

    op.create_table(
        "network_alerts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=16), nullable=False),
        sa.Column("rule_name", sa.String(length=48), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("observed_value", sa.Float(), nullable=False),
        sa.Column("threshold", sa.Float(), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=True),
        sa.Column("src_ip", sa.String(length=45), nullable=True),
        sa.Column("dst_ip", sa.String(length=45), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=16), nullable=True),
        sa.Column("first_observed", _timestamp(), nullable=False),
        sa.Column("last_observed", _timestamp(), nullable=False),
        sa.Column("created_at", _timestamp(), nullable=False),
        sa.Column("evidence", JSON_TYPE, nullable=False),
        sa.Column("enrichment", JSON_TYPE, nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_network_alerts")),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["capture_sessions.id"],
            name=op.f("fk_network_alerts_session_id_capture_sessions"),
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name=op.f("ck_network_alerts_severity"),
        ),
        sa.CheckConstraint(
            "observed_value >= 0", name=op.f("ck_network_alerts_observed_non_negative")
        ),
        sa.CheckConstraint("threshold >= 0", name=op.f("ck_network_alerts_threshold_non_negative")),
        sa.CheckConstraint(
            "window_seconds IS NULL OR window_seconds > 0",
            name=op.f("ck_network_alerts_window_positive"),
        ),
        sa.CheckConstraint(
            "last_observed >= first_observed", name=op.f("ck_network_alerts_last_after_first")
        ),
        sa.CheckConstraint(
            "dst_port IS NULL OR (dst_port >= 0 AND dst_port <= 65535)",
            name=op.f("ck_network_alerts_dst_port"),
        ),
    )
    op.create_index(
        op.f("ix_network_alerts_session_created"),
        "network_alerts",
        ["session_id", "created_at"],
    )
    op.create_index(op.f("ix_network_alerts_src_ip"), "network_alerts", ["src_ip"])


def downgrade() -> None:
    # Dropping a table also drops its indexes; alerts and flows go before their session.
    op.drop_table("network_alerts")
    op.drop_table("network_flows")
    op.drop_table("capture_sessions")
