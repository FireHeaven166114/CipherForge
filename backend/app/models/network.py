"""Network-monitoring tables.

* ``capture_sessions`` - one live capture, or one analysed capture file.
* ``network_flows``    - the conversations seen during a session.
* ``network_alerts``   - detection-rule findings, each with the evidence behind it.

Only packet metadata is stored: addresses, ports, protocol, sizes, timestamps and TCP flags.
Packet payloads are never written to these tables.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.enums import AlertSeverity, CaptureSource, CaptureStatus, FlowCloseReason
from app.models.types import JSONType, UTCDateTime, in_list, utcnow

# SQLite only auto-increments a column declared INTEGER PRIMARY KEY, so the 64-bit key
# degrades to INTEGER there (which is 64-bit in SQLite anyway).
_BIG_ID = BigInteger().with_variant(Integer, "sqlite")


class CaptureSession(Base):
    __tablename__ = "capture_sessions"
    __table_args__ = (
        CheckConstraint(in_list("source_kind", CaptureSource), name="source_kind"),
        CheckConstraint(in_list("status", CaptureStatus), name="status"),
        CheckConstraint("packets_total >= 0", name="packets_total_non_negative"),
        CheckConstraint("bytes_total >= 0", name="bytes_total_non_negative"),
        CheckConstraint("flows_total >= 0", name="flows_total_non_negative"),
        CheckConstraint("alerts_total >= 0", name="alerts_total_non_negative"),
        CheckConstraint("packets_dropped >= 0", name="packets_dropped_non_negative"),
        CheckConstraint("ended_at IS NULL OR ended_at >= started_at", name="ended_after_started"),
        Index("ix_capture_sessions_owner_started", "owner", "started_at"),
        Index("ix_capture_sessions_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # The authenticated principal's subject; sessions are only visible to their owner.
    owner: Mapped[str] = mapped_column(String(256), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(8), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    # Live captures: the operator-visible interface name. Capture files: a sanitized display
    # name; the uploaded path is never kept.
    interface: Mapped[str | None] = mapped_column(String(256), nullable=True)
    source_label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    packets_total: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    bytes_total: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    flows_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    alerts_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Packets discarded because the analysis buffer was full (live capture only).
    packets_dropped: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    # A short machine-readable failure code (never a stack trace or a path).
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Protocol distribution, top talkers, malformed counts, enrichment summary.
    stats: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)


class NetworkFlow(Base):
    """One bidirectional conversation. ``src`` is the side that sent the first packet."""

    __tablename__ = "network_flows"
    __table_args__ = (
        CheckConstraint(in_list("close_reason", FlowCloseReason), name="close_reason"),
        CheckConstraint(
            "src_port IS NULL OR (src_port >= 0 AND src_port <= 65535)", name="src_port"
        ),
        CheckConstraint(
            "dst_port IS NULL OR (dst_port >= 0 AND dst_port <= 65535)", name="dst_port"
        ),
        CheckConstraint(
            "packets_out >= 0 AND packets_in >= 0 AND bytes_out >= 0 AND bytes_in >= 0",
            name="counters_non_negative",
        ),
        CheckConstraint("last_seen >= first_seen", name="last_after_first"),
        Index("ix_network_flows_session_first_seen", "session_id", "first_seen"),
        Index("ix_network_flows_last_seen", "last_seen"),
    )

    id: Mapped[int] = mapped_column(_BIG_ID, primary_key=True, autoincrement=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("capture_sessions.id", ondelete="CASCADE"), nullable=False
    )
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    packets_out: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    packets_in: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    bytes_out: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    bytes_in: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    # TCP flag bits OR-ed over every packet of the flow (null for other protocols).
    tcp_flags: Mapped[int | None] = mapped_column(Integer, nullable=True)
    close_reason: Mapped[str] = mapped_column(String(16), nullable=False)


class NetworkAlert(Base):
    __tablename__ = "network_alerts"
    __table_args__ = (
        CheckConstraint(in_list("severity", AlertSeverity), name="severity"),
        CheckConstraint("observed_value >= 0", name="observed_non_negative"),
        CheckConstraint("threshold >= 0", name="threshold_non_negative"),
        CheckConstraint("window_seconds IS NULL OR window_seconds > 0", name="window_positive"),
        CheckConstraint("last_observed >= first_observed", name="last_after_first"),
        CheckConstraint(
            "dst_port IS NULL OR (dst_port >= 0 AND dst_port <= 65535)", name="dst_port"
        ),
        Index("ix_network_alerts_session_created", "session_id", "created_at"),
        Index("ix_network_alerts_src_ip", "src_ip"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("capture_sessions.id", ondelete="CASCADE"), nullable=False
    )
    # Stable rule identifier (NET-001 ...) and its machine name (port_scan ...).
    rule_id: Mapped[str] = mapped_column(String(16), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(48), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    observed_value: Mapped[float] = mapped_column(Float, nullable=False)
    threshold: Mapped[float] = mapped_column(Float, nullable=False)
    # Null for rules that are not evaluated over a time window.
    window_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    first_observed: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_observed: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    # The measurements behind the alert (sample ports, top destinations, ...).
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    # External-intelligence context, filled in asynchronously; empty until requested.
    enrichment: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
