"""Append-oriented audit trail (spec section 19).

Rows are only ever inserted. Database triggers (created by migration ``0002_threat_intel``)
reject UPDATE, DELETE and TRUNCATE, so tampering needs schema-level privileges rather than
just a bug in the application. A database superuser can still drop the triggers: ship the
table to write-once storage if that threat matters (see docs/security.md).
"""

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.types import JSONType, UTCDateTime, utcnow


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_action_timestamp", "action", "timestamp"),)

    # BIGINT on PostgreSQL; SQLite only auto-increments an INTEGER primary key.
    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow, index=True
    )
    # The authenticated principal's stable subject identifier, never a token or secret.
    actor: Mapped[str] = mapped_column(String(256), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    # "<indicator_type>:<canonical value>" for indicator actions; null when none was accepted.
    target: Mapped[str | None] = mapped_column(String(2100), nullable=True)
    result: Mapped[str] = mapped_column(String(32), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
