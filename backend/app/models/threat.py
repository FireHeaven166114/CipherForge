"""Threat-intelligence tables.

* ``threat_indicators``   - one row per normalized indicator (type + canonical value).
* ``threat_observations`` - what one provider said about one indicator at one point in time.
  Many observations reference a single indicator; they are never merged into it, so every
  score can be traced back to the provider evidence behind it.
* ``threat_sources``      - the providers that produced observations.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.enums import IndicatorStatus, IndicatorType, ObservationStatus
from app.models.types import JSONType, UTCDateTime, in_list, utcnow


class ThreatSource(Base):
    __tablename__ = "threat_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    __table_args__ = (
        UniqueConstraint(
            "indicator_type", "indicator_value", name="uq_threat_indicators_type_value"
        ),
        CheckConstraint(in_list("indicator_type", IndicatorType), name="indicator_type"),
        CheckConstraint(in_list("status", IndicatorStatus), name="status"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="risk_score_range"),
        CheckConstraint("confidence >= 0 AND confidence <= 100", name="confidence_range"),
        CheckConstraint("source_count >= 0", name="source_count_non_negative"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    indicator_type: Mapped[str] = mapped_column(String(16), nullable=False)
    # Canonical form produced by app.services.normalization (never the raw user input).
    indicator_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Evidence timestamps reported by providers, not the time CipherForge looked.
    first_seen: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # Providers that currently contribute signal.
    source_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tags: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    # The full score breakdown (factors, uncertainty, recommended actions).
    score_detail: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    scored_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=IndicatorStatus.STALE.value
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow, onupdate=utcnow
    )
    last_checked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class ThreatObservation(Base):
    """One provider answer. Only ``ok`` and ``no_data`` answers are stored.

    Freshness is computed when read (``fetched_at`` plus the provider TTL) so changing a TTL
    takes effect immediately and no row ever needs rewriting.
    """

    __tablename__ = "threat_observations"
    __table_args__ = (
        CheckConstraint(in_list("status", ObservationStatus), name="status"),
        CheckConstraint("signal >= 0 AND signal <= 1", name="signal_range"),
        Index("ix_threat_observations_lookup", "indicator_id", "source_id", "fetched_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    indicator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("threat_indicators.id", ondelete="CASCADE"), nullable=False
    )
    source_id: Mapped[int] = mapped_column(
        ForeignKey("threat_sources.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    # Provider-normalized strength of the evidence, 0..1. Not a probability of malice.
    signal: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    # When the provider says the activity happened (latest / earliest), if it says so.
    evidence_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    first_evidence_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # A whitelisted, length-limited extract of the provider response; never the raw payload.
    summary: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    tags: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
