"""Request and response models for the threat-intelligence API."""

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.correlation.scoring import Classification
from app.models.enums import IndicatorStatus, IndicatorType
from app.services.normalization import MAX_INDICATOR_LENGTH

ProviderViewStatus = Literal[
    "ok", "no_data", "not_configured", "unsupported", "rate_limited", "error", "not_queried"
]


class InvestigateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Validated and canonicalised by app.services.normalization, never trusted as typed.
    indicator: str = Field(min_length=1, max_length=MAX_INDICATOR_LENGTH)
    # Ask the providers again even if a cached answer is still fresh (rate-limited server-side).
    refresh: bool = False


class IndicatorOut(BaseModel):
    indicator_id: uuid.UUID
    indicator_type: IndicatorType
    indicator_value: str
    risk_score: int
    classification: Classification
    confidence: int
    first_seen: datetime | None
    last_seen: datetime | None
    source_count: int
    tags: list[str]
    status: IndicatorStatus
    created_at: datetime
    scored_at: datetime | None
    last_checked_at: datetime | None


class ProviderView(BaseModel):
    """One provider's independent answer, shown before any correlation."""

    provider: str
    display_name: str
    status: ProviderViewStatus
    # "fresh" while inside the provider's cache window, "stale" after it, None without data.
    freshness: Literal["fresh", "stale"] | None
    # Strength of this provider's evidence (0..1). Not a probability of malice.
    signal: float | None
    fetched_at: datetime | None
    evidence_at: datetime | None
    first_evidence_at: datetime | None
    cache_expires_at: datetime | None
    # True when the answer was served from storage instead of a new provider call.
    from_cache: bool
    # Whitelisted facts from the provider. Free-text values are community-supplied: render as text.
    summary: dict[str, Any]
    tags: list[str]
    message: str | None


class ScoreFactorOut(BaseModel):
    code: str
    label: str
    points: int
    detail: str


class ScoreOut(BaseModel):
    methodology: str
    score: int
    classification: Classification
    confidence: int
    answered_sources: int
    contributing_sources: int
    supporting_sources: int
    factors: list[ScoreFactorOut]
    uncertainty: list[str]
    recommended_actions: list[str]
    # The score is a snapshot: it is recomputed whenever the indicator is investigated.
    scored_at: datetime | None


class InternalEvidenceOut(BaseModel):
    """Evidence from CipherForge's own telemetry (Sentinel, SOC, Case). None exists yet."""

    available: bool
    message: str


class InvestigationResponse(BaseModel):
    indicator: IndicatorOut
    providers: list[ProviderView]
    score: ScoreOut
    internal_evidence: InternalEvidenceOut


class IndicatorPage(BaseModel):
    items: list[IndicatorOut]
    total: int
    limit: int
    offset: int


class ProviderInfo(BaseModel):
    name: str
    display_name: str
    # Whether an API key is set. The key itself is never returned.
    configured: bool
    supported_types: list[IndicatorType]


class StatsResponse(BaseModel):
    total_indicators: int
    by_classification: dict[str, int]
    by_type: dict[str, int]
    lookups_last_24h: int
    providers: list[ProviderInfo]
