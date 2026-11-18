"""Request and response models for the threat-intelligence API."""

import uuid
from datetime import date, datetime
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


# As many as one page of the list can hold (its `limit` is capped at 100), so a whole page can be
# selected and deleted in one request.
MAX_DELETE_BATCH = 100


class DeleteIndicatorsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Ids only: there is deliberately no "delete everything matching these filters", so a request
    # can never remove more than the caller named. Repeated ids count once.
    indicator_ids: list[uuid.UUID] = Field(min_length=1, max_length=MAX_DELETE_BATCH)


class DeleteIndicatorsResponse(BaseModel):
    # The indicators this request removed.
    deleted: list[uuid.UUID]
    # Ids that matched nothing: already deleted, or never stored. That is not an error.
    not_found: list[uuid.UUID]
    # Provider answers that were removed along with the deleted indicators.
    observations_removed: int


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
    # True only for the dev-only demo adapters (backend/devtools), which return invented answers.
    simulated: bool = False


class StatsResponse(BaseModel):
    total_indicators: int
    by_classification: dict[str, int]
    by_type: dict[str, int]
    lookups_last_24h: int
    providers: list[ProviderInfo]


class SampleIndicator(BaseModel):
    """A short reference to a stored indicator, used to drill into a dashboard figure."""

    indicator_id: uuid.UUID
    indicator_type: IndicatorType
    indicator_value: str
    risk_score: int
    classification: Classification


class FacetEntry(BaseModel):
    """One value of a provider-reported attribute (country, malware family, ...)."""

    key: str
    # Distinct indicators whose latest provider answer carries this value.
    count: int
    max_risk: int
    samples: list[SampleIndicator]


class OverviewKpis(BaseModel):
    total_indicators: int
    new_indicators_24h: int
    new_indicators_prev_24h: int
    lookups_24h: int
    lookups_prev_24h: int
    # High and Critical, among indicators that at least one provider answered for.
    high_risk_indicators: int
    critical_indicators: int
    # No provider answered: neither "clean" nor "risky".
    not_assessed_indicators: int


class DayPoint(BaseModel):
    day: date
    lookups: int
    high_risk_lookups: int
    new_indicators: int


class ActivityRow(BaseModel):
    day: date
    # Completed lookups per UTC hour of the day (24 entries).
    hours: list[int]


class MatrixRow(BaseModel):
    indicator_type: IndicatorType
    # Keyed by classification value plus "not_assessed".
    counts: dict[str, int]


class OverviewScope(BaseModel):
    """How much data the figures were computed from, so the dashboard can say so honestly."""

    series_days: int
    activity_days: int
    lookups_scanned: int
    lookups_truncated: bool
    answers_scanned: int
    answers_truncated: bool


class OverviewResponse(BaseModel):
    generated_at: datetime
    kpis: OverviewKpis
    # Assessed indicators by band, plus "not_assessed".
    by_classification: dict[str, int]
    by_type: dict[str, int]
    matrix: list[MatrixRow]
    series: list[DayPoint]
    activity: list[ActivityRow]
    # Provider-reported registration country of IP addresses. Not where an attacker is.
    countries: list[FacetEntry]
    malware_families: list[FacetEntry]
    attack_techniques: list[FacetEntry]
    tags: list[FacetEntry]
    top_risk: list[IndicatorOut]
    recent: list[IndicatorOut]
    providers: list[ProviderInfo]
    scope: OverviewScope
