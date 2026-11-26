"""Risk scoring methodology ``intel-risk-v1``.

A pure, deterministic function from provider evidence to a 0-100 score. Every point is
attributed to a named factor, the factors always add up to the score, and the result lists what
is *not* known so a number is never presented as more certain than it is.

Principles:

* No single provider dominates. One provider contributes at most ``MAX_PROVIDER_POINTS``, and a
  score that fewer than two sources support is capped at ``SINGLE_SOURCE_CAP`` (never above
  "Medium"). An indicator is never rated High or Critical on one source's word.
* Recent evidence counts more than old evidence (see ``freshness_weight``).
* Corroboration by independent sources is rewarded explicitly, as its own factor.
* "No data" is not "safe": it scores 0 and the uncertainty notes say so.
* Confidence measures the quality and amount of evidence gathered, not the chance of malice.

All arithmetic is integer (thousandths) so results never depend on float rounding.
"""

import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from app.core.timeutil import format_ist

METHODOLOGY = "intel-risk-v1"

MAX_SCORE = 100
MAX_PROVIDER_POINTS = 45
SINGLE_SOURCE_CAP = 60
MALWARE_FAMILY_POINTS_EACH = 5
MALWARE_FAMILY_POINTS_MAX = 10
# Corroboration needs independent sources: two earn the small bonus, three or more the large one.
MIN_CORROBORATING_SOURCES = 2
FULL_CORROBORATING_SOURCES = 3
CORROBORATION_POINTS_TWO = 8
CORROBORATION_POINTS_THREE_PLUS = 16

CONFIDENCE_FRESH_ANSWER = 35
CONFIDENCE_STALE_ANSWER = 15
CONFIDENCE_CORROBORATED = 20
CONFIDENCE_MAX = 90

_THOUSAND = 1_000
_MILLIONTH = 1_000_000
# A source "supports" an indicator when signal x freshness is at least 0.4.
_SUPPORT_THRESHOLD = 400_000

_FRESHNESS_STEPS: tuple[tuple[timedelta, int], ...] = (
    (timedelta(days=7), 1_000),
    (timedelta(days=30), 900),
    (timedelta(days=90), 700),
    (timedelta(days=180), 500),
)
_FRESHNESS_OLDER = 300
_FRESHNESS_UNKNOWN = 600


class Classification(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Inclusive upper bound of each band; the lower bound is the previous band's bound + 1.
_BANDS: tuple[tuple[int, Classification], ...] = (
    (20, Classification.INFORMATIONAL),
    (40, Classification.LOW),
    (60, Classification.MEDIUM),
    (80, Classification.HIGH),
    (100, Classification.CRITICAL),
)

_ACTIONS: dict[Classification, tuple[str, ...]] = {
    Classification.INFORMATIONAL: (
        "No provider reports meaningful malicious activity for this indicator. "
        "No action is needed based on this evidence alone.",
        "If the indicator came from an alert, check your own telemetry before closing it.",
    ),
    Classification.LOW: (
        "Treat this as context, not a finding. Do not act on this indicator alone.",
        "Check whether it appears in your own logs or alerts before deciding anything.",
        "Re-check later; provider reputation changes as new reports arrive.",
    ),
    Classification.MEDIUM: (
        "Investigate: search your own telemetry (DNS, proxy, firewall, EDR) for this indicator.",
        "Review any affected assets before deciding on containment.",
        "Look for independent corroboration before treating it as confirmed malicious.",
    ),
    Classification.HIGH: (
        "Prioritize investigation: search for past and present contact with this indicator.",
        "If you confirm activity, follow your incident process and consider containment "
        "(for example blocking or isolating hosts). That decision is yours; CipherForge never "
        "blocks anything automatically.",
        "Record your findings so they can be reviewed later.",
    ),
    Classification.CRITICAL: (
        "Escalate for immediate analyst review: independent sources corroborate this indicator.",
        "Search for past and present contact with this indicator across all available telemetry.",
        "Containment (for example blocking the indicator or isolating affected hosts) is advised "
        "once activity is confirmed. CipherForge recommends actions but never applies them "
        "automatically.",
    ),
}

# Used instead of the band's advice when no provider answered: a score of zero then says nothing
# about the indicator, and "no action needed" would read as a clean bill of health.
NO_EVIDENCE_ACTIONS: tuple[str, ...] = (
    "No provider answered, so CipherForge has no evidence about this indicator and cannot say "
    "whether it is safe.",
    "Configure a provider or investigate again later, and check your own telemetry in the "
    "meantime.",
)


def classify(score: int) -> Classification:
    if not 0 <= score <= MAX_SCORE:
        raise ValueError(f"score must be between 0 and {MAX_SCORE}, got {score}")
    for upper, classification in _BANDS:
        if score <= upper:
            return classification
    raise AssertionError("unreachable: the last band ends at MAX_SCORE")


def score_range(classification: Classification) -> tuple[int, int]:
    """Inclusive (lowest, highest) score of a band."""
    lower = 0
    for upper, band in _BANDS:
        if band is classification:
            return lower, upper
        lower = upper + 1
    raise ValueError(f"unknown classification: {classification!r}")


def recommended_actions(classification: Classification) -> tuple[str, ...]:
    """Advice for the analyst. CipherForge recommends; it never blocks or changes anything."""
    return _ACTIONS[classification]


def freshness_weight(evidence_at: datetime | None, now: datetime) -> int:
    """How much recent evidence counts, in thousandths (1000 = full weight).

    Evidence dated in the future (clock skew) counts as brand new. Evidence whose date the
    provider did not give gets a middling weight rather than being trusted or discarded.
    """
    if evidence_at is None:
        return _FRESHNESS_UNKNOWN
    age = max(now - evidence_at, timedelta(0))
    for limit, weight in _FRESHNESS_STEPS:
        if age <= limit:
            return weight
    return _FRESHNESS_OLDER


def provider_points(signal: float, weight: int) -> int:
    """Points one provider contributes: ``MAX_PROVIDER_POINTS`` x signal x weight, half up."""
    return (
        MAX_PROVIDER_POINTS * _signal_thousandths(signal) * weight + _MILLIONTH // 2
    ) // _MILLIONTH


class EvidenceState(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    UNAVAILABLE = "unavailable"
    NOT_CONFIGURED = "not_configured"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class ProviderEvidence:
    """What one provider contributes to a score, built from its stored observation."""

    provider: str
    display_name: str
    state: EvidenceState
    signal: float = 0.0
    evidence_at: datetime | None = None
    fetched_at: datetime | None = None
    malware_families: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def answered(self) -> bool:
        return self.state in (EvidenceState.FRESH, EvidenceState.STALE)


@dataclass(frozen=True, slots=True)
class ScoreFactor:
    code: str
    label: str
    points: int
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "label": self.label,
            "points": self.points,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class ScoreResult:
    methodology: str
    score: int
    classification: Classification
    confidence: int
    answered_sources: int
    contributing_sources: int
    supporting_sources: int
    factors: tuple[ScoreFactor, ...]
    uncertainty: tuple[str, ...]
    recommended_actions: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "methodology": self.methodology,
            "score": self.score,
            "classification": self.classification.value,
            "confidence": self.confidence,
            "answered_sources": self.answered_sources,
            "contributing_sources": self.contributing_sources,
            "supporting_sources": self.supporting_sources,
            "factors": [factor.to_dict() for factor in self.factors],
            "uncertainty": list(self.uncertainty),
            "recommended_actions": list(self.recommended_actions),
        }


def score_indicator(evidence: Sequence[ProviderEvidence], *, now: datetime) -> ScoreResult:
    """Score an indicator from per-provider evidence. ``now`` must be timezone-aware."""
    factors: list[ScoreFactor] = []
    answered = [item for item in evidence if item.answered]
    supporting: list[ProviderEvidence] = []
    contributing = 0

    for item in answered:
        signal = _signal_thousandths(item.signal)
        weight = freshness_weight(item.evidence_at, now)
        points = provider_points(item.signal, weight)
        factors.append(
            ScoreFactor(
                code=f"provider:{item.provider}",
                label=f"{item.display_name} evidence",
                points=points,
                detail=_provider_detail(item, signal, weight),
            )
        )
        if points > 0:
            contributing += 1
        if signal * weight >= _SUPPORT_THRESHOLD:
            supporting.append(item)

    bonus = _corroboration_points(len(supporting))
    if bonus:
        factors.append(
            ScoreFactor(
                code="corroboration",
                label="Independent corroboration",
                points=bonus,
                detail=f"{len(supporting)} sources independently support this indicator.",
            )
        )

    families = {name.casefold() for item in supporting for name in item.malware_families}
    family_points = min(MALWARE_FAMILY_POINTS_MAX, MALWARE_FAMILY_POINTS_EACH * len(families))
    if family_points:
        factors.append(
            ScoreFactor(
                code="malware_family",
                label="Malware family association",
                points=family_points,
                detail=(
                    f"Supporting sources name {len(families)} distinct malware "
                    f"{'family' if len(families) == 1 else 'families'}."
                ),
            )
        )

    total = sum(factor.points for factor in factors)
    single_source = len(supporting) < MIN_CORROBORATING_SOURCES
    ceiling = SINGLE_SOURCE_CAP if single_source else MAX_SCORE
    if total > ceiling:
        factors.append(
            ScoreFactor(
                code="single_source_cap" if single_source else "score_cap",
                label="Single-source cap" if single_source else "Maximum score",
                points=ceiling - total,
                detail=(
                    f"Fewer than two sources support this indicator, so the score cannot "
                    f"exceed {ceiling}."
                    if single_source
                    else f"Scores are capped at {ceiling}."
                ),
            )
        )
        total = ceiling

    classification = classify(total)
    actions = recommended_actions(classification) if answered else NO_EVIDENCE_ACTIONS
    return ScoreResult(
        methodology=METHODOLOGY,
        score=total,
        classification=classification,
        confidence=_confidence(answered, len(supporting)),
        answered_sources=len(answered),
        contributing_sources=contributing,
        supporting_sources=len(supporting),
        factors=tuple(factors),
        uncertainty=tuple(_uncertainty(evidence, answered, len(supporting))),
        recommended_actions=actions,
    )


def _signal_thousandths(signal: float) -> int:
    if not math.isfinite(signal):
        return 0
    return round(min(max(signal, 0.0), 1.0) * _THOUSAND)


def _corroboration_points(supporting: int) -> int:
    if supporting >= FULL_CORROBORATING_SOURCES:
        return CORROBORATION_POINTS_THREE_PLUS
    if supporting >= MIN_CORROBORATING_SOURCES:
        return CORROBORATION_POINTS_TWO
    return 0


def _confidence(answered: Sequence[ProviderEvidence], supporting: int) -> int:
    confidence = sum(
        CONFIDENCE_FRESH_ANSWER if item.state is EvidenceState.FRESH else CONFIDENCE_STALE_ANSWER
        for item in answered
    )
    if supporting >= MIN_CORROBORATING_SOURCES:
        confidence += CONFIDENCE_CORROBORATED
    return min(confidence, CONFIDENCE_MAX)


def _provider_detail(item: ProviderEvidence, signal: int, weight: int) -> str:
    if signal == 0:
        return "No malicious signal reported by this provider."
    when = (
        f"latest activity {format_ist(item.evidence_at)}"
        if item.evidence_at
        else "activity date not reported"
    )
    return (
        f"Evidence strength {signal / _THOUSAND:.2f}, recency weight {weight / _THOUSAND:.1f} "
        f"({when}); up to {MAX_PROVIDER_POINTS} points."
    )


def _uncertainty(
    evidence: Sequence[ProviderEvidence], answered: Sequence[ProviderEvidence], supporting: int
) -> list[str]:
    notes = [
        "No internal telemetry was available; this score reflects external provider evidence only."
    ]

    if not answered:
        notes.append("No provider returned evidence for this indicator.")
    elif len(answered) == 1:
        notes.append(
            f"Only {answered[0].display_name} returned an answer, so this result could not be "
            "cross-checked against another source."
        )
    elif supporting == 1:
        notes.append("Only one source supports this score; independent corroboration is missing.")

    for item in evidence:
        if item.state is EvidenceState.NOT_CONFIGURED:
            notes.append(f"{item.display_name} is not configured, so it contributed no evidence.")
        elif item.state is EvidenceState.UNAVAILABLE:
            notes.append(
                f"{item.display_name} could not be queried, so it contributed no evidence."
            )
        elif item.state is EvidenceState.STALE:
            since = f" ({format_ist(item.fetched_at)})" if item.fetched_at else ""
            notes.append(
                f"{item.display_name}'s latest answer{since} is older than its cache window; "
                "investigate again to refresh it."
            )
        if item.answered:
            notes.extend(item.notes)
            if item.signal > 0 and item.evidence_at is None:
                notes.append(
                    f"{item.display_name} did not say when the activity occurred, so its "
                    "evidence is weighted as moderately recent."
                )

    if supporting == 0:
        notes.append(
            "Absence of reports is not proof that an indicator is safe; providers only know "
            "what has been reported to them."
        )
    return notes
