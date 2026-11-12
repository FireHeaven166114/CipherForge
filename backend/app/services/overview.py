"""Aggregates for the overview dashboard.

Everything here is read-only and computed from stored data: the indicators, the latest answer
each provider gave for each indicator, and the lookup audit trail. Nothing calls a provider.

The attribute breakdowns (countries, malware families, techniques, tags) are computed in Python
from JSON that providers supplied, because JSON querying differs between PostgreSQL and SQLite.
To keep a request cheap they read a bounded number of the most recent answers, and the response
reports when a bound was reached so the dashboard can say so instead of implying completeness.
"""

import re
import uuid
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime, time, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.correlation.scoring import Classification, classify
from app.models.audit import AuditLog
from app.models.enums import IndicatorType, ObservationStatus
from app.models.threat import ThreatIndicator, ThreatObservation
from app.schemas.intel import (
    ActivityRow,
    DayPoint,
    FacetEntry,
    IndicatorOut,
    MatrixRow,
    OverviewKpis,
    OverviewResponse,
    OverviewScope,
    ProviderInfo,
    SampleIndicator,
)
from app.services.audit import IOC_LOOKUP, RESULT_PARTIAL, RESULT_SUCCESS

SERIES_DAYS = 14
ACTIVITY_DAYS = 7
HOURS_PER_DAY = 24
SCAN_LIMIT = 20_000
ANSWER_SCAN_LIMIT = 2_000
COUNTRY_LIMIT = 40
FACET_LIMIT = 10
SAMPLES_PER_FACET = 5
LIST_LIMIT = 8
NOT_ASSESSED = "not_assessed"

_HIGH_RISK = frozenset({Classification.HIGH.value, Classification.CRITICAL.value})
_COUNTRY = re.compile(r"[A-Z]{2}")
_ATTACK_ID = re.compile(r"T\d{4}(?:\.\d{3})?")
_MAX_NAME_LENGTH = 64
_MAX_LIST_ITEMS = 50

IndicatorOutBuilder = Callable[[ThreatIndicator], IndicatorOut]
FacetTable = dict[str, dict[uuid.UUID, SampleIndicator]]


def build_overview(
    session: Session,
    *,
    now: datetime,
    providers: Sequence[ProviderInfo],
    indicator_out: IndicatorOutBuilder,
) -> OverviewResponse:
    today = now.astimezone(UTC).date()
    days = [today - timedelta(days=offset) for offset in range(SERIES_DAYS - 1, -1, -1)]
    since = datetime.combine(days[0], time.min, tzinfo=UTC)

    matrix, by_type = _matrix(session)
    by_classification = {
        key: sum(row.counts[key] for row in matrix)
        for key in (*(member.value for member in Classification), NOT_ASSESSED)
    }

    lookups, lookups_truncated = _lookups(session, since, now)
    created = _created_times(session, since, now)
    last_day = now - timedelta(hours=24)
    previous_day = now - timedelta(hours=48)

    lookups_per_day: Counter[Any] = Counter()
    high_risk_per_day: Counter[Any] = Counter()
    hourly: Counter[tuple[Any, int]] = Counter()
    for at, high_risk in lookups:
        day = at.astimezone(UTC).date()
        lookups_per_day[day] += 1
        hourly[(day, at.astimezone(UTC).hour)] += 1
        if high_risk:
            high_risk_per_day[day] += 1
    new_per_day = Counter(created_at.astimezone(UTC).date() for created_at in created)

    series = [
        DayPoint(
            day=day,
            lookups=lookups_per_day[day],
            high_risk_lookups=high_risk_per_day[day],
            new_indicators=new_per_day[day],
        )
        for day in days
    ]
    activity = [
        ActivityRow(day=day, hours=[hourly[(day, hour)] for hour in range(HOURS_PER_DAY)])
        for day in days[-ACTIVITY_DAYS:]
    ]

    facets, answers_scanned, answers_truncated = _facets(session)

    top_risk = session.scalars(
        select(ThreatIndicator)
        .where(ThreatIndicator.risk_score > 0)
        .order_by(
            ThreatIndicator.risk_score.desc(), ThreatIndicator.updated_at.desc(), ThreatIndicator.id
        )
        .limit(LIST_LIMIT)
    ).all()
    recent = session.scalars(
        select(ThreatIndicator)
        .order_by(ThreatIndicator.updated_at.desc(), ThreatIndicator.id)
        .limit(LIST_LIMIT)
    ).all()

    return OverviewResponse(
        generated_at=now,
        kpis=OverviewKpis(
            total_indicators=sum(by_type.values()),
            new_indicators_24h=sum(1 for created_at in created if created_at >= last_day),
            new_indicators_prev_24h=sum(
                1 for created_at in created if previous_day <= created_at < last_day
            ),
            lookups_24h=sum(1 for at, _ in lookups if at >= last_day),
            lookups_prev_24h=sum(1 for at, _ in lookups if previous_day <= at < last_day),
            high_risk_indicators=by_classification[Classification.HIGH.value]
            + by_classification[Classification.CRITICAL.value],
            critical_indicators=by_classification[Classification.CRITICAL.value],
            not_assessed_indicators=by_classification[NOT_ASSESSED],
        ),
        by_classification=by_classification,
        by_type=by_type,
        matrix=matrix,
        series=series,
        activity=activity,
        countries=_entries(facets["countries"], COUNTRY_LIMIT),
        malware_families=_entries(facets["malware_families"], FACET_LIMIT),
        attack_techniques=_entries(facets["attack_techniques"], FACET_LIMIT),
        tags=_entries(facets["tags"], FACET_LIMIT),
        top_risk=[indicator_out(row) for row in top_risk],
        recent=[indicator_out(row) for row in recent],
        providers=list(providers),
        scope=OverviewScope(
            series_days=SERIES_DAYS,
            activity_days=ACTIVITY_DAYS,
            lookups_scanned=len(lookups),
            lookups_truncated=lookups_truncated,
            answers_scanned=answers_scanned,
            answers_truncated=answers_truncated,
        ),
    )


def _matrix(session: Session) -> tuple[list[MatrixRow], dict[str, int]]:
    """Indicator counts by type and band. "Not assessed" (no provider answered) is its own
    column, never folded into "informational", which would read as a clean bill of health.
    """
    by_type = {member.value: 0 for member in IndicatorType}
    counts = {
        member.value: {
            **{band.value: 0 for band in Classification},
            NOT_ASSESSED: 0,
        }
        for member in IndicatorType
    }
    grouped = (ThreatIndicator.indicator_type, ThreatIndicator.risk_score)
    for indicator_type, risk_score, count in session.execute(
        select(*grouped, func.count()).group_by(*grouped)
    ):
        by_type[indicator_type] += count
        counts[indicator_type][classify(risk_score).value] += count
    # Confidence is built from provider answers, so 0 means no provider ever answered.
    for indicator_type, risk_score, count in session.execute(
        select(*grouped, func.count()).where(ThreatIndicator.confidence == 0).group_by(*grouped)
    ):
        counts[indicator_type][classify(risk_score).value] -= count
        counts[indicator_type][NOT_ASSESSED] += count
    rows = [MatrixRow(indicator_type=IndicatorType(key), counts=counts[key]) for key in counts]
    return rows, by_type


def _lookups(
    session: Session, since: datetime, now: datetime
) -> tuple[list[tuple[datetime, bool]], bool]:
    """Completed lookups (rejected inputs are not lookups), newest first, with a high-risk flag."""
    rows = session.execute(
        select(AuditLog.timestamp, AuditLog.details)
        .where(
            AuditLog.action == IOC_LOOKUP,
            AuditLog.result.in_((RESULT_SUCCESS, RESULT_PARTIAL)),
            AuditLog.timestamp >= since,
            AuditLog.timestamp <= now,
        )
        .order_by(AuditLog.timestamp.desc())
        .limit(SCAN_LIMIT)
    ).all()
    lookups = [
        (timestamp, isinstance(details, dict) and details.get("classification") in _HIGH_RISK)
        for timestamp, details in rows
    ]
    return lookups, len(rows) >= SCAN_LIMIT


def _created_times(session: Session, since: datetime, now: datetime) -> list[datetime]:
    return list(
        session.scalars(
            select(ThreatIndicator.created_at)
            .where(ThreatIndicator.created_at >= since, ThreatIndicator.created_at <= now)
            .order_by(ThreatIndicator.created_at.desc())
            .limit(SCAN_LIMIT)
        )
    )


def _facets(session: Session) -> tuple[dict[str, FacetTable], int, bool]:
    """Countries, malware families, techniques and tags from each provider's latest answer."""
    rows = session.execute(
        select(
            ThreatObservation.indicator_id,
            ThreatObservation.source_id,
            ThreatObservation.summary,
            ThreatObservation.tags,
            ThreatIndicator.indicator_type,
            ThreatIndicator.indicator_value,
            ThreatIndicator.risk_score,
        )
        .join(ThreatIndicator, ThreatIndicator.id == ThreatObservation.indicator_id)
        .where(ThreatObservation.status == ObservationStatus.OK.value)
        .order_by(ThreatObservation.fetched_at.desc(), ThreatObservation.id.desc())
        .limit(ANSWER_SCAN_LIMIT)
    ).all()

    tables: dict[str, FacetTable] = {
        "countries": {},
        "malware_families": {},
        "attack_techniques": {},
        "tags": {},
    }
    seen: set[tuple[uuid.UUID, int]] = set()
    for row in rows:
        # Rows are newest first, so the first answer per indicator and provider is the latest.
        if (row.indicator_id, row.source_id) in seen:
            continue
        seen.add((row.indicator_id, row.source_id))
        sample = SampleIndicator(
            indicator_id=row.indicator_id,
            indicator_type=IndicatorType(row.indicator_type),
            indicator_value=row.indicator_value,
            risk_score=row.risk_score,
            classification=classify(row.risk_score),
        )
        summary = row.summary if isinstance(row.summary, dict) else {}
        country = summary.get("country_code")
        if isinstance(country, str) and _COUNTRY.fullmatch(country):
            _add(tables["countries"], country, sample)
        for family in _strings(summary.get("malware_families")):
            _add(tables["malware_families"], family, sample)
        for technique in _strings(summary.get("attack_ids")):
            if _ATTACK_ID.fullmatch(technique):
                _add(tables["attack_techniques"], technique, sample)
        for tag in _strings(row.tags):
            _add(tables["tags"], tag, sample)
    return tables, len(rows), len(rows) >= ANSWER_SCAN_LIMIT


def _strings(value: Any) -> Iterable[str]:
    if not isinstance(value, list):
        return
    for item in value[:_MAX_LIST_ITEMS]:
        if isinstance(item, str) and item.strip():
            yield item.strip()[:_MAX_NAME_LENGTH]


def _add(table: FacetTable, key: str, sample: SampleIndicator) -> None:
    table.setdefault(key, {})[sample.indicator_id] = sample


def _entries(table: FacetTable, limit: int) -> list[FacetEntry]:
    entries = []
    for key, members in table.items():
        ordered = sorted(members.values(), key=lambda s: (-s.risk_score, s.indicator_value))
        entries.append(
            FacetEntry(
                key=key,
                count=len(ordered),
                max_risk=ordered[0].risk_score,
                samples=ordered[:SAMPLES_PER_FACET],
            )
        )
    entries.sort(key=lambda entry: (-entry.count, -entry.max_risk, entry.key))
    return entries[:limit]
