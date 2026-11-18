"""Threat-intelligence investigation: the use case behind ``POST /api/v1/intel/investigate``.

One investigation normalizes the indicator, finds or creates its row, reuses stored provider
answers that are still fresh, queries the others concurrently, stores each answer as a new
observation, rescores the indicator from the stored evidence, and writes an audit record.

Only provider HTTP calls run on worker threads. A database session never leaves the request
thread, and the connection is released before any network call is made.
"""

import contextvars
import logging
import math
import time
import uuid
from collections import Counter
from collections.abc import Callable, Collection, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal

import httpx2
from pydantic import ValidationError
from sqlalchemy import ColumnElement, delete, func, or_, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy.orm.exc import StaleDataError

from app.collectors.base import Collector, ProviderResult, ProviderStatus
from app.correlation.scoring import (
    Classification,
    EvidenceState,
    ProviderEvidence,
    ScoreResult,
    classify,
    score_indicator,
    score_range,
)
from app.models.audit import AuditLog
from app.models.base import Base
from app.models.enums import IndicatorStatus, IndicatorType
from app.models.threat import ThreatIndicator, ThreatObservation, ThreatSource
from app.models.types import utcnow
from app.schemas.intel import (
    DeleteIndicatorsResponse,
    IndicatorOut,
    IndicatorPage,
    InternalEvidenceOut,
    InvestigationResponse,
    OverviewResponse,
    ProviderInfo,
    ProviderView,
    ProviderViewStatus,
    ScoreOut,
    StatsResponse,
)
from app.services.audit import (
    IOC_DELETE,
    IOC_LOOKUP,
    RESULT_PARTIAL,
    RESULT_REJECTED,
    RESULT_SUCCESS,
    record_audit,
)
from app.services.normalization import (
    InvalidIndicatorError,
    NormalizedIndicator,
    normalize_indicator,
)
from app.services.overview import build_overview

logger = logging.getLogger("cipherforge.intel")

# A provider is asked again at most this often for one indicator, even with refresh=true, so a
# user cannot burn the provider's free quota by clicking "refresh".
MIN_REFRESH_INTERVAL_SECONDS = 60
MAX_TAGS = 20
STATS_WINDOW = timedelta(hours=24)
# Added to the provider timeout when waiting on a worker. httpx bounds each network operation
# but not DNS resolution, so the service enforces its own deadline as well.
_WAIT_GRACE_SECONDS = 7.0

SortOrder = Literal["recent", "risk"]

INTERNAL_EVIDENCE = InternalEvidenceOut(
    available=False,
    message=(
        "CipherForge has no internal telemetry (Sentinel, SOC, Case) connected yet, so no "
        "internal sightings are included."
    ),
)

_CACHE_HIT = "hit"
_CACHE_MISS = "miss"
_CACHE_NONE = "none"


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Who is asking, for the audit trail."""

    actor: str
    source_ip: str | None = None


class IndicatorDeletedError(Exception):
    """The indicator was deleted while its investigation was waiting on the providers.

    The answers are discarded rather than bringing back something that was just deleted.
    """


@dataclass(slots=True)
class _Run:
    """One provider's part in one investigation, filled in as the investigation proceeds."""

    collector: Collector
    source_id: int | None
    # The provider's own reason to make no call (unsupported type, or no API key).
    skipped: ProviderResult | None
    latest: ThreatObservation | None
    needs_call: bool = False
    result: ProviderResult | None = None
    observation: ThreatObservation | None = None


@dataclass(frozen=True, slots=True)
class _Outcome:
    """What an investigation can say about one provider."""

    collector: Collector
    state: EvidenceState
    observation: ThreatObservation | None
    status: ProviderViewStatus
    from_cache: bool
    message: str | None
    cache: str
    # A provider call was attempted and produced no answer (error or rate limit).
    failed: bool = False


class IntelService:
    def __init__(
        self,
        collectors: Sequence[Collector],
        *,
        http_client: httpx2.Client | None = None,
        clock: Callable[[], datetime] = utcnow,
        provider_timeout_seconds: float = 10.0,
        min_refresh_interval_seconds: int = MIN_REFRESH_INTERVAL_SECONDS,
    ) -> None:
        self._collectors = tuple(collectors)
        self._http_client = http_client
        self._clock = clock
        self._wait_seconds = provider_timeout_seconds + _WAIT_GRACE_SECONDS
        self._min_refresh = timedelta(seconds=min_refresh_interval_seconds)
        self._executor = ThreadPoolExecutor(
            max_workers=max(4, 2 * len(self._collectors)), thread_name_prefix="intel-lookup"
        )

    def close(self) -> None:
        """Release the worker threads and the HTTP client. Safe to call more than once."""
        self._executor.shutdown(wait=False, cancel_futures=True)
        if self._http_client is not None:
            self._http_client.close()

    # --- Investigate -------------------------------------------------------------

    def investigate(
        self, session: Session, context: RequestContext, raw: str, *, refresh: bool = False
    ) -> InvestigationResponse:
        """Investigate one indicator. Raises :class:`InvalidIndicatorError` if it is not valid.

        The caller's session is committed. A lookup is audited whatever happens to it: success,
        partial (a provider failed) or rejected (the input was not a valid indicator).
        :class:`IndicatorDeletedError` is raised, after the lookup is audited, if another request
        deleted the indicator while the providers were being asked.
        """
        started = time.perf_counter()
        now = self._clock()
        try:
            normalized = normalize_indicator(raw)
        except InvalidIndicatorError as exc:
            # The message is generic by design and the input is never recorded.
            record_audit(
                session,
                actor=context.actor,
                action=IOC_LOOKUP,
                result=RESULT_REJECTED,
                source_ip=context.source_ip,
                details={"reason": str(exc)},
                timestamp=now,
            )
            session.commit()
            raise

        indicator = self._get_or_create_indicator(session, normalized, now)
        indicator_id = indicator.id
        source_ids = self._source_ids(session, create=True)
        runs = [
            self._plan(session, collector, indicator.id, source_ids, normalized, now, refresh)
            for collector in self._collectors
        ]
        # Return the connection to the pool before the slow network calls.
        session.commit()

        self._fetch(normalized, [run for run in runs if run.needs_call])
        for run in runs:
            if run.result is not None and run.result.is_answer:
                run.observation = _store_observation(session, indicator.id, run, now)

        outcomes = [_outcome(run, now) for run in runs]
        score = score_indicator([_evidence(outcome) for outcome in outcomes], now=now)
        _apply_score(indicator, outcomes, score, now)

        partial = any(outcome.failed for outcome in outcomes)
        record_audit(
            session,
            actor=context.actor,
            action=IOC_LOOKUP,
            result=RESULT_PARTIAL if partial else RESULT_SUCCESS,
            target=normalized.target,
            source_ip=context.source_ip,
            details={
                "refresh": refresh,
                "providers": {
                    run.collector.name: {
                        "status": run.result.status.value if run.result else outcome.status,
                        "cache": outcome.cache,
                    }
                    for run, outcome in zip(runs, outcomes, strict=True)
                },
                "score": score.score,
                "classification": score.classification.value,
            },
            timestamp=now,
        )
        try:
            session.commit()
        except (IntegrityError, StaleDataError):
            # Another request may have deleted the indicator while the providers were being
            # asked: its row is gone, so these answers have nothing to attach to.
            session.rollback()
            if _indicator_exists(session, indicator_id):
                raise
            record_audit(
                session,
                actor=context.actor,
                action=IOC_LOOKUP,
                result=RESULT_PARTIAL,
                target=normalized.target,
                source_ip=context.source_ip,
                details={"refresh": refresh, "discarded": "indicator_deleted"},
                timestamp=now,
            )
            session.commit()
            logger.info("investigation_discarded", extra={"reason": "indicator_deleted"})
            raise IndicatorDeletedError from None

        # The indicator value is deliberately absent: the audit table is where it is recorded.
        logger.info(
            "investigation_completed",
            extra={
                "indicator_type": normalized.indicator_type.value,
                "risk_score": score.score,
                "classification": score.classification.value,
                "partial": partial,
                "refresh": refresh,
                "duration_ms": round((time.perf_counter() - started) * 1000),
            },
        )
        return InvestigationResponse(
            indicator=_indicator_out(indicator),
            providers=[_provider_view(outcome) for outcome in outcomes],
            score=_score_out(score.to_dict(), indicator.scored_at),
            internal_evidence=INTERNAL_EVIDENCE,
        )

    def _get_or_create_indicator(
        self, session: Session, normalized: NormalizedIndicator, now: datetime
    ) -> ThreatIndicator:
        query = select(ThreatIndicator).where(
            ThreatIndicator.indicator_type == normalized.indicator_type.value,
            ThreatIndicator.indicator_value == normalized.indicator_value,
        )
        indicator = session.scalars(query).first()
        if indicator is None:
            # Two requests may race to create the same indicator: the loser's insert is
            # ignored and both read the one row that exists.
            _insert_ignoring_conflict(
                session,
                ThreatIndicator,
                {
                    "indicator_type": normalized.indicator_type.value,
                    "indicator_value": normalized.indicator_value,
                    "created_at": now,
                    "updated_at": now,
                },
                ("indicator_type", "indicator_value"),
            )
            indicator = session.scalars(query).one()
        return indicator

    def _source_ids(self, session: Session, *, create: bool) -> dict[str, int]:
        names = [collector.name for collector in self._collectors]
        found = _source_rows(session, names)
        if create:
            for collector in self._collectors:
                if collector.name not in found:
                    _insert_ignoring_conflict(
                        session,
                        ThreatSource,
                        {
                            "name": collector.name,
                            "display_name": collector.display_name,
                            "created_at": self._clock(),
                        },
                        ("name",),
                    )
            found = _source_rows(session, names)
        return found

    def _plan(
        self,
        session: Session,
        collector: Collector,
        indicator_id: uuid.UUID,
        source_ids: dict[str, int],
        normalized: NormalizedIndicator,
        now: datetime,
        refresh: bool,
    ) -> _Run:
        source_id = source_ids.get(collector.name)
        skipped = collector.precheck(normalized)
        if skipped is not None and skipped.status is ProviderStatus.UNSUPPORTED:
            return _Run(collector, source_id, skipped, None)
        latest = _latest_observation(session, indicator_id, source_id)
        needs_call = False
        if skipped is None:
            if latest is None:
                needs_call = True
            else:
                age = now - latest.fetched_at
                expired = age >= timedelta(seconds=collector.cache_ttl_seconds)
                needs_call = expired or (refresh and age >= self._min_refresh)
        return _Run(collector, source_id, skipped, latest, needs_call)

    def _fetch(self, indicator: NormalizedIndicator, runs: Sequence[_Run]) -> None:
        """Query the providers concurrently. Never raises: failures become results."""
        if not runs:
            return
        started = time.monotonic()
        futures: list[Future[ProviderResult]] = []
        for run in runs:
            # Each worker gets its own copy of the context so its logs carry the correlation id.
            context = contextvars.copy_context()
            futures.append(self._executor.submit(context.run, run.collector.lookup, indicator))
        for run, future in zip(runs, futures, strict=True):
            collector = run.collector
            remaining = max(0.0, self._wait_seconds - (time.monotonic() - started))
            try:
                run.result = future.result(timeout=remaining)
            except TimeoutError:
                future.cancel()
                run.result = ProviderResult(
                    collector.name,
                    ProviderStatus.ERROR,
                    message=f"{collector.display_name} did not respond in time.",
                )
            except Exception as exc:
                logger.warning(
                    "provider_worker_failed",
                    extra={"provider": collector.name, "error_type": type(exc).__name__},
                )
                run.result = ProviderResult(
                    collector.name,
                    ProviderStatus.ERROR,
                    message=f"Unexpected error while querying {collector.display_name}.",
                )

    # --- Read back (no provider calls) ----------------------------------------------

    def get_investigation(
        self, session: Session, indicator_id: uuid.UUID
    ) -> InvestigationResponse | None:
        """The stored view of an indicator, or None if it does not exist. Never calls providers.

        The score is the snapshot taken when the indicator was last investigated (see
        ``scored_at``); freshness of each provider answer is computed now.
        """
        indicator = session.get(ThreatIndicator, indicator_id)
        if indicator is None:
            return None
        now = self._clock()
        normalized = NormalizedIndicator(
            IndicatorType(indicator.indicator_type), indicator.indicator_value
        )
        source_ids = self._source_ids(session, create=False)
        runs = []
        for collector in self._collectors:
            source_id = source_ids.get(collector.name)
            skipped = collector.precheck(normalized)
            unsupported = skipped is not None and skipped.status is ProviderStatus.UNSUPPORTED
            latest = None if unsupported else _latest_observation(session, indicator.id, source_id)
            runs.append(_Run(collector, source_id, skipped, latest))
        outcomes = [_outcome(run, now) for run in runs]

        score = _stored_score(indicator)
        override: ScoreResult | None = None
        if score is None:
            override = score_indicator([_evidence(outcome) for outcome in outcomes], now=now)
            score = _score_out(override.to_dict(), None)
        return InvestigationResponse(
            indicator=_indicator_out(indicator, override),
            providers=[_provider_view(outcome) for outcome in outcomes],
            score=score,
            internal_evidence=INTERNAL_EVIDENCE,
        )

    def list_indicators(
        self,
        session: Session,
        *,
        indicator_type: IndicatorType | None = None,
        classifications: Collection[Classification] = (),
        assessed: bool | None = None,
        query: str | None = None,
        sort: SortOrder = "recent",
        limit: int = 25,
        offset: int = 0,
    ) -> IndicatorPage:
        """Stored indicators, newest or riskiest first.

        ``classifications`` are score bands (any of them matches; none means any band).
        ``assessed`` separates indicators a provider answered for from those none did: confidence
        is built from provider answers, so 0 means not assessed, and its score says nothing.
        """
        conditions: list[ColumnElement[bool]] = []
        if indicator_type is not None:
            conditions.append(ThreatIndicator.indicator_type == indicator_type.value)
        if classifications:
            conditions.append(
                or_(
                    *(
                        ThreatIndicator.risk_score.between(*score_range(band))
                        for band in dict.fromkeys(classifications)
                    )
                )
            )
        if assessed is not None:
            conditions.append(
                ThreatIndicator.confidence > 0 if assessed else ThreatIndicator.confidence == 0
            )
        if query:
            # autoescape: "%" and "_" in the search text match themselves, not any character.
            conditions.append(ThreatIndicator.indicator_value.icontains(query, autoescape=True))

        total = session.scalar(select(func.count()).select_from(ThreatIndicator).where(*conditions))
        order = (
            (ThreatIndicator.risk_score.desc(), ThreatIndicator.updated_at.desc())
            if sort == "risk"
            else (ThreatIndicator.updated_at.desc(),)
        )
        rows = session.scalars(
            select(ThreatIndicator)
            .where(*conditions)
            .order_by(*order, ThreatIndicator.id)
            .limit(limit)
            .offset(offset)
        ).all()
        return IndicatorPage(
            items=[_indicator_out(row) for row in rows],
            total=total or 0,
            limit=limit,
            offset=offset,
        )

    def stats(self, session: Session) -> StatsResponse:
        by_type = {member.value: 0 for member in IndicatorType}
        for indicator_type, count in session.execute(
            select(ThreatIndicator.indicator_type, func.count()).group_by(
                ThreatIndicator.indicator_type
            )
        ):
            by_type[indicator_type] = count

        by_classification = {member.value: 0 for member in Classification}
        for risk_score, count in session.execute(
            select(ThreatIndicator.risk_score, func.count()).group_by(ThreatIndicator.risk_score)
        ):
            by_classification[classify(risk_score).value] += count

        lookups = session.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.action == IOC_LOOKUP,
                AuditLog.result.in_((RESULT_SUCCESS, RESULT_PARTIAL)),
                AuditLog.timestamp >= self._clock() - STATS_WINDOW,
            )
        )
        return StatsResponse(
            total_indicators=sum(by_type.values()),
            by_classification=by_classification,
            by_type=by_type,
            lookups_last_24h=lookups or 0,
            providers=self.providers(),
        )

    def providers(self) -> list[ProviderInfo]:
        return [
            ProviderInfo(
                name=collector.name,
                display_name=collector.display_name,
                configured=collector.configured,
                supported_types=sorted(collector.supported_types),
                simulated=collector.simulated,
            )
            for collector in self._collectors
        ]

    def overview(self, session: Session) -> OverviewResponse:
        """Dashboard aggregates over stored data. Read-only: never calls a provider."""
        return build_overview(
            session, now=self._clock(), providers=self.providers(), indicator_out=_indicator_out
        )

    # --- Delete ------------------------------------------------------------------------------

    def delete_indicators(
        self, session: Session, context: RequestContext, indicator_ids: Sequence[uuid.UUID]
    ) -> DeleteIndicatorsResponse:
        """Delete stored indicators together with the provider answers kept for them.

        An id that matches nothing is reported in ``not_found`` instead of failing the request,
        so repeating a request, or racing another analyst, does no harm. Every deleted indicator
        is audited with a row of its own, committed together with the deletion. The audit trail
        is append-only and is never touched: it keeps its record of the indicator's lookups.
        """
        ids = list(dict.fromkeys(indicator_ids))
        now = self._clock()

        # The answers go first so that each audit row can say how many went with its indicator;
        # the foreign key would cascade them anyway. RETURNING names what this statement removed
        # (not what a separate read saw), so a concurrent deletion is never counted twice.
        answers_removed = Counter(
            session.scalars(
                delete(ThreatObservation)
                .where(ThreatObservation.indicator_id.in_(ids))
                .returning(ThreatObservation.indicator_id)
                .execution_options(synchronize_session=False)
            )
        )
        removed = session.execute(
            delete(ThreatIndicator)
            .where(ThreatIndicator.id.in_(ids))
            .returning(
                ThreatIndicator.id, ThreatIndicator.indicator_type, ThreatIndicator.indicator_value
            )
            .execution_options(synchronize_session=False)
        ).all()

        for row in removed:
            target = NormalizedIndicator(IndicatorType(row.indicator_type), row.indicator_value)
            record_audit(
                session,
                actor=context.actor,
                action=IOC_DELETE,
                result=RESULT_SUCCESS,
                target=target.target,
                source_ip=context.source_ip,
                details={"observations_removed": answers_removed[row.id]},
                timestamp=now,
            )
        session.commit()

        deleted_ids = {row.id for row in removed}
        response = DeleteIndicatorsResponse(
            deleted=[item for item in ids if item in deleted_ids],
            not_found=[item for item in ids if item not in deleted_ids],
            observations_removed=sum(answers_removed.values()),
        )
        # Counts only: indicator values are recorded in the audit table, never in the logs.
        logger.info(
            "indicators_deleted",
            extra={
                "deleted": len(response.deleted),
                "not_found": len(response.not_found),
                "observations_removed": response.observations_removed,
            },
        )
        return response


# --- Persistence helpers --------------------------------------------------------------


def _insert_ignoring_conflict(
    session: Session,
    model: type[Base],
    values: dict[str, Any],
    conflict_columns: tuple[str, ...],
) -> None:
    """INSERT ... ON CONFLICT DO NOTHING, so concurrent get-or-create calls cannot fail."""
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        statement: Any = postgresql.insert(model).values(**values)
    elif dialect == "sqlite":
        statement = sqlite.insert(model).values(**values)
    else:
        raise NotImplementedError(f"Unsupported database dialect: {dialect}")
    session.execute(statement.on_conflict_do_nothing(index_elements=list(conflict_columns)))


def _source_rows(session: Session, names: list[str]) -> dict[str, int]:
    rows = session.execute(
        select(ThreatSource.name, ThreatSource.id).where(ThreatSource.name.in_(names))
    )
    return {row.name: row.id for row in rows}


def _indicator_exists(session: Session, indicator_id: uuid.UUID) -> bool:
    found = session.scalar(select(ThreatIndicator.id).where(ThreatIndicator.id == indicator_id))
    return found is not None


def _latest_observation(
    session: Session, indicator_id: uuid.UUID, source_id: int | None
) -> ThreatObservation | None:
    if source_id is None:
        return None
    return session.scalars(
        select(ThreatObservation)
        .where(
            ThreatObservation.indicator_id == indicator_id,
            ThreatObservation.source_id == source_id,
        )
        .order_by(ThreatObservation.fetched_at.desc(), ThreatObservation.id.desc())
        .limit(1)
    ).first()


def _store_observation(
    session: Session, indicator_id: uuid.UUID, run: _Run, now: datetime
) -> ThreatObservation:
    result = run.result
    if result is None or run.source_id is None:
        raise RuntimeError("only answered lookups with a known source are stored")
    observation = ThreatObservation(
        indicator_id=indicator_id,
        source_id=run.source_id,
        status=result.status.value,
        signal=_clamp_signal(result.signal),
        fetched_at=now,
        evidence_at=result.evidence_at,
        first_evidence_at=result.first_evidence_at,
        summary=result.summary,
        tags=list(result.tags),
    )
    session.add(observation)
    return observation


def _clamp_signal(signal: float) -> float:
    # The database rejects values outside 0..1; a provider quirk must not fail the request.
    if not math.isfinite(signal):
        return 0.0
    return min(max(signal, 0.0), 1.0)


# --- Outcomes and views -----------------------------------------------------------------


def _outcome(run: _Run, now: datetime) -> _Outcome:
    collector = run.collector
    result = run.result

    if run.observation is not None:
        observation = run.observation
        return _Outcome(
            collector,
            EvidenceState.FRESH,
            observation,
            observation.status,
            False,
            None,
            _CACHE_MISS,
        )

    if run.latest is not None:
        latest = run.latest
        attempted = result is not None
        message = result.message if result is not None else None
        fresh = now - latest.fetched_at < timedelta(seconds=collector.cache_ttl_seconds)
        if message is None and not fresh and not collector.configured:
            message = (
                f"{collector.display_name} is not configured, so this older answer "
                "cannot be refreshed."
            )
        return _Outcome(
            collector,
            EvidenceState.FRESH if fresh else EvidenceState.STALE,
            latest,
            latest.status,
            True,
            message,
            _CACHE_MISS if attempted else _CACHE_HIT,
            failed=attempted,
        )

    if run.skipped is not None:
        unsupported = run.skipped.status is ProviderStatus.UNSUPPORTED
        return _Outcome(
            collector,
            EvidenceState.UNSUPPORTED if unsupported else EvidenceState.NOT_CONFIGURED,
            None,
            run.skipped.status.value,
            False,
            run.skipped.message,
            _CACHE_NONE,
        )

    if result is not None:
        return _Outcome(
            collector,
            EvidenceState.UNAVAILABLE,
            None,
            result.status.value,
            False,
            result.message,
            _CACHE_MISS,
            failed=True,
        )

    return _Outcome(
        collector,
        EvidenceState.UNAVAILABLE,
        None,
        "not_queried",
        False,
        (
            f"No stored answer from {collector.display_name}: it was not queried, or the lookup "
            "failed. Investigate the indicator again to retry."
        ),
        _CACHE_NONE,
    )


def _strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _evidence(outcome: _Outcome) -> ProviderEvidence:
    collector = outcome.collector
    observation = outcome.observation
    if observation is None:
        return ProviderEvidence(collector.name, collector.display_name, outcome.state)
    summary = observation.summary or {}
    return ProviderEvidence(
        provider=collector.name,
        display_name=collector.display_name,
        state=outcome.state,
        signal=observation.signal,
        evidence_at=observation.evidence_at,
        fetched_at=observation.fetched_at,
        malware_families=_strings(summary.get("malware_families")),
        notes=_strings(summary.get("notes")),
    )


def _apply_score(
    indicator: ThreatIndicator, outcomes: Sequence[_Outcome], score: ScoreResult, now: datetime
) -> None:
    observations = [o.observation for o in outcomes if o.observation is not None]
    firsts = [t for obs in observations if (t := obs.first_evidence_at or obs.evidence_at)]
    lasts = [obs.evidence_at for obs in observations if obs.evidence_at is not None]
    fresh = any(outcome.state is EvidenceState.FRESH for outcome in outcomes)

    indicator.risk_score = score.score
    indicator.confidence = score.confidence
    indicator.source_count = score.contributing_sources
    indicator.first_seen = min(firsts, default=None)
    indicator.last_seen = max(lasts, default=None)
    indicator.tags = list(dict.fromkeys(tag for obs in observations for tag in obs.tags))[:MAX_TAGS]
    indicator.status = (IndicatorStatus.ACTIVE if fresh else IndicatorStatus.STALE).value
    indicator.score_detail = score.to_dict()
    indicator.scored_at = now
    indicator.last_checked_at = now
    # "Recently investigated" follows the same single clock as everything else. An unchanged
    # value (a brand-new indicator is created with ``now``) must still be written: otherwise the
    # column's onupdate default would stamp the real clock instead.
    indicator.updated_at = now
    flag_modified(indicator, "updated_at")


def _stored_score(indicator: ThreatIndicator) -> ScoreOut | None:
    if not indicator.score_detail:
        return None
    try:
        return _score_out(indicator.score_detail, indicator.scored_at)
    except ValidationError:
        # A snapshot written by an older methodology: recompute instead of failing the request.
        return None


def _score_out(detail: dict[str, Any], scored_at: datetime | None) -> ScoreOut:
    return ScoreOut.model_validate({**detail, "scored_at": scored_at})


def _indicator_out(indicator: ThreatIndicator, override: ScoreResult | None = None) -> IndicatorOut:
    risk_score = override.score if override else indicator.risk_score
    return IndicatorOut(
        indicator_id=indicator.id,
        indicator_type=IndicatorType(indicator.indicator_type),
        indicator_value=indicator.indicator_value,
        risk_score=risk_score,
        classification=classify(risk_score),
        confidence=override.confidence if override else indicator.confidence,
        first_seen=indicator.first_seen,
        last_seen=indicator.last_seen,
        source_count=override.contributing_sources if override else indicator.source_count,
        tags=list(indicator.tags or []),
        status=IndicatorStatus(indicator.status),
        created_at=indicator.created_at,
        scored_at=indicator.scored_at,
        last_checked_at=indicator.last_checked_at,
    )


def _provider_view(outcome: _Outcome) -> ProviderView:
    collector = outcome.collector
    observation = outcome.observation
    return ProviderView(
        provider=collector.name,
        display_name=collector.display_name,
        status=outcome.status,
        freshness=outcome.state.value
        if outcome.state in (EvidenceState.FRESH, EvidenceState.STALE)
        else None,
        signal=observation.signal if observation else None,
        fetched_at=observation.fetched_at if observation else None,
        evidence_at=observation.evidence_at if observation else None,
        first_evidence_at=observation.first_evidence_at if observation else None,
        cache_expires_at=(
            observation.fetched_at + timedelta(seconds=collector.cache_ttl_seconds)
            if observation
            else None
        ),
        from_cache=outcome.from_cache,
        summary=dict(observation.summary or {}) if observation else {},
        tags=list(observation.tags or []) if observation else [],
        message=outcome.message,
    )
