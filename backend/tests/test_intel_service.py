"""The investigation use case against a real, migrated database (SQLite and PostgreSQL).

Providers are scripted fakes, so these tests exercise everything CipherForge itself does:
caching, refresh limits, storage, scoring, auditing and the read-back queries.
"""

import json
import logging
import threading
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, get_args

import httpx2
import pytest
from sqlalchemy import Engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.collectors.base import Collector, ProviderStatus
from app.core.config import Settings
from app.core.context import correlation_id_var
from app.correlation.scoring import Classification
from app.database.session import build_engine, build_session_factory
from app.models.audit import AuditLog
from app.models.enums import IndicatorType
from app.models.threat import ThreatIndicator, ThreatObservation, ThreatSource
from app.schemas.intel import ProviderViewStatus
from app.services import intel_service
from app.services.intel_service import MAX_TAGS, IntelService, RequestContext
from app.services.normalization import InvalidIndicatorError
from tests.intel_helpers import (
    MODERATE,
    STRONG,
    Clock,
    ExplodingCollector,
    FakeAbuse,
    FakeOtx,
    answer,
    failure,
)

IP = "185.220.101.45"
TARGET = f"ipv4:{IP}"
OTHER_IP = "45.76.19.203"
CONTEXT = RequestContext(actor="analyst-1", source_ip="203.0.113.9")

ServiceFactory = Callable[..., IntelService]


# --- Fixtures and helpers -----------------------------------------------------------------


@pytest.fixture
def engine(make_settings: Callable[..., Settings], db_url: str) -> Iterator[Engine]:
    engine = build_engine(make_settings(database_url=db_url))
    yield engine
    engine.dispose()


@pytest.fixture
def session_factory(engine: Engine) -> sessionmaker[Session]:
    return build_session_factory(engine)


@pytest.fixture
def session(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    with session_factory() as db:
        yield db


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def build_service(clock: Clock) -> Iterator[ServiceFactory]:
    services: list[IntelService] = []

    def factory(*collectors: Collector, **options: Any) -> IntelService:
        service = IntelService(collectors, clock=clock, **options)
        services.append(service)
        return service

    yield factory
    for service in services:
        service.close()


def stored(session_factory: sessionmaker[Session], statement: Any) -> list[Any]:
    """Rows as committed to the database, read through a separate session."""
    with session_factory() as reader:
        return list(reader.scalars(statement))


def count(session_factory: sessionmaker[Session], model: type[Any]) -> int:
    with session_factory() as reader:
        return reader.scalar(select(func.count()).select_from(model)) or 0


def seed_indicator(
    session: Session,
    value: str,
    *,
    kind: IndicatorType = IndicatorType.DOMAIN,
    score: int = 0,
    updated_at: datetime | None = None,
    **columns: Any,
) -> ThreatIndicator:
    row = ThreatIndicator(
        indicator_type=kind.value,
        indicator_value=value,
        risk_score=score,
        updated_at=updated_at or datetime.now(UTC),
        **columns,
    )
    session.add(row)
    session.commit()
    return row


def strong_abuse(clock: Clock, **options: Any) -> FakeAbuse:
    return FakeAbuse([answer("abuseipdb", signal=STRONG, evidence_at=clock.ago(days=1))], **options)


# --- First investigation ------------------------------------------------------------------


def test_a_first_investigation_queries_stores_scores_and_audits(
    session: Session,
    session_factory: sessionmaker[Session],
    clock: Clock,
    build_service: ServiceFactory,
) -> None:
    abuse = FakeAbuse(
        [answer("abuseipdb", signal=STRONG, evidence_at=clock.ago(days=1), tags=["scanner"])]
    )
    otx = FakeOtx(
        [
            answer(
                "otx",
                signal=MODERATE,
                evidence_at=clock.ago(days=2),
                first_evidence_at=clock.ago(days=40),
                tags=["botnet", "scanner"],
            )
        ]
    )
    service = build_service(abuse, otx)

    response = service.investigate(session, CONTEXT, IP)

    assert abuse.calls == [TARGET]
    assert otx.calls == [TARGET]
    assert response.indicator.indicator_type is IndicatorType.IPV4
    assert response.indicator.indicator_value == IP
    assert [view.provider for view in response.providers] == ["abuseipdb", "otx"]
    for view in response.providers:
        assert (view.status, view.freshness, view.from_cache) == ("ok", "fresh", False)
        assert view.fetched_at == clock.now
        assert view.cache_expires_at == clock.now + timedelta(hours=1)
    assert response.score.methodology == "intel-risk-v1"
    assert response.score.score == 78
    assert response.score.classification is Classification.HIGH
    assert response.score.confidence == 90
    assert response.score.scored_at == clock.now
    assert response.internal_evidence.available is False

    [indicator] = stored(session_factory, select(ThreatIndicator))
    assert indicator.id == response.indicator.indicator_id
    assert (indicator.risk_score, indicator.confidence, indicator.source_count) == (78, 90, 2)
    assert indicator.status == "active"
    assert indicator.tags == ["scanner", "botnet"]
    assert indicator.first_seen == clock.ago(days=40)
    assert indicator.last_seen == clock.ago(days=1)
    assert indicator.scored_at == indicator.last_checked_at == indicator.updated_at == clock.now
    assert indicator.score_detail is not None
    assert indicator.score_detail["methodology"] == "intel-risk-v1"

    observations = stored(session_factory, select(ThreatObservation))
    assert sorted(obs.signal for obs in observations) == [MODERATE, STRONG]
    assert {obs.fetched_at for obs in observations} == {clock.now}
    assert {obs.indicator_id for obs in observations} == {indicator.id}

    sources = stored(session_factory, select(ThreatSource).order_by(ThreatSource.name))
    assert [(src.name, src.display_name) for src in sources] == [
        ("abuseipdb", "AbuseIPDB"),
        ("otx", "AlienVault OTX"),
    ]

    [audit] = stored(session_factory, select(AuditLog))
    assert (audit.action, audit.result, audit.actor) == ("IOC_LOOKUP", "success", "analyst-1")
    assert (audit.target, audit.source_ip) == (TARGET, "203.0.113.9")
    assert audit.details == {
        "refresh": False,
        "providers": {
            "abuseipdb": {"status": "ok", "cache": "miss"},
            "otx": {"status": "ok", "cache": "miss"},
        },
        "score": 78,
        "classification": "high",
    }


def test_a_provider_with_nothing_to_report_is_an_answer_not_a_failure(
    session: Session,
    session_factory: sessionmaker[Session],
    build_service: ServiceFactory,
) -> None:
    service = build_service(FakeAbuse())

    response = service.investigate(session, CONTEXT, IP)

    [view] = response.providers
    assert (view.status, view.freshness, view.signal) == ("no_data", "fresh", 0.0)
    [observation] = stored(session_factory, select(ThreatObservation))
    assert observation.status == "no_data"
    [audit] = stored(session_factory, select(AuditLog))
    assert audit.result == "success"


def test_tags_are_deduplicated_and_capped(
    session: Session, clock: Clock, build_service: ServiceFactory
) -> None:
    tags = [f"tag-{index}" for index in range(MAX_TAGS + 10)] + ["tag-0"]
    abuse = FakeAbuse(
        [answer("abuseipdb", signal=STRONG, evidence_at=clock.ago(days=1), tags=tags)]
    )

    response = build_service(abuse).investigate(session, CONTEXT, IP)

    assert response.indicator.tags == tags[:MAX_TAGS]


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (IP, "185[.]220[.]101[.]45"),
        (IP, f"  {IP}\n"),
        ("example.com", "EXAMPLE.COM"),
        ("example.com", "example[.]com"),
    ],
)
def test_equivalent_spellings_resolve_to_one_indicator(
    first: str,
    second: str,
    session: Session,
    session_factory: sessionmaker[Session],
    build_service: ServiceFactory,
) -> None:
    otx = FakeOtx()
    service = build_service(otx)

    one = service.investigate(session, CONTEXT, first)
    two = service.investigate(session, CONTEXT, second)

    assert one.indicator.indicator_id == two.indicator.indicator_id
    assert len(otx.calls) == 1
    assert count(session_factory, ThreatIndicator) == 1


# --- Caching and refresh ------------------------------------------------------------------


def test_a_fresh_answer_is_served_from_the_database(
    session: Session,
    session_factory: sessionmaker[Session],
    clock: Clock,
    build_service: ServiceFactory,
) -> None:
    abuse = strong_abuse(clock)
    service = build_service(abuse)
    first = service.investigate(session, CONTEXT, IP)

    clock.advance(minutes=30)
    second = service.investigate(session, CONTEXT, IP)

    assert len(abuse.calls) == 1
    [view] = second.providers
    assert (view.status, view.freshness, view.from_cache) == ("ok", "fresh", True)
    assert view.fetched_at == first.providers[0].fetched_at
    assert view.cache_expires_at == view.fetched_at + timedelta(hours=1)
    assert second.score.score == first.score.score
    assert second.score.scored_at == clock.now
    assert count(session_factory, ThreatObservation) == 1
    cache_outcomes = [
        row.details["providers"]["abuseipdb"]["cache"]
        for row in stored(session_factory, select(AuditLog).order_by(AuditLog.id))
    ]
    assert cache_outcomes == ["miss", "hit"]


@pytest.mark.parametrize(("age_seconds", "calls"), [(3599, 1), (3600, 2)])
def test_answers_expire_exactly_at_the_provider_ttl(
    age_seconds: int,
    calls: int,
    session: Session,
    clock: Clock,
    build_service: ServiceFactory,
) -> None:
    abuse = strong_abuse(clock)
    service = build_service(abuse)
    service.investigate(session, CONTEXT, IP)

    clock.advance(seconds=age_seconds)
    service.investigate(session, CONTEXT, IP)

    assert len(abuse.calls) == calls


def test_each_provider_uses_its_own_ttl(
    session: Session, clock: Clock, build_service: ServiceFactory
) -> None:
    abuse = strong_abuse(clock, cache_ttl_seconds=600)
    otx = FakeOtx(cache_ttl_seconds=7200)
    service = build_service(abuse, otx)
    service.investigate(session, CONTEXT, IP)

    clock.advance(minutes=30)
    service.investigate(session, CONTEXT, IP)

    assert (len(abuse.calls), len(otx.calls)) == (2, 1)


def test_refresh_asks_again_but_never_faster_than_the_minimum_interval(
    session: Session, clock: Clock, build_service: ServiceFactory
) -> None:
    abuse = strong_abuse(clock)
    service = build_service(abuse)
    service.investigate(session, CONTEXT, IP)

    clock.advance(seconds=59)
    too_soon = service.investigate(session, CONTEXT, IP, refresh=True)
    assert len(abuse.calls) == 1
    assert too_soon.providers[0].from_cache is True

    clock.advance(seconds=1)
    refreshed = service.investigate(session, CONTEXT, IP, refresh=True)
    assert len(abuse.calls) == 2
    assert refreshed.providers[0].from_cache is False


def test_a_refresh_replaces_the_answer_and_rescores(
    session: Session,
    session_factory: sessionmaker[Session],
    clock: Clock,
    build_service: ServiceFactory,
) -> None:
    abuse = FakeAbuse(
        [
            answer("abuseipdb", signal=0.2, evidence_at=clock.ago(days=1)),
            answer("abuseipdb", signal=STRONG, evidence_at=clock.ago(days=1)),
        ]
    )
    service = build_service(abuse)
    first = service.investigate(session, CONTEXT, IP)

    clock.advance(hours=2)
    second = service.investigate(session, CONTEXT, IP)

    assert (first.score.score, second.score.score) == (9, 45)
    assert second.score.classification is Classification.MEDIUM
    [indicator] = stored(session_factory, select(ThreatIndicator))
    assert indicator.risk_score == 45
    # History is kept: both answers are stored, and the newest one drives the score.
    assert count(session_factory, ThreatObservation) == 2
    assert second.providers[0].signal == STRONG
    assert second.providers[0].fetched_at == clock.now


def test_reinvestigating_moves_an_indicator_to_the_top_of_the_recent_list(
    session: Session, build_service: ServiceFactory, clock: Clock
) -> None:
    service = build_service(FakeOtx())
    service.investigate(session, CONTEXT, "first.example.com")
    clock.advance(minutes=1)
    service.investigate(session, CONTEXT, "second.example.com")
    clock.advance(minutes=1)
    service.investigate(session, CONTEXT, "first.example.com")

    page = service.list_indicators(session, sort="recent")

    assert [item.indicator_value for item in page.items] == [
        "first.example.com",
        "second.example.com",
    ]


# --- Providers that cannot answer ---------------------------------------------------------


def test_unsupported_and_unconfigured_providers_are_skipped_without_calls(
    session: Session,
    session_factory: sessionmaker[Session],
    build_service: ServiceFactory,
) -> None:
    abuse = FakeAbuse()  # IP addresses only
    otx = FakeOtx(api_key=None)
    service = build_service(abuse, otx)

    response = service.investigate(session, CONTEXT, "example.com")

    assert abuse.calls == []
    assert otx.calls == []
    assert [(view.provider, view.status) for view in response.providers] == [
        ("abuseipdb", "unsupported"),
        ("otx", "not_configured"),
    ]
    for view in response.providers:
        assert (view.freshness, view.signal, view.from_cache) == (None, None, False)
        assert view.message
    assert response.score.answered_sources == 0
    assert count(session_factory, ThreatObservation) == 0
    [audit] = stored(session_factory, select(AuditLog))
    assert audit.result == "success"
    assert audit.details["providers"] == {
        "abuseipdb": {"status": "unsupported", "cache": "none"},
        "otx": {"status": "not_configured", "cache": "none"},
    }


@pytest.mark.parametrize("status", [ProviderStatus.RATE_LIMITED, ProviderStatus.ERROR])
def test_a_failing_provider_does_not_fail_the_investigation(
    status: ProviderStatus,
    session: Session,
    session_factory: sessionmaker[Session],
    clock: Clock,
    build_service: ServiceFactory,
) -> None:
    abuse = FakeAbuse([failure(status, "AbuseIPDB could not help.")])
    otx = FakeOtx([answer("otx", signal=MODERATE, evidence_at=clock.ago(days=1))])
    service = build_service(abuse, otx)

    response = service.investigate(session, CONTEXT, IP)

    failed, healthy = response.providers
    assert failed.status == status.value
    assert failed.message == "AbuseIPDB could not help."
    assert (failed.freshness, failed.signal, failed.from_cache) == (None, None, False)
    assert healthy.status == "ok"
    # Failures are never stored: they say nothing about the indicator.
    [observation] = stored(session_factory, select(ThreatObservation))
    assert observation.signal == MODERATE
    [audit] = stored(session_factory, select(AuditLog))
    assert audit.result == "partial"
    assert audit.details["providers"]["abuseipdb"] == {"status": status.value, "cache": "miss"}


def test_a_stale_answer_is_kept_and_labelled_when_the_refresh_fails(
    session: Session,
    session_factory: sessionmaker[Session],
    clock: Clock,
    build_service: ServiceFactory,
) -> None:
    abuse = FakeAbuse(
        [
            answer("abuseipdb", signal=STRONG, evidence_at=clock.ago(days=1)),
            failure(ProviderStatus.RATE_LIMITED, "AbuseIPDB rate limit reached; try again later."),
        ]
    )
    service = build_service(abuse)
    first = service.investigate(session, CONTEXT, IP)

    clock.advance(hours=2)
    second = service.investigate(session, CONTEXT, IP)

    [view] = second.providers
    assert (view.status, view.freshness, view.from_cache) == ("ok", "stale", True)
    assert view.message == "AbuseIPDB rate limit reached; try again later."
    assert second.score.score == first.score.score  # the evidence itself has not aged much
    assert second.score.confidence < first.score.confidence  # but a stale answer is trusted less
    assert second.indicator.status.value == "stale"
    assert count(session_factory, ThreatObservation) == 1
    audit = stored(session_factory, select(AuditLog).order_by(AuditLog.id))[-1]
    assert audit.result == "partial"
    assert audit.details["providers"]["abuseipdb"] == {"status": "rate_limited", "cache": "miss"}


def test_a_stale_answer_from_a_provider_that_lost_its_key_says_it_cannot_be_refreshed(
    session: Session,
    session_factory: sessionmaker[Session],
    clock: Clock,
    build_service: ServiceFactory,
) -> None:
    build_service(strong_abuse(clock)).investigate(session, CONTEXT, IP)
    clock.advance(hours=2)
    keyless = FakeAbuse(api_key=None)

    response = build_service(keyless).investigate(session, CONTEXT, IP)

    [view] = response.providers
    assert (view.status, view.freshness, view.from_cache) == ("ok", "stale", True)
    assert view.message is not None
    assert "cannot be refreshed" in view.message
    assert keyless.calls == []
    audit = stored(session_factory, select(AuditLog).order_by(AuditLog.id))[-1]
    assert audit.result == "success"  # nothing was attempted, so nothing failed


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(1.7, 1.0), (-0.3, 0.0), (float("nan"), 0.0), (float("inf"), 0.0)],
)
def test_out_of_range_signals_are_clamped_instead_of_failing_the_request(
    raw: float,
    expected: float,
    session: Session,
    session_factory: sessionmaker[Session],
    clock: Clock,
    build_service: ServiceFactory,
) -> None:
    abuse = FakeAbuse([answer("abuseipdb", signal=raw, evidence_at=clock.ago(days=1))])

    build_service(abuse).investigate(session, CONTEXT, IP)

    [observation] = stored(session_factory, select(ThreatObservation))
    assert observation.signal == expected


def test_a_provider_that_never_answers_times_out_without_blocking_the_others(
    monkeypatch: pytest.MonkeyPatch,
    session: Session,
    session_factory: sessionmaker[Session],
    clock: Clock,
    build_service: ServiceFactory,
) -> None:
    monkeypatch.setattr(intel_service, "_WAIT_GRACE_SECONDS", 0.0)
    release = threading.Event()
    hung = FakeAbuse(block=release)
    otx = FakeOtx([answer("otx", signal=MODERATE, evidence_at=clock.ago(days=1))])
    service = build_service(hung, otx, provider_timeout_seconds=0.2)

    try:
        response = service.investigate(session, CONTEXT, IP)
    finally:
        release.set()

    timed_out, healthy = response.providers
    assert timed_out.status == "error"
    assert timed_out.message == "AbuseIPDB did not respond in time."
    assert healthy.status == "ok"
    [observation] = stored(session_factory, select(ThreatObservation))
    assert observation.signal == MODERATE
    [audit] = stored(session_factory, select(AuditLog))
    assert audit.result == "partial"


def test_a_provider_that_breaks_its_contract_is_contained(
    caplog: pytest.LogCaptureFixture,
    session: Session,
    session_factory: sessionmaker[Session],
    clock: Clock,
    build_service: ServiceFactory,
) -> None:
    caplog.set_level(logging.WARNING, logger="cipherforge.intel")
    abuse = strong_abuse(clock)
    service = build_service(abuse, ExplodingCollector())

    response = service.investigate(session, CONTEXT, IP)

    healthy, broken = response.providers
    assert healthy.status == "ok"
    assert broken.status == "error"
    assert broken.message == "Unexpected error while querying AlienVault OTX."
    [record] = [r for r in caplog.records if r.getMessage() == "provider_worker_failed"]
    assert record.error_type == "RuntimeError"  # type: ignore[attr-defined]
    assert "boom" not in caplog.text  # the exception text could carry sensitive data
    [audit] = stored(session_factory, select(AuditLog))
    assert audit.result == "partial"


# --- Audit, logging and context -----------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "not an indicator",
        "10.0.0.1",
        "' OR 1=1 --",
        "<script>alert(1)</script>",
        "d41d8cd98f00b204e9800998ecf8427e",
        "ftp://example.com/payload",
    ],
)
def test_invalid_input_is_rejected_and_audited_without_the_input(
    raw: str,
    session: Session,
    session_factory: sessionmaker[Session],
    build_service: ServiceFactory,
) -> None:
    abuse = FakeAbuse()
    service = build_service(abuse)

    with pytest.raises(InvalidIndicatorError):
        service.investigate(session, CONTEXT, raw)

    assert abuse.calls == []
    assert count(session_factory, ThreatIndicator) == 0
    [audit] = stored(session_factory, select(AuditLog))
    assert (audit.action, audit.result, audit.actor) == ("IOC_LOOKUP", "rejected", "analyst-1")
    assert audit.target is None
    everything = json.dumps(
        [audit.actor, audit.action, audit.result, audit.target, audit.source_ip, audit.details]
    )
    assert raw not in everything


def test_logs_never_contain_the_indicator_or_an_api_key(
    caplog: pytest.LogCaptureFixture,
    session: Session,
    clock: Clock,
    build_service: ServiceFactory,
) -> None:
    caplog.set_level(logging.DEBUG)
    secret = "sk-live-0123456789abcdef"
    answers = {TARGET: answer("abuseipdb", signal=STRONG, evidence_at=clock.ago(days=1))}
    service = build_service(FakeAbuse(answers=answers, api_key=secret), FakeOtx(api_key=secret))

    service.investigate(session, CONTEXT, IP)
    with pytest.raises(InvalidIndicatorError):
        service.investigate(session, CONTEXT, "10.0.0.1")

    everything = "\n".join(f"{record.getMessage()} {record.__dict__}" for record in caplog.records)
    assert IP not in everything
    assert "10.0.0.1" not in everything
    assert secret not in everything
    [completed] = [r for r in caplog.records if r.getMessage() == "investigation_completed"]
    assert completed.indicator_type == "ipv4"  # type: ignore[attr-defined]
    assert completed.risk_score == 45  # type: ignore[attr-defined]


def test_the_correlation_id_reaches_the_audit_row_and_the_provider_workers(
    session: Session,
    session_factory: sessionmaker[Session],
    clock: Clock,
    build_service: ServiceFactory,
) -> None:
    abuse = strong_abuse(clock)
    service = build_service(abuse)

    token = correlation_id_var.set("req-123")
    try:
        service.investigate(session, CONTEXT, IP)
    finally:
        correlation_id_var.reset(token)

    [audit] = stored(session_factory, select(AuditLog))
    assert audit.correlation_id == "req-123"
    assert abuse.correlation_ids == ["req-123"]


# --- Concurrency --------------------------------------------------------------------------


def test_two_requests_creating_the_same_indicator_at_once_share_one_row(
    engine: Engine,
    session_factory: sessionmaker[Session],
    clock: Clock,
    build_service: ServiceFactory,
) -> None:
    # Hold both requests between "look the indicator up" and "create it" so that each one
    # finds nothing and both try to insert, which is the race the conflict handling covers.
    barrier = threading.Barrier(2)
    waited = threading.local()

    def rendezvous(*args: Any) -> None:
        statement = args[2]
        if "FROM threat_indicators" in statement and not getattr(waited, "done", False):
            waited.done = True
            barrier.wait(timeout=10)

    service = build_service(strong_abuse(clock), FakeOtx())
    results: list[Any] = []
    errors: list[BaseException] = []

    def investigate() -> None:
        try:
            with session_factory() as worker_session:
                results.append(service.investigate(worker_session, CONTEXT, IP))
        except BaseException as exc:
            errors.append(exc)

    event.listen(engine, "after_cursor_execute", rendezvous)
    try:
        threads = [threading.Thread(target=investigate) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
    finally:
        event.remove(engine, "after_cursor_execute", rendezvous)

    assert errors == []
    assert len(results) == 2
    assert len({result.indicator.indicator_id for result in results}) == 1
    assert count(session_factory, ThreatIndicator) == 1
    assert count(session_factory, ThreatSource) == 2
    assert count(session_factory, AuditLog) == 2
    indicator_id = results[0].indicator.indicator_id
    observations = stored(session_factory, select(ThreatObservation))
    assert {obs.indicator_id for obs in observations} == {indicator_id}


# --- Reading stored indicators ------------------------------------------------------------


def test_reading_a_stored_indicator_makes_no_provider_calls_and_writes_nothing(
    session: Session,
    session_factory: sessionmaker[Session],
    clock: Clock,
    build_service: ServiceFactory,
) -> None:
    abuse, otx = strong_abuse(clock), FakeOtx()
    service = build_service(abuse, otx)
    investigated = service.investigate(session, CONTEXT, IP)
    audits, observations = (
        count(session_factory, AuditLog),
        count(session_factory, ThreatObservation),
    )

    clock.advance(minutes=5)
    read = service.get_investigation(session, investigated.indicator.indicator_id)

    assert read is not None
    assert (len(abuse.calls), len(otx.calls)) == (1, 1)
    assert read.score == investigated.score  # the stored snapshot, not a recomputation
    assert [(v.status, v.from_cache, v.freshness) for v in read.providers] == [
        ("ok", True, "fresh"),
        ("no_data", True, "fresh"),
    ]
    assert count(session_factory, AuditLog) == audits
    assert count(session_factory, ThreatObservation) == observations


def test_a_read_shows_current_freshness_next_to_the_stored_score(
    session: Session, clock: Clock, build_service: ServiceFactory
) -> None:
    service = build_service(strong_abuse(clock))
    investigated = service.investigate(session, CONTEXT, IP)
    scored_at = clock.now

    clock.advance(hours=2)
    read = service.get_investigation(session, investigated.indicator.indicator_id)

    assert read is not None
    assert read.providers[0].freshness == "stale"
    assert read.score.scored_at == scored_at
    assert read.score.score == investigated.score.score


def test_an_unknown_indicator_is_not_found(session: Session, build_service: ServiceFactory) -> None:
    assert build_service(FakeAbuse()).get_investigation(session, uuid.uuid4()) is None


@pytest.mark.parametrize("snapshot", [None, {"methodology": "intel-risk-v0"}])
def test_an_indicator_without_a_usable_snapshot_is_scored_on_the_fly_and_nothing_is_written(
    snapshot: dict[str, Any] | None,
    session: Session,
    session_factory: sessionmaker[Session],
    build_service: ServiceFactory,
) -> None:
    row = seed_indicator(session, IP, kind=IndicatorType.IPV4, score=55, score_detail=snapshot)
    service = build_service(FakeAbuse(), FakeOtx())

    read = service.get_investigation(session, row.id)

    assert read is not None
    assert [view.status for view in read.providers] == ["not_queried", "not_queried"]
    assert all(view.message for view in read.providers)
    assert read.score.scored_at is None
    assert read.score.answered_sources == 0
    assert read.indicator.risk_score == read.score.score == 0
    # The recomputed values are shown but not persisted, and no provider rows were created.
    [persisted] = stored(session_factory, select(ThreatIndicator))
    assert persisted.risk_score == 55
    assert persisted.score_detail == snapshot
    assert count(session_factory, ThreatSource) == 0
    assert count(session_factory, ThreatObservation) == 0


# --- Listing and statistics ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("classification", "scores"),
    [
        (Classification.INFORMATIONAL, {0, 20}),
        (Classification.LOW, {21, 40}),
        (Classification.MEDIUM, {41, 60}),
        (Classification.HIGH, {61, 80}),
        (Classification.CRITICAL, {81, 100}),
    ],
)
def test_filtering_by_classification_uses_the_documented_bands(
    classification: Classification,
    scores: set[int],
    session: Session,
    build_service: ServiceFactory,
) -> None:
    for score in (0, 20, 21, 40, 41, 60, 61, 80, 81, 100):
        seed_indicator(session, f"host-{score}.example.com", score=score)

    page = build_service().list_indicators(session, classification=classification)

    assert {item.risk_score for item in page.items} == scores
    assert page.total == len(scores)
    assert {item.classification for item in page.items} == {classification}


def test_filtering_by_type(session: Session, build_service: ServiceFactory) -> None:
    seed_indicator(session, "example.com", kind=IndicatorType.DOMAIN)
    seed_indicator(session, IP, kind=IndicatorType.IPV4)
    seed_indicator(session, "a" * 64, kind=IndicatorType.SHA256)

    page = build_service().list_indicators(session, indicator_type=IndicatorType.IPV4)

    assert [item.indicator_value for item in page.items] == [IP]


def test_search_text_is_matched_literally_and_case_insensitively(
    session: Session, build_service: ServiceFactory
) -> None:
    for value in ("a_b.example.com", "axb.example.com", "50%.example.com", "Mixed.Example.com"):
        seed_indicator(session, value)
    service = build_service()

    def search(text: str) -> list[str]:
        page = service.list_indicators(session, query=text, sort="risk")
        return sorted(item.indicator_value for item in page.items)

    assert search("a_b") == ["a_b.example.com"]  # "_" is not a wildcard
    assert search("%") == ["50%.example.com"]  # neither is "%"
    assert search("MIXED.example") == ["Mixed.Example.com"]
    assert search("' OR '1'='1") == []
    assert search("\\") == []
    assert len(search("example.com")) == 4


def test_sorting_by_risk_and_by_recency(session: Session, build_service: ServiceFactory) -> None:
    base = datetime(2025, 1, 1, tzinfo=UTC)
    for index, score in enumerate([10, 90, 50, 90, 30]):
        seed_indicator(
            session,
            f"host-{index}.example.com",
            score=score,
            updated_at=base + timedelta(minutes=index),
        )
    service = build_service()

    by_risk = service.list_indicators(session, sort="risk")
    by_recency = service.list_indicators(session, sort="recent")

    # Equal scores are ordered by recency.
    assert [item.indicator_value for item in by_risk.items] == [
        "host-3.example.com",
        "host-1.example.com",
        "host-2.example.com",
        "host-4.example.com",
        "host-0.example.com",
    ]
    assert [item.indicator_value for item in by_recency.items] == [
        f"host-{index}.example.com" for index in (4, 3, 2, 1, 0)
    ]


def test_pages_are_stable_and_disjoint_even_when_every_row_ties(
    session: Session, build_service: ServiceFactory
) -> None:
    moment = datetime(2025, 1, 1, tzinfo=UTC)
    for index in range(7):
        seed_indicator(session, f"tie-{index}.example.com", score=50, updated_at=moment)
    service = build_service()

    pages = [service.list_indicators(session, limit=3, offset=offset) for offset in (0, 3, 6)]

    assert [len(page.items) for page in pages] == [3, 3, 1]
    assert {(page.total, page.limit) for page in pages} == {(7, 3)}
    paged = [item.indicator_id for page in pages for item in page.items]
    assert len(set(paged)) == 7
    everything = service.list_indicators(session, limit=100)
    assert paged == [item.indicator_id for item in everything.items]
    assert service.list_indicators(session, limit=3, offset=50).items == []


def test_statistics_cover_every_bucket_and_only_recent_completed_lookups(
    session: Session,
    session_factory: sessionmaker[Session],
    clock: Clock,
    build_service: ServiceFactory,
) -> None:
    abuse = FakeAbuse(
        answers={
            TARGET: answer("abuseipdb", signal=STRONG, evidence_at=clock.ago(days=1)),
            f"ipv4:{OTHER_IP}": failure(ProviderStatus.RATE_LIMITED, "Slow down."),
        },
    )
    service = build_service(abuse, FakeOtx(api_key=None))
    service.investigate(session, CONTEXT, IP)  # success
    service.investigate(session, CONTEXT, OTHER_IP)  # partial: still a lookup
    with pytest.raises(InvalidIndicatorError):
        service.investigate(session, CONTEXT, "10.0.0.1")  # rejected: not a lookup
    session.add(
        AuditLog(
            timestamp=clock.ago(hours=25), actor="analyst-1", action="IOC_LOOKUP", result="success"
        )
    )
    session.commit()

    stats = service.stats(session)

    assert stats.lookups_last_24h == 2
    assert stats.total_indicators == 2
    assert stats.by_type == {"ipv4": 2, "ipv6": 0, "domain": 0, "url": 0, "sha256": 0}
    assert stats.by_classification == {
        "informational": 1,
        "low": 0,
        "medium": 1,
        "high": 0,
        "critical": 0,
    }
    abuse_info, otx_info = stats.providers
    assert (abuse_info.name, abuse_info.configured) == ("abuseipdb", True)
    assert abuse_info.supported_types == [IndicatorType.IPV4, IndicatorType.IPV6]
    assert (otx_info.name, otx_info.configured) == ("otx", False)
    assert len(otx_info.supported_types) == len(IndicatorType)


def test_statistics_of_an_empty_database_still_list_every_bucket(
    session: Session, build_service: ServiceFactory
) -> None:
    stats = build_service(FakeAbuse()).stats(session)

    assert stats.total_indicators == 0
    assert stats.lookups_last_24h == 0
    assert set(stats.by_type) == {member.value for member in IndicatorType}
    assert set(stats.by_classification) == {member.value for member in Classification}
    assert set(stats.by_type.values()) | set(stats.by_classification.values()) == {0}


# --- Lifecycle and contracts --------------------------------------------------------------


def test_close_is_idempotent_and_closes_the_http_client() -> None:
    client = httpx2.Client()
    service = IntelService([FakeAbuse()], http_client=client)

    service.close()
    service.close()

    assert client.is_closed


def test_every_provider_status_can_be_shown_by_the_api() -> None:
    assert {status.value for status in ProviderStatus} | {"not_queried"} == set(
        get_args(ProviderViewStatus)
    )
