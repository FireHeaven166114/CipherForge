"""The overview aggregates: figures computed from stored indicators, answers and audit rows.

Providers are scripted fakes and the service clock is controlled, so the figures are exact.
"""

import uuid
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.collectors.base import Collector
from app.core.config import Settings
from app.core.timeutil import IST
from app.correlation.scoring import Classification
from app.database.session import build_engine, build_session_factory
from app.models.audit import AuditLog
from app.models.enums import IndicatorType
from app.models.threat import ThreatIndicator, ThreatObservation, ThreatSource
from app.schemas.intel import FacetEntry
from app.services import overview as overview_module
from app.services.intel_service import IntelService, RequestContext
from app.services.normalization import InvalidIndicatorError
from tests.intel_helpers import MODERATE, STRONG, Clock, FakeAbuse, FakeOtx, answer

CONTEXT = RequestContext(actor="analyst-1", source_ip="203.0.113.9")
IP_A = "185.220.101.45"
IP_B = "45.76.19.203"
IP_C = "103.27.108.53"
DOMAIN_A = "alpha.example.com"
DOMAIN_B = "beta.example.com"

ServiceFactory = Callable[..., IntelService]


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

    def factory(*collectors: Collector) -> IntelService:
        service = IntelService(collectors, clock=clock)
        services.append(service)
        return service

    yield factory
    for service in services:
        service.close()


def keyed(entries: Sequence[FacetEntry]) -> dict[str, int]:
    return {entry.key: entry.count for entry in entries}


def scripted_service(clock: Clock, build_service: ServiceFactory) -> IntelService:
    """Five indicators whose latest answers carry known countries, families and techniques."""
    evidence = clock.ago(days=1)
    abuse = FakeAbuse(
        answers={
            f"ipv4:{IP_A}": answer(
                "abuseipdb",
                signal=STRONG,
                evidence_at=evidence,
                tags=["tor"],
                summary={"country_code": "NL"},
            ),
            f"ipv4:{IP_B}": answer(
                "abuseipdb",
                signal=MODERATE,
                evidence_at=evidence,
                summary={"country_code": "NL"},
            ),
            f"ipv4:{IP_C}": answer(
                "abuseipdb",
                signal=STRONG,
                evidence_at=evidence,
                summary={"country_code": "DE"},
            ),
        }
    )
    otx = FakeOtx(
        answers={
            f"domain:{DOMAIN_A}": answer(
                "otx",
                signal=STRONG,
                evidence_at=evidence,
                tags=["phishing"],
                families=["Emotet"],
                summary={"attack_ids": ["T1059", "T1566"]},
            ),
            f"ipv4:{IP_A}": answer(
                "otx",
                signal=MODERATE,
                evidence_at=evidence,
                tags=["botnet"],
                families=["Emotet", "TrickBot"],
                summary={"attack_ids": ["T1059"]},
            ),
        }
    )
    return build_service(abuse, otx)


def test_an_empty_database_yields_a_complete_zeroed_overview(
    session: Session, clock: Clock, build_service: ServiceFactory
) -> None:
    result = build_service(FakeAbuse(), FakeOtx()).overview(session)

    assert result.generated_at == clock.now
    assert set(result.kpis.model_dump().values()) == {0}
    assert [point.day for point in result.series] == [
        clock.now.date() - timedelta(days=offset) for offset in range(13, -1, -1)
    ]
    assert [len(row.hours) for row in result.activity] == [24] * 7
    assert [row.indicator_type for row in result.matrix] == list(IndicatorType)
    assert set(result.by_classification.values()) == {0}
    for entries in (result.countries, result.malware_families, result.attack_techniques):
        assert entries == []
    assert result.top_risk == [] and result.recent == []
    assert not result.scope.lookups_truncated and not result.scope.answers_truncated


def test_the_overview_counts_bands_attributes_and_rankings(
    session: Session, clock: Clock, build_service: ServiceFactory
) -> None:
    service = scripted_service(clock, build_service)
    investigated = {}
    for value in (IP_A, IP_B, IP_C, DOMAIN_A, DOMAIN_B):
        investigated[value] = service.investigate(session, CONTEXT, value).indicator
        clock.advance(seconds=1)
    # No provider answered for this one: it is "not assessed", not "informational".
    session.add(ThreatIndicator(indicator_type="domain", indicator_value="unseen.example.net"))
    session.commit()

    result = service.overview(session)

    bands = Counter(item.classification.value for item in investigated.values())
    assert result.by_classification == {
        "informational": bands["informational"],
        "low": bands["low"],
        "medium": bands["medium"],
        "high": bands["high"],
        "critical": bands["critical"],
        "not_assessed": 1,
    }
    assert result.kpis.total_indicators == 6
    assert result.kpis.not_assessed_indicators == 1
    assert result.kpis.high_risk_indicators == bands["high"] + bands["critical"]
    assert result.by_type == {
        "ipv4": 3,
        "ipv6": 0,
        "domain": 3,
        "url": 0,
        "md5": 0,
        "sha1": 0,
        "sha256": 0,
    }
    domains = next(row for row in result.matrix if row.indicator_type is IndicatorType.DOMAIN)
    assert domains.counts["not_assessed"] == 1
    assert sum(domains.counts.values()) == 3

    assert keyed(result.countries) == {"NL": 2, "DE": 1}
    assert keyed(result.malware_families) == {"Emotet": 2, "TrickBot": 1}
    assert keyed(result.attack_techniques) == {"T1059": 2, "T1566": 1}
    assert keyed(result.tags) == {"botnet": 1, "phishing": 1, "tor": 1}
    emotet = result.malware_families[0]
    assert emotet.key == "Emotet"
    assert {sample.indicator_value for sample in emotet.samples} == {IP_A, DOMAIN_A}
    assert emotet.max_risk == max(sample.risk_score for sample in emotet.samples)
    assert [sample.risk_score for sample in emotet.samples] == sorted(
        (sample.risk_score for sample in emotet.samples), reverse=True
    )

    scores = [item.risk_score for item in result.top_risk]
    assert scores == sorted(scores, reverse=True) and 0 not in scores
    recent = [item.indicator_value for item in result.recent if item.confidence > 0]
    assert recent == [DOMAIN_B, DOMAIN_A, IP_C, IP_B, IP_A]


def test_every_overview_count_equals_the_total_of_the_list_it_leads_to(
    session: Session, clock: Clock, build_service: ServiceFactory
) -> None:
    service = scripted_service(clock, build_service)
    for value in (IP_A, IP_B, IP_C, DOMAIN_A, DOMAIN_B):
        service.investigate(session, CONTEXT, value)
        clock.advance(seconds=1)
    session.add(ThreatIndicator(indicator_type="domain", indicator_value="unseen.example.net"))
    session.commit()

    result = service.overview(session)

    def total(**filters: Any) -> int:
        return service.list_indicators(session, **filters).total

    assert result.kpis.not_assessed_indicators == 1, "the data must hold an unassessed indicator"
    assert total() == result.kpis.total_indicators
    assert total(assessed=False) == result.by_classification["not_assessed"]
    for band in Classification:
        assert total(classifications=[band], assessed=True) == result.by_classification[band.value]
    assert (
        total(classifications=[Classification.HIGH, Classification.CRITICAL], assessed=True)
        == result.kpis.high_risk_indicators
    )
    for row in result.matrix:
        assert total(indicator_type=row.indicator_type) == result.by_type[row.indicator_type.value]
        assert (
            total(indicator_type=row.indicator_type, assessed=False) == row.counts["not_assessed"]
        )
        for band in Classification:
            assert (
                total(indicator_type=row.indicator_type, classifications=[band], assessed=True)
                == row.counts[band.value]
            )


def test_lookups_are_bucketed_by_ist_day_and_compared_with_the_previous_24_hours(
    session: Session, clock: Clock, build_service: ServiceFactory
) -> None:
    service = build_service(FakeAbuse(), FakeOtx())
    base = clock.now
    moments = [base - timedelta(hours=30), base - timedelta(hours=3), base - timedelta(days=5)]
    for moment, value in zip(moments, (IP_A, IP_B, DOMAIN_A), strict=True):
        clock.now = moment
        service.investigate(session, CONTEXT, value)
    clock.now = base

    result = service.overview(session)

    assert result.kpis.lookups_24h == 1
    assert result.kpis.lookups_prev_24h == 1
    assert result.kpis.new_indicators_24h == 1
    assert result.kpis.new_indicators_prev_24h == 1
    per_day = {point.day: point.lookups for point in result.series if point.lookups}
    assert per_day == dict(Counter(moment.astimezone(IST).date() for moment in moments))
    cells = {row.day: row.hours for row in result.activity}
    recent = moments[1].astimezone(IST)
    assert cells[recent.date()][recent.hour] >= 1
    assert sum(sum(row.hours) for row in result.activity) == 3


def test_a_lookup_just_after_midnight_in_india_belongs_to_the_next_ist_day(
    session: Session, clock: Clock, build_service: ServiceFactory
) -> None:
    service = build_service(FakeAbuse(), FakeOtx())
    # 18:00 UTC is 23:30 IST on 10 June; 19:00 UTC is 00:30 IST on 11 June.
    before_midnight = datetime(2025, 6, 10, 18, 0, tzinfo=UTC)
    after_midnight = datetime(2025, 6, 10, 19, 0, tzinfo=UTC)
    for moment, value in ((before_midnight, IP_A), (after_midnight, IP_B)):
        clock.now = moment
        service.investigate(session, CONTEXT, value)
    clock.now = datetime(2025, 6, 11, 10, 0, tzinfo=UTC)

    result = service.overview(session)

    per_day = {point.day.isoformat(): point.lookups for point in result.series if point.lookups}
    assert per_day == {"2025-06-10": 1, "2025-06-11": 1}
    cells = {row.day.isoformat(): row.hours for row in result.activity}
    assert cells["2025-06-10"][23] == 1
    assert cells["2025-06-11"][0] == 1
    assert result.series[-1].day.isoformat() == "2025-06-11"


def test_rejected_inputs_and_old_lookups_are_not_counted(
    session: Session, clock: Clock, build_service: ServiceFactory
) -> None:
    service = build_service(FakeAbuse(), FakeOtx())
    with pytest.raises(InvalidIndicatorError):
        service.investigate(session, CONTEXT, "10.0.0.1")
    session.add(
        AuditLog(timestamp=clock.ago(days=15), actor="a", action="IOC_LOOKUP", result="success")
    )
    session.commit()

    result = service.overview(session)

    assert result.kpis.lookups_24h == 0
    assert sum(point.lookups for point in result.series) == 0


def test_a_lookup_is_flagged_high_risk_from_the_classification_it_was_audited_with(
    session: Session, clock: Clock, build_service: ServiceFactory
) -> None:
    service = scripted_service(clock, build_service)
    strong = service.investigate(session, CONTEXT, IP_A).indicator
    service.investigate(session, CONTEXT, DOMAIN_B)

    result = service.overview(session)

    today = result.series[-1]
    assert today.lookups == 2
    assert today.high_risk_lookups == (
        1 if strong.classification.value in {"high", "critical"} else 0
    )


def test_audit_rows_carry_the_service_clock(
    session: Session, clock: Clock, build_service: ServiceFactory
) -> None:
    clock.now = clock.ago(days=3)

    build_service(FakeAbuse(), FakeOtx()).investigate(session, CONTEXT, IP_A)

    assert session.scalars(select(AuditLog.timestamp)).one() == clock.now


def add_answer(
    session: Session,
    indicator: ThreatIndicator,
    source: ThreatSource,
    *,
    fetched_at: datetime,
    summary: dict[str, Any],
    tags: list[Any] | None = None,
    status: str = "ok",
) -> None:
    session.add(
        ThreatObservation(
            indicator_id=indicator.id,
            source_id=source.id,
            status=status,
            signal=0.5,
            fetched_at=fetched_at,
            summary=summary,
            tags=tags or [],
        )
    )


@pytest.fixture
def source(session: Session) -> ThreatSource:
    row = ThreatSource(name="otx", display_name="AlienVault OTX")
    session.add(row)
    session.commit()
    return row


def indicator_row(session: Session, value: str, score: int = 50) -> ThreatIndicator:
    row = ThreatIndicator(
        indicator_type="domain", indicator_value=value, risk_score=score, confidence=40
    )
    session.add(row)
    session.commit()
    return row


def test_only_the_latest_answer_per_provider_and_indicator_counts(
    session: Session, clock: Clock, source: ThreatSource, build_service: ServiceFactory
) -> None:
    row = indicator_row(session, DOMAIN_A)
    add_answer(
        session, row, source, fetched_at=clock.ago(days=2), summary={"malware_families": ["Old"]}
    )
    add_answer(
        session, row, source, fetched_at=clock.ago(hours=1), summary={"malware_families": ["New"]}
    )
    session.commit()

    result = build_service(FakeAbuse(), FakeOtx()).overview(session)

    assert keyed(result.malware_families) == {"New": 1}
    assert result.scope.answers_scanned == 2


def test_malformed_provider_json_is_ignored_not_trusted(
    session: Session, clock: Clock, source: ThreatSource, build_service: ServiceFactory
) -> None:
    row = indicator_row(session, DOMAIN_A)
    add_answer(
        session,
        row,
        source,
        fetched_at=clock.now,
        summary={
            "country_code": "zz1",
            "malware_families": "not-a-list",
            "attack_ids": ["T1059", "T1059.001", "nope", 5, None, "T12"],
        },
        tags=["ok", 5, "", "  ", "x" * 200],
    )
    other = indicator_row(session, DOMAIN_B)
    add_answer(session, other, source, fetched_at=clock.now, summary={"country_code": "us"})
    no_data = indicator_row(session, "gamma.example.com")
    add_answer(
        session,
        no_data,
        source,
        fetched_at=clock.now,
        summary={"malware_families": ["Ignored"]},
        status="no_data",
    )
    session.commit()

    result = build_service(FakeAbuse(), FakeOtx()).overview(session)

    assert result.countries == []
    assert result.malware_families == []
    assert keyed(result.attack_techniques) == {"T1059": 1, "T1059.001": 1}
    assert set(keyed(result.tags)) == {"ok", "x" * 64}


def test_the_answer_scan_is_bounded_and_says_so(
    session: Session,
    clock: Clock,
    source: ThreatSource,
    build_service: ServiceFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for index in range(3):
        row = indicator_row(session, f"host{index}.example.com")
        add_answer(
            session,
            row,
            source,
            fetched_at=clock.ago(minutes=index),
            summary={"malware_families": [f"Family{index}"]},
        )
    session.commit()
    monkeypatch.setattr(overview_module, "ANSWER_SCAN_LIMIT", 2)

    result = build_service(FakeAbuse(), FakeOtx()).overview(session)

    assert result.scope.answers_truncated is True
    assert result.scope.answers_scanned == 2
    assert set(keyed(result.malware_families)) == {"Family0", "Family1"}  # the newest answers


def test_facet_samples_are_capped_and_listed_highest_risk_first(
    session: Session, clock: Clock, source: ThreatSource, build_service: ServiceFactory
) -> None:
    for index in range(7):
        row = indicator_row(session, f"host{index}.example.com", score=10 * (index + 1))
        add_answer(
            session, row, source, fetched_at=clock.now, summary={"malware_families": ["Emotet"]}
        )
    session.commit()

    entry = build_service(FakeAbuse(), FakeOtx()).overview(session).malware_families[0]

    assert entry.count == 7
    assert [sample.risk_score for sample in entry.samples] == [70, 60, 50, 40, 30]
    assert entry.max_risk == 70


def test_simulated_adapters_are_flagged_and_real_ones_are_not(
    build_service: ServiceFactory,
) -> None:
    class SimulatedOtx(FakeOtx):
        simulated = True

    providers = build_service(FakeAbuse(), SimulatedOtx()).providers()

    assert [provider.simulated for provider in providers] == [False, True]


def test_an_indicator_id_in_a_sample_resolves_to_the_stored_indicator(
    session: Session, clock: Clock, source: ThreatSource, build_service: ServiceFactory
) -> None:
    row = indicator_row(session, DOMAIN_A, score=64)
    add_answer(session, row, source, fetched_at=clock.now, summary={"malware_families": ["X"]})
    session.commit()

    sample = build_service(FakeAbuse(), FakeOtx()).overview(session).malware_families[0].samples[0]

    assert isinstance(sample.indicator_id, uuid.UUID)
    assert (sample.indicator_value, sample.risk_score) == (DOMAIN_A, 64)
    assert sample.classification.value == "high"
