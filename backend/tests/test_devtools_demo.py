"""The demo tooling: a catalogue that cannot accuse real hosts, simulated providers that run
through the real adapters, a replayable seeded history and a database path that stays confined.

Nothing here needs the network. Simulated answers are synthetic by construction.
"""

import hashlib
import ipaddress
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.collectors.abuseipdb import AbuseIPDBCollector
from app.collectors.base import Collector, ProviderResult, ProviderStatus
from app.collectors.otx import OTXCollector
from app.correlation.scoring import Classification, classify
from app.database.session import build_engine, build_session_factory
from app.models.audit import AuditLog
from app.models.enums import IndicatorType
from app.models.threat import ThreatIndicator
from app.schemas.intel import OverviewResponse
from app.services.audit import IOC_LOOKUP, RESULT_REJECTED
from app.services.intel_service import IntelService, RequestContext
from app.services.normalization import NormalizedIndicator, normalize_indicator
from devtools import demo_server
from devtools.demo_data import (
    BENIGN_DOMAINS,
    BENIGN_IPV4,
    FAILURE_SAMPLES,
    HASH_SAMPLE,
    HISTORY_DAYS,
    REJECTED_INPUTS,
    UNALLOCATED_IPV6_PREFIX,
    DemoClock,
    DemoIndicator,
    SeedSummary,
    build_catalogue,
    plan_history,
    seed_demo,
    tiers_of,
)
from devtools.demo_server import (
    DEFAULT_DATABASE_NAME,
    create_demo_app,
    demo_database_path,
    demo_settings,
    prepare_database,
)
from devtools.simulated_providers import Tier, build_simulated_collectors

# A Wednesday afternoon: every one of the 14 charted days has at least six elapsed hours.
FIXED_NOW = datetime(2025, 6, 11, 15, 20, tzinfo=UTC)
DOCUMENTATION_SUFFIXES = (".example.com", ".example.org", ".example.net")
MALICIOUS_TIERS = (Tier.CRITICAL, Tier.HIGH, Tier.MEDIUM, Tier.LOW)
IP_TYPES = (IndicatorType.IPV4, IndicatorType.IPV6)


def _host(entry: DemoIndicator) -> str:
    if entry.indicator_type is IndicatorType.URL:
        return urlsplit(entry.value).hostname or ""
    return entry.value


# --- Catalogue ---------------------------------------------------------------------------


def test_catalogue_values_are_unique_and_already_canonical() -> None:
    catalogue = build_catalogue()
    keys = [(entry.indicator_type, entry.value) for entry in catalogue]
    assert len(keys) == len(set(keys))
    for entry in catalogue:
        normalized = normalize_indicator(entry.value)
        assert (normalized.indicator_type, normalized.indicator_value) == (
            entry.indicator_type,
            entry.value,
        )


def test_catalogue_is_deterministic_and_covers_every_type() -> None:
    first, second = build_catalogue(), build_catalogue()
    assert first == second
    assert {entry.indicator_type for entry in first} == set(IndicatorType)
    assert {entry.tier for entry in first} == set(Tier)


def test_catalogue_cannot_accuse_a_real_host() -> None:
    sample_hashes = {
        hashlib.sha256(HASH_SAMPLE.format(number=number).encode()).hexdigest()
        for number in range(1, 500)
    }
    unallocated = ipaddress.ip_network(f"{UNALLOCATED_IPV6_PREFIX}::/16")
    for entry in build_catalogue():
        match entry.indicator_type:
            case IndicatorType.IPV4:
                # Only well-known public resolvers, and only ever simulated as clean.
                assert entry.value in BENIGN_IPV4
                assert entry.tier is Tier.CLEAN
            case IndicatorType.IPV6:
                assert ipaddress.ip_address(entry.value) in unallocated
            case IndicatorType.DOMAIN | IndicatorType.URL:
                host = _host(entry)
                if host in BENIGN_DOMAINS:
                    assert entry.tier is Tier.CLEAN
                else:
                    assert host.endswith(DOCUMENTATION_SUFFIXES), host
            case IndicatorType.SHA256:
                assert entry.value in sample_hashes


def test_the_unallocated_prefix_is_accepted_by_the_real_normalizer() -> None:
    # If the normalizer ever started refusing it, the demo would silently lose its IP addresses.
    assert normalize_indicator("2100:4a:1c::7").indicator_type is IndicatorType.IPV6


# --- Simulated providers -----------------------------------------------------------------


@dataclass(frozen=True)
class Simulation:
    catalogue: list[DemoIndicator]
    collectors: tuple[Collector, ...]

    def lookup(self, indicator_type: IndicatorType, value: str) -> dict[str, ProviderResult]:
        indicator = NormalizedIndicator(indicator_type, value)
        return {
            collector.name: collector.lookup(indicator)
            for collector in self.collectors
            if collector.supports(indicator_type)
        }


@pytest.fixture
def simulation() -> Iterator[Simulation]:
    catalogue = build_catalogue()
    collectors, client = build_simulated_collectors(lambda: FIXED_NOW, tiers=tiers_of(catalogue))
    yield Simulation(catalogue, collectors)
    client.close()


def test_simulated_adapters_are_flagged_and_the_real_ones_are_not(simulation: Simulation) -> None:
    assert all(collector.simulated for collector in simulation.collectors)
    assert {collector.name for collector in simulation.collectors} == {"abuseipdb", "otx"}
    assert AbuseIPDBCollector.simulated is False
    assert OTXCollector.simulated is False


def test_simulated_answers_parse_through_the_real_adapters(simulation: Simulation) -> None:
    for entry in simulation.catalogue:
        if entry.value in FAILURE_SAMPLES:
            continue
        results = simulation.lookup(entry.indicator_type, entry.value)
        expected = {"abuseipdb", "otx"} if entry.indicator_type in IP_TYPES else {"otx"}
        assert set(results) == expected
        for result in results.values():
            assert result.status in (ProviderStatus.OK, ProviderStatus.NO_DATA), entry
            if entry.tier in MALICIOUS_TIERS:
                assert result.status is ProviderStatus.OK, entry
                assert result.signal > 0, entry
                assert result.evidence_at is not None
                assert result.evidence_at <= FIXED_NOW
            else:
                assert result.signal == 0, entry


def test_simulated_answers_are_deterministic(simulation: Simulation) -> None:
    other, client = build_simulated_collectors(
        lambda: FIXED_NOW, tiers=tiers_of(simulation.catalogue)
    )
    try:
        again = Simulation(simulation.catalogue, other)
        for entry in simulation.catalogue[:30]:
            kind, value = entry.indicator_type, entry.value
            assert again.lookup(kind, value) == simulation.lookup(kind, value)
    finally:
        client.close()


def test_simulated_pulses_are_labelled_and_never_link_to_a_real_pulse(
    simulation: Simulation,
) -> None:
    for entry in simulation.catalogue:
        if entry.tier not in MALICIOUS_TIERS:
            continue
        pulses = simulation.lookup(entry.indicator_type, entry.value)["otx"].summary["top_pulses"]
        assert pulses
        for pulse in pulses:
            assert pulse["name"].endswith("(simulated)")
            assert not pulse.get("id")


@pytest.mark.parametrize(
    ("value", "status"),
    [
        ("rate-limit.example.com", ProviderStatus.RATE_LIMITED),
        ("provider-error.example.com", ProviderStatus.ERROR),
        (FAILURE_SAMPLES[0], ProviderStatus.RATE_LIMITED),
        (FAILURE_SAMPLES[1], ProviderStatus.ERROR),
    ],
)
def test_failure_markers_surface_as_provider_failures(
    simulation: Simulation, value: str, status: ProviderStatus
) -> None:
    result = simulation.lookup(IndicatorType.DOMAIN, value)["otx"]
    assert result.status is status
    assert not result.is_answer


# --- Seeded history ----------------------------------------------------------------------


def test_planned_history_is_replayable_and_covers_the_catalogue() -> None:
    catalogue = build_catalogue()
    plan = plan_history(catalogue, FIXED_NOW)
    assert plan == plan_history(catalogue, FIXED_NOW)
    assert [step.moment for step in plan] == sorted(step.moment for step in plan)
    window_start = (FIXED_NOW - timedelta(days=HISTORY_DAYS - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    assert all(window_start <= step.moment <= FIXED_NOW for step in plan)
    planned = {step.value for step in plan}
    assert {entry.value for entry in catalogue} <= planned
    assert set(REJECTED_INPUTS) <= planned


@dataclass
class Seeded:
    summary: SeedSummary
    catalogue: list[DemoIndicator]
    session_factory: sessionmaker[Session]
    service: IntelService
    clock: DemoClock

    def overview(self) -> OverviewResponse:
        self.clock.pin(FIXED_NOW)
        try:
            with self.session_factory() as session:
                return self.service.overview(session)
        finally:
            self.clock.unpin()


@pytest.fixture(scope="module")
def seeded(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Seeded]:
    path = tmp_path_factory.mktemp("demo") / DEFAULT_DATABASE_NAME
    assert prepare_database(path, reset=False, now=FIXED_NOW) is True
    catalogue = build_catalogue()
    clock = DemoClock()
    collectors, client = build_simulated_collectors(clock, tiers=tiers_of(catalogue))
    service = IntelService(collectors, http_client=client, clock=clock)
    engine = build_engine(demo_settings(path))
    session_factory = build_session_factory(engine)
    try:
        summary = seed_demo(service, session_factory, clock, catalogue=catalogue, now=FIXED_NOW)
        yield Seeded(summary, catalogue, session_factory, service, clock)
    finally:
        service.close()
        engine.dispose()


def test_seeding_replays_every_catalogue_entry_through_the_real_service(seeded: Seeded) -> None:
    assert seeded.summary.indicators == len(seeded.catalogue)
    assert seeded.summary.rejected == len(REJECTED_INPUTS)
    assert seeded.summary.lookups >= len(seeded.catalogue) + 80
    with seeded.session_factory() as session:
        stored = set(session.scalars(select(ThreatIndicator.indicator_value)))
    assert stored == {entry.value for entry in seeded.catalogue}


def test_rejected_inputs_are_audited_without_recording_the_input(seeded: Seeded) -> None:
    with seeded.session_factory() as session:
        rows = session.scalars(
            select(AuditLog).where(
                AuditLog.action == IOC_LOOKUP, AuditLog.result == RESULT_REJECTED
            )
        ).all()
    assert len(rows) == len(REJECTED_INPUTS)
    assert all(row.target is None for row in rows)
    assert all(row.timestamp <= FIXED_NOW for row in rows)


def test_seeded_scores_follow_the_methodology(seeded: Seeded) -> None:
    tiers = tiers_of(seeded.catalogue)
    with seeded.session_factory() as session:
        indicators = session.scalars(select(ThreatIndicator)).all()
    assert len(indicators) == len(seeded.catalogue)
    for row in indicators:
        tier = tiers[(row.indicator_type, row.indicator_value)]
        band = classify(row.risk_score)
        if row.indicator_value in FAILURE_SAMPLES:
            assert row.confidence == 0, "no provider answered, so it is not assessed"
        elif tier in (Tier.CLEAN, Tier.UNKNOWN):
            assert band is Classification.INFORMATIONAL, row.indicator_value
        elif row.indicator_type not in IP_TYPES:
            # One provider only: never High or Critical on a single source's word.
            assert band not in (Classification.HIGH, Classification.CRITICAL)
        elif tier is Tier.CRITICAL:
            assert band in (Classification.HIGH, Classification.CRITICAL), row.indicator_value
        elif tier is Tier.LOW:
            assert band in (Classification.LOW, Classification.MEDIUM), row.indicator_value


def test_seeded_overview_is_rich_enough_to_demonstrate_the_dashboard(seeded: Seeded) -> None:
    overview = seeded.overview()
    kpis = overview.kpis
    assert kpis.total_indicators == len(seeded.catalogue)
    assert kpis.lookups_24h > 0
    assert kpis.lookups_prev_24h > 0
    assert kpis.new_indicators_24h > 0
    assert kpis.not_assessed_indicators == len(FAILURE_SAMPLES)

    for band in Classification:
        assert overview.by_classification[band.value] > 0, band
    assert set(overview.by_type) == {kind.value for kind in IndicatorType}

    assert len(overview.series) == HISTORY_DAYS
    assert all(point.lookups > 0 for point in overview.series)
    assert any(point.high_risk_lookups > 0 for point in overview.series)

    assert len(overview.countries) >= 10
    assert len(overview.malware_families) >= 5
    assert len(overview.attack_techniques) >= 5
    assert len(overview.tags) >= 5
    assert overview.top_risk
    assert overview.top_risk[0].classification is Classification.CRITICAL
    assert all(provider.simulated for provider in overview.providers)
    assert overview.scope.lookups_truncated is False


# --- Demo server -------------------------------------------------------------------------


@pytest.fixture
def demo_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / ".demo"
    directory.mkdir()
    monkeypatch.setattr(demo_server, "DEMO_DIR", directory)
    monkeypatch.delenv("CIPHERFORGE_DEMO_DB", raising=False)
    return directory


def test_demo_database_defaults_to_the_demo_directory(demo_dir: Path) -> None:
    assert demo_database_path() == demo_dir.resolve() / DEFAULT_DATABASE_NAME


def test_demo_database_can_be_renamed_inside_the_demo_directory(
    demo_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CIPHERFORGE_DEMO_DB", str(demo_dir / "e2e.db"))
    assert demo_database_path() == demo_dir.resolve() / "e2e.db"


@pytest.mark.parametrize(
    "relative",
    ["../elsewhere.db", "nested/deeper.db", "plain.sqlite", "../.demo/../escape.db", "demo.db/.."],
)
def test_demo_database_refuses_anything_outside_the_demo_directory(
    demo_dir: Path, monkeypatch: pytest.MonkeyPatch, relative: str
) -> None:
    monkeypatch.setenv("CIPHERFORGE_DEMO_DB", str(demo_dir / relative))
    with pytest.raises(RuntimeError, match=r"backend/\.demo"):
        demo_database_path()


def test_demo_database_refuses_a_real_database_path(
    demo_dir: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("CIPHERFORGE_DEMO_DB", str(tmp_path / "cipherforge.db"))
    with pytest.raises(RuntimeError):
        demo_database_path()


def test_demo_settings_ignore_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A real database URL in the environment must never be picked up by the demo.
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://real-user:secret@db.internal/prod")
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("AUTH_MODE", "entra")
    path = tmp_path / "demo.db"
    settings = demo_settings(path)
    assert settings.environment == "development"
    assert settings.auth_mode == "dev"
    assert settings.database_url.get_secret_value() == f"sqlite+pysqlite:///{path.as_posix()}"


def test_prepare_database_seeds_only_when_empty_or_stale_or_reset(tmp_path: Path) -> None:
    path = tmp_path / "demo.db"
    assert prepare_database(path, reset=False, now=FIXED_NOW) is True

    engine = build_engine(demo_settings(path))
    factory = build_session_factory(engine)
    clock = DemoClock()
    collectors, client = build_simulated_collectors(clock)
    service = IntelService(collectors, http_client=client, clock=clock)
    try:
        clock.pin(FIXED_NOW - timedelta(hours=2))
        with factory() as session:
            service.investigate(session, RequestContext("tester", "203.0.113.7"), "8.8.8.8")
    finally:
        service.close()
        engine.dispose()

    assert prepare_database(path, reset=False, now=FIXED_NOW) is False
    assert prepare_database(path, reset=False, now=FIXED_NOW + timedelta(days=2)) is True
    assert prepare_database(path, reset=True, now=FIXED_NOW) is True


def test_create_demo_app_serves_a_simulated_seeded_dashboard(
    demo_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CIPHERFORGE_DEMO_DB", str(demo_dir / "app.db"))
    with TestClient(create_demo_app()) as client:
        assert client.get("/api/v1/me").json()["roles"] == ["SecurityAnalyst"]

        overview = client.get("/api/v1/intel/overview")
        assert overview.status_code == 200
        body = overview.json()
        assert body["kpis"]["total_indicators"] == len(build_catalogue())
        assert body["providers"]
        assert all(provider["simulated"] for provider in body["providers"])

        fresh = client.post("/api/v1/intel/investigate", json={"indicator": "2100:abcd::99"})
        assert fresh.status_code == 200
        assert {view["status"] for view in fresh.json()["providers"]} <= {"ok", "no_data"}

        limited = client.post(
            "/api/v1/intel/investigate", json={"indicator": "rate-limit.example.com"}
        )
        assert limited.status_code == 200
        statuses = {view["provider"]: view["status"] for view in limited.json()["providers"]}
        assert statuses["otx"] == "rate_limited"
