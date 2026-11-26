"""SessionRecorder: what reaches the database, what is only counted, and what a database that is
locked, gone or slow does to it."""

import threading
import uuid
from collections.abc import Callable, Iterator
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.database.session import build_engine, build_session_factory
from app.detection.network_rules import PORT_SCAN, NetworkRuleConfig, RawAlert, severity_for
from app.models.enums import AlertSeverity, CaptureSource, CaptureStatus, FlowCloseReason
from app.models.network import CaptureSession, NetworkAlert, NetworkFlow
from app.models.types import utcnow
from app.network import recorder as recorder_module
from app.network.analyzer import Analyzer, AnalyzerOutput, AnalyzerSnapshot
from app.network.flows import Flow
from app.network.recorder import SessionRecorder, alert_row, flow_row, initial_enrichment
from app.network.repository import delete_session
from tests.network_helpers import (
    HOST,
    RESOLVER,
    SCANNER,
    SERVER,
    T0,
    FlakyFactory,
    assert_no_module_threads,
    scan_packets,
    seed_session,
)

SessionFactory = sessionmaker[Session]


@pytest.fixture
def factory(make_settings: Callable[..., Settings], db_url: str) -> Iterator[SessionFactory]:
    engine = build_engine(make_settings(database_url=db_url))
    yield build_session_factory(engine)
    engine.dispose()


@pytest.fixture(autouse=True)
def _no_leaked_threads() -> Iterator[None]:
    yield
    assert_no_module_threads()


@pytest.fixture
def make_recorder(factory: SessionFactory) -> Callable[..., SessionRecorder]:
    def build(session_id: Any, *, session_factory: Any = None, **overrides: Any) -> SessionRecorder:
        options: dict[str, Any] = {
            "max_stored_flows": 1000,
            "enrichment_enabled": True,
            "stats_lock": threading.Lock(),
            "retry_delay": 0.0,
        }
        options.update(overrides)
        return SessionRecorder(session_factory or factory, session_id, **options)

    return build


def running_session(factory: SessionFactory, **overrides: Any) -> Any:
    options: dict[str, Any] = {
        "status": CaptureStatus.RUNNING,
        "source": CaptureSource.LIVE,
        "interface": "Test Ethernet",
        "label": None,
    }
    options.update(overrides)
    return seed_session(factory, **options)


def snapshot_of(analyzer: Analyzer | None = None) -> AnalyzerSnapshot:
    return (analyzer or Analyzer(NetworkRuleConfig(), idle_timeout=60.0, max_flows=100)).snapshot()


def raw_alert(index: int, *, src: str | None = None, dst: str | None = SERVER) -> RawAlert:
    return RawAlert(
        rule_id="NET-001",
        rule_name="port_scan",
        severity=AlertSeverity.MEDIUM,
        explanation=f"Alert {index}.",
        observed_value=20,
        threshold=20,
        window_seconds=60,
        first_observed=T0 + index,
        last_observed=T0 + index,
        src_ip=src or f"10.0.1.{index}",
        dst_ip=dst,
        protocol="tcp",
    )


def flow(index: int) -> Flow:
    return Flow(
        protocol="tcp",
        src_ip=HOST,
        src_port=40000 + index,
        dst_ip=SERVER,
        dst_port=80,
        first_seen=T0 + index,
        last_seen=T0 + index,
        packets_out=1,
        bytes_out=60,
        tcp_flags=2,
        close_reason=FlowCloseReason.CLOSED,
    )


def output(*, alerts: int = 0, flows: int = 0, first_flow: int = 0) -> AnalyzerOutput:
    return AnalyzerOutput(
        alerts=[raw_alert(index) for index in range(1, alerts + 1)],
        flows=[flow(first_flow + index) for index in range(flows)],
    )


def store(
    recorder: SessionRecorder,
    batch: AnalyzerOutput,
    snapshot: AnalyzerSnapshot | None = None,
    *,
    dropped: int = 0,
    stats: dict[str, Any] | None = None,
) -> bool:
    snapshot = snapshot or snapshot_of()
    return recorder.write(
        batch,
        snapshot,
        stats=stats if stats is not None else snapshot.as_stats(),
        packets_dropped=dropped,
    )


def session_row(factory: SessionFactory, session_id: Any) -> CaptureSession:
    with factory() as db:
        row = db.get(CaptureSession, session_id)
        assert row is not None
        return row


def children(factory: SessionFactory, model: Any, session_id: Any) -> list[Any]:
    with factory() as db:
        return list(db.scalars(select(model).where(model.session_id == session_id)))


# --- Storing a batch -------------------------------------------------------------------------


def test_write_stores_flows_alerts_and_totals(
    factory: SessionFactory, make_recorder: Callable[..., SessionRecorder]
) -> None:
    session_id = running_session(factory)
    analyzer = Analyzer(NetworkRuleConfig(), idle_timeout=60.0, max_flows=1000)
    for packet in scan_packets():
        analyzer.process(packet)
    analyzer.finish()
    recorder = make_recorder(session_id)

    assert store(recorder, analyzer.take_output(), analyzer.snapshot(), dropped=7)

    row = session_row(factory, session_id)
    assert (row.packets_total, row.bytes_total, row.flows_total) == (30, 30 * 60, 30)
    assert (row.alerts_total, row.packets_dropped) == (1, 7)
    assert row.stats["flows_stored"] == 30
    assert row.stats["flows_not_stored"] == 0
    assert row.stats["alerts_lost"] == 0
    assert row.stats["write_failures"] == 0
    assert row.stats["protocols"] == [{"protocol": "tcp", "packets": 30, "bytes": 1800}]

    flows = children(factory, NetworkFlow, session_id)
    assert sorted(item.dst_port for item in flows) == list(range(2000, 2030))
    for item in flows:
        assert (item.src_ip, item.dst_ip, item.protocol) == (SCANNER, SERVER, "tcp")
        assert (item.packets_out, item.packets_in, item.bytes_out, item.tcp_flags) == (1, 0, 60, 2)
        assert item.close_reason == "ended"
        assert item.last_seen >= item.first_seen

    (alert,) = children(factory, NetworkAlert, session_id)
    assert (alert.rule_id, alert.rule_name) == ("NET-001", "port_scan")
    assert alert.severity == severity_for(PORT_SCAN, 20, 20).value
    assert (alert.src_ip, alert.protocol, alert.window_seconds) == (SCANNER, "tcp", 60)
    assert (alert.threshold, alert.observed_value >= 20.0) == (20.0, True)
    assert alert.first_observed <= alert.last_observed
    assert alert.evidence
    assert alert.enrichment == {"status": "pending", "address": SCANNER}
    assert (recorder.flows_stored, recorder.pending) == (30, 0)


def test_alerts_total_is_added_to_not_overwritten(
    factory: SessionFactory, make_recorder: Callable[..., SessionRecorder]
) -> None:
    session_id = running_session(factory)
    recorder = make_recorder(session_id)

    assert store(recorder, output(alerts=2))
    assert session_row(factory, session_id).alerts_total == 2
    assert store(recorder, output(alerts=3))
    assert session_row(factory, session_id).alerts_total == 5
    assert len(children(factory, NetworkAlert, session_id)) == 5


def test_alerts_total_keeps_alerts_the_enrichment_worker_added(
    factory: SessionFactory, make_recorder: Callable[..., SessionRecorder]
) -> None:
    session_id = running_session(factory, alerts=4)
    recorder = make_recorder(session_id)

    assert store(recorder, output(alerts=1))

    assert session_row(factory, session_id).alerts_total == 5


def test_stats_of_other_writers_survive_and_the_enrichment_key_cannot_be_replaced(
    factory: SessionFactory, make_recorder: Callable[..., SessionRecorder]
) -> None:
    answer = {"status": "completed", "address": SCANNER, "risk_score": 80, "assessed": True}
    session_id = running_session(
        factory, stats={"enrichment": {SCANNER: answer}, "kept_by_someone_else": 1}
    )
    recorder = make_recorder(session_id)

    assert store(recorder, output(flows=1), stats={"protocols": [], "enrichment": {"x": {}}})

    stats = session_row(factory, session_id).stats
    assert stats["enrichment"] == {SCANNER: answer}
    assert stats["kept_by_someone_else"] == 1
    assert stats["protocols"] == []


def test_the_count_of_alerts_the_enrichment_worker_raised_survives_every_write(
    factory: SessionFactory, make_recorder: Callable[..., SessionRecorder]
) -> None:
    session_id = running_session(factory, alerts=1, stats={"enrichment_alerts": {"NET-005": 1}})
    recorder = make_recorder(session_id)

    for batch in (output(alerts=2), output(flows=3), output()):
        assert store(recorder, batch)

    row = session_row(factory, session_id)
    assert row.stats["enrichment_alerts"] == {"NET-005": 1}
    assert row.stats["alerts_by_rule"] == {}  # the recorder's own counts are rewritten each time
    assert row.alerts_total == 3  # the lookup's alert and the two that were stored
    assert len(children(factory, NetworkAlert, session_id)) == 2


def test_an_alert_about_an_address_already_looked_up_starts_with_that_answer(
    factory: SessionFactory, make_recorder: Callable[..., SessionRecorder]
) -> None:
    answer = {"status": "completed", "address": SCANNER, "risk_score": 80, "assessed": True}
    session_id = running_session(factory, stats={"enrichment": {SCANNER: answer}})
    recorder = make_recorder(session_id)
    batch = AnalyzerOutput(alerts=[raw_alert(1, src=SCANNER)], flows=[])

    assert store(recorder, batch)

    (alert,) = children(factory, NetworkAlert, session_id)
    assert alert.enrichment == answer
    assert alert.enrichment is not answer


def test_alert_enrichment_depends_on_the_public_address_and_the_setting(
    factory: SessionFactory, make_recorder: Callable[..., SessionRecorder]
) -> None:
    session_id = running_session(factory)
    batch = AnalyzerOutput(
        alerts=[
            raw_alert(1, src=SCANNER),
            raw_alert(2, src="10.0.1.2"),
            raw_alert(3, src="10.0.1.3", dst=RESOLVER),
        ],
        flows=[],
    )
    assert store(make_recorder(session_id), batch)
    states = {a.src_ip: a.enrichment for a in children(factory, NetworkAlert, session_id)}
    assert states[SCANNER] == {"status": "pending", "address": SCANNER}
    assert states["10.0.1.2"] == {"status": "not_applicable"}
    assert states["10.0.1.3"] == {"status": "pending", "address": RESOLVER}

    disabled_id = running_session(factory)
    recorder = make_recorder(disabled_id, enrichment_enabled=False)
    assert store(recorder, AnalyzerOutput(alerts=[raw_alert(1, src=SCANNER)], flows=[]))
    (alert,) = children(factory, NetworkAlert, disabled_id)
    assert alert.enrichment == {"status": "disabled", "address": SCANNER}


def test_initial_enrichment_ignores_answers_without_a_status() -> None:
    alert = raw_alert(1, src=SCANNER)
    for known in (None, {}, {SCANNER: {}}, {SCANNER: "completed"}, {SCANNER: {"status": ""}}):
        assert initial_enrichment(alert, enabled=True, known=known) == {
            "status": "pending",
            "address": SCANNER,
        }


# --- Limits ----------------------------------------------------------------------------------


def test_flows_beyond_the_stored_cap_are_counted_not_stored(
    factory: SessionFactory, make_recorder: Callable[..., SessionRecorder]
) -> None:
    session_id = running_session(factory)
    recorder = make_recorder(session_id, max_stored_flows=10)

    assert store(recorder, output(flows=30))
    stats = session_row(factory, session_id).stats
    assert (stats["flows_stored"], stats["flows_not_stored"]) == (10, 20)

    assert store(recorder, output(flows=5, first_flow=30))
    stats = session_row(factory, session_id).stats
    assert (stats["flows_stored"], stats["flows_not_stored"]) == (10, 25)
    assert len(children(factory, NetworkFlow, session_id)) == 10
    # The oldest flows are the ones kept.
    ports = {item.src_port for item in children(factory, NetworkFlow, session_id)}
    assert ports == set(range(40000, 40010))


def test_the_flow_cap_leaves_room_for_what_the_next_batch_needs(
    factory: SessionFactory, make_recorder: Callable[..., SessionRecorder]
) -> None:
    session_id = running_session(factory)
    recorder = make_recorder(session_id, max_stored_flows=10)

    assert store(recorder, output(flows=6))
    assert store(recorder, output(flows=6, first_flow=6))

    stats = session_row(factory, session_id).stats
    assert (stats["flows_stored"], stats["flows_not_stored"]) == (10, 2)


# --- A database that fails -------------------------------------------------------------------


def test_a_failed_write_is_retried_with_the_next_batch_exactly_once(
    factory: SessionFactory, make_recorder: Callable[..., SessionRecorder]
) -> None:
    session_id = running_session(factory)
    flaky = FlakyFactory(factory, failures=2)
    recorder = make_recorder(session_id, session_factory=flaky)

    assert not store(recorder, output(alerts=1, flows=2))
    assert recorder.pending == 3
    assert not store(recorder, output(flows=1, first_flow=2))
    assert recorder.pending == 4
    assert children(factory, NetworkFlow, session_id) == []

    assert store(recorder, output())

    assert recorder.pending == 0
    assert len(children(factory, NetworkFlow, session_id)) == 3
    assert len(children(factory, NetworkAlert, session_id)) == 1
    row = session_row(factory, session_id)
    assert row.alerts_total == 1
    assert (row.stats["write_failures"], row.stats["alerts_lost"]) == (2, 0)
    assert (recorder.write_failures, recorder.flows_stored) == (2, 3)


def test_a_long_outage_loses_only_the_oldest_pending_rows_and_says_so(
    factory: SessionFactory,
    make_recorder: Callable[..., SessionRecorder],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(recorder_module, "MAX_PENDING_FLOWS", 5)
    monkeypatch.setattr(recorder_module, "MAX_PENDING_ALERTS", 2)
    session_id = running_session(factory)
    flaky = FlakyFactory(factory, failures=-1)
    recorder = make_recorder(session_id, session_factory=flaky)

    assert not store(recorder, output(alerts=3, flows=8))
    assert recorder.pending == 5 + 2

    flaky.failures = 0
    assert store(recorder, output())

    row = session_row(factory, session_id)
    assert row.stats["flows_stored"] == 5
    assert row.stats["flows_not_stored"] == 3
    assert row.stats["alerts_lost"] == 1
    assert row.alerts_total == 2
    assert {item.src_port for item in children(factory, NetworkFlow, session_id)} == set(
        range(40003, 40008)
    )
    assert {item.explanation for item in children(factory, NetworkAlert, session_id)} == {
        "Alert 2.",
        "Alert 3.",
    }


def test_a_session_deleted_while_it_runs_stops_the_recorder(
    factory: SessionFactory, make_recorder: Callable[..., SessionRecorder]
) -> None:
    session_id = running_session(factory)
    counting = FlakyFactory(factory)
    recorder = make_recorder(session_id, session_factory=counting)
    assert store(recorder, output(flows=2))
    with factory() as db:
        delete_session(db, session_id)
        db.commit()
    calls = counting.calls

    assert not store(recorder, output(alerts=1, flows=3))

    assert recorder.gone
    assert recorder.pending == 0
    assert counting.calls == calls + 1
    assert not store(recorder, output(flows=1))
    assert counting.calls == calls + 1, "a recorder that is gone must not touch the database"
    assert not recorder.set_status(CaptureStatus.STOPPED, ended=True)
    assert children(factory, NetworkFlow, session_id) == []
    assert children(factory, NetworkAlert, session_id) == []


# --- Lifecycle status ------------------------------------------------------------------------


def test_set_status_records_the_status_and_keeps_the_code_unless_given_one(
    factory: SessionFactory, make_recorder: Callable[..., SessionRecorder]
) -> None:
    session_id = running_session(factory, status=CaptureStatus.STARTING)
    recorder = make_recorder(session_id)

    assert recorder.set_status(CaptureStatus.RUNNING)
    row = session_row(factory, session_id)
    assert (row.status, row.error_code, row.ended_at) == ("running", None, None)

    assert recorder.set_status(CaptureStatus.FAILED, error_code="capture_failed", ended=True)
    row = session_row(factory, session_id)
    assert (row.status, row.error_code) == ("failed", "capture_failed")
    assert row.ended_at is not None
    assert row.ended_at >= row.started_at


def test_ended_at_is_never_before_started_at(
    factory: SessionFactory, make_recorder: Callable[..., SessionRecorder]
) -> None:
    future = utcnow() + timedelta(hours=1)
    session_id = running_session(factory, started=future)

    assert make_recorder(session_id).set_status(CaptureStatus.STOPPED, ended=True)

    row = session_row(factory, session_id)
    assert row.ended_at == row.started_at


def test_set_status_retries_briefly_and_then_reports_failure(
    factory: SessionFactory, make_recorder: Callable[..., SessionRecorder]
) -> None:
    session_id = running_session(factory)
    flaky = FlakyFactory(factory, failures=2)
    recorder = make_recorder(session_id, session_factory=flaky)
    assert recorder.set_status(CaptureStatus.STOPPED, ended=True)
    assert flaky.calls == 3
    assert session_row(factory, session_id).status == "stopped"

    other_id = running_session(factory)
    broken = FlakyFactory(factory, failures=-1)
    recorder = make_recorder(other_id, session_factory=broken)
    assert not recorder.set_status(CaptureStatus.STOPPED, ended=True)
    assert broken.calls == 3
    assert session_row(factory, other_id).status == "running"


def test_set_status_on_a_missing_session_marks_the_recorder_gone(
    make_recorder: Callable[..., SessionRecorder],
) -> None:
    recorder = make_recorder(uuid.uuid4())

    assert not recorder.set_status(CaptureStatus.STOPPED, ended=True)

    assert recorder.gone


# --- Row builders ----------------------------------------------------------------------------


def test_row_builders_clamp_times_and_default_the_close_reason() -> None:
    item = flow(0)
    item.last_seen = item.first_seen - 5
    item.close_reason = None
    row = flow_row(uuid.uuid4(), item)
    assert row.last_seen == row.first_seen
    assert row.close_reason == "ended"

    reversed_alert = raw_alert(1)
    object.__setattr__(reversed_alert, "last_observed", reversed_alert.first_observed - 9)
    stored = alert_row(uuid.uuid4(), reversed_alert, {"status": "not_applicable"})
    assert stored.last_observed == stored.first_observed
    assert isinstance(stored.observed_value, float)
