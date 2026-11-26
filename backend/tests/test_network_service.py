"""NetworkService, live capture: interfaces, rules, the status of the capture slot, start and stop.

The database, the analyzer, the recorder, the enrichment worker and the capture thread are real.
The interface catalog, the packet sources and the intelligence service are doubles.
"""

import logging
import threading
from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.errors import ApiError
from app.database.session import build_engine, build_session_factory
from app.models.enums import CaptureSource, CaptureStatus
from app.network import service as service_module
from app.network.errors import message_for
from app.schemas.network import NetworkStatus
from app.services.intel_service import RequestContext
from tests.network_helpers import (
    ALICE,
    BOB,
    OTHER_INTERFACE,
    RESOLVER,
    SCAN_FLOWS,
    SCANNER,
    TEST_INTERFACE,
    Background,
    FakeCatalog,
    FakeClock,
    FakeSource,
    ServiceRig,
    StubIntel,
    assert_no_module_threads,
    provider_view,
    reply,
    rig_builder,
    scan_traffic,
    seed_session,
    wait_until,
)

SessionFactory = sessionmaker[Session]
LIVE_STATES = ("starting", "running", "stopping")
CAROL = RequestContext(actor="carol", source_ip="203.0.113.12")


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
def make_rig(
    factory: SessionFactory,
    make_settings: Callable[..., Settings],
    db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Callable[..., ServiceRig]]:
    yield from rig_builder(factory, make_settings, db_url, tmp_path / "spool", monkeypatch)


@pytest.fixture
def rig(make_rig: Callable[..., ServiceRig]) -> ServiceRig:
    return make_rig()


class ImpatientSource(FakeSource):
    """A source that never makes the capture wait for it to report in."""

    def wait_started(self, timeout: float) -> bool:
        return self._ready.wait(0)


def ended_status(rig: ServiceRig, who: RequestContext = ALICE) -> NetworkStatus:
    """The caller's status once the capture holding the slot has finished."""
    return wait_until(
        lambda: (current := rig.status(who)).state not in LIVE_STATES and current,
        what="the capture to end",
    )


def target_of(session_id: Any) -> str:
    return f"network-session:{session_id}"


# --- Interfaces and rules -----------------------------------------------------------------------


def test_interfaces_are_the_catalogs_and_a_refresh_is_passed_on(rig: ServiceRig) -> None:
    listing = rig.service.interfaces()

    assert (listing.backend.name, listing.backend.available) == ("fakepcap", True)
    assert [
        (item.id, item.name, item.description, item.addresses) for item in listing.interfaces
    ] == [
        (
            TEST_INTERFACE.id,
            TEST_INTERFACE.name,
            TEST_INTERFACE.description,
            list(TEST_INTERFACE.addresses),
        ),
        (OTHER_INTERFACE.id, OTHER_INTERFACE.name, OTHER_INTERFACE.description, []),
    ]
    assert rig.catalog.refreshes == 0

    rig.service.interfaces(refresh=True)

    assert rig.catalog.refreshes == 1


def test_without_a_capture_backend_there_are_no_interfaces_and_the_status_says_so(
    make_rig: Callable[..., ServiceRig],
) -> None:
    rig = make_rig(catalog=FakeCatalog(available=False))

    listing = rig.service.interfaces(refresh=True)
    status = rig.status(ALICE)

    assert (listing.backend.available, listing.interfaces) == (False, [])
    assert rig.catalog.refreshes == 0
    assert status.state == "not_configured"
    assert (status.interface, status.session_id) == (None, None)
    assert status.error_code == "capture_backend_missing"
    assert status.message == message_for("capture_backend_missing")
    assert status.backend.available is False


def test_an_interface_listing_that_fails_gives_no_interfaces(
    make_rig: Callable[..., ServiceRig], caplog: pytest.LogCaptureFixture
) -> None:
    class Broken(FakeCatalog):
        def interfaces(self, *, refresh: bool = False) -> list[Any]:
            raise OSError("adapter-name-that-must-not-be-logged")

    rig = make_rig(catalog=Broken())

    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        listing = rig.service.interfaces()

    assert (listing.backend.available, listing.interfaces) == (True, [])
    (record,) = [item for item in caplog.records if item.getMessage() == "interface_listing_failed"]
    assert record.error == "OSError"
    assert "adapter-name-that-must-not-be-logged" not in caplog.text


def test_the_rules_describe_the_configured_thresholds(
    make_rig: Callable[..., ServiceRig],
) -> None:
    rig = make_rig({"port_scan_threshold": 7, "high_volume_threshold_mb": 5})

    rules = {rule.rule_id: rule for rule in rig.service.rules()}

    assert list(rules) == [f"NET-00{number}" for number in range(1, 8)]
    port_scan = rules["NET-001"]
    assert (port_scan.threshold, port_scan.unit, port_scan.window_seconds) == (7.0, "ports", 60)
    assert rules["NET-004"].threshold == 5.0
    assert rules["NET-005"].threshold == 61.0
    assert all(rule.active for rule in rules.values())
    assert all(len(rule.severities) == 3 for rule in rules.values())


def test_the_known_malicious_rule_is_inactive_while_enrichment_is_off(
    make_rig: Callable[..., ServiceRig],
) -> None:
    rig = make_rig({"external_enrichment_enabled": False})

    rules = rig.service.rules()

    assert [rule.rule_id for rule in rules if not rule.active] == ["NET-005"]
    assert rig.status(ALICE).enrichment_enabled is False


# --- Status -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "error_code", "state"),
    [
        (CaptureStatus.STOPPED, None, "stopped"),
        (CaptureStatus.COMPLETED, None, "stopped"),
        (CaptureStatus.FAILED, "capture_failed", "failed"),
        (CaptureStatus.FAILED, "interface_unavailable", "failed"),
        (CaptureStatus.PERMISSION_DENIED, "capture_permission_denied", "permission_denied"),
    ],
)
def test_once_a_capture_has_ended_the_status_says_how(
    rig: ServiceRig, status: CaptureStatus, error_code: str | None, state: str
) -> None:
    session_id = seed_session(
        rig.factory,
        status=status,
        source=CaptureSource.LIVE,
        interface=TEST_INTERFACE.name,
        label=None,
        error_code=error_code,
    )

    result = rig.status(ALICE)

    assert result.state == state
    assert (result.session_id, result.interface, result.error_code) == (
        session_id,
        TEST_INTERFACE.name,
        error_code,
    )
    assert result.message == message_for(error_code)
    assert result.busy is False


def test_the_status_follows_the_callers_latest_live_capture_only(rig: ServiceRig) -> None:
    first = seed_session(
        rig.factory,
        status=CaptureStatus.FAILED,
        source=CaptureSource.LIVE,
        error_code="capture_failed",
        label=None,
    )
    latest = seed_session(
        rig.factory,
        status=CaptureStatus.STOPPED,
        source=CaptureSource.LIVE,
        started=rig.row(first).started_at + timedelta(hours=1),
        label=None,
    )
    seed_session(
        rig.factory,
        owner="bob",
        status=CaptureStatus.FAILED,
        source=CaptureSource.LIVE,
        started=rig.row(first).started_at + timedelta(hours=2),
        error_code="capture_failed",
        label=None,
    )
    seed_session(
        rig.factory,
        status=CaptureStatus.COMPLETED,
        source=CaptureSource.PCAP,
        started=rig.row(first).started_at + timedelta(hours=3),
    )

    mine = rig.status(ALICE)

    assert (mine.state, mine.session_id) == ("stopped", latest)
    assert rig.status(BOB).state == "failed"
    assert rig.status(CAROL).state == "ready"


def test_a_session_left_active_in_the_database_does_not_make_the_status_busy(
    rig: ServiceRig,
) -> None:
    seed_session(rig.factory, status=CaptureStatus.RUNNING, source=CaptureSource.LIVE, label=None)

    status = rig.status(ALICE)

    assert (status.state, status.busy, status.session_id) == ("ready", False, None)


# --- Starting a capture ---------------------------------------------------------------------------


def test_a_capture_runs_from_start_to_stop_with_an_audit_trail(rig: ServiceRig) -> None:
    started = rig.start(ALICE)

    session_id = started.session_id
    assert session_id is not None
    assert (started.state, started.interface, started.busy) == (
        "running",
        TEST_INTERFACE.name,
        False,
    )
    # The capture library is opened by the interface's id, not by the name shown to people.
    assert rig.requested == [TEST_INTERFACE.id]
    row = rig.row(session_id)
    assert (row.owner, row.source_kind, row.status) == ("alice", "live", "running")
    assert (row.interface, row.source_label, row.ended_at) == (TEST_INTERFACE.name, None, None)
    others = rig.status(BOB)
    assert (others.state, others.busy, others.session_id) == ("ready", True, None)

    stopped = rig.stop(ALICE)

    assert (stopped.state, stopped.session_id) == ("stopped", session_id)
    row = rig.row(session_id)
    assert (row.status, row.error_code) == ("stopped", None)
    assert row.ended_at is not None
    assert row.ended_at >= row.started_at
    assert rig.status(BOB).busy is False
    (start,) = rig.audit("NETWORK_CAPTURE_START")
    assert (start.actor, start.result, start.target) == ("alice", "success", target_of(session_id))
    assert start.source_ip == ALICE.source_ip
    # The name of the interface, never the addresses it carries.
    assert start.details == {"interface": TEST_INTERFACE.name}
    (stop,) = rig.audit("NETWORK_CAPTURE_STOP")
    assert (stop.actor, stop.result, stop.target) == ("alice", "success", target_of(session_id))
    assert stop.details == {"finished": True}


def test_a_start_without_a_backend_is_refused_and_audited(
    make_rig: Callable[..., ServiceRig],
) -> None:
    rig = make_rig(catalog=FakeCatalog(available=False))

    with pytest.raises(ApiError) as caught:
        rig.start(ALICE)

    assert (caught.value.status_code, caught.value.code) == (503, "capture_backend_missing")
    (entry,) = rig.audit("NETWORK_CAPTURE_START")
    assert (entry.actor, entry.result, entry.target) == ("alice", "rejected", None)
    assert entry.details == {"reason": "capture_backend_missing"}
    assert rig.sessions() == []
    assert rig.requested == []


@pytest.mark.parametrize("listing_fails", [False, True])
def test_an_unknown_interface_is_refused_and_audited(
    make_rig: Callable[..., ServiceRig],
    caplog: pytest.LogCaptureFixture,
    listing_fails: bool,
) -> None:
    catalog = FakeCatalog()

    def broken(interface_id: str) -> None:
        raise OSError("adapter-name-that-must-not-be-logged")

    if listing_fails:
        catalog.resolve = broken  # type: ignore[method-assign]
    rig = make_rig(catalog=catalog)

    with (
        caplog.at_level(logging.DEBUG, logger="cipherforge.network"),
        pytest.raises(ApiError) as caught,
    ):
        rig.start(ALICE, "no-such-adapter")

    assert (caught.value.status_code, caught.value.code) == (404, "interface_not_found")
    (entry,) = rig.audit("NETWORK_CAPTURE_START")
    assert (entry.result, entry.target) == ("rejected", None)
    assert entry.details == {"reason": "interface_not_found"}
    assert rig.sessions() == []
    assert rig.requested == []
    assert rig.status(ALICE).state == "ready"
    assert "adapter-name-that-must-not-be-logged" not in caplog.text


@pytest.mark.parametrize("second", [ALICE, BOB], ids=["same-user", "other-user"])
def test_a_second_capture_is_refused_whoever_asks(rig: ServiceRig, second: RequestContext) -> None:
    first = rig.start(ALICE)

    with pytest.raises(ApiError) as caught:
        rig.start(second, OTHER_INTERFACE.id)

    assert (caught.value.status_code, caught.value.code) == (409, "capture_already_running")
    (refused,) = [
        entry for entry in rig.audit("NETWORK_CAPTURE_START") if entry.result != "success"
    ]
    assert (refused.actor, refused.result, refused.target) == (second.actor, "rejected", None)
    assert refused.details == {"reason": "capture_already_running"}
    assert len(rig.sessions()) == 1
    # No second source was created, and the first one went on.
    assert rig.requested == [TEST_INTERFACE.id]
    assert rig.sources[0].stop_calls == 0
    running = rig.status(ALICE)
    assert (running.state, running.session_id) == ("running", first.session_id)


def test_simultaneous_starts_let_exactly_one_through(rig: ServiceRig) -> None:
    barrier = threading.Barrier(2)

    def attempt(who: RequestContext) -> NetworkStatus:
        barrier.wait(5)
        return rig.start(who)

    calls = [Background(attempt, ALICE), Background(attempt, BOB)]
    for call in calls:
        call.join()

    won = [call for call in calls if call.error is None]
    lost = [call for call in calls if call.error is not None]
    assert (len(won), len(lost)) == (1, 1)
    assert isinstance(lost[0].error, ApiError)
    assert lost[0].error.code == "capture_already_running"
    assert len(rig.sessions()) == 1
    assert len(rig.sources) == 1


def test_the_slot_is_free_again_once_a_capture_has_been_stopped(rig: ServiceRig) -> None:
    rig.start(ALICE)
    rig.stop(ALICE)

    second = rig.start(BOB, OTHER_INTERFACE.id)

    assert (second.state, second.interface) == ("running", OTHER_INTERFACE.name)
    assert rig.status(ALICE).busy is True
    assert rig.requested == [TEST_INTERFACE.id, OTHER_INTERFACE.id]


def test_a_capture_that_is_still_being_built_already_holds_the_slot(rig: ServiceRig) -> None:
    gate = rig.hold_sources()
    starting = Background(rig.start, ALICE)
    wait_until(rig.source_entered.is_set, what="the source factory to be asked for a source")

    own = rig.status(ALICE)
    session_id = own.session_id
    assert session_id is not None
    assert (own.state, own.interface) == ("starting", TEST_INTERFACE.name)
    assert rig.status(BOB).busy is True
    assert rig.row(session_id).status == "starting"
    with pytest.raises(ApiError) as taken:
        rig.start(BOB)
    assert taken.value.code == "capture_already_running"
    with pytest.raises(ApiError) as nothing_to_stop:
        rig.stop(ALICE)
    assert nothing_to_stop.value.code == "capture_not_running"
    with pytest.raises(ApiError) as active:
        rig.call("delete_session", ALICE, session_id)
    assert (active.value.status_code, active.value.code) == (409, "session_running")

    gate.set()
    starting.join()

    assert starting.error is None
    assert starting.result.state == "running"
    assert starting.result.session_id == session_id


def test_a_source_that_is_slow_to_open_leaves_the_capture_starting_until_it_reports_in(
    rig: ServiceRig,
) -> None:
    rig.prepared.append(ImpatientSource(autostart=False))

    started = rig.start(ALICE)

    session_id = started.session_id
    assert session_id is not None
    assert started.state == "starting"
    assert rig.row(session_id).status == "starting"
    assert rig.status(BOB).busy is True

    rig.sources[0].become_ready()

    wait_until(lambda: rig.row(session_id).status == "running", what="the capture to be promoted")
    assert rig.status(ALICE).state == "running"


def test_a_capture_that_is_still_starting_can_be_stopped(rig: ServiceRig) -> None:
    rig.prepared.append(ImpatientSource(autostart=False))
    started = rig.start(ALICE)
    session_id = started.session_id
    assert session_id is not None

    rig.stop(ALICE)

    row = rig.row(session_id)
    assert (row.status, row.error_code) == ("stopped", None)
    assert row.ended_at is not None
    assert rig.status(BOB).busy is False


REFUSALS = [
    (PermissionError("Operation not permitted"), "capture_permission_denied", "permission_denied"),
    (OSError("No such device exists"), "interface_unavailable", "failed"),
    (RuntimeError("source-detail-that-must-not-leak"), "capture_failed", "failed"),
]


@pytest.mark.parametrize(("error", "code", "status"), REFUSALS)
def test_a_source_that_cannot_start_ends_the_session_and_frees_the_slot(
    rig: ServiceRig, error: Exception, code: str, status: str
) -> None:
    rig.prepared.append(FakeSource(start_error=error))

    with pytest.raises(ApiError) as caught:
        rig.start(ALICE)

    assert (caught.value.status_code, caught.value.code) == (503, code)
    assert str(error) not in str(caught.value.detail)
    (row,) = rig.sessions()
    assert (row.status, row.error_code) == (status, code)
    assert row.ended_at is not None
    (refused,) = rig.audit("NETWORK_CAPTURE_START")
    assert (refused.result, refused.target) == ("rejected", target_of(row.id))
    assert refused.details == {"reason": code}
    assert rig.audit("NETWORK_CAPTURE_STOP") == []
    # A refusal is shown, and stays shown, in the status; it does not hold the slot.
    after = rig.status(ALICE)
    assert (after.state, after.session_id, after.error_code) == (status, row.id, code)
    assert after.message == message_for(code)
    assert (after.busy, rig.status(BOB).busy) == (False, False)
    assert rig.start(ALICE).state == "running"
    assert rig.status(ALICE).error_code is None


def test_a_source_that_cannot_be_created_fails_the_session_and_frees_the_slot(
    rig: ServiceRig,
) -> None:
    rig.source_error = RuntimeError("cannot open")

    with pytest.raises(RuntimeError):
        rig.start(ALICE)

    (row,) = rig.sessions()
    assert (row.status, row.error_code) == ("failed", "capture_failed")
    assert row.ended_at is not None
    assert rig.status(ALICE).state == "failed"
    assert rig.status(BOB).busy is False
    rig.source_error = None
    assert rig.start(ALICE).state == "running"


def test_a_capture_is_stopped_when_its_audit_record_cannot_be_written(
    rig: ServiceRig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_args: Any, **_kwargs: Any) -> None:
        raise OperationalError("INSERT", {}, Exception("database is locked"))

    monkeypatch.setattr(rig.service, "_audit", refuse)

    with pytest.raises(OperationalError):
        rig.start(ALICE)

    (row,) = rig.sessions()
    assert (row.status, row.error_code) == ("stopped", None)
    assert rig.sources[0].stop_calls >= 1
    assert rig.audit("NETWORK_CAPTURE_START") == []
    assert rig.status(BOB).busy is False


def test_a_capture_that_cannot_be_built_leaves_no_session_behind(
    rig: ServiceRig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("cannot build")

    with monkeypatch.context() as patch:
        patch.setattr(service_module, "SessionMonitor", broken)
        with pytest.raises(RuntimeError):
            rig.start(ALICE)

    # No session is left "starting" for good: it could not be deleted and would never end.
    assert rig.sessions() == []
    assert rig.status(ALICE).state == "ready"
    assert rig.status(BOB).busy is False
    assert rig.start(ALICE).state == "running"


# --- Sources that end on their own ----------------------------------------------------------------

DEATHS = [
    (OSError("The network is down"), "interface_unavailable", "failed", "failed"),
    (
        PermissionError("denied"),
        "capture_permission_denied",
        "permission_denied",
        "permission_denied",
    ),
    (None, "capture_failed", "failed", "failed"),
]


@pytest.mark.parametrize(("error", "code", "status", "state"), DEATHS)
def test_a_source_that_dies_during_the_capture_ends_the_session_as_failed(
    rig: ServiceRig, error: Exception | None, code: str, status: str, state: str
) -> None:
    started = rig.start(ALICE)
    session_id = started.session_id
    assert session_id is not None

    rig.sources[0].die(error)

    row = rig.wait_for_end(session_id)
    assert (row.status, row.error_code) == (status, code)
    assert row.ended_at is not None
    after = ended_status(rig)
    assert (after.state, after.error_code, after.busy) == (state, code, False)
    with pytest.raises(ApiError) as caught:
        rig.stop(ALICE)
    assert caught.value.code == "capture_not_running"
    assert rig.audit("NETWORK_CAPTURE_STOP") == []
    assert rig.start(ALICE).state == "running"


# --- Stopping -----------------------------------------------------------------------------------


def test_only_the_owner_can_stop_a_capture_and_only_while_it_runs(rig: ServiceRig) -> None:
    with pytest.raises(ApiError) as nothing:
        rig.stop(ALICE)
    assert (nothing.value.status_code, nothing.value.code) == (409, "capture_not_running")
    rig.start(ALICE)

    with pytest.raises(ApiError) as theirs:
        rig.stop(BOB)

    # Bob is told nothing about Alice's capture.
    assert theirs.value.code == "capture_not_running"
    assert rig.status(ALICE).state == "running"
    assert rig.sources[0].stop_calls == 0
    assert rig.audit("NETWORK_CAPTURE_STOP") == []
    rig.stop(ALICE)
    with pytest.raises(ApiError) as again:
        rig.stop(ALICE)
    assert again.value.code == "capture_not_running"
    assert len(rig.audit("NETWORK_CAPTURE_STOP")) == 1


def test_a_capture_that_does_not_finish_stopping_in_time_keeps_the_slot(
    rig: ServiceRig, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = threading.Event()
    rig.gates.append(gate)
    original = service_module.SessionMonitor.finish

    def slow_finish(self: Any, status: CaptureStatus, error_code: str | None = None) -> None:
        gate.wait(10)
        original(self, status, error_code)

    monkeypatch.setattr(service_module.SessionMonitor, "finish", slow_finish)
    monkeypatch.setattr(service_module, "STOP_TIMEOUT_SECONDS", 0.05)
    started = rig.start(ALICE)

    stopping = rig.stop(ALICE)

    assert (stopping.state, stopping.session_id) == ("stopping", started.session_id)
    (entry,) = rig.audit("NETWORK_CAPTURE_STOP")
    assert (entry.result, entry.details) == ("partial", {"finished": False})
    assert rig.status(BOB).busy is True
    with pytest.raises(ApiError) as taken:
        rig.start(BOB)
    assert taken.value.code == "capture_already_running"

    gate.set()

    assert ended_status(rig).state == "stopped"
    assert rig.start(BOB).state == "running"


# --- A capture from the first packet to the last ------------------------------------------------


def test_a_running_capture_stores_what_it_sees_and_keeps_the_lookups(
    make_rig: Callable[..., ServiceRig],
) -> None:
    clock = FakeClock()
    intel = StubIntel({SCANNER: reply(provider_view(), score=90, classification="critical")})
    rig = make_rig(intel=intel, clock=clock)
    started = rig.start(ALICE)
    session_id = started.session_id
    assert session_id is not None

    rig.sources[0].emit(*scan_traffic())

    def stored() -> bool:
        # Each look moves the clock past the flush interval, so the capture stores what it has.
        clock.advance(3)
        return rig.row(session_id).packets_total == SCAN_FLOWS

    wait_until(stored, what="the packets to be stored while the capture runs")
    assert rig.row(session_id).status == "running"
    wait_until(
        lambda: {alert.rule_id for alert in rig.alerts(session_id)} >= {"NET-001"},
        what="the port scan to be stored while the capture runs",
    )

    rig.stop(ALICE)

    row = rig.row(session_id)
    assert row.status == "stopped"
    assert (row.packets_total, row.flows_total) == (SCAN_FLOWS, SCAN_FLOWS)
    assert len(rig.flows(session_id)) == SCAN_FLOWS
    assert row.stats["non_ip_packets"] == 1
    # The scanner is looked up and found malicious; the private hosts are never asked about.
    entries = rig.wait_for_lookups(session_id, {SCANNER, RESOLVER})
    assert entries[SCANNER]["status"] == "completed"
    assert set(intel.calls) == {SCANNER, RESOLVER}
    assert {context.actor for context in intel.contexts} == {"system:network-monitor"}
    wait_until(
        lambda: sorted(alert.rule_id for alert in rig.alerts(session_id)) == ["NET-001", "NET-005"],
        what="the known-malicious alert",
    )
    final = rig.row(session_id)
    assert final.alerts_total == 2
    assert rig.call("get_session", ALICE.actor, session_id).alerts_by_rule == {
        "NET-001": 1,
        "NET-005": 1,
    }
    # The last stored results did not overwrite the answers the lookups had recorded.
    assert final.stats["enrichment"][SCANNER]["status"] == "completed"
    assert final.stats["enrichment"][RESOLVER]["status"] == "completed"


def test_packets_the_capture_cannot_keep_up_with_are_counted_not_lost_silently(
    make_rig: Callable[..., ServiceRig], monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = make_rig({"monitoring_buffer_size": 100})
    gate = threading.Event()
    entered = threading.Event()
    rig.gates.append(gate)
    original = service_module.SessionMonitor.process_batch

    def held(self: Any, packets: Any) -> None:
        entered.set()
        gate.wait(10)
        original(self, packets)

    monkeypatch.setattr(service_module.SessionMonitor, "process_batch", held)
    started = rig.start(ALICE)
    session_id = started.session_id
    assert session_id is not None
    frames = scan_traffic(ports=100)

    # With the consumer held inside its first batch, the queue of 100 takes what comes next and
    # the rest is dropped: 102 IP packets follow the first.
    rig.sources[0].emit(frames[0])
    wait_until(entered.is_set, what="the consumer to take the first packet")
    rig.sources[0].emit(*frames[1:])
    gate.set()
    rig.stop(ALICE)

    row = rig.row(session_id)
    assert row.status == "stopped"
    assert (row.packets_total, row.packets_dropped) == (101, 2)
    assert row.stats["non_ip_packets"] == 1


# --- Shutdown -------------------------------------------------------------------------------------


def test_shutting_down_stops_a_running_capture_and_may_be_repeated(rig: ServiceRig) -> None:
    started = rig.start(ALICE)
    session_id = started.session_id
    assert session_id is not None

    rig.service.shutdown()

    row = rig.row(session_id)
    assert (row.status, row.error_code) == ("stopped", None)
    assert row.ended_at is not None
    assert rig.sources[0].stop_calls >= 1
    rig.service.shutdown()


def test_shutting_down_is_not_stopped_by_a_source_that_cannot_stop(
    rig: ServiceRig, caplog: pytest.LogCaptureFixture
) -> None:
    rig.prepared.append(FakeSource(stop_error=OSError("handle-that-must-not-be-logged")))
    started = rig.start(ALICE)
    session_id = started.session_id
    assert session_id is not None

    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        rig.service.shutdown()

    assert rig.row(session_id).status == "stopped"
    assert "handle-that-must-not-be-logged" not in caplog.text
