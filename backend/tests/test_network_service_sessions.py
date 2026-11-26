"""NetworkService, stored sessions: who can see what, paging, deleting, looking an address up
again, and what the service cleans up when it starts and stops.

The database, the analyzer, the recorder and the enrichment worker are real. The intelligence
service is a double. Retention is judged against the real clock, so every row is dated relative to
now, and a fake clock stands in for the one the purge interval is measured with.
"""

import functools
import json
import logging
import shutil
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.database.session import build_engine, build_session_factory
from app.models.enums import CaptureSource, CaptureStatus
from app.models.network import CaptureSession, NetworkAlert, NetworkFlow
from app.network import service as service_module
from app.network.analyzer import subject_address
from app.network.errors import message_for
from app.services.intel_service import IndicatorDeletedError, RequestContext
from tests.network_helpers import (
    ALICE,
    BOB,
    DOCUMENTATION,
    HOST,
    RESOLVER,
    SCANNER,
    SERVER,
    TEST_INTERFACE,
    Background,
    FakeClock,
    FlakyFactory,
    ServiceRig,
    ago,
    assert_no_module_threads,
    assert_not_logged,
    backdate,
    logged,
    provider_view,
    refusal,
    reply,
    rig_builder,
    scan_capture_files,
    seed_alert,
    seed_flow,
    seed_session,
    wait_until,
)

SessionFactory = sessionmaker[Session]
ADMIN = RequestContext(actor="root-admin", source_ip="203.0.113.99")
LABEL = "payroll-capture-2026.pcap"
SECRET = "sk-live-0123456789"
NOT_FOUND = (404, "session_not_found", "Monitoring session not found.")
PAGE = {"limit": 50, "offset": 0}
EVERYTHING = {"severities": (), "rule_id": None, **PAGE}
THREE_DAYS = 3 * 24 * 3600


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


@pytest.fixture(scope="module")
def scan_files(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bytes]:
    return scan_capture_files(tmp_path_factory.mktemp("scan"))


@pytest.fixture(params=[BOB, ADMIN], ids=["another-user", "an-administrator"])
def stranger(request: pytest.FixtureRequest) -> RequestContext:
    """Someone who owns none of Alice's sessions. The service has no role that sees across
    owners, so an administrator is simply another owner here."""
    return request.param


@dataclass(frozen=True)
class World:
    """Alice's finished capture file with five flows and four alerts, and Bob's with one each."""

    mine: uuid.UUID
    my_flows: list[int]
    my_alerts: list[uuid.UUID]
    theirs: uuid.UUID
    their_flows: list[int]
    their_alert: uuid.UUID


@pytest.fixture
def world(factory: SessionFactory) -> World:
    base = ago(hours=2)
    mine = seed_session(factory, owner="alice", started=base, flows=5, alerts=4, label=LABEL)
    my_flows = [
        seed_flow(factory, mine, dport=80 + index, first=base + timedelta(seconds=index))
        for index in range(5)
    ]
    kinds = [
        ("NET-001", "port_scan", "low"),
        ("NET-002", "connection_rate", "medium"),
        ("NET-001", "port_scan", "high"),
        ("NET-007", "unexpected_protocol", "critical"),
    ]
    my_alerts = [
        seed_alert(
            factory,
            mine,
            rule_id=rule,
            rule_name=name,
            severity=severity,
            created=base + timedelta(seconds=index),
        )
        for index, (rule, name, severity) in enumerate(kinds)
    ]
    theirs = seed_session(factory, owner="bob", started=base, flows=1, alerts=1)
    return World(
        mine=mine,
        my_flows=my_flows,
        my_alerts=my_alerts,
        theirs=theirs,
        their_flows=[seed_flow(factory, theirs)],
        their_alert=seed_alert(factory, theirs),
    )


def target_of(session_id: Any) -> str:
    return f"network-session:{session_id}"


def seed_expired(
    factory: SessionFactory,
    *,
    owner: str = "alice",
    hours: float = 100.0,
    status: CaptureStatus = CaptureStatus.COMPLETED,
) -> uuid.UUID:
    """A finished session that ended ``hours`` ago, with a flow and an alert."""
    session_id = seed_session(
        factory,
        owner=owner,
        status=status,
        started=ago(hours=hours + 1),
        ended=ago(hours=hours),
        flows=1,
        alerts=1,
    )
    seed_flow(factory, session_id)
    seed_alert(factory, session_id)
    return session_id


def an_alert(
    factory: SessionFactory,
    *,
    owner: str = "alice",
    src: str | None = SCANNER,
    dst: str | None = SERVER,
) -> tuple[uuid.UUID, uuid.UUID]:
    """A stored alert between two addresses, whose lookup has failed. Returns (session, alert)."""
    session_id = seed_session(factory, owner=owner, started=ago(hours=1))
    address = subject_address(src, dst)
    state = {"status": "failed", "address": address, "error_code": "lookup_failed"}
    alert_id = seed_alert(factory, session_id, src=src, dst=dst, enrichment=state)
    return session_id, alert_id


def lookups_waiting(rig: ServiceRig) -> int:
    return rig.service._enrichment.pending_count()


def snapshot(row: CaptureSession) -> tuple[Any, ...]:
    return (row.status, row.error_code, row.started_at, row.ended_at)


def enrichment_of(rig: ServiceRig, session_id: uuid.UUID, alert_id: uuid.UUID) -> Any:
    page = rig.call("list_alerts", "alice", session_id, **EVERYTHING)
    return next(item for item in page.items if item.id == alert_id).enrichment


def stale_upload(spool_base: Path) -> Path:
    """What a crashed process leaves in the upload spool: an old directory with a file in it."""
    directory = spool_base / "cipherforge-pcap-left-by-a-crash"
    directory.mkdir()
    (directory / "old.upload").write_bytes(b"x")
    backdate(directory, THREE_DAYS)
    return directory


# --- Starting without a migrated database ---------------------------------------------------------


def test_a_server_whose_database_is_not_migrated_still_clears_its_old_uploads(
    make_settings: Callable[..., Settings], tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    settings = make_settings()  # a database nobody has migrated
    engine = build_engine(settings)
    spool_base = tmp_path / "spool"
    spool_base.mkdir()
    left_behind = stale_upload(spool_base)
    rig = ServiceRig(settings, build_session_factory(engine), spool_base)
    try:
        with caplog.at_level(logging.INFO, logger="cipherforge.network"):
            rig.service.startup()
    finally:
        rig.close()
        engine.dispose()

    (skipped,) = logged(caplog, "network_startup_skipped")
    assert skipped.error == "OperationalError"
    assert not left_behind.exists()
    (cleanup,) = logged(caplog, "network_startup_cleanup")
    assert (cleanup.sessions_interrupted, cleanup.lookups_interrupted) == (0, 0)
    assert (cleanup.sessions_purged, cleanup.stale_uploads_removed) == (0, 1)


def test_a_database_that_cannot_be_written_does_not_stop_the_start_either(
    make_rig: Callable[..., ServiceRig], factory: SessionFactory, caplog: pytest.LogCaptureFixture
) -> None:
    rig = make_rig(service_sessions=FlakyFactory(factory, failures=-1))
    running = seed_session(factory, status=CaptureStatus.RUNNING, source=CaptureSource.LIVE)
    left_behind = stale_upload(rig.spool_base)

    with caplog.at_level(logging.INFO, logger="cipherforge.network"):
        rig.service.startup()

    assert [record.error for record in logged(caplog, "network_startup_skipped")] == [
        "OperationalError"
    ]
    assert not left_behind.exists()
    assert rig.row(running).status == "running"


# --- Who sees what -----------------------------------------------------------------------------


def test_another_owners_session_is_refused_like_one_that_is_not_there(
    rig: ServiceRig, world: World, stranger: RequestContext
) -> None:
    unknown = uuid.uuid4()
    reads = {"get_session": {}, "list_flows": PAGE, "list_alerts": EVERYTHING}
    for method, options in reads.items():
        theirs = refusal(functools.partial(rig.call, method, stranger.actor, world.mine, **options))
        nothing = refusal(functools.partial(rig.call, method, stranger.actor, unknown, **options))
        assert theirs == nothing == NOT_FOUND, method

    assert refusal(functools.partial(rig.call, "delete_session", stranger, world.mine)) == NOT_FOUND
    assert refusal(functools.partial(rig.call, "delete_session", stranger, unknown)) == NOT_FOUND

    assert (rig.count(CaptureSession), rig.count(NetworkFlow), rig.count(NetworkAlert)) == (2, 6, 5)
    assert rig.audit() == []


def test_another_owners_alert_is_refused_like_one_that_is_not_there(
    rig: ServiceRig, factory: SessionFactory, stranger: RequestContext
) -> None:
    session_id, alert_id = an_alert(factory)
    before = enrichment_of(rig, session_id, alert_id)

    foreign = refusal(functools.partial(rig.call, "enrich_alert", stranger, alert_id))
    unknown = refusal(functools.partial(rig.call, "enrich_alert", ALICE, uuid.uuid4()))

    assert foreign == unknown == (404, "alert_not_found", "Alert not found.")
    assert rig.intel.calls == []
    assert rig.audit() == []
    assert enrichment_of(rig, session_id, alert_id) == before


def test_a_listing_holds_only_the_callers_own_sessions(rig: ServiceRig, world: World) -> None:
    pages = {
        owner: rig.call("list_sessions", owner, **PAGE) for owner in ("alice", "bob", "root-admin")
    }

    assert [(owner, [item.id for item in page.items]) for owner, page in pages.items()] == [
        ("alice", [world.mine]),
        ("bob", [world.theirs]),
        ("root-admin", []),
    ]
    assert [page.total for page in pages.values()] == [1, 1, 0]


# --- Paging and filtering ---------------------------------------------------------------------


def test_sessions_are_paged_newest_first(rig: ServiceRig, factory: SessionFactory) -> None:
    ids = [
        seed_session(factory, started=ago(hours=5) + timedelta(minutes=index)) for index in range(5)
    ]

    first = rig.call("list_sessions", "alice", limit=2, offset=0)
    last = rig.call("list_sessions", "alice", limit=2, offset=4)
    beyond = rig.call("list_sessions", "alice", limit=2, offset=9)

    assert [item.id for item in first.items] == [ids[4], ids[3]]
    assert (first.total, first.limit, first.offset) == (5, 2, 0)
    assert [item.id for item in last.items] == [ids[0]]
    assert (beyond.items, beyond.total, beyond.offset) == ([], 5, 9)


def test_flows_are_paged_newest_first(rig: ServiceRig, world: World) -> None:
    page = rig.call("list_flows", "alice", world.mine, limit=2, offset=1)

    assert [item.id for item in page.items] == [world.my_flows[3], world.my_flows[2]]
    assert [item.dst_port for item in page.items] == [83, 82]
    assert (page.total, page.limit, page.offset) == (5, 2, 1)
    beyond = rig.call("list_flows", "alice", world.mine, limit=2, offset=40)
    assert (beyond.items, beyond.total) == ([], 5)


@pytest.mark.parametrize(
    ("filters", "expected"),
    [
        ({}, [3, 2, 1, 0]),
        ({"severities": ("high", "critical")}, [3, 2]),
        ({"severities": {"low"}}, [0]),
        ({"rule_id": "NET-001"}, [2, 0]),
        ({"severities": ("high", "critical"), "rule_id": "NET-001"}, [2]),
        ({"severities": ("low",), "rule_id": "NET-002"}, []),
        ({"rule_id": "NET-006"}, []),
        ({"limit": 1, "offset": 2}, [1]),
        ({"rule_id": "NET-001", "limit": 1, "offset": 1}, [0]),
    ],
)
def test_alerts_are_filtered_and_paged_newest_first(
    rig: ServiceRig, world: World, filters: dict[str, Any], expected: list[int]
) -> None:
    options = {**EVERYTHING, **filters}

    page = rig.call("list_alerts", "alice", world.mine, **options)

    assert [item.id for item in page.items] == [world.my_alerts[index] for index in expected]
    narrowed = {key: value for key, value in options.items() if key not in ("limit", "offset")}
    everything = rig.call("list_alerts", "alice", world.mine, **narrowed, limit=50, offset=0)
    assert page.total == len(everything.items)
    assert (page.limit, page.offset) == (options["limit"], options["offset"])


def test_a_session_without_flows_or_alerts_has_empty_pages(
    rig: ServiceRig, factory: SessionFactory
) -> None:
    empty = seed_session(factory, started=ago(hours=1))

    flows = rig.call("list_flows", "alice", empty, **PAGE)
    alerts = rig.call("list_alerts", "alice", empty, **EVERYTHING)

    assert (flows.items, flows.total, alerts.items, alerts.total) == ([], 0, [], 0)


# --- Deleting -----------------------------------------------------------------------------------


def test_a_deleted_session_goes_with_its_flows_and_alerts_and_is_audited(
    rig: ServiceRig, world: World
) -> None:
    assert rig.call("delete_session", ALICE, world.mine) is None

    assert not rig.exists(world.mine)
    assert (rig.flows(world.mine), rig.alerts(world.mine)) == ([], [])
    assert [flow.id for flow in rig.flows(world.theirs)] == world.their_flows
    assert [alert.id for alert in rig.alerts(world.theirs)] == [world.their_alert]
    (entry,) = rig.audit("NETWORK_SESSION_DELETE")
    assert (entry.actor, entry.result, entry.target) == ("alice", "success", target_of(world.mine))
    assert entry.source_ip == ALICE.source_ip
    assert entry.details == {"source": "pcap", "flows": 5, "alerts": 4}
    assert refusal(functools.partial(rig.call, "delete_session", ALICE, world.mine)) == NOT_FOUND
    assert len(rig.audit("NETWORK_SESSION_DELETE")) == 1


@pytest.mark.parametrize("source", [CaptureSource.LIVE, CaptureSource.PCAP])
@pytest.mark.parametrize(
    "status", [CaptureStatus.STARTING, CaptureStatus.RUNNING, CaptureStatus.STOPPING]
)
def test_a_session_that_is_still_running_cannot_be_deleted(
    rig: ServiceRig, factory: SessionFactory, status: CaptureStatus, source: CaptureSource
) -> None:
    session_id = seed_session(factory, status=status, source=source, started=ago(minutes=5))
    seed_flow(factory, session_id)
    seed_alert(factory, session_id)

    status_code, code, _ = refusal(functools.partial(rig.call, "delete_session", ALICE, session_id))

    assert (status_code, code) == (409, "session_running")
    assert rig.row(session_id).status == status.value
    assert (len(rig.flows(session_id)), len(rig.alerts(session_id))) == (1, 1)
    assert rig.audit() == []


@pytest.mark.parametrize(
    "status",
    [
        CaptureStatus.STOPPED,
        CaptureStatus.COMPLETED,
        CaptureStatus.FAILED,
        CaptureStatus.PERMISSION_DENIED,
    ],
)
def test_every_kind_of_finished_session_can_be_deleted(
    rig: ServiceRig, factory: SessionFactory, status: CaptureStatus
) -> None:
    session_id = seed_session(factory, status=status, source=CaptureSource.LIVE)

    rig.call("delete_session", ALICE, session_id)

    assert not rig.exists(session_id)
    (entry,) = rig.audit("NETWORK_SESSION_DELETE")
    assert entry.details == {"source": "live", "flows": 0, "alerts": 0}


def test_a_delete_that_cannot_be_committed_leaves_the_session_and_the_audit_alone(
    rig: ServiceRig, factory: SessionFactory, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken() -> None:
        raise OperationalError("COMMIT", {}, Exception("database is locked"))

    with factory() as db:
        monkeypatch.setattr(db, "commit", broken)
        with pytest.raises(OperationalError):
            rig.service.delete_session(db, ALICE, world.mine)

    assert rig.exists(world.mine)
    assert (len(rig.flows(world.mine)), len(rig.alerts(world.mine))) == (5, 4)
    assert rig.audit() == []


def test_deleting_a_session_drops_the_lookups_that_have_not_started(
    rig: ServiceRig, scan_files: dict[str, bytes], caplog: pytest.LogCaptureFixture
) -> None:
    gate = rig.intel.gate = threading.Event()
    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        accepted = rig.analyze(scan_files["pcap"], ALICE)
        wait_until(rig.intel.entered.is_set, what="the first lookup to start")
        rig.wait_for_end(accepted.id)
        wait_until(lambda: lookups_waiting(rig) == 2, what="both addresses to be queued")

        rig.call("delete_session", ALICE, accepted.id)
        gate.set()
        wait_until(lambda: lookups_waiting(rig) == 0, what="the lookups to be over")

    # The lookup already under way finished into a session that was no longer there.
    assert len(rig.intel.calls) == 1
    assert (rig.count(CaptureSession), rig.count(NetworkFlow), rig.count(NetworkAlert)) == (0, 0, 0)
    assert [record for record in caplog.records if record.levelno >= logging.WARNING] == []


# --- Looking an address up again ---------------------------------------------------------------


def test_an_alert_is_looked_up_again_for_the_caller_and_audited(
    rig: ServiceRig, factory: SessionFactory
) -> None:
    rig.intel.replies[SCANNER] = reply(
        provider_view("abuseipdb", "ok", verdict="suspicious"),
        provider_view("otx", "no_data", verdict=None),
        score=30,
        classification="low",
    )
    session_id, alert_id = an_alert(factory)

    shown = rig.call("enrich_alert", ALICE, alert_id)

    assert (shown.id, shown.session_id) == (alert_id, session_id)
    assert (shown.enrichment.status, shown.enrichment.address) == ("completed", SCANNER)
    assert (shown.enrichment.risk_score, shown.enrichment.classification) == (30, "low")
    assert shown.enrichment.error_code is None
    assert [(item.provider, item.status, item.verdict) for item in shown.enrichment.providers] == [
        ("abuseipdb", "ok", "suspicious"),
        ("otx", "no_data", None),
    ]
    assert rig.intel.calls == [SCANNER]
    assert rig.intel.contexts == [ALICE]
    assert rig.intel.refresh_flags == [False]
    assert enrichment_of(rig, session_id, alert_id).risk_score == 30
    assert rig.row(session_id).stats["enrichment"][SCANNER]["status"] == "completed"
    (entry,) = rig.audit("NETWORK_ENRICH")
    assert (entry.actor, entry.result, entry.source_ip) == ("alice", "success", ALICE.source_ip)
    assert entry.target == f"network-alert:{alert_id}"
    assert entry.details == {"status": "completed", "error_code": None}


@pytest.mark.parametrize(
    ("outcome", "status", "error_code"),
    [
        (reply(provider_view(status="rate_limited")), "failed", "rate_limited"),
        (reply(provider_view(status="error")), "failed", "provider_error"),
        (reply(provider_view(status="not_configured")), "unavailable", "no_provider_available"),
        (RuntimeError(SECRET), "failed", "lookup_failed"),
        (IndicatorDeletedError(), "unavailable", "indicator_deleted"),
    ],
    ids=["rate-limited", "provider-error", "no-provider", "crash", "indicator-deleted"],
)
def test_a_lookup_that_got_no_answer_is_shown_and_audited_as_partial(
    rig: ServiceRig,
    factory: SessionFactory,
    caplog: pytest.LogCaptureFixture,
    outcome: Any,
    status: str,
    error_code: str,
) -> None:
    rig.intel.replies[SCANNER] = outcome
    _, alert_id = an_alert(factory)

    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        shown = rig.call("enrich_alert", ALICE, alert_id)

    assert (shown.enrichment.status, shown.enrichment.error_code) == (status, error_code)
    assert shown.enrichment.risk_score is None
    (entry,) = rig.audit("NETWORK_ENRICH")
    assert entry.result == "partial"
    assert entry.details == {"status": status, "error_code": error_code}
    assert_not_logged(caplog, SECRET)
    assert SECRET not in json.dumps(entry.details)


@pytest.mark.parametrize(
    ("src", "dst", "subject"),
    [
        (SCANNER, SERVER, SCANNER),
        (HOST, RESOLVER, RESOLVER),
        (SCANNER, RESOLVER, SCANNER),
        (RESOLVER, SCANNER, RESOLVER),
        ("2001:4860:4860::8888", HOST, "2001:4860:4860::8888"),
        (None, RESOLVER, RESOLVER),
    ],
)
def test_the_address_looked_up_is_the_public_one_of_the_alert(
    rig: ServiceRig, factory: SessionFactory, src: str | None, dst: str | None, subject: str
) -> None:
    _, alert_id = an_alert(factory, src=src, dst=dst)

    shown = rig.call("enrich_alert", ALICE, alert_id)

    assert rig.intel.calls == [subject]
    assert (shown.enrichment.status, shown.enrichment.address) == ("completed", subject)


@pytest.mark.parametrize(
    ("src", "dst"),
    [
        (HOST, SERVER),
        (DOCUMENTATION, "198.51.100.7"),
        ("100.64.0.1", "169.254.1.1"),
        ("::1", "2001:db8::1"),
        (None, None),
    ],
)
def test_an_alert_without_a_public_address_has_nothing_to_look_up(
    rig: ServiceRig, factory: SessionFactory, src: str | None, dst: str | None
) -> None:
    _, alert_id = an_alert(factory, src=src, dst=dst)

    refused = refusal(functools.partial(rig.call, "enrich_alert", ALICE, alert_id))

    assert refused[:2] == (422, "address_not_public")
    assert rig.intel.calls == []
    assert rig.audit() == []


def test_nothing_is_looked_up_while_enrichment_is_switched_off(
    make_rig: Callable[..., ServiceRig], factory: SessionFactory
) -> None:
    rig = make_rig({"external_enrichment_enabled": False})
    _, public = an_alert(factory)
    _, private = an_alert(factory, src=HOST, dst=SERVER)

    for alert_id in (public, private):  # the switch is read before the address is
        refused = refusal(functools.partial(rig.call, "enrich_alert", ALICE, alert_id))
        assert refused[:2] == (409, "enrichment_disabled")
    missing = refusal(functools.partial(rig.call, "enrich_alert", ALICE, uuid.uuid4()))
    assert missing[:2] == (404, "alert_not_found")

    assert rig.intel.calls == []
    assert rig.audit() == []


def test_a_bad_reputation_raises_one_alert_however_often_the_address_is_asked_about(
    rig: ServiceRig, scan_files: dict[str, bytes]
) -> None:
    accepted = rig.analyze(scan_files["pcap"], ALICE)
    rig.wait_for_end(accepted.id)
    rig.wait_for_lookups(accepted.id, [SCANNER, RESOLVER])
    (port_scan,) = rig.alerts(accepted.id)
    assert port_scan.rule_id == "NET-001"
    rig.intel.replies[SCANNER] = reply(provider_view(), score=95, classification="critical")

    first = rig.call("enrich_alert", ALICE, port_scan.id)
    again = rig.call("enrich_alert", ALICE, port_scan.id)

    assert [shown.enrichment.risk_score for shown in (first, again)] == [95, 95]
    alerts = rig.alerts(accepted.id)
    assert [alert.rule_id for alert in alerts] == ["NET-001", "NET-005"]
    assert alerts[1].severity == "critical"
    assert rig.row(accepted.id).alerts_total == 2
    shown = rig.call("get_session", ALICE.actor, accepted.id)
    assert shown.alerts_by_rule == {"NET-001": 1, "NET-005": 1}  # counted once, not once per ask
    assert [entry.result for entry in rig.audit("NETWORK_ENRICH")] == ["success", "success"]


# --- Retention ---------------------------------------------------------------------------------


def test_old_sessions_are_purged_when_sessions_are_listed_but_not_every_time(
    rig: ServiceRig, factory: SessionFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FakeClock(1000.0)
    monkeypatch.setattr(service_module, "time", SimpleNamespace(monotonic=clock, time=time.time))
    old = [seed_expired(factory, owner="alice"), seed_expired(factory, owner="bob")]
    recent = seed_session(factory, started=ago(hours=2), ended=ago(hours=1))
    running = seed_session(
        factory, status=CaptureStatus.RUNNING, source=CaptureSource.LIVE, started=ago(hours=100)
    )

    first = rig.call("list_sessions", "alice", **PAGE)

    assert sorted(item.id for item in first.items) == sorted([recent, running])
    assert first.total == 2
    assert not any(rig.exists(session_id) for session_id in old)
    assert (rig.count(NetworkFlow), rig.count(NetworkAlert)) == (0, 0)

    later = seed_expired(factory)
    clock.advance(service_module.PURGE_INTERVAL_SECONDS - 1)
    rig.call("list_sessions", "alice", **PAGE)
    assert rig.exists(later)
    clock.advance(2)
    rig.call("list_sessions", "alice", **PAGE)
    assert not rig.exists(later)


def test_the_retention_period_is_the_one_configured(
    make_rig: Callable[..., ServiceRig], factory: SessionFactory
) -> None:
    rig = make_rig({"network_retention_hours": 2})
    kept = seed_expired(factory, hours=1.5)
    purged = seed_expired(factory, hours=2.5)

    assert rig.service.purge_expired() == 1

    assert rig.exists(kept)
    assert not rig.exists(purged)


def test_a_purge_removes_a_bounded_number_of_sessions_per_call(
    rig: ServiceRig, factory: SessionFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_module, "_PURGE_BATCH", 2)
    monkeypatch.setattr(service_module, "_MAX_PURGE_ROUNDS", 2)
    ids = [seed_expired(factory, hours=100 + index) for index in range(7)]  # the oldest last
    live = seed_session(
        factory, status=CaptureStatus.STOPPING, source=CaptureSource.LIVE, started=ago(hours=500)
    )

    assert rig.service.purge_expired() == 4
    assert [rig.exists(session_id) for session_id in ids] == [True] * 3 + [False] * 4
    assert rig.service.purge_expired() == 3
    assert rig.service.purge_expired() == 0

    assert not any(rig.exists(session_id) for session_id in ids)
    assert rig.exists(live)
    assert (rig.count(NetworkFlow), rig.count(NetworkAlert)) == (0, 0)


def test_a_purge_that_fails_is_logged_and_not_tried_again_at_once(
    make_rig: Callable[..., ServiceRig], factory: SessionFactory, caplog: pytest.LogCaptureFixture
) -> None:
    flaky = FlakyFactory(factory, failures=-1)
    rig = make_rig(service_sessions=flaky)
    expired = seed_expired(factory)

    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        assert rig.service.purge_expired() == 0
        page = rig.call("list_sessions", "alice", **PAGE)  # the first listing tries once more
        rig.call("list_sessions", "alice", **PAGE)  # and the next ones leave the database be

    assert [record.error for record in logged(caplog, "network_purge_failed")] == [
        "OperationalError"
    ] * 2
    assert flaky.calls == 2
    assert [item.id for item in page.items] == [expired]
    assert rig.exists(expired)


def test_a_purge_in_progress_does_not_hold_up_a_listing(
    rig: ServiceRig, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered, release = threading.Event(), threading.Event()
    calls: list[int] = []

    def slow_purge() -> int:
        calls.append(1)
        entered.set()
        release.wait(10)
        return 0

    monkeypatch.setattr(rig.service, "purge_expired", slow_purge)
    rig.gates.append(release)
    first = Background(rig.call, "list_sessions", "alice", **PAGE)
    wait_until(entered.is_set, what="the purge to start")

    second = rig.call("list_sessions", "alice", **PAGE)

    assert (second.total, len(calls), first.done) == (0, 1, False)
    release.set()
    assert first.join().error is None


# --- Start-up ---------------------------------------------------------------------------------


def test_startup_ends_the_sessions_the_last_run_left_running(
    rig: ServiceRig, factory: SessionFactory, caplog: pytest.LogCaptureFixture
) -> None:
    def live(owner: str, status: CaptureStatus, **options: Any) -> uuid.UUID:
        return seed_session(
            factory, owner=owner, status=status, source=CaptureSource.LIVE, label=None, **options
        )

    left = {
        "starting": live("alice", CaptureStatus.STARTING, started=ago(minutes=30)),
        "running": live("bob", CaptureStatus.RUNNING, started=ago(minutes=20)),
        "stopping": live("carol", CaptureStatus.STOPPING, started=ago(minutes=10)),
        "file": seed_session(factory, status=CaptureStatus.RUNNING, started=ago(minutes=5)),
    }
    finished = [
        live("alice", CaptureStatus.STOPPED, started=ago(hours=3)),
        live("bob", CaptureStatus.FAILED, started=ago(hours=2), error_code="capture_failed"),
        seed_session(factory, status=CaptureStatus.COMPLETED, started=ago(hours=1)),
    ]
    before = {session_id: snapshot(rig.row(session_id)) for session_id in finished}

    with caplog.at_level(logging.INFO, logger="cipherforge.network"):
        rig.service.startup()
        rig.service.startup()

    for name, session_id in left.items():
        row = rig.row(session_id)
        assert (row.status, row.error_code) == ("failed", "interrupted"), name
        assert row.ended_at is not None
        assert row.ended_at >= row.started_at, name
    assert {session_id: snapshot(rig.row(session_id)) for session_id in finished} == before
    (cleanup,) = logged(caplog, "network_startup_cleanup")
    assert cleanup.sessions_interrupted == 4
    status = rig.status(ALICE)
    assert (status.state, status.session_id, status.busy) == ("failed", left["starting"], False)
    assert (status.error_code, status.message) == ("interrupted", message_for("interrupted"))


def test_startup_settles_the_lookups_nobody_will_finish(
    rig: ServiceRig, factory: SessionFactory, caplog: pytest.LogCaptureFixture
) -> None:
    session_id = seed_session(factory, started=ago(hours=1))
    waiting = seed_alert(factory, session_id, enrichment={"status": "pending", "address": SCANNER})

    with caplog.at_level(logging.INFO, logger="cipherforge.network"):
        rig.service.startup()

    shown = enrichment_of(rig, session_id, waiting)
    assert (shown.status, shown.error_code, shown.address) == (
        "unavailable",
        "interrupted",
        SCANNER,
    )
    (cleanup,) = logged(caplog, "network_startup_cleanup")
    assert cleanup.lookups_interrupted == 1


def test_startup_purges_what_has_expired_and_what_a_crash_left_in_the_spool(
    rig: ServiceRig,
    factory: SessionFactory,
    caplog: pytest.LogCaptureFixture,
    request: pytest.FixtureRequest,
) -> None:
    expired = [seed_expired(factory, owner="alice"), seed_expired(factory, owner="bob")]
    recent = seed_expired(factory, hours=1)
    # Older than the retention period, but running: it is ended first, so it is not purged.
    ancient = seed_session(
        factory, status=CaptureStatus.RUNNING, source=CaptureSource.LIVE, started=ago(hours=200)
    )
    stale = stale_upload(rig.spool_base)
    fresh = rig.spool_base / "cipherforge-pcap-in-use"
    fresh.mkdir()
    unrelated = rig.spool_base / "somebody-elses-directory"
    unrelated.mkdir()
    backdate(unrelated, THREE_DAYS)
    for leftover in (fresh, unrelated):
        request.addfinalizer(functools.partial(shutil.rmtree, leftover, ignore_errors=True))

    with caplog.at_level(logging.INFO, logger="cipherforge.network"):
        rig.service.startup()

    assert not any(rig.exists(session_id) for session_id in expired)
    assert rig.exists(recent)
    assert (rig.row(ancient).status, rig.row(ancient).error_code) == ("failed", "interrupted")
    assert (rig.count(NetworkFlow), rig.count(NetworkAlert)) == (1, 1)
    assert not stale.exists()
    assert fresh.is_dir()
    assert unrelated.is_dir()
    (cleanup,) = logged(caplog, "network_startup_cleanup")
    assert (cleanup.sessions_interrupted, cleanup.lookups_interrupted) == (1, 0)
    assert (cleanup.sessions_purged, cleanup.stale_uploads_removed) == (2, 1)


def test_a_startup_with_nothing_to_clean_up_says_nothing(
    rig: ServiceRig, factory: SessionFactory, caplog: pytest.LogCaptureFixture
) -> None:
    seed_session(factory, started=ago(hours=1))

    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        rig.service.startup()

    assert [record for record in caplog.records if record.name == "cipherforge.network"] == []


# --- Shutdown ---------------------------------------------------------------------------------


def test_shutdown_can_be_repeated_and_leaves_no_thread_or_file_behind(
    rig: ServiceRig, scan_files: dict[str, bytes]
) -> None:
    accepted = rig.analyze(scan_files["pcap"], ALICE)
    rig.wait_for_end(accepted.id)
    rig.wait_for_lookups(accepted.id, [SCANNER, RESOLVER])
    assert rig.service.spool.directory().is_dir()

    rig.service.shutdown()
    rig.service.shutdown()

    assert_no_module_threads()
    assert list(rig.spool_base.iterdir()) == []


def test_shutdown_settles_the_lookups_still_waiting(
    rig: ServiceRig, factory: SessionFactory
) -> None:
    session_id = seed_session(factory, started=ago(hours=1))
    waiting = seed_alert(factory, session_id, enrichment={"status": "pending", "address": SCANNER})

    rig.service.shutdown()

    shown = enrichment_of(rig, session_id, waiting)
    assert (shown.status, shown.error_code) == ("unavailable", "interrupted")


def test_shutdown_finishes_even_when_the_database_cannot_be_written(
    make_rig: Callable[..., ServiceRig], factory: SessionFactory, caplog: pytest.LogCaptureFixture
) -> None:
    rig = make_rig(service_sessions=FlakyFactory(factory, failures=-1))
    session_id = seed_session(factory, started=ago(hours=1))
    seed_alert(factory, session_id, enrichment={"status": "pending", "address": SCANNER})
    spool_directory = rig.service.spool.directory()

    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        rig.service.shutdown()

    assert [record.error for record in logged(caplog, "network_shutdown_cleanup_failed")] == [
        "OperationalError"
    ]
    assert not spool_directory.exists()


# --- What must stay out of the record --------------------------------------------------------


def test_no_file_name_address_or_secret_reaches_the_audit_trail_or_the_logs(
    rig: ServiceRig,
    factory: SessionFactory,
    scan_files: dict[str, bytes],
    caplog: pytest.LogCaptureFixture,
) -> None:
    rig.intel.replies[RESOLVER] = RuntimeError(SECRET)
    _, alert_id = an_alert(factory, src=RESOLVER, dst=SERVER)

    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        accepted = rig.analyze(scan_files["pcap"], ALICE, name=LABEL)
        rig.wait_for_end(accepted.id)
        wait_until(lambda: lookups_waiting(rig) == 0, what="the lookups to be over")
        rig.start(ALICE)
        rig.stop(ALICE)
        rig.call("enrich_alert", ALICE, alert_id)
        rig.call("delete_session", ALICE, accepted.id)

    entries = rig.audit()
    assert {entry.action for entry in entries} == {
        "NETWORK_PCAP_ANALYZE",
        "NETWORK_CAPTURE_START",
        "NETWORK_CAPTURE_STOP",
        "NETWORK_ENRICH",
        "NETWORK_SESSION_DELETE",
    }
    trail = json.dumps([[entry.actor, entry.target, entry.details] for entry in entries])
    private = (LABEL, SECRET, *TEST_INTERFACE.addresses, str(rig.spool_base))
    for text in private:
        assert text not in trail
        assert_not_logged(caplog, text)
