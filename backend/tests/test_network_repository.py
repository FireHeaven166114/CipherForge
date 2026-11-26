"""Network repository: owner scoping, ordering and paging, retention, and crash recovery."""

import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.database.session import build_engine, build_session_factory
from app.models.enums import CaptureSource, CaptureStatus
from app.models.network import CaptureSession, NetworkAlert, NetworkFlow
from app.models.types import utcnow
from app.network import repository
from tests.network_helpers import (
    SCANNER,
    SERVER,
    T0,
    seed_alert,
    seed_flow,
    seed_session,
)

SessionFactory = sessionmaker[Session]

BASE = datetime.fromtimestamp(T0, tz=UTC)
ACTIVE = (CaptureStatus.STARTING, CaptureStatus.RUNNING, CaptureStatus.STOPPING)
FINISHED = (
    CaptureStatus.STOPPED,
    CaptureStatus.COMPLETED,
    CaptureStatus.FAILED,
    CaptureStatus.PERMISSION_DENIED,
)


@pytest.fixture
def factory(make_settings: Callable[..., Settings], db_url: str) -> Iterator[SessionFactory]:
    engine = build_engine(make_settings(database_url=db_url))
    yield build_session_factory(engine)
    engine.dispose()


def at(minutes: float = 0) -> datetime:
    return BASE + timedelta(minutes=minutes)


def fixed_id(number: int) -> uuid.UUID:
    return uuid.UUID(int=number)


def fetch(factory: SessionFactory, session_id: uuid.UUID) -> CaptureSession | None:
    with factory() as db:
        return db.get(CaptureSession, session_id)


def count(factory: SessionFactory, model: Any, *conditions: Any) -> int:
    with factory() as db:
        return int(db.scalar(select(func.count()).select_from(model).where(*conditions)) or 0)


def clear_end(factory: SessionFactory, session_id: uuid.UUID) -> None:
    with factory() as db:
        row = db.get(CaptureSession, session_id)
        assert row is not None
        row.ended_at = None
        db.commit()


def ids(rows: Any) -> list[Any]:
    return [row.id for row in rows]


# --- new_session --------------------------------------------------------------------------


def test_a_new_session_is_complete_right_after_the_commit(factory: SessionFactory) -> None:
    # The upload endpoint answers from this object, so the column defaults must already be
    # there when the insert has been committed.
    session_id = uuid.uuid4()
    before = utcnow()
    with factory() as db:
        row = repository.new_session(
            db,
            session_id=session_id,
            owner="alice",
            source_kind=CaptureSource.PCAP,
            status=CaptureStatus.RUNNING,
            source_label="scan.pcap",
        )
        db.commit()
        assert (row.id, row.owner, row.source_kind, row.status) == (
            session_id,
            "alice",
            "pcap",
            "running",
        )
        counters = (
            row.packets_total,
            row.bytes_total,
            row.flows_total,
            row.alerts_total,
            row.packets_dropped,
        )
        assert counters == (0, 0, 0, 0, 0)
        assert row.stats == {}
        assert row.ended_at is None
        assert row.error_code is None
        assert row.interface is None
        assert row.started_at.tzinfo is not None
        assert before <= row.started_at <= utcnow()
    stored = fetch(factory, session_id)
    assert stored is not None
    assert (stored.source_label, stored.interface, stored.stats) == ("scan.pcap", None, {})


def test_the_session_is_not_stored_until_the_caller_commits(factory: SessionFactory) -> None:
    session_id = uuid.uuid4()
    with factory() as db:
        repository.new_session(
            db,
            session_id=session_id,
            owner="alice",
            source_kind=CaptureSource.LIVE,
            status=CaptureStatus.STARTING,
            interface="Fake NIC",
        )
        db.rollback()
    assert fetch(factory, session_id) is None


def test_the_interface_and_label_are_cut_to_the_column_sizes(factory: SessionFactory) -> None:
    session_id = uuid.uuid4()
    with factory() as db:
        repository.new_session(
            db,
            session_id=session_id,
            owner="alice",
            source_kind=CaptureSource.LIVE,
            status=CaptureStatus.STARTING,
            interface="i" * 300,
            source_label="l" * 200,
        )
        db.commit()
    stored = fetch(factory, session_id)
    assert stored is not None
    assert stored.interface == "i" * 256
    assert stored.source_label == "l" * 128


@pytest.mark.parametrize("blank", [None, ""])
def test_a_blank_interface_or_label_is_stored_as_null(
    factory: SessionFactory, blank: str | None
) -> None:
    session_id = uuid.uuid4()
    with factory() as db:
        repository.new_session(
            db,
            session_id=session_id,
            owner="alice",
            source_kind=CaptureSource.PCAP,
            status=CaptureStatus.RUNNING,
            interface=blank,
            source_label=blank,
        )
        db.commit()
    stored = fetch(factory, session_id)
    assert stored is not None
    assert (stored.interface, stored.source_label) == (None, None)


# --- Owner scoping ------------------------------------------------------------------------


class World:
    """Two owners with a session, a flow and an alert each, plus a look-alike third owner."""

    def __init__(self, factory: SessionFactory) -> None:
        self.alice_live = seed_session(
            factory, owner="alice", source=CaptureSource.LIVE, started=at(0), interface="Fake NIC"
        )
        self.alice_pcap = seed_session(factory, owner="alice", started=at(5))
        self.bob_pcap = seed_session(factory, owner="bob", started=at(10))
        self.bob_live = seed_session(
            factory, owner="bob", source=CaptureSource.LIVE, started=at(20), interface="Fake NIC"
        )
        self.alice_flow = seed_flow(factory, self.alice_pcap)
        self.bob_flow = seed_flow(factory, self.bob_pcap)
        self.alice_alert = seed_alert(factory, self.alice_pcap)
        self.bob_alert = seed_alert(factory, self.bob_pcap)


@pytest.fixture
def world(factory: SessionFactory) -> World:
    return World(factory)


def test_get_session_returns_only_the_owners_session(factory: SessionFactory, world: World) -> None:
    with factory() as db:
        mine = repository.get_session(db, "alice", world.alice_pcap)
        assert mine is not None and mine.id == world.alice_pcap
        assert repository.get_session(db, "bob", world.alice_pcap) is None
        assert repository.get_session(db, "alice", world.bob_pcap) is None
        assert repository.get_session(db, "alice", uuid.uuid4()) is None


@pytest.mark.parametrize(
    "owner",
    ["admin", "Alice", "ALICE", "alice ", " alice", "alice%", "%", "_lice", "alic_", "", "*"],
)
def test_another_owner_never_matches_by_pattern_case_or_padding(
    factory: SessionFactory, world: World, owner: str
) -> None:
    # Ownership is an exact comparison: no wildcard, case folding or trimming, and an
    # administrator has no cross-owner view.
    with factory() as db:
        assert repository.get_session(db, owner, world.alice_pcap) is None
        assert repository.get_owned_alert(db, owner, world.alice_alert) is None
        assert repository.latest_live_session(db, owner) is None
        assert repository.list_sessions(db, owner, limit=100, offset=0) == ([], 0)


def test_list_sessions_counts_and_returns_only_the_owners_sessions(
    factory: SessionFactory, world: World
) -> None:
    with factory() as db:
        rows, total = repository.list_sessions(db, "alice", limit=100, offset=0)
        assert (ids(rows), total) == ([world.alice_pcap, world.alice_live], 2)
        rows, total = repository.list_sessions(db, "bob", limit=100, offset=0)
        assert (ids(rows), total) == ([world.bob_live, world.bob_pcap], 2)
        assert repository.list_sessions(db, "carol", limit=100, offset=0) == ([], 0)


def test_latest_live_session_is_the_owners_newest_live_one(
    factory: SessionFactory, world: World
) -> None:
    newer = seed_session(
        factory, owner="alice", source=CaptureSource.LIVE, started=at(3), interface="Other NIC"
    )
    seed_session(factory, owner="alice", started=at(60))
    with factory() as db:
        latest = repository.latest_live_session(db, "alice")
        assert latest is not None and latest.id == newer
        bobs = repository.latest_live_session(db, "bob")
        assert bobs is not None and bobs.id == world.bob_live
        assert repository.latest_live_session(db, "carol") is None


def test_latest_live_session_ignores_capture_files(factory: SessionFactory) -> None:
    seed_session(factory, owner="alice", source=CaptureSource.PCAP, started=at(10))
    with factory() as db:
        assert repository.latest_live_session(db, "alice") is None


def test_latest_live_session_breaks_a_tie_by_id(factory: SessionFactory) -> None:
    first = seed_session(
        factory, source=CaptureSource.LIVE, started=at(1), session_id=fixed_id(1), interface="a"
    )
    seed_session(
        factory, source=CaptureSource.LIVE, started=at(1), session_id=fixed_id(2), interface="b"
    )
    with factory() as db:
        latest = repository.latest_live_session(db, "alice")
        assert latest is not None and latest.id == first


def test_get_owned_alert_follows_the_session_owner(factory: SessionFactory, world: World) -> None:
    other_session = seed_session(factory, owner="alice", started=at(40))
    second_alert = seed_alert(
        factory, other_session, rule_id="NET-002", rule_name="connection_rate"
    )
    with factory() as db:
        found = repository.get_owned_alert(db, "alice", world.alice_alert)
        assert found is not None and found.session_id == world.alice_pcap
        again = repository.get_owned_alert(db, "alice", second_alert)
        assert again is not None and again.session_id == other_session
        assert repository.get_owned_alert(db, "bob", world.alice_alert) is None
        assert repository.get_owned_alert(db, "alice", world.bob_alert) is None
        assert repository.get_owned_alert(db, "alice", uuid.uuid4()) is None


# --- Paging and ordering ------------------------------------------------------------------


def test_sessions_are_listed_newest_first_with_ties_broken_by_id(factory: SessionFactory) -> None:
    oldest = seed_session(factory, started=at(0), session_id=fixed_id(9))
    tie_low = seed_session(factory, started=at(5), session_id=fixed_id(2))
    tie_high = seed_session(factory, started=at(5), session_id=fixed_id(3))
    newest = seed_session(factory, started=at(9), session_id=fixed_id(1))
    with factory() as db:
        rows, total = repository.list_sessions(db, "alice", limit=10, offset=0)
    assert ids(rows) == [newest, tie_low, tie_high, oldest]
    assert total == 4


def test_session_pages_cover_every_row_exactly_once(factory: SessionFactory) -> None:
    created = [
        seed_session(factory, started=at(index // 2), session_id=fixed_id(index + 1))
        for index in range(7)
    ]
    seen: list[uuid.UUID] = []
    with factory() as db:
        everything, _ = repository.list_sessions(db, "alice", limit=100, offset=0)
        for offset in range(0, 9, 3):
            rows, total = repository.list_sessions(db, "alice", limit=3, offset=offset)
            assert total == 7
            seen.extend(ids(rows))
    assert seen == ids(everything)
    assert sorted(seen) == sorted(created)
    assert len(set(seen)) == 7


def test_paging_beyond_the_end_gives_no_rows_but_the_true_total(
    factory: SessionFactory, world: World
) -> None:
    with factory() as db:
        assert repository.list_sessions(db, "alice", limit=10, offset=50) == ([], 2)
        rows, total = repository.list_sessions(db, "alice", limit=1, offset=1)
        assert (ids(rows), total) == ([world.alice_live], 2)
        assert repository.list_flows(db, world.alice_pcap, limit=10, offset=9) == ([], 1)
        assert repository.list_alerts(db, world.alice_pcap, limit=10, offset=9) == ([], 1)


def test_flows_are_listed_newest_first_with_ties_broken_by_newest_id(
    factory: SessionFactory,
) -> None:
    session_id = seed_session(factory)
    oldest = seed_flow(factory, session_id, first=at(0), dport=1)
    tie_first = seed_flow(factory, session_id, first=at(5), dport=2)
    tie_second = seed_flow(factory, session_id, first=at(5), dport=3)
    newest = seed_flow(factory, session_id, first=at(9), dport=4)
    with factory() as db:
        rows, total = repository.list_flows(db, session_id, limit=10, offset=0)
        assert ids(rows) == [newest, tie_second, tie_first, oldest]
        assert total == 4
        page, total = repository.list_flows(db, session_id, limit=2, offset=1)
        assert ids(page) == [tie_second, tie_first]
        assert total == 4


def test_flows_of_other_sessions_are_not_listed(factory: SessionFactory) -> None:
    mine = seed_session(factory)
    other = seed_session(factory, owner="bob")
    own_flow = seed_flow(factory, mine)
    seed_flow(factory, other)
    seed_flow(factory, other)
    with factory() as db:
        rows, total = repository.list_flows(db, mine, limit=10, offset=0)
        assert (ids(rows), total) == ([own_flow], 1)
        assert repository.list_flows(db, uuid.uuid4(), limit=10, offset=0) == ([], 0)


def seed_alerts(factory: SessionFactory, session_id: uuid.UUID) -> dict[str, uuid.UUID]:
    return {
        "scan_low": seed_alert(factory, session_id, severity="low", created=at(1)),
        "scan_high": seed_alert(factory, session_id, severity="high", created=at(2)),
        "rate_medium": seed_alert(
            factory,
            session_id,
            rule_id="NET-002",
            rule_name="connection_rate",
            severity="medium",
            created=at(3),
        ),
        "port_critical": seed_alert(
            factory,
            session_id,
            rule_id="NET-006",
            rule_name="suspicious_port",
            severity="critical",
            created=at(4),
        ),
        "port_high": seed_alert(
            factory,
            session_id,
            rule_id="NET-006",
            rule_name="suspicious_port",
            severity="high",
            created=at(5),
        ),
    }


def test_alerts_are_listed_newest_first(factory: SessionFactory) -> None:
    session_id = seed_session(factory)
    alerts = seed_alerts(factory, session_id)
    with factory() as db:
        rows, total = repository.list_alerts(db, session_id, limit=10, offset=0)
        assert total == 5
        assert ids(rows) == [
            alerts["port_high"],
            alerts["port_critical"],
            alerts["rate_medium"],
            alerts["scan_high"],
            alerts["scan_low"],
        ]
        page, total = repository.list_alerts(db, session_id, limit=2, offset=3)
        assert (ids(page), total) == ([alerts["scan_high"], alerts["scan_low"]], 5)


def test_alerts_created_together_are_ordered_by_id(factory: SessionFactory) -> None:
    session_id = seed_session(factory)
    created = [seed_alert(factory, session_id, created=at(1), dst_port=port) for port in range(6)]
    with factory() as db:
        rows, _ = repository.list_alerts(db, session_id, limit=10, offset=0)
        assert ids(rows) == sorted(created)
        first_page, _ = repository.list_alerts(db, session_id, limit=4, offset=0)
        second_page, _ = repository.list_alerts(db, session_id, limit=4, offset=4)
        assert ids(first_page) + ids(second_page) == sorted(created)


@pytest.mark.parametrize(
    ("severities", "rule_id", "expected"),
    [
        ((), None, {"scan_low", "scan_high", "rate_medium", "port_critical", "port_high"}),
        (["high"], None, {"scan_high", "port_high"}),
        (("high", "critical"), None, {"scan_high", "port_critical", "port_high"}),
        ({"low", "medium"}, None, {"scan_low", "rate_medium"}),
        ((), "NET-006", {"port_critical", "port_high"}),
        (["high"], "NET-006", {"port_high"}),
        (["low"], "NET-006", set()),
        (["unknown"], None, set()),
        ((), "NET-999", set()),
        ((), "", {"scan_low", "scan_high", "rate_medium", "port_critical", "port_high"}),
        ((), "NET-0%", set()),
        ((), "NET-00_", set()),
    ],
)
def test_alert_filters_narrow_the_rows_and_the_total(
    factory: SessionFactory,
    severities: Any,
    rule_id: str | None,
    expected: set[str],
) -> None:
    session_id = seed_session(factory)
    alerts = seed_alerts(factory, session_id)
    with factory() as db:
        rows, total = repository.list_alerts(
            db, session_id, severities=severities, rule_id=rule_id, limit=100, offset=0
        )
    assert set(ids(rows)) == {alerts[name] for name in expected}
    assert total == len(expected)


def test_the_alert_total_ignores_the_page_size(factory: SessionFactory) -> None:
    session_id = seed_session(factory)
    seed_alerts(factory, session_id)
    with factory() as db:
        rows, total = repository.list_alerts(db, session_id, severities=["high"], limit=1, offset=0)
    assert len(rows) == 1
    assert total == 2


def test_alerts_of_other_sessions_are_not_listed(factory: SessionFactory) -> None:
    mine = seed_session(factory)
    other = seed_session(factory, owner="bob")
    own_alert = seed_alert(factory, mine)
    seed_alert(factory, other)
    with factory() as db:
        rows, total = repository.list_alerts(db, mine, limit=10, offset=0)
        assert (ids(rows), total) == ([own_alert], 1)
        assert repository.list_alerts(db, uuid.uuid4(), limit=10, offset=0) == ([], 0)


# --- Deleting a session -------------------------------------------------------------------


def test_deleting_a_session_removes_its_flows_and_alerts_only(factory: SessionFactory) -> None:
    doomed = seed_session(factory)
    kept = seed_session(factory)
    for session_id in (doomed, kept):
        seed_flow(factory, session_id)
        seed_flow(factory, session_id, dport=443)
        seed_alert(factory, session_id)
    with factory() as db:
        repository.delete_session(db, doomed)
        db.commit()
    assert fetch(factory, doomed) is None
    assert count(factory, NetworkFlow, NetworkFlow.session_id == doomed) == 0
    assert count(factory, NetworkAlert, NetworkAlert.session_id == doomed) == 0
    assert fetch(factory, kept) is not None
    assert count(factory, NetworkFlow, NetworkFlow.session_id == kept) == 2
    assert count(factory, NetworkAlert, NetworkAlert.session_id == kept) == 1


def test_deleting_leaves_the_commit_to_the_caller(factory: SessionFactory) -> None:
    session_id = seed_session(factory)
    seed_flow(factory, session_id)
    seed_alert(factory, session_id)
    with factory() as db:
        repository.delete_session(db, session_id)
        db.rollback()
    assert fetch(factory, session_id) is not None
    assert count(factory, NetworkFlow, NetworkFlow.session_id == session_id) == 1
    assert count(factory, NetworkAlert, NetworkAlert.session_id == session_id) == 1


def test_deleting_an_unknown_session_does_nothing(factory: SessionFactory, world: World) -> None:
    with factory() as db:
        repository.delete_session(db, uuid.uuid4())
        db.commit()
    assert count(factory, CaptureSession) == 4


def test_the_database_cascades_a_session_delete_to_flows_and_alerts(
    factory: SessionFactory,
) -> None:
    # Retention and manual clean-up may remove a session row directly.
    session_id = seed_session(factory)
    seed_flow(factory, session_id)
    seed_alert(factory, session_id)
    with factory() as db:
        row = db.get(CaptureSession, session_id)
        assert row is not None
        db.delete(row)
        db.commit()
    assert count(factory, NetworkFlow) == 0
    assert count(factory, NetworkAlert) == 0


# --- Retention ----------------------------------------------------------------------------


@pytest.mark.parametrize("status", FINISHED)
def test_a_finished_session_older_than_the_cutoff_is_purged(
    factory: SessionFactory, status: CaptureStatus
) -> None:
    session_id = seed_session(factory, status=status, started=at(-120))
    with factory() as db:
        assert repository.purge_finished_before(db, at(0)) == 1
    assert fetch(factory, session_id) is None


@pytest.mark.parametrize("status", ACTIVE)
def test_a_session_still_in_progress_is_never_purged(
    factory: SessionFactory, status: CaptureStatus
) -> None:
    session_id = seed_session(
        factory, status=status, source=CaptureSource.LIVE, started=at(-100000)
    )
    seed_flow(factory, session_id)
    with factory() as db:
        assert repository.purge_finished_before(db, at(0)) == 0
    assert fetch(factory, session_id) is not None
    assert count(factory, NetworkFlow) == 1


def test_the_cutoff_is_judged_by_the_end_time(factory: SessionFactory) -> None:
    long_but_recent = seed_session(factory, started=at(-600), ended=at(-5))
    ended_before = seed_session(factory, started=at(-100), ended=at(-61))
    ended_at_cutoff = seed_session(factory, started=at(-100), ended=at(-60))
    ended_after = seed_session(factory, started=at(-100), ended=at(-59))
    with factory() as db:
        assert repository.purge_finished_before(db, at(-60)) == 1
    assert fetch(factory, ended_before) is None
    for kept in (long_but_recent, ended_at_cutoff, ended_after):
        assert fetch(factory, kept) is not None


def test_a_finished_session_without_an_end_time_falls_back_to_its_start(
    factory: SessionFactory,
) -> None:
    old = seed_session(factory, status=CaptureStatus.FAILED, started=at(-120))
    recent = seed_session(factory, status=CaptureStatus.FAILED, started=at(-10))
    for session_id in (old, recent):
        clear_end(factory, session_id)
    with factory() as db:
        assert repository.purge_finished_before(db, at(-60)) == 1
    assert fetch(factory, old) is None
    assert fetch(factory, recent) is not None


def test_purging_removes_flows_and_alerts_and_spares_other_sessions(
    factory: SessionFactory,
) -> None:
    old = seed_session(factory, owner="alice", started=at(-300))
    old_other_owner = seed_session(factory, owner="bob", started=at(-300))
    recent = seed_session(factory, owner="alice", started=at(-5))
    for session_id in (old, old_other_owner, recent):
        seed_flow(factory, session_id)
        seed_flow(factory, session_id, dport=443)
        seed_alert(factory, session_id)
    with factory() as db:
        assert repository.purge_finished_before(db, at(-60)) == 2
    assert (fetch(factory, old), fetch(factory, old_other_owner)) == (None, None)
    assert fetch(factory, recent) is not None
    assert count(factory, NetworkFlow) == 2
    assert count(factory, NetworkAlert) == 1
    assert count(factory, NetworkFlow, NetworkFlow.session_id == recent) == 2


def test_a_purge_takes_the_oldest_sessions_first_and_at_most_one_batch(
    factory: SessionFactory,
) -> None:
    created = [seed_session(factory, started=at(-100 + 10 * index)) for index in range(5)]
    with factory() as db:
        assert repository.purge_finished_before(db, at(0), batch=2) == 2
    assert [fetch(factory, session_id) is None for session_id in created] == [
        True,
        True,
        False,
        False,
        False,
    ]
    with factory() as db:
        assert repository.purge_finished_before(db, at(0), batch=2) == 2
        assert repository.purge_finished_before(db, at(0), batch=2) == 1
        assert repository.purge_finished_before(db, at(0), batch=2) == 0
    assert count(factory, CaptureSession) == 0


def test_repeated_purges_drain_more_than_the_default_batch(factory: SessionFactory) -> None:
    with factory() as db:
        for index in range(450):
            started = at(-1000 + index)
            session = CaptureSession(
                id=fixed_id(index + 1),
                owner="alice",
                source_kind="pcap",
                status="completed",
                started_at=started,
                ended_at=started + timedelta(seconds=1),
                stats={},
            )
            db.add(session)
        db.commit()
        db.add_all(
            NetworkFlow(
                session_id=fixed_id(index + 1),
                protocol="udp",
                src_ip="10.0.0.5",
                dst_ip="10.0.0.9",
                first_seen=at(-1000),
                last_seen=at(-1000),
                close_reason="idle",
            )
            for index in range(450)
        )
        db.commit()
    with factory() as db:
        removed = [repository.purge_finished_before(db, at(0)) for _ in range(4)]
    assert removed == [200, 200, 50, 0]
    assert count(factory, CaptureSession) == 0
    assert count(factory, NetworkFlow) == 0


def test_purging_nothing_changes_nothing(factory: SessionFactory, world: World) -> None:
    with factory() as db:
        assert repository.purge_finished_before(db, at(-1000)) == 0
    assert count(factory, CaptureSession) == 4


# --- Crash recovery -----------------------------------------------------------------------


@pytest.mark.parametrize("status", ACTIVE)
def test_a_session_left_active_ends_as_interrupted(
    factory: SessionFactory, status: CaptureStatus
) -> None:
    started = utcnow() - timedelta(minutes=5)
    session_id = seed_session(
        factory, status=status, source=CaptureSource.LIVE, started=started, interface="Fake NIC"
    )
    with factory() as db:
        assert repository.interrupt_unfinished_sessions(db) == 1
    row = fetch(factory, session_id)
    assert row is not None
    assert (row.status, row.error_code) == ("failed", "interrupted")
    assert row.ended_at is not None
    assert row.started_at <= row.ended_at <= utcnow()


def test_a_session_that_started_in_the_future_still_ends_after_it_started(
    factory: SessionFactory,
) -> None:
    started = utcnow() + timedelta(hours=2)
    session_id = seed_session(factory, status=CaptureStatus.RUNNING, started=started)
    with factory() as db:
        assert repository.interrupt_unfinished_sessions(db) == 1
    row = fetch(factory, session_id)
    assert row is not None
    assert row.ended_at == row.started_at


def test_recovery_leaves_finished_sessions_alone_and_counts_the_rest(
    factory: SessionFactory,
) -> None:
    finished = {
        status: seed_session(
            factory,
            status=status,
            started=at(1),
            ended=at(2),
            error_code="capture_failed" if status is CaptureStatus.FAILED else None,
        )
        for status in FINISHED
    }
    active = [
        seed_session(factory, owner=owner, status=status, started=at(3))
        for owner in ("alice", "bob")
        for status in ACTIVE
    ]
    with factory() as db:
        assert repository.interrupt_unfinished_sessions(db) == 6
        assert repository.interrupt_unfinished_sessions(db) == 0
    for status, session_id in finished.items():
        row = fetch(factory, session_id)
        assert row is not None
        assert (row.status, row.ended_at) == (status.value, at(2))
        assert row.error_code == ("capture_failed" if status is CaptureStatus.FAILED else None)
    for session_id in active:
        row = fetch(factory, session_id)
        assert row is not None and (row.status, row.error_code) == ("failed", "interrupted")


def test_recovery_with_nothing_to_do_returns_zero(factory: SessionFactory, world: World) -> None:
    with factory() as db:
        assert repository.interrupt_unfinished_sessions(db) == 0
        assert repository.interrupt_pending_lookups(db) == 0


def lookup_state(factory: SessionFactory, alert_id: uuid.UUID) -> Any:
    with factory() as db:
        row = db.get(NetworkAlert, alert_id)
        assert row is not None
        return row.enrichment


def test_a_pending_lookup_is_settled_as_interrupted(factory: SessionFactory) -> None:
    session_id = seed_session(factory)
    pending = seed_alert(
        factory,
        session_id,
        enrichment={"status": "pending", "address": SCANNER, "providers": [{"provider": "x"}]},
    )
    with factory() as db:
        assert repository.interrupt_pending_lookups(db) == 1
        assert repository.interrupt_pending_lookups(db) == 0
    assert lookup_state(factory, pending) == {
        "status": "unavailable",
        "address": SCANNER,
        "error_code": "interrupted",
    }


def test_a_pending_lookup_without_an_address_keeps_the_gap(factory: SessionFactory) -> None:
    session_id = seed_session(factory)
    pending = seed_alert(factory, session_id, enrichment={"status": "pending"})
    with factory() as db:
        assert repository.interrupt_pending_lookups(db) == 1
    assert lookup_state(factory, pending) == {
        "status": "unavailable",
        "address": None,
        "error_code": "interrupted",
    }


def test_only_alerts_whose_status_is_pending_are_changed(factory: SessionFactory) -> None:
    session_id = seed_session(
        factory, stats={"enrichment": {SCANNER: {"status": "completed", "note": "pending"}}}
    )
    # Each of these mentions the word without being a lookup in progress.
    untouched = {
        "completed": {"status": "completed", "address": SCANNER, "risk_score": 70},
        "word in a provider": {
            "status": "completed",
            "providers": [{"provider": "pending-review", "verdict": "pending"}],
        },
        "word in the address": {"status": "failed", "address": "pending.example"},
        "uppercase status": {"status": "PENDING"},
        "padded status": {"status": " pending"},
        "empty": {},
    }
    alerts = {
        name: seed_alert(factory, session_id, enrichment=value) for name, value in untouched.items()
    }
    pending = seed_alert(factory, session_id, enrichment={"status": "pending", "address": SERVER})
    with factory() as db:
        assert repository.interrupt_pending_lookups(db) == 1
    for name, value in untouched.items():
        assert lookup_state(factory, alerts[name]) == value, name
    assert lookup_state(factory, pending)["error_code"] == "interrupted"
    row = fetch(factory, session_id)
    assert row is not None
    assert row.stats == {"enrichment": {SCANNER: {"status": "completed", "note": "pending"}}}


def test_pending_lookups_are_settled_in_every_session_and_owner(factory: SessionFactory) -> None:
    alerts = [
        seed_alert(
            factory,
            seed_session(factory, owner=owner, status=status),
            enrichment={"status": "pending", "address": SCANNER},
        )
        for owner in ("alice", "bob")
        for status in (CaptureStatus.COMPLETED, CaptureStatus.RUNNING)
    ]
    with factory() as db:
        assert repository.interrupt_pending_lookups(db) == 4
    assert {lookup_state(factory, alert_id)["error_code"] for alert_id in alerts} == {"interrupted"}


@pytest.mark.parametrize(
    "odd",
    [["pending"], "pending", ["status", "pending"], [{"status": "pending"}], 5],
)
def test_an_alert_with_an_odd_enrichment_value_cannot_stop_recovery(
    factory: SessionFactory, odd: Any
) -> None:
    # A value that is not an object is not a lookup in progress; it must not make start-up fail.
    session_id = seed_session(factory)
    odd_alert = seed_alert(factory, session_id, enrichment=odd)
    pending = seed_alert(factory, session_id, enrichment={"status": "pending", "address": SERVER})
    with factory() as db:
        assert repository.interrupt_pending_lookups(db) == 1
    assert lookup_state(factory, odd_alert) == odd
    assert lookup_state(factory, pending)["error_code"] == "interrupted"
