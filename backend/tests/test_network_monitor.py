"""SessionMonitor: packets in, results stored on schedule, lookups handed over, and a session that
ends with the right status however the database behaves."""

import threading
import uuid
from collections.abc import Callable, Collection, Iterator, Sequence
from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.database.session import build_engine, build_session_factory
from app.models.enums import CaptureStatus
from app.network import monitor as monitor_module
from app.network.enrichment import PRIORITY_ALERT, PRIORITY_TALKER, EnrichmentRequest
from app.network.packets import PacketMeta
from app.network.recorder import EnrichmentStatus
from app.network.repository import delete_session
from app.services.normalization import is_public_address
from tests.network_helpers import (
    DOCUMENTATION,
    HOST,
    RESOLVER,
    SCANNER,
    SERVER,
    T0,
    FlakyFactory,
    assert_no_module_threads,
    build_rig,
    packet,
    scan_packets,
    syn,
)
from tests.network_helpers import MonitorRig as Rig

SessionFactory = sessionmaker[Session]

# Public addresses that stand in for the internet. Nothing here ever contacts them.
PUBLIC = [f"{50 + index}.1.2.3" for index in range(12)]


@pytest.fixture
def factory(make_settings: Callable[..., Settings], db_url: str) -> Iterator[SessionFactory]:
    engine = build_engine(make_settings(database_url=db_url))
    yield build_session_factory(engine)
    engine.dispose()


@pytest.fixture(autouse=True)
def _no_leaked_threads() -> Iterator[None]:
    yield
    assert_no_module_threads()


class RecordingWorker:
    """Stands in for the enrichment worker: it records what the monitor hands it."""

    def __init__(self, *, reject: Collection[str] = ()) -> None:
        self.reject = set(reject)
        self.requests: list[EnrichmentRequest] = []
        self.marks: list[tuple[set[str], EnrichmentStatus, str | None]] = []
        self.settled: list[set[str]] = []
        self.pending: set[str] = set()

    def submit(
        self, session_id: uuid.UUID, requests: Sequence[EnrichmentRequest]
    ) -> list[EnrichmentRequest]:
        self.requests.extend(requests)
        return [request for request in requests if request.address in self.reject]

    def mark(
        self,
        session_id: uuid.UUID,
        addresses: Collection[str],
        status: EnrichmentStatus,
        *,
        error_code: str | None = None,
    ) -> int:
        self.marks.append((set(addresses), status, error_code))
        return 0

    def settle(self, session_id: uuid.UUID, keep: Collection[str]) -> int:
        self.settled.append(set(keep))
        return 0

    def is_pending(self, session_id: uuid.UUID, address: str) -> bool:
        return address in self.pending

    @property
    def addresses(self) -> list[str]:
        return [request.address for request in self.requests]

    def request_for(self, address: str) -> EnrichmentRequest:
        (request,) = [item for item in self.requests if item.address == address]
        return request


@pytest.fixture
def make_rig(
    factory: SessionFactory,
    make_settings: Callable[..., Settings],
    db_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[..., Rig]:
    monkeypatch.setattr(monitor_module, "_FINAL_FLUSH_DELAY", 0.0)

    def build(**options: Any) -> Rig:
        settings_overrides = {
            name: options.pop(name)
            for name in list(options)
            if name not in {"stream_time", "worker", "session_factory", "flush_interval"}
        }
        settings = make_settings(database_url=db_url, **settings_overrides)
        return build_rig(factory, settings, **options)

    return build


def talkers(addresses: Sequence[str], *, start: float = T0) -> list[PacketMeta]:
    """HOST sends one datagram to each address; earlier addresses are the heavier talkers."""
    return [
        packet(
            start + index,
            HOST,
            address,
            protocol="udp",
            sport=40000 + index,
            dport=53,
            length=1000 - index,
        )
        for index, address in enumerate(addresses)
    ]


def test_the_public_addresses_used_here_are_public() -> None:
    assert all(is_public_address(address) for address in [*PUBLIC, SCANNER, RESOLVER])
    assert not any(is_public_address(address) for address in [HOST, SERVER, DOCUMENTATION])


# --- Packets in, results out -----------------------------------------------------------------


def test_a_batch_reaches_the_analyzer_and_the_first_tick_stores_it(
    make_rig: Callable[..., Rig],
) -> None:
    rig = make_rig()

    rig.monitor.process_batch(scan_packets())

    assert rig.monitor.packets_processed == 30
    assert len(rig.writes) == 1
    row = rig.row()
    assert (row.packets_total, row.bytes_total, row.flows_total) == (30, 1800, 30)
    assert row.alerts_total == 1
    assert row.status == "running"
    assert row.stats["active_flows"] == 30
    assert len(rig.alerts()) == 1
    assert rig.flows() == [], "flows that are still open are stored when they finish"


def test_results_are_stored_every_flush_interval_and_only_when_something_changed(
    make_rig: Callable[..., Rig],
) -> None:
    rig = make_rig(flush_interval=2.0)
    packets = scan_packets()

    rig.monitor.process_batch(packets[:5])
    assert len(rig.writes) == 1

    rig.clock.advance(1.0)
    rig.monitor.process_batch(packets[5:10])
    assert len(rig.writes) == 1
    assert rig.row().packets_total == 5

    rig.clock.advance(0.9)
    rig.monitor.tick()
    assert len(rig.writes) == 1

    rig.clock.advance(0.1)
    rig.monitor.tick()
    assert len(rig.writes) == 2
    assert rig.row().packets_total == 10

    # Nothing happened since: the interval passes but nothing is written.
    rig.clock.advance(10.0)
    rig.monitor.tick()
    assert len(rig.writes) == 2

    rig.monitor.process_batch(packets[10:11])
    assert len(rig.writes) == 2
    rig.clock.advance(2.0)
    rig.monitor.tick()
    assert len(rig.writes) == 3
    assert rig.row().packets_total == 11


def test_a_live_session_retires_quiet_flows_by_the_wall_clock(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig(stream_time=False, flow_idle_timeout_seconds=5)
    rig.monitor.process_batch([syn(T0, HOST, SERVER, 80)])
    assert rig.flows() == []

    rig.clock.advance(30.0)
    rig.monitor.tick()

    (stored,) = rig.flows()
    assert (stored.dst_port, stored.close_reason) == (80, "idle")
    assert rig.row().stats["active_flows"] == 0


def test_a_capture_file_retires_flows_by_packet_time_and_ignores_the_wall_clock(
    make_rig: Callable[..., Rig],
) -> None:
    rig = make_rig(stream_time=True, flow_idle_timeout_seconds=5)
    rig.monitor.process_batch([syn(T0, HOST, SERVER, 80)])

    rig.clock.advance(3600.0)
    rig.monitor.tick()
    assert rig.flows() == [], "an hour on the wall clock is no time at all in the file"

    rig.monitor.process_batch([syn(T0 + 30, HOST, SERVER, 81)])
    rig.clock.advance(2.0)
    rig.monitor.tick()

    (stored,) = rig.flows()
    assert (stored.dst_port, stored.close_reason) == (80, "idle")


def test_counts_noted_by_the_capture_thread_are_stored_once(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig()
    rig.monitor.note_dropped(5)
    rig.monitor.note_non_ip(2)
    rig.monitor.note_malformed(1)
    assert rig.monitor.packets_dropped == 5

    assert rig.monitor.flush(force=True)
    row = rig.row()
    assert row.packets_dropped == 5
    assert (row.stats["non_ip_packets"], row.stats["malformed_packets"]) == (2, 1)

    assert rig.monitor.flush(force=True)
    row = rig.row()
    assert (row.stats["non_ip_packets"], row.stats["malformed_packets"]) == (2, 1)

    rig.monitor.note_non_ip()
    rig.monitor.note_dropped()
    assert rig.monitor.flush()
    row = rig.row()
    assert (row.packets_dropped, row.stats["non_ip_packets"]) == (6, 3)


def test_noting_counts_from_many_threads_loses_none(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig()

    def note() -> None:
        for _ in range(2500):
            rig.monitor.note_dropped()
            rig.monitor.note_non_ip()
            rig.monitor.note_malformed()

    threads = [threading.Thread(target=note) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert not any(thread.is_alive() for thread in threads)

    assert rig.monitor.flush(force=True)
    row = rig.row()
    assert row.packets_dropped == 10_000
    assert (row.stats["non_ip_packets"], row.stats["malformed_packets"]) == (10_000, 10_000)


def test_a_flush_with_nothing_new_writes_nothing_unless_forced(
    make_rig: Callable[..., Rig],
) -> None:
    rig = make_rig(flush_interval=float("inf"))
    rig.monitor.process_batch(scan_packets())
    assert rig.writes == []

    assert rig.monitor.flush()
    assert len(rig.writes) == 1
    assert rig.monitor.flush()
    assert len(rig.writes) == 1
    assert rig.monitor.flush(force=True)
    assert len(rig.writes) == 2


def test_a_failed_write_is_retried_even_when_nothing_new_arrived(
    factory: SessionFactory, make_rig: Callable[..., Rig]
) -> None:
    flaky = FlakyFactory(factory, failures=1)
    rig = make_rig(session_factory=flaky, flush_interval=float("inf"))
    rig.monitor.process_batch(scan_packets())

    assert not rig.monitor.flush()
    assert rig.row().packets_total == 0

    assert rig.monitor.flush()
    row = rig.row()
    assert (row.packets_total, row.alerts_total) == (30, 1)
    assert len(rig.alerts()) == 1, "the alert of the failed write is stored once, by the retry"

    # A failed write of mere counters (nothing pending in the recorder) is retried too.
    flaky.failures = 1
    rig.monitor.note_dropped(3)
    assert not rig.monitor.flush()
    assert rig.monitor.flush()
    assert rig.row().packets_dropped == 3


def test_set_status_is_recorded_in_the_session_row(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig()

    assert rig.monitor.set_status(CaptureStatus.STOPPING)
    assert rig.row().status == "stopping"

    assert rig.monitor.set_status(CaptureStatus.FAILED, "capture_failed")
    row = rig.row()
    assert (row.status, row.error_code, row.ended_at) == ("failed", "capture_failed", None)


# --- Finishing -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (CaptureStatus.COMPLETED, None),
        (CaptureStatus.STOPPED, None),
        (CaptureStatus.FAILED, "capture_failed"),
        (CaptureStatus.PERMISSION_DENIED, "capture_permission_denied"),
    ],
)
def test_finish_stores_what_is_left_and_records_the_final_status(
    make_rig: Callable[..., Rig], status: CaptureStatus, code: str | None
) -> None:
    rig = make_rig()
    rig.monitor.process_batch(scan_packets())
    rig.monitor.note_dropped(2)

    rig.monitor.finish(status, code)

    row = rig.row()
    assert (row.status, row.error_code) == (status.value, code)
    assert row.ended_at is not None
    assert row.ended_at >= row.started_at
    assert (row.packets_total, row.flows_total, row.alerts_total) == (30, 30, 1)
    assert row.packets_dropped == 2
    assert row.stats["active_flows"] == 0
    flows = rig.flows()
    assert len(flows) == 30
    assert {item.close_reason for item in flows} == {"ended"}
    assert row.stats["flows_stored"] == 30


def test_finish_retries_the_last_flush_and_says_when_the_results_are_incomplete(
    factory: SessionFactory, make_rig: Callable[..., Rig]
) -> None:
    flaky = FlakyFactory(factory, failures=2)
    rig = make_rig(session_factory=flaky, flush_interval=float("inf"))
    rig.monitor.process_batch(scan_packets())

    rig.monitor.finish(CaptureStatus.COMPLETED)

    row = rig.row()
    assert (row.status, row.error_code) == ("completed", None)
    assert len(rig.flows()) == 30
    assert row.stats["write_failures"] == 2

    hopeless = FlakyFactory(factory, failures=3)
    other = make_rig(session_factory=hopeless, flush_interval=float("inf"))
    other.monitor.process_batch(scan_packets())
    other.monitor.finish(CaptureStatus.COMPLETED)
    row = other.row()
    assert (row.status, row.error_code) == ("completed", "results_incomplete")
    assert row.ended_at is not None
    assert other.flows() == []
    assert len(other.writes) == 3

    failing = FlakyFactory(factory, failures=3)
    third = make_rig(session_factory=failing, flush_interval=float("inf"))
    third.monitor.process_batch(scan_packets())
    third.monitor.finish(CaptureStatus.FAILED, "capture_failed")
    assert third.row().error_code == "capture_failed"


def test_finish_after_the_session_was_deleted_ends_quietly(
    factory: SessionFactory, make_rig: Callable[..., Rig]
) -> None:
    rig = make_rig()
    rig.monitor.process_batch(scan_packets())
    with factory() as db:
        delete_session(db, rig.session_id)
        db.commit()

    rig.monitor.note_dropped()
    assert not rig.monitor.flush(force=True)
    assert rig.monitor.gone
    writes = len(rig.writes)

    rig.monitor.finish(CaptureStatus.STOPPED)

    assert len(rig.writes) == writes + 1, "no retries for a session that is gone"
    assert rig.flows() == []
    assert rig.alerts() == []


def test_finishing_twice_stores_nothing_twice(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig()
    rig.monitor.process_batch(scan_packets())
    rig.monitor.finish(CaptureStatus.COMPLETED)
    first = rig.row()
    flows, alerts = len(rig.flows()), len(rig.alerts())

    rig.monitor.finish(CaptureStatus.COMPLETED)

    second = rig.row()
    assert (len(rig.flows()), len(rig.alerts())) == (flows, alerts) == (30, 1)
    assert (second.packets_total, second.flows_total, second.alerts_total) == (
        first.packets_total,
        first.flows_total,
        first.alerts_total,
    )
    assert second.status == "completed"
    assert second.stats["flows_stored"] == 30


# --- Handing addresses to the enrichment worker ----------------------------------------------


def test_alert_subjects_go_first_and_only_public_addresses_are_handed_over(
    make_rig: Callable[..., Rig],
) -> None:
    worker = RecordingWorker()
    rig = make_rig(worker=worker)
    traffic = [
        *scan_packets(),
        packet(T0 + 4, HOST, RESOLVER, protocol="udp", sport=40001, dport=53),
        syn(T0 + 5, HOST, DOCUMENTATION, 443),
        syn(T0 + 6, HOST, SERVER, 80),
    ]

    rig.monitor.process_batch(traffic)

    assert sorted(worker.addresses) == sorted([SCANNER, RESOLVER])
    scanner = worker.request_for(SCANNER)
    assert scanner.priority == PRIORITY_ALERT
    assert scanner.facts["address"] == SCANNER
    assert scanner.facts["alerted"] is True
    assert scanner.facts["packets"] == 30
    assert scanner.facts["sent_to"] is False
    assert scanner.facts["peers"] == [SERVER]
    resolver = worker.request_for(RESOLVER)
    assert resolver.priority == PRIORITY_TALKER
    assert resolver.facts["alerted"] is False
    assert (resolver.facts["sent_to"], resolver.facts["protocols"]) == (True, ["udp"])
    assert worker.marks == []


def test_each_address_is_handed_over_once(make_rig: Callable[..., Rig]) -> None:
    worker = RecordingWorker()
    rig = make_rig(worker=worker)
    rig.monitor.process_batch(scan_packets())
    rig.clock.advance(2.0)
    rig.monitor.process_batch(scan_packets(start=T0 + 10))
    rig.clock.advance(2.0)
    rig.monitor.process_batch(scan_packets(start=T0 + 20, ports=25))
    rig.monitor.flush(force=True)

    assert worker.addresses == [SCANNER]


def test_the_traffic_details_of_public_peers_are_kept_with_the_session_within_bounds(
    make_rig: Callable[..., Rig],
) -> None:
    peers = [f"{60 + index}.9.9.9" for index in range(30)]
    worker = RecordingWorker()
    rig = make_rig(worker=worker, network_enrichment_max_ips=5)

    rig.monitor.process_batch(talkers(peers))
    assert rig.monitor.flush(force=True)

    stored = rig.row().stats["external_peers"]
    assert len(stored) == 25
    assert len({item["address"] for item in stored}) == 25
    assert stored[0]["address"] == peers[0], "the heaviest talker comes first"
    assert {"address", "packets", "bytes", "sent_to", "alerted", "protocols"} <= set(stored[0])

    # What was handed over for lookup is listed first from then on.
    assert rig.monitor.flush(force=True)
    stored = rig.row().stats["external_peers"]
    assert [item["address"] for item in stored[: len(worker.addresses)]] == worker.addresses


def test_the_lookup_budget_leaves_room_for_alerts_and_marks_the_rest_skipped(
    make_rig: Callable[..., Rig],
) -> None:
    worker = RecordingWorker()
    rig = make_rig(worker=worker, network_enrichment_max_ips=5)

    rig.monitor.process_batch(talkers(PUBLIC[:10]))
    assert worker.addresses == PUBLIC[:4], "talkers may use all but a fifth of the budget"
    assert {request.priority for request in worker.requests} == {PRIORITY_TALKER}

    rig.clock.advance(2.0)
    rig.monitor.process_batch(scan_packets(src=PUBLIC[10], start=T0 + 20))
    assert worker.addresses == [*PUBLIC[:4], PUBLIC[10]]
    assert worker.request_for(PUBLIC[10]).priority == PRIORITY_ALERT
    assert worker.marks == []

    rig.clock.advance(2.0)
    rig.monitor.process_batch(scan_packets(src=PUBLIC[11], start=T0 + 40))
    assert len(worker.addresses) == 5
    assert worker.marks == [({PUBLIC[11]}, EnrichmentStatus.SKIPPED_BUDGET, None)]

    # Marked once, not on every flush.
    rig.monitor.flush(force=True)
    rig.clock.advance(2.0)
    rig.monitor.process_batch(talkers([PUBLIC[11]], start=T0 + 60))
    assert len(worker.marks) == 1


def test_lookups_the_worker_cannot_queue_are_marked_failed(make_rig: Callable[..., Rig]) -> None:
    worker = RecordingWorker(reject=[SCANNER])
    rig = make_rig(worker=worker)

    rig.monitor.process_batch(scan_packets())

    assert worker.marks == [({SCANNER}, EnrichmentStatus.FAILED, "queue_full")]


def test_nothing_is_handed_over_until_the_results_are_stored(
    factory: SessionFactory, make_rig: Callable[..., Rig]
) -> None:
    worker = RecordingWorker()
    flaky = FlakyFactory(factory, failures=1)
    rig = make_rig(worker=worker, session_factory=flaky)

    rig.monitor.process_batch(scan_packets())
    assert worker.requests == []

    assert rig.monitor.flush()
    assert worker.addresses == [SCANNER]
    assert worker.request_for(SCANNER).priority == PRIORITY_ALERT


def test_finish_settles_the_alerts_whose_lookup_is_still_waiting(
    make_rig: Callable[..., Rig],
) -> None:
    worker = RecordingWorker()
    rig = make_rig(worker=worker)
    rig.monitor.process_batch(scan_packets() + talkers([RESOLVER], start=T0 + 5))
    worker.pending = {SCANNER}

    rig.monitor.finish(CaptureStatus.STOPPED)

    assert worker.settled == [{SCANNER}]


def test_a_session_without_enrichment_never_touches_the_worker(
    make_rig: Callable[..., Rig],
) -> None:
    worker = RecordingWorker()
    rig = make_rig(worker=worker, external_enrichment_enabled=False)

    rig.monitor.process_batch(scan_packets() + talkers([RESOLVER], start=T0 + 5))
    rig.monitor.finish(CaptureStatus.COMPLETED)

    assert (worker.requests, worker.marks, worker.settled) == ([], [], [])
    (alert,) = rig.alerts()
    assert alert.enrichment == {"status": "disabled", "address": SCANNER}


# --- Many threads ----------------------------------------------------------------------------


def test_feeding_flushing_and_counting_at_once_loses_and_duplicates_nothing(
    make_rig: Callable[..., Rig],
) -> None:
    rig = make_rig(flush_interval=0.0)
    batches = [
        [
            packet(
                T0 + batch + index / 1000,
                HOST,
                SERVER,
                sport=10_000 + batch * 100 + index,
                dport=80,
                flags=2,
            )
            for index in range(100)
        ]
        for batch in range(10)
    ]
    errors: list[BaseException] = []

    def guarded(job: Callable[[], None]) -> Callable[[], None]:
        def run() -> None:
            try:
                job()
            except BaseException as exc:  # reported by the test thread
                errors.append(exc)

        return run

    def feed() -> None:
        for batch in batches:
            rig.monitor.process_batch(batch)

    def flush() -> None:
        for _ in range(20):
            rig.monitor.flush()

    def count() -> None:
        for _ in range(500):
            rig.monitor.note_dropped()
            rig.monitor.note_non_ip()
            rig.monitor.note_malformed()

    threads = [threading.Thread(target=guarded(job)) for job in (feed, flush, count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert not any(thread.is_alive() for thread in threads), "the monitor deadlocked"
    assert errors == []

    rig.monitor.finish(CaptureStatus.COMPLETED)

    row = rig.row()
    assert (row.packets_total, row.flows_total, row.packets_dropped) == (1000, 1000, 500)
    assert (row.stats["non_ip_packets"], row.stats["malformed_packets"]) == (500, 500)
    assert (row.stats["flows_stored"], row.stats["flows_not_stored"]) == (1000, 0)
    ports = [item.src_port for item in rig.flows()]
    assert len(ports) == len(set(ports)) == 1000
