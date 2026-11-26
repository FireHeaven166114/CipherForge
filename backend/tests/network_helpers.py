"""Builders shared by the network-monitoring tests."""

import logging
import os
import struct
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.errors import ApiError
from app.models.audit import AuditLog
from app.models.enums import CaptureSource, CaptureStatus
from app.models.network import CaptureSession, NetworkAlert, NetworkFlow
from app.models.types import utcnow
from app.network import capture as capture_module
from app.network import enrichment as enrichment_module
from app.network import monitor as monitor_module
from app.network import service as service_module
from app.network.capture import BackendInfo, InterfaceInfo
from app.network.monitor import SessionMonitor
from app.network.packets import TCP_ACK, TCP_SYN, PacketMeta
from app.network.pcap import ReceivedUpload, UploadSpool
from app.network.recorder import SessionRecorder
from app.network.scapy_support import load_scapy
from app.network.service import NetworkService
from app.schemas.network import NetworkStatus, SessionDetail
from app.services.intel_service import RequestContext

# Every test timeline starts here: 2026-01-15 10:00:00 UTC.
T0 = 1_768_471_200.0


def packet(
    ts: float,
    src: str = "10.0.0.5",
    dst: str = "10.0.0.9",
    *,
    protocol: str = "tcp",
    sport: int | None = 40000,
    dport: int | None = 80,
    flags: int | None = None,
    length: int = 60,
) -> PacketMeta:
    if protocol not in {"tcp", "udp", "sctp"}:
        sport = dport = None
    if protocol != "tcp":
        flags = None
    return PacketMeta(
        timestamp=ts,
        src_ip=src,
        dst_ip=dst,
        protocol=protocol,
        length=length,
        src_port=sport,
        dst_port=dport,
        tcp_flags=flags,
    )


def syn(ts: float, src: str, dst: str, dport: int, sport: int = 40000) -> PacketMeta:
    return packet(ts, src, dst, sport=sport, dport=dport, flags=TCP_SYN)


def syn_ack(ts: float, src: str, dst: str, sport: int, dport: int) -> PacketMeta:
    return packet(ts, src, dst, sport=sport, dport=dport, flags=TCP_SYN | TCP_ACK)


def write_pcap(path: Path, packets: Iterable, *, ng: bool = False) -> Path:
    """Write Scapy packets to a capture file. Each packet's ``time`` becomes its timestamp."""
    scapy = load_scapy()
    writer = scapy.PcapNgWriter if ng else scapy.PcapWriter
    with writer(str(path)) as out:
        for item in packets:
            out.write(item)
    return path


def read_pcap(path: Path) -> list:
    scapy = load_scapy()
    reader = scapy.PcapNgReader if path.suffix == ".pcapng" else scapy.PcapReader
    with reader(str(path)) as source:
        return list(source)


def write_raw_pcap(path: Path, frames: Iterable[tuple[float, bytes]], linktype: int = 1) -> Path:
    """A classic capture file of the given raw frames (no Scapy involved), for hostile input."""
    with path.open("wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for stamp, frame in frames:
            seconds = int(stamp)
            micros = int((stamp - seconds) * 1_000_000)
            out.write(struct.pack("<IIII", seconds, micros, len(frame), len(frame)))
            out.write(frame)
    return path


def scapy_syn(ts: float, src: str, dst: str, dport: int, sport: int = 40000, *, vlan: bool = False):
    """An Ethernet/IPv4/TCP SYN as Scapy builds it, stamped with ``ts``."""
    scapy = load_scapy()
    frame = scapy.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    if vlan:
        frame = frame / scapy.Dot1Q(vlan=7)
    built = frame / scapy.IP(src=src, dst=dst) / scapy.TCP(sport=sport, dport=dport, flags="S")
    built.time = ts
    return built


# --- More Scapy frames ----------------------------------------------------------------------


def _ethernet(scapy):
    return scapy.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def scapy_udp(ts: float, src: str, dst: str, dport: int, sport: int = 40000, payload: bytes = b""):
    """An Ethernet/IPv4/UDP datagram as Scapy builds it, stamped with ``ts``."""
    scapy = load_scapy()
    built = _ethernet(scapy) / scapy.IP(src=src, dst=dst) / scapy.UDP(sport=sport, dport=dport)
    if payload:
        built = built / payload
    built.time = ts
    return built


def scapy_icmp(ts: float, src: str, dst: str):
    scapy = load_scapy()
    built = _ethernet(scapy) / scapy.IP(src=src, dst=dst) / scapy.ICMP()
    built.time = ts
    return built


def scapy_arp(ts: float):
    """A frame without an IP layer, which the monitor counts as non-IP traffic."""
    scapy = load_scapy()
    built = _ethernet(scapy) / scapy.ARP(psrc="10.0.0.5", pdst="10.0.0.9")
    built.time = ts
    return built


# --- A deterministic port scan ---------------------------------------------------------------

# Stand-in addresses: nothing ever contacts them. SCANNER and RESOLVER are public; HOST, SERVER and
# DOCUMENTATION (a reserved documentation range) are not, so they must never be looked up.
SCANNER = "45.33.32.156"
RESOLVER = "8.8.8.8"
HOST = "10.0.0.5"
SERVER = "10.0.0.9"
DOCUMENTATION = "192.0.2.77"
SCAN_PORTS = 30
# What ``scan_traffic()`` holds: 34 frames (one is ARP), 33 flows, and exactly one alert: NET-001
# for SCANNER, raised by its 20th distinct port.
SCAN_FRAMES = SCAN_PORTS + 4
SCAN_FLOWS = SCAN_PORTS + 3


def scan_packets(
    *, ports: int = SCAN_PORTS, start: float = T0, src: str = SCANNER, dst: str = SERVER
) -> list[PacketMeta]:
    """``src`` sends a SYN to ``ports`` ports of ``dst``, a tenth of a second apart."""
    return [syn(start + 0.1 * index, src, dst, 2000 + index) for index in range(ports)]


def scan_traffic(*, ports: int = SCAN_PORTS) -> list:
    """The scan as Scapy frames, followed by ordinary traffic and one non-IP frame."""
    frames = [scapy_syn(T0 + 0.1 * index, SCANNER, SERVER, 2000 + index) for index in range(ports)]
    end = T0 + 0.1 * ports
    frames.append(scapy_udp(end + 1, HOST, RESOLVER, 53, payload=b"\x00" * 20))
    frames.append(scapy_syn(end + 2, HOST, DOCUMENTATION, 443))
    frames.append(scapy_syn(end + 3, HOST, SERVER, 80))
    frames.append(scapy_arp(end + 4))
    return frames


def write_scan_capture(path: Path, *, ng: bool = False, ports: int = SCAN_PORTS) -> Path:
    return write_pcap(path, scan_traffic(ports=ports), ng=ng)


# --- Waiting, and threads the module must not leave behind -----------------------------------

MODULE_THREAD_NAMES = frozenset(
    {"cipherforge-network-enrichment", "cipherforge-capture-consumer", "cipherforge-pcap-analysis"}
)


def wait_until(
    condition: Callable[[], Any],
    *,
    timeout: float = 5.0,
    interval: float = 0.005,
    what: str = "the condition",
) -> Any:
    """Poll until ``condition`` returns something truthy, and return it. Fails after ``timeout``."""
    deadline = time.monotonic() + timeout
    while True:
        value = condition()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"Timed out after {timeout} s waiting for {what}.")
        time.sleep(interval)


def module_threads() -> list[threading.Thread]:
    return [
        thread
        for thread in threading.enumerate()
        if thread.name in MODULE_THREAD_NAMES and thread.is_alive()
    ]


def assert_no_module_threads(timeout: float = 3.0) -> None:
    """Fail if a thread of the network module is still running once ``timeout`` has passed."""
    try:
        wait_until(lambda: not module_threads(), timeout=timeout, what="module threads to exit")
    except AssertionError:
        names = sorted(thread.name for thread in module_threads())
        raise AssertionError(f"Threads of the network module are still running: {names}") from None


class FakeClock:
    """A clock the test moves by hand."""

    def __init__(self, start: float = T0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> float:
        self.now += seconds
        return self.now


# --- Doubles ---------------------------------------------------------------------------------


class FakeSource:
    """A ``PacketSource`` the test drives by hand.

    ``start_hook`` runs inside ``start()`` (to make it slow, or to observe the consumer thread),
    ``start_error`` makes ``start()`` raise, and ``autostart=False`` leaves ``wait_started`` false
    until ``become_ready()``.
    """

    def __init__(
        self,
        *,
        autostart: bool = True,
        start_error: BaseException | None = None,
        start_hook: Callable[["FakeSource"], None] | None = None,
        stop_error: BaseException | None = None,
    ) -> None:
        self.autostart = autostart
        self.start_error = start_error
        self.start_hook = start_hook
        self.stop_error = stop_error
        self.error: BaseException | None = None
        self.handler: Callable[[Any], None] | None = None
        self.start_calls = 0
        self.stop_calls = 0
        self._alive = False
        self._ready = threading.Event()

    @property
    def alive(self) -> bool:
        return self._alive

    def start(self, handler: Callable[[Any], None]) -> None:
        self.start_calls += 1
        self.handler = handler
        if self.start_hook is not None:
            self.start_hook(self)
        if self.start_error is not None:
            raise self.start_error
        self._alive = True
        if self.autostart:
            self._ready.set()

    def wait_started(self, timeout: float) -> bool:
        return self._ready.wait(timeout)

    def stop(self) -> None:
        self.stop_calls += 1
        self._alive = False
        if self.stop_error is not None:
            raise self.stop_error

    def become_ready(self) -> None:
        self._ready.set()

    def emit(self, *items: Any) -> None:
        assert self.handler is not None, "the capture has not started the source"
        for item in items:
            self.handler(item)

    def die(self, error: BaseException | None = None) -> None:
        """The capture library's thread ended on its own, with or without an error."""
        self.error = error
        self._alive = False


class RecordingMonitor:
    """Stands in for ``SessionMonitor`` where only the capture's calls to it matter.

    ``gate`` makes ``process_batch`` wait, so a test can hold the consumer thread still.
    """

    def __init__(self, *, gate: threading.Event | None = None) -> None:
        self.gate = gate
        self.batches: list[list[Any]] = []
        self.statuses: list[CaptureStatus] = []
        self.finished: list[tuple[CaptureStatus, str | None]] = []
        self.finish_error: Exception | None = None
        self.dropped = 0
        self.non_ip = 0
        self.malformed = 0
        self.ticks = 0
        self.gone = False
        self.entered = threading.Event()

    def set_status(self, status: CaptureStatus, error_code: str | None = None) -> bool:
        self.statuses.append(status)
        return True

    def process_batch(self, packets: Any) -> None:
        self.entered.set()
        if self.gate is not None:
            self.gate.wait(10)
        self.batches.append(list(packets))

    def tick(self) -> None:
        self.ticks += 1

    def finish(self, status: CaptureStatus, error_code: str | None = None) -> None:
        if self.finish_error is not None:
            raise self.finish_error
        self.finished.append((status, error_code))

    def note_dropped(self, count: int = 1) -> None:
        self.dropped += count

    def note_non_ip(self, count: int = 1) -> None:
        self.non_ip += count

    def note_malformed(self, count: int = 1) -> None:
        self.malformed += count

    @property
    def processed(self) -> list[Any]:
        return [item for batch in self.batches for item in batch]


TEST_INTERFACE = InterfaceInfo(
    id="test-eth0", name="Test Ethernet", description="Synthetic adapter", addresses=("192.0.2.10",)
)
OTHER_INTERFACE = InterfaceInfo(
    id="test-wlan0", name="Test Wi-Fi", description="Second synthetic adapter", addresses=()
)


class FakeCatalog:
    """An ``InterfaceCatalog`` with fixed interfaces, and a switch for a missing backend."""

    def __init__(
        self, interfaces: Iterable[InterfaceInfo] | None = None, *, available: bool = True
    ) -> None:
        self.available = available
        self.items = (
            list(interfaces) if interfaces is not None else [TEST_INTERFACE, OTHER_INTERFACE]
        )
        self.refreshes = 0

    def backend(self) -> BackendInfo:
        return BackendInfo("fakepcap" if self.available else "none", self.available)

    def interfaces(self, *, refresh: bool = False) -> list[InterfaceInfo]:
        if refresh:
            self.refreshes += 1
        return list(self.items) if self.available else []

    def resolve(self, interface_id: str) -> InterfaceInfo | None:
        return next((info for info in self.interfaces() if info.id == interface_id), None)


def provider_view(
    provider: str = "abuseipdb",
    status: str = "ok",
    *,
    verdict: str | None = "suspicious",
    cached: bool = False,
    display_name: str | None = None,
) -> SimpleNamespace:
    """What the enrichment worker reads of one provider's answer (``ProviderView``)."""
    return SimpleNamespace(
        provider=provider,
        display_name=display_name or provider.title(),
        status=status,
        verdict=verdict,
        from_cache=cached,
    )


def reply(
    *views: SimpleNamespace,
    score: int = 10,
    classification: str = "low",
    indicator_id: uuid.UUID | None = None,
) -> SimpleNamespace:
    """What the enrichment worker reads of an ``InvestigationResponse``."""
    return SimpleNamespace(
        indicator=SimpleNamespace(
            indicator_id=indicator_id or uuid.uuid4(),
            risk_score=score,
            classification=classification,
        ),
        providers=list(views) if views else [provider_view()],
    )


class StubIntel:
    """An ``IntelService`` that answers from a script and records every call.

    ``replies`` maps an address to a reply, an exception (raised), or a callable taking the
    address. ``gate`` holds every lookup until it is set.
    """

    def __init__(self, replies: dict[str, Any] | None = None, *, default: Any = None) -> None:
        self.replies = replies or {}
        self.default = default if default is not None else reply()
        self.gate: threading.Event | None = None
        self.calls: list[str] = []
        self.times: list[float] = []
        self.contexts: list[Any] = []
        self.refresh_flags: list[bool] = []
        self.closed = False
        self.entered = threading.Event()
        self._lock = threading.Lock()

    def investigate(self, db: Session, context: Any, raw: str, *, refresh: bool = False) -> Any:
        with self._lock:
            self.calls.append(raw)
            self.times.append(time.monotonic())
            self.contexts.append(context)
            self.refresh_flags.append(refresh)
        self.entered.set()
        if self.gate is not None:
            self.gate.wait(10)
        outcome = self.replies.get(raw, self.default)
        if isinstance(outcome, BaseException):
            raise outcome
        if callable(outcome):
            outcome = outcome(raw)
        return outcome

    def close(self) -> None:
        self.closed = True


class FlakyFactory:
    """A session factory whose next ``failures`` sessions fail when they commit.

    A negative ``failures`` fails every session until it is set back to 0. ``calls`` counts the
    sessions asked for, so a test can show that nothing touched the database.
    """

    def __init__(self, factory: sessionmaker[Session], *, failures: int = 0) -> None:
        self.factory = factory
        self.failures = failures
        self.calls = 0

    def __call__(self) -> Session:
        self.calls += 1
        session = self.factory()
        if self.failures:
            if self.failures > 0:
                self.failures -= 1
            session.commit = _failing_commit
        return session


def _failing_commit(*_args: Any, **_kwargs: Any) -> None:
    raise OperationalError("COMMIT", {}, Exception("database is locked"))


# --- Rows ------------------------------------------------------------------------------------

_FINISHED = {
    CaptureStatus.STOPPED,
    CaptureStatus.COMPLETED,
    CaptureStatus.FAILED,
    CaptureStatus.PERMISSION_DENIED,
}


def seed_session(
    factory: sessionmaker[Session],
    *,
    owner: str = "alice",
    status: CaptureStatus = CaptureStatus.COMPLETED,
    source: CaptureSource = CaptureSource.PCAP,
    started: datetime | None = None,
    ended: datetime | None = None,
    session_id: uuid.UUID | None = None,
    interface: str | None = None,
    label: str | None = "seed.pcap",
    error_code: str | None = None,
    stats: dict[str, Any] | None = None,
    packets: int = 0,
    size: int = 0,
    flows: int = 0,
    alerts: int = 0,
    dropped: int = 0,
) -> uuid.UUID:
    """Insert a capture session. A finished one gets an ``ended_at`` a minute after it started."""
    started = started or datetime.fromtimestamp(T0, tz=UTC)
    if ended is None and status in _FINISHED:
        ended = started + timedelta(minutes=1)
    row = CaptureSession(
        id=session_id or uuid.uuid4(),
        owner=owner,
        source_kind=source.value,
        status=status.value,
        interface=interface,
        source_label=label,
        started_at=started,
        ended_at=ended,
        packets_total=packets,
        bytes_total=size,
        flows_total=flows,
        alerts_total=alerts,
        packets_dropped=dropped,
        error_code=error_code,
        stats=stats if stats is not None else {},
    )
    with factory() as db:
        db.add(row)
        db.commit()
    return row.id


def seed_flow(
    factory: sessionmaker[Session],
    session_id: uuid.UUID,
    *,
    src: str = HOST,
    dst: str = SERVER,
    sport: int | None = 40000,
    dport: int | None = 80,
    protocol: str = "tcp",
    first: datetime | None = None,
    last: datetime | None = None,
    close_reason: str = "closed",
) -> int:
    first = first or datetime.fromtimestamp(T0, tz=UTC)
    row = NetworkFlow(
        session_id=session_id,
        protocol=protocol,
        src_ip=src,
        src_port=sport,
        dst_ip=dst,
        dst_port=dport,
        first_seen=first,
        last_seen=last or first,
        packets_out=1,
        packets_in=1,
        bytes_out=60,
        bytes_in=60,
        tcp_flags=2 if protocol == "tcp" else None,
        close_reason=close_reason,
    )
    with factory() as db:
        db.add(row)
        db.commit()
    return row.id


def seed_alert(
    factory: sessionmaker[Session],
    session_id: uuid.UUID,
    *,
    rule_id: str = "NET-001",
    rule_name: str = "port_scan",
    severity: str = "medium",
    src: str | None = SCANNER,
    dst: str | None = SERVER,
    dst_port: int | None = None,
    created: datetime | None = None,
    enrichment: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
) -> uuid.UUID:
    when = datetime.fromtimestamp(T0, tz=UTC)
    row = NetworkAlert(
        session_id=session_id,
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        explanation="Seeded alert.",
        observed_value=20.0,
        threshold=20.0,
        window_seconds=60,
        src_ip=src,
        dst_ip=dst,
        dst_port=dst_port,
        protocol="tcp",
        first_observed=when,
        last_observed=when,
        created_at=created or when,
        evidence=evidence if evidence is not None else {},
        enrichment=enrichment if enrichment is not None else {},
    )
    with factory() as db:
        db.add(row)
        db.commit()
    return row.id


# --- A monitor over a real recorder ----------------------------------------------------------


class MonitorRig:
    """One ``SessionMonitor`` over a real recorder and database, with the clock in the test's hands.

    ``writes`` records every batch the monitor handed to the recorder.
    """

    def __init__(
        self,
        factory: sessionmaker[Session],
        monitor: SessionMonitor,
        recorder: SessionRecorder,
        session_id: uuid.UUID,
        clock: FakeClock,
        worker: Any,
        writes: list[dict[str, Any]],
    ) -> None:
        self.factory = factory
        self.monitor = monitor
        self.recorder = recorder
        self.session_id = session_id
        self.clock = clock
        self.worker = worker
        self.writes = writes

    def row(self) -> CaptureSession:
        with self.factory() as db:
            row = db.get(CaptureSession, self.session_id)
            assert row is not None
            return row

    def flows(self) -> list[NetworkFlow]:
        with self.factory() as db:
            return list(
                db.scalars(select(NetworkFlow).where(NetworkFlow.session_id == self.session_id))
            )

    def alerts(self) -> list[NetworkAlert]:
        with self.factory() as db:
            return list(
                db.scalars(select(NetworkAlert).where(NetworkAlert.session_id == self.session_id))
            )


def build_rig(
    factory: sessionmaker[Session],
    settings: Settings,
    *,
    stream_time: bool = False,
    worker: Any = None,
    session_factory: Any = None,
    flush_interval: float = 2.0,
    stats_lock: Any = None,
    source: CaptureSource = CaptureSource.LIVE,
    session_id: uuid.UUID | None = None,
) -> MonitorRig:
    """Seed a running session and build the monitor and recorder that serve it.

    ``session_factory`` is what the recorder uses (to make its database fail); the test reads the
    results through ``factory``. A worker that writes to the same session must share
    ``stats_lock``.
    """
    session_id = session_id or seed_session(
        factory,
        status=CaptureStatus.RUNNING,
        source=source,
        interface="Test Ethernet" if source is CaptureSource.LIVE else None,
        label=None if source is CaptureSource.LIVE else "rig.pcap",
    )
    recorder = SessionRecorder(
        session_factory or factory,
        session_id,
        max_stored_flows=settings.network_max_stored_flows,
        enrichment_enabled=settings.external_enrichment_enabled,
        stats_lock=stats_lock or threading.Lock(),
        retry_delay=0.0,
    )
    writes: list[dict[str, Any]] = []
    original = recorder.write

    def spy(output: Any, snapshot: Any, *, stats: dict[str, Any], packets_dropped: int) -> bool:
        writes.append(
            {
                "alerts": len(output.alerts),
                "flows": len(output.flows),
                "packets": snapshot.packets,
                "dropped": packets_dropped,
            }
        )
        return original(output, snapshot, stats=stats, packets_dropped=packets_dropped)

    recorder.write = spy
    clock = FakeClock()
    monitor = SessionMonitor(
        session_id,
        settings=settings,
        recorder=recorder,
        enrichment=worker,
        stream_time=stream_time,
        clock=clock,
        flush_interval=flush_interval,
    )
    return MonitorRig(factory, monitor, recorder, session_id, clock, worker, writes)


# --- Handcrafted capture files ---------------------------------------------------------------


def scan_frames(*, ports: int = SCAN_PORTS) -> list[tuple[float, bytes]]:
    """The frames of ``scan_traffic()`` as (timestamp, bytes), for building files by hand."""
    return [(float(frame.time), bytes(frame)) for frame in scan_traffic(ports=ports)]


def pcap_record_header(
    included: int,
    *,
    original: int | None = None,
    seconds: int = 0,
    fraction: int = 0,
    endian: str = "<",
) -> bytes:
    """A classic record header. ``included`` may claim more bytes than the file has."""
    original = included if original is None else original
    return struct.pack(endian + "IIII", seconds, fraction, included, original)


def classic_pcap(
    frames: Iterable[tuple[float, bytes]] = (),
    *,
    endian: str = "<",
    nano: bool = False,
    linktype: int = 1,
    version: tuple[int, int] = (2, 4),
) -> bytes:
    """A classic capture file of raw frames, in either byte order and timestamp resolution."""
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = bytearray(struct.pack(endian + "IHHiIII", magic, *version, 0, 0, 65535, linktype))
    scale = 1_000_000_000 if nano else 1_000_000
    for stamp, frame in frames:
        seconds = int(stamp)
        fraction = round((stamp - seconds) * scale)
        out += pcap_record_header(len(frame), seconds=seconds, fraction=fraction, endian=endian)
        out += frame
    return bytes(out)


def pcapng_block(kind: int, body: bytes = b"", *, endian: str = "<") -> bytes:
    """One PCAPNG block: its type, its length, the body padded to four bytes, its length again."""
    padded = body + b"\x00" * (-len(body) % 4)
    total = len(padded) + 12
    return struct.pack(endian + "II", kind, total) + padded + struct.pack(endian + "I", total)


def pcapng_file(
    frames: Iterable[tuple[float, bytes]] = (),
    *,
    endian: str = "<",
    linktype: int = 1,
    version: tuple[int, int] = (1, 0),
    simple: bool = False,
) -> bytes:
    """A PCAPNG file: a section header, one interface and a packet block per frame.

    Packet blocks are enhanced ones with microsecond stamps, or ``simple`` ones, which have none.
    """
    section = struct.pack(endian + "IHHq", 0x1A2B3C4D, *version, -1)
    out = pcapng_block(0x0A0D0D0A, section, endian=endian)
    out += pcapng_block(1, struct.pack(endian + "HHI", linktype, 0, 65535), endian=endian)
    for stamp, frame in frames:
        if simple:
            body = struct.pack(endian + "I", len(frame)) + frame
            out += pcapng_block(3, body, endian=endian)
            continue
        ticks = round(stamp * 1_000_000)
        head = struct.pack(
            endian + "IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame)
        )
        out += pcapng_block(6, head + frame, endian=endian)
    return bytes(out)


# --- The service over a real database --------------------------------------------------------

ALICE = RequestContext(actor="alice", source_ip="203.0.113.10")
BOB = RequestContext(actor="bob", source_ip="203.0.113.11")
ACTIVE_VALUES = frozenset(
    {CaptureStatus.STARTING.value, CaptureStatus.RUNNING.value, CaptureStatus.STOPPING.value}
)


def scan_capture_files(directory: Path) -> dict[str, bytes]:
    """The scan capture as the bytes of a classic file and of a PCAPNG file."""
    return {
        "pcap": write_scan_capture(directory / "scan.pcap").read_bytes(),
        "pcapng": write_scan_capture(directory / "scan.pcapng", ng=True).read_bytes(),
    }


class Background:
    """Runs a call on a thread of its own and keeps what it returned or raised."""

    def __init__(self, target: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        self.result: Any = None
        self.error: Exception | None = None
        self._thread = threading.Thread(
            target=self._run, args=(target, args, kwargs), name="test-background", daemon=True
        )
        self._thread.start()

    def _run(self, target: Callable[..., Any], args: tuple, kwargs: dict[str, Any]) -> None:
        try:
            self.result = target(*args, **kwargs)
        except Exception as exc:
            self.error = exc

    @property
    def done(self) -> bool:
        return not self._thread.is_alive()

    def join(self, timeout: float = 10.0) -> "Background":
        self._thread.join(timeout)
        assert self.done, "the background call did not finish"
        return self


class AnalysisGate:
    """Holds the analysis of a file at its start until it is released (or cancelled)."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()


def hold_analyses(monkeypatch: Any) -> AnalysisGate:
    """Make every file analysis wait at its start until the returned gate is released.

    A cancelled analysis (shutdown) goes on without waiting, so nothing is left hanging.
    """
    gate = AnalysisGate()
    real = service_module.analyze_file

    def held(
        path: Path, info: Any, monitor: Any, *, cancel: threading.Event, **options: Any
    ) -> Any:
        gate.entered.set()
        wait_until(
            lambda: gate.release.is_set() or cancel.is_set(), timeout=15, what="the gate to open"
        )
        return real(path, info, monitor, cancel=cancel, **options)

    monkeypatch.setattr(service_module, "analyze_file", held)
    return gate


class ServiceRig:
    """A ``NetworkService`` over a real database, with a fake catalog, fake packet sources and a
    stub intelligence service. Every call opens its own database session, as a request does.

    ``prepared`` holds the sources the next captures will use (a plain ``FakeSource`` otherwise),
    ``requested`` the interface ids the service asked the source factory for.
    """

    def __init__(
        self,
        settings: Settings,
        factory: sessionmaker[Session],
        spool_base: Path,
        *,
        intel: StubIntel | None = None,
        catalog: FakeCatalog | None = None,
        clock: Callable[[], float] | None = None,
        service_sessions: Callable[[], Session] | None = None,
    ) -> None:
        self.settings = settings
        self.factory = factory
        self.spool_base = spool_base
        self.intel = intel or StubIntel()
        self.catalog = catalog or FakeCatalog()
        self.spool = UploadSpool(spool_base)
        self.prepared: deque[FakeSource] = deque()
        self.sources: list[FakeSource] = []
        self.requested: list[str] = []
        self.source_entered = threading.Event()
        self.source_gate: threading.Event | None = None
        self.source_error: Exception | None = None
        self.gates: list[threading.Event] = []
        self.service = NetworkService(
            settings,
            service_sessions or factory,
            intel_service=self.intel,
            catalog=self.catalog,
            source_factory=self.make_source,
            spool=self.spool,
            pacing_interval=0.0,
            clock=clock or time.time,
        )

    # --- Sources -----------------------------------------------------------------------

    def make_source(self, interface_id: str) -> FakeSource:
        self.requested.append(interface_id)
        self.source_entered.set()
        if self.source_gate is not None:
            self.source_gate.wait(10)
        if self.source_error is not None:
            raise self.source_error
        source = self.prepared.popleft() if self.prepared else FakeSource()
        self.sources.append(source)
        return source

    def hold_sources(self) -> threading.Event:
        """Make the source factory wait until the returned event is set."""
        gate = self.source_gate = threading.Event()
        self.gates.append(gate)
        return gate

    # --- Calls, each in a session of its own -------------------------------------------------

    def call(self, method: str, *args: Any, **kwargs: Any) -> Any:
        """Call a service method that takes a database session first, in a session of its own."""
        with self.factory() as db:
            return getattr(self.service, method)(db, *args, **kwargs)

    def start(
        self, who: RequestContext = ALICE, interface: str = TEST_INTERFACE.id
    ) -> NetworkStatus:
        with self.factory() as db:
            return self.service.start_live(db, who, interface)

    def stop(self, who: RequestContext = ALICE) -> NetworkStatus:
        with self.factory() as db:
            return self.service.stop_live(db, who)

    def status(self, who: RequestContext = ALICE) -> NetworkStatus:
        with self.factory() as db:
            return self.service.status(db, who.actor)

    def upload(self, data: bytes) -> ReceivedUpload:
        """Put ``data`` where ``receive_upload`` would have put an uploaded body."""
        path = self.spool.new_file()
        path.write_bytes(data)
        return ReceivedUpload(path=path, size=len(data))

    def analyze(
        self, data: bytes, who: RequestContext = ALICE, name: str = "scan.pcap"
    ) -> SessionDetail:
        upload = self.upload(data)
        with self.factory() as db:
            return self.service.analyze_pcap(db, who, upload=upload, name=name)

    # --- What is stored ----------------------------------------------------------------------

    def row(self, session_id: uuid.UUID) -> CaptureSession:
        with self.factory() as db:
            row = db.get(CaptureSession, session_id)
            assert row is not None, "the session is not stored"
            return row

    def exists(self, session_id: uuid.UUID) -> bool:
        with self.factory() as db:
            return db.get(CaptureSession, session_id) is not None

    def sessions(self) -> list[CaptureSession]:
        with self.factory() as db:
            return list(
                db.scalars(
                    select(CaptureSession).order_by(CaptureSession.started_at, CaptureSession.id)
                )
            )

    def flows(self, session_id: uuid.UUID) -> list[NetworkFlow]:
        with self.factory() as db:
            return list(
                db.scalars(
                    select(NetworkFlow)
                    .where(NetworkFlow.session_id == session_id)
                    .order_by(NetworkFlow.id)
                )
            )

    def alerts(self, session_id: uuid.UUID) -> list[NetworkAlert]:
        with self.factory() as db:
            return list(
                db.scalars(
                    select(NetworkAlert)
                    .where(NetworkAlert.session_id == session_id)
                    .order_by(NetworkAlert.created_at, NetworkAlert.id)
                )
            )

    def count(self, model: Any) -> int:
        with self.factory() as db:
            return db.scalar(select(func.count()).select_from(model)) or 0

    def audit(self, action: str | None = None) -> list[AuditLog]:
        with self.factory() as db:
            query = select(AuditLog).order_by(AuditLog.timestamp, AuditLog.id)
            if action is not None:
                query = query.where(AuditLog.action == action)
            return list(db.scalars(query))

    def spool_files(self) -> list[Path]:
        return sorted(path for path in self.spool_base.rglob("*") if path.is_file())

    # --- Waiting -----------------------------------------------------------------------------

    def wait_for_end(self, session_id: uuid.UUID, *, timeout: float = 10.0) -> CaptureSession:
        """Wait until the session is no longer starting, running or stopping; return its row."""
        wait_until(
            lambda: self.row(session_id).status not in ACTIVE_VALUES,
            timeout=timeout,
            what="the session to end",
        )
        return self.row(session_id)

    def wait_for_lookups(
        self, session_id: uuid.UUID, addresses: Iterable[str], *, timeout: float = 10.0
    ) -> dict[str, Any]:
        """Wait until every address has an answer recorded; return the session's enrichment."""
        wanted = set(addresses)

        def answered() -> dict[str, Any] | None:
            entries = (self.row(session_id).stats or {}).get("enrichment") or {}
            if wanted <= set(entries) and all(
                entries[address].get("status") != "pending" for address in wanted
            ):
                return entries
            return None

        return wait_until(answered, timeout=timeout, what="the lookups to be recorded")

    def close(self) -> None:
        for gate in self.gates:
            gate.set()
        if self.intel.gate is not None:
            self.intel.gate.set()
        self.service.shutdown()


def rig_builder(
    factory: sessionmaker[Session],
    make_settings: Callable[..., Settings],
    db_url: str,
    spool_base: Path,
    monkeypatch: Any,
) -> Iterator[Callable[..., ServiceRig]]:
    """The body of a ``make_rig`` fixture (``yield from`` it): rigs with quick polling, every one
    shut down when the test ends and the upload spool checked to be empty."""
    monkeypatch.setattr(capture_module, "_POLL_SECONDS", 0.01)
    monkeypatch.setattr(enrichment_module, "_POLL_SECONDS", 0.01)
    monkeypatch.setattr(monitor_module, "_FINAL_FLUSH_DELAY", 0.0)
    spool_base.mkdir()
    rigs: list[ServiceRig] = []

    def build(settings: dict[str, Any] | None = None, **options: Any) -> ServiceRig:
        rig = ServiceRig(
            make_settings(database_url=db_url, **(settings or {})), factory, spool_base, **options
        )
        rigs.append(rig)
        return rig

    yield build
    for rig in reversed(rigs):
        rig.close()
    assert list(spool_base.iterdir()) == []


# --- Reading what a test caused ----------------------------------------------------------------


def ago(**interval: float) -> datetime:
    """A moment this long before now: retention is judged against the real clock."""
    return utcnow() - timedelta(**interval)


def backdate(path: Path, seconds: float) -> None:
    """Make a file or directory look as if it was last touched ``seconds`` ago."""
    moment = time.time() - seconds
    os.utime(path, (moment, moment))


def refusal(call: Callable[[], Any]) -> tuple[int, str, str]:
    """Run a call that must be refused; the status, code and message of the refusal."""
    try:
        call()
    except ApiError as error:
        return error.status_code, error.code, str(error.detail)
    raise AssertionError("the call was not refused")


def logged(caplog: Any, message: str) -> list[logging.LogRecord]:
    """The records with exactly this message. Their ``extra`` values are attributes."""
    return [record for record in caplog.records if record.getMessage() == message]


def assert_not_logged(caplog: Any, secret: str) -> None:
    """The text appears neither in a log message nor in any value logged with it."""
    assert secret not in caplog.text
    assert not any(secret in str(vars(record)) for record in caplog.records)
