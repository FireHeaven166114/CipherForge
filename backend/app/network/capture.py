"""Live packet capture: finding interfaces, and running a capture away from the request threads.

Scapy does the capturing, through Npcap on Windows and libpcap (or raw sockets) elsewhere. A
capture has three moving parts, each on its own thread so none of them waits on another:

* the capture library's sniffer thread calls ``LiveCapture._on_packet`` for every packet. That
  reduces the packet to its metadata and puts it on a bounded queue, nothing more. A full queue
  means the packet is counted as dropped, never that the sniffer waits;
* a consumer thread takes batches off the queue and feeds the session's :class:`SessionMonitor`.
  It also watches the sniffer and notices if it dies;
* the request that started the capture returns as soon as the sniffer reports it is running.

Packet payloads are never read beyond the headers, and nothing is kept but the metadata.
"""

import ipaddress
import logging
import queue
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, NoReturn, Protocol

from app.models.enums import CaptureStatus
from app.network.errors import CaptureFailure
from app.network.monitor import SessionMonitor
from app.network.packets import extract_packet
from app.network.scapy_support import CaptureLibraryMissingError, load_scapy

logger = logging.getLogger("cipherforge.network")

INTERFACE_CACHE_SECONDS = 30.0
_MAX_ADDRESSES = 4
_BATCH_SIZE = 256
_POLL_SECONDS = 0.25
START_TIMEOUT_SECONDS = 5.0
STOP_TIMEOUT_SECONDS = 10.0

_PERMISSION_MARKERS = (
    "permission",
    "access is denied",
    "not permitted",
    "privilege",
    "administrator",
)
_BACKEND_MARKERS = ("winpcap", "npcap", "libpcap", "wpcap", "not available at layer 2")
_INTERFACE_MARKERS = (
    "no such device",
    "no such interface",
    "device not found",
    "interface is down",
    "network is down",
    "not ready",
    "disconnected",
    "cannot find",
    "not found",
)


@dataclass(frozen=True, slots=True)
class InterfaceInfo:
    id: str
    name: str
    description: str
    addresses: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BackendInfo:
    """Which capture driver is in use. ``available`` is False when capture cannot work at all."""

    name: str
    available: bool


def classify_capture_error(exc: BaseException) -> str:
    """Map whatever a capture library raised to one of the module's error codes."""
    if isinstance(exc, CaptureFailure):
        return exc.code
    if isinstance(exc, CaptureLibraryMissingError):
        return "capture_backend_missing"
    text = f"{type(exc).__name__} {exc}".lower()
    if isinstance(exc, PermissionError) or any(marker in text for marker in _PERMISSION_MARKERS):
        return "capture_permission_denied"
    if any(marker in text for marker in _BACKEND_MARKERS):
        return "capture_backend_missing"
    if any(marker in text for marker in _INTERFACE_MARKERS):
        return "interface_unavailable"
    return "capture_failed"


# --- Interfaces ----------------------------------------------------------------------------


def _identity(iface: Any) -> str:
    return str(getattr(iface, "network_name", "") or getattr(iface, "name", "") or "")


def _addresses(iface: Any) -> tuple[str, ...]:
    candidates: list[Any] = []
    ips = getattr(iface, "ips", None)
    if isinstance(ips, dict):
        for group in ips.values():
            candidates.extend(group if isinstance(group, list | tuple | set) else [group])
    candidates.append(getattr(iface, "ip", None))
    found: list[str] = []
    for candidate in candidates:
        try:
            address = ipaddress.ip_address(str(candidate))
        except ValueError:
            continue
        text = str(address)
        if address.is_unspecified or text in found:
            continue
        found.append(text)
        if len(found) == _MAX_ADDRESSES:
            break
    return tuple(found)


def _read_interfaces(scapy: Any) -> list[InterfaceInfo]:
    found: dict[str, InterfaceInfo] = {}
    for iface in list(scapy.conf.ifaces.values()):
        if getattr(iface, "dummy", False) or getattr(iface, "invalid", False):
            continue
        identity = _identity(iface)
        if not identity or identity in found:
            continue
        name = str(getattr(iface, "name", "") or identity)
        found[identity] = InterfaceInfo(
            id=identity[:256],
            name=name[:128],
            description=str(getattr(iface, "description", "") or "")[:256],
            addresses=_addresses(iface),
        )
    # Interfaces with an address are the ones traffic is likely to flow through.
    return sorted(found.values(), key=lambda info: (not info.addresses, info.name.lower()))


def probe_backend() -> BackendInfo:
    try:
        conf = load_scapy().conf
    except CaptureLibraryMissingError:
        return BackendInfo("none", False)
    use_pcap = bool(getattr(conf, "use_pcap", False))
    if sys.platform == "win32":
        if not use_pcap:
            return BackendInfo("none", False)
        return BackendInfo("npcap" if getattr(conf, "use_npcap", False) else "winpcap", True)
    return BackendInfo("libpcap" if use_pcap else "native", True)


class InterfaceCatalog:
    """The capture backend and interfaces of this machine, looked up lazily and kept briefly.

    Scapy is imported on first use, never at start-up, and interface discovery can take a moment
    on Windows, so answers are reused for ``INTERFACE_CACHE_SECONDS``.
    """

    def __init__(
        self,
        *,
        ttl: float = INTERFACE_CACHE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl
        self._clock = clock
        self._lock = threading.Lock()
        self._backend: BackendInfo | None = None
        self._interfaces: list[InterfaceInfo] = []
        self._loaded_at: float | None = None

    def backend(self) -> BackendInfo:
        with self._lock:
            if self._backend is None:
                self._backend = probe_backend()
            return self._backend

    def interfaces(self, *, refresh: bool = False) -> list[InterfaceInfo]:
        """Every interface capture can be started on. Empty when capture is not available."""
        if not self.backend().available:
            return []
        with self._lock:
            if refresh or self._loaded_at is None or self._clock() - self._loaded_at > self._ttl:
                self._load(reload_system=refresh)
            return list(self._interfaces)

    def resolve(self, interface_id: str) -> InterfaceInfo | None:
        """The interface with this id, checked against the interfaces that exist right now."""
        for info in self.interfaces():
            if info.id == interface_id:
                return info
        for info in self.interfaces(refresh=True):
            if info.id == interface_id:
                return info
        return None

    def _load(self, *, reload_system: bool) -> None:
        scapy = load_scapy()
        if reload_system:
            try:
                scapy.conf.ifaces.reload()
            except Exception as exc:  # the cached list is still usable
                logger.warning("interface_reload_failed", extra={"error": type(exc).__name__})
        self._interfaces = _read_interfaces(scapy)
        self._loaded_at = self._clock()


# --- Sources -------------------------------------------------------------------------------


class PacketSource(Protocol):
    """Something that delivers captured packets, from a thread of its own, to a handler."""

    @property
    def alive(self) -> bool: ...

    @property
    def error(self) -> BaseException | None: ...

    def start(self, handler: Callable[[Any], None]) -> None: ...

    def wait_started(self, timeout: float) -> bool: ...

    def stop(self) -> None: ...


class ScapyLiveSource:
    """Scapy's ``AsyncSniffer`` on one interface."""

    def __init__(self, interface_id: str) -> None:
        self._interface_id = interface_id
        self._started = threading.Event()
        self._sniffer: Any = None

    @property
    def alive(self) -> bool:
        thread = getattr(self._sniffer, "thread", None)
        return thread is not None and thread.is_alive()

    @property
    def error(self) -> BaseException | None:
        return getattr(self._sniffer, "exception", None)

    def start(self, handler: Callable[[Any], None]) -> None:
        scapy = load_scapy()
        interface = next(
            (
                iface
                for iface in list(scapy.conf.ifaces.values())
                if _identity(iface) == self._interface_id
            ),
            None,
        )
        if interface is None:
            raise CaptureFailure("interface_unavailable")
        # store=False: packets are handed to the handler and not kept. promisc=False: only the
        # traffic addressed to or from this machine is captured.
        self._sniffer = scapy.AsyncSniffer(
            iface=interface,
            prn=handler,
            store=False,
            promisc=False,
            started_callback=self._started.set,
        )
        self._sniffer.start()

    def wait_started(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            if self._started.is_set():
                return True
            if not self.alive or time.monotonic() >= deadline:
                return self._started.is_set()
            time.sleep(0.05)

    def stop(self) -> None:
        sniffer = self._sniffer
        thread = getattr(sniffer, "thread", None)
        if thread is None or thread is threading.current_thread():
            return
        deadline = time.monotonic() + STOP_TIMEOUT_SECONDS
        # Asked again until the thread ends: a request made while the interface is still being
        # opened is ignored by Scapy, so the first one can be lost.
        while thread.is_alive() and time.monotonic() < deadline:
            try:
                if getattr(sniffer, "running", False):
                    sniffer.stop(join=False)
            except Exception as exc:  # a sniffer that already failed re-raises its own error
                logger.debug("sniffer_stop_raised", extra={"error": type(exc).__name__})
            thread.join(0.2)
        if thread.is_alive():
            logger.warning("sniffer_thread_did_not_stop")


# --- The capture ---------------------------------------------------------------------------


class LiveCapture:
    """One running live capture: a source, a bounded queue, and a thread that analyses packets."""

    def __init__(
        self,
        monitor: SessionMonitor,
        source: PacketSource,
        *,
        buffer_size: int,
        start_timeout: float = START_TIMEOUT_SECONDS,
    ) -> None:
        self._monitor = monitor
        self._source = source
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=buffer_size)
        self._start_timeout = start_timeout
        self._lock = threading.Lock()
        self._state = CaptureStatus.STARTING
        self._stopping = threading.Event()
        self._source_stopped = threading.Event()
        # Set once the source has been started: a source that is not running yet has not died.
        self._source_started = threading.Event()
        self._failure: str | None = None
        self._thread = threading.Thread(
            target=self._consume, name="cipherforge-capture-consumer", daemon=True
        )

    @property
    def state(self) -> CaptureStatus:
        with self._lock:
            return self._state

    @property
    def active(self) -> bool:
        """True from start until the consumer has stored the final results."""
        return self._thread.is_alive() or self.state in (
            CaptureStatus.STARTING,
            CaptureStatus.RUNNING,
            CaptureStatus.STOPPING,
        )

    @property
    def error_code(self) -> str | None:
        return self._failure

    def start(self) -> None:
        """Begin capturing. Raises ``CaptureFailure`` if the capture cannot start."""
        self._thread.start()
        try:
            self._source.start(self._on_packet)
            self._source_started.set()
            started = self._source.wait_started(self._start_timeout)
        except Exception as exc:
            self._abort(classify_capture_error(exc), exc)
        if started:
            self._promote()
        elif not self._source.alive:
            error = self._source.error
            self._abort(
                classify_capture_error(error) if error is not None else "capture_failed", error
            )
        # Otherwise the sniffer is still opening the interface; the consumer thread promotes the
        # session to running once it reports in.

    def stop(self, timeout: float = STOP_TIMEOUT_SECONDS) -> bool:
        """Stop capturing and wait for the results to be stored. False if that took too long."""
        with self._lock:
            if self._state in (CaptureStatus.STARTING, CaptureStatus.RUNNING):
                self._state = CaptureStatus.STOPPING
                self._monitor.set_status(CaptureStatus.STOPPING)
        self._stopping.set()
        try:
            self._source.stop()
        except Exception as exc:  # the consumer thread stops it again and ends the session
            logger.warning("capture_source_stop_failed", extra={"error": type(exc).__name__})
        finally:
            self._source_stopped.set()
        if self._thread.is_alive() and self._thread is not threading.current_thread():
            self._thread.join(timeout)
        return not self._thread.is_alive()

    # --- Sniffer thread ----------------------------------------------------------------

    def _on_packet(self, raw: Any) -> None:
        """Called by the capture library for every packet. Never raises and never waits."""
        try:
            meta = extract_packet(raw)
        except Exception:
            self._monitor.note_malformed()
            return
        if meta is None:
            self._monitor.note_non_ip()
            return
        try:
            self._queue.put_nowait(meta)
        except queue.Full:
            self._monitor.note_dropped()

    # --- Consumer thread ---------------------------------------------------------------

    def _consume(self) -> None:
        try:
            while True:
                batch = self._next_batch()
                if batch:
                    self._monitor.process_batch(batch)
                else:
                    self._monitor.tick()
                self._watch_source()
                if self._failure is not None or self._monitor.gone:
                    break
                if self._source_stopped.is_set() and self._queue.empty():
                    break
        except Exception as exc:  # a bug here must end the session cleanly, not leave it hanging
            logger.error("capture_consumer_failed", extra={"error": type(exc).__name__})
            self._failure = self._failure or "capture_failed"
        finally:
            self._finish()

    def _next_batch(self) -> list[Any]:
        try:
            batch = [self._queue.get(timeout=_POLL_SECONDS)]
        except queue.Empty:
            return []
        while len(batch) < _BATCH_SIZE:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return batch

    def _watch_source(self) -> None:
        if not self._source_started.is_set():
            return
        if self.state is CaptureStatus.STARTING and self._source.wait_started(0):
            self._promote()
        if self._stopping.is_set() or self._failure is not None or self._source.alive:
            return
        error = self._source.error
        self._failure = classify_capture_error(error) if error is not None else "capture_failed"
        if error is not None:
            logger.error("capture_source_failed", extra={"error": type(error).__name__})
        else:
            logger.error("capture_source_ended_unexpectedly")

    def _promote(self) -> None:
        with self._lock:
            if self._state is not CaptureStatus.STARTING:
                return
            self._state = CaptureStatus.RUNNING
        self._monitor.set_status(CaptureStatus.RUNNING)

    def _finish(self) -> None:
        try:
            self._source.stop()
        except Exception as exc:
            logger.warning("capture_source_stop_failed", extra={"error": type(exc).__name__})
        self._source_stopped.set()
        # Packets queued before the sniffer stopped still belong to the session.
        leftovers: list[Any] = []
        while True:
            try:
                leftovers.append(self._queue.get_nowait())
            except queue.Empty:
                break
        try:
            for start in range(0, len(leftovers), _BATCH_SIZE):
                self._monitor.process_batch(leftovers[start : start + _BATCH_SIZE])
        except Exception as exc:
            logger.warning("capture_drain_failed", extra={"error": type(exc).__name__})
        if self._failure is None:
            status, code = CaptureStatus.STOPPED, None
        elif self._failure == "capture_permission_denied":
            status, code = CaptureStatus.PERMISSION_DENIED, self._failure
        else:
            status, code = CaptureStatus.FAILED, self._failure
        try:
            self._monitor.finish(status, code)
        except Exception as exc:
            logger.error("capture_finish_failed", extra={"error": type(exc).__name__})
        with self._lock:
            self._state = status

    def _abort(self, code: str, error: BaseException | None) -> NoReturn:
        """The capture could not start: end the session as failed and tell the caller."""
        self._failure = code
        if error is not None:
            logger.warning("capture_start_failed", extra={"error": type(error).__name__})
        self._stopping.set()
        self._source_stopped.set()
        self._thread.join(STOP_TIMEOUT_SECONDS)
        raise CaptureFailure(code)
