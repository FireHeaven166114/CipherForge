"""Live capture: the interface catalogue, the Scapy source and the thread that runs a capture.

Nothing here captures real packets. A ``FakeSource`` stands in for the capture library, and the
Scapy-facing code is exercised against a fake ``scapy`` module.
"""

import contextlib
import logging
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

from app.core.config import Settings
from app.database.session import build_engine, build_session_factory
from app.models.enums import CaptureStatus
from app.network import capture as capture_module
from app.network.capture import (
    BackendInfo,
    InterfaceCatalog,
    LiveCapture,
    ScapyLiveSource,
    classify_capture_error,
    probe_backend,
)
from app.network.errors import CaptureFailure
from app.network.packets import extract_packet as real_extract_packet
from app.network.scapy_support import CaptureLibraryMissingError
from tests.network_helpers import (
    SCAN_FLOWS,
    SCAN_FRAMES,
    T0,
    FakeClock,
    FakeSource,
    RecordingMonitor,
    assert_no_module_threads,
    build_rig,
    packet,
    scan_traffic,
    scapy_arp,
    wait_until,
)

FAST_POLL = 0.02
NON_IP = "non-ip"
UNREADABLE = "unreadable"


def fake_extract(raw: Any) -> Any:
    """Stands in for ``extract_packet``: tests hand over ready-made packet metadata."""
    if raw == NON_IP:
        return None
    if raw == UNREADABLE:
        raise ValueError("cannot be read")
    return raw


@pytest.fixture(autouse=True)
def _no_leaked_threads() -> Iterator[None]:
    yield
    assert_no_module_threads()


@pytest.fixture(autouse=True)
def _quick_polling(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(capture_module, "_POLL_SECONDS", FAST_POLL)
    monkeypatch.setattr(capture_module, "extract_packet", fake_extract)


@dataclass
class Run:
    capture: LiveCapture
    monitor: Any
    source: Any


@pytest.fixture
def make_run() -> Iterator[Callable[..., Run]]:
    """Captures that are stopped, and whose monitors are released, whatever the test did."""
    runs: list[Run] = []

    def build(
        source: Any = None,
        monitor: Any = None,
        *,
        buffer_size: int = 1000,
        start_timeout: float = 1.0,
        start: bool = True,
    ) -> Run:
        monitor = monitor if monitor is not None else RecordingMonitor()
        source = source if source is not None else FakeSource()
        capture = LiveCapture(monitor, source, buffer_size=buffer_size, start_timeout=start_timeout)
        run = Run(capture, monitor, source)
        runs.append(run)
        if start:
            capture.start()
        return run

    yield build
    for run in runs:
        gate = getattr(run.monitor, "gate", None)
        if gate is not None:
            gate.set()
        with contextlib.suppress(Exception):
            run.capture.stop(timeout=5)


def finished_without_error(run: Run) -> bool:
    return run.monitor.finished == [(CaptureStatus.STOPPED, None)]


# --- Mapping what the capture library raises to the module's error codes ----------------------


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (CaptureFailure("interface_unavailable"), "interface_unavailable"),
        (CaptureFailure("something_new"), "something_new"),
        (CaptureLibraryMissingError("Scapy is not installed."), "capture_backend_missing"),
        (PermissionError(13, "denied"), "capture_permission_denied"),
        (OSError(1, "Operation not permitted"), "capture_permission_denied"),
        (RuntimeError("Access is denied."), "capture_permission_denied"),
        (RuntimeError("You must be an Administrator to capture"), "capture_permission_denied"),
        (RuntimeError("elevated privileges are required"), "capture_permission_denied"),
        (RuntimeError("No libpcap provider available !"), "capture_backend_missing"),
        (RuntimeError("Npcap is not installed"), "capture_backend_missing"),
        (OSError("wpcap.dll could not be loaded"), "capture_backend_missing"),
        (OSError("No such device exists"), "interface_unavailable"),
        (RuntimeError("The network is down"), "interface_unavailable"),
        (RuntimeError("Interface is down"), "interface_unavailable"),
        (ValueError("something else entirely"), "capture_failed"),
        (KeyError("x"), "capture_failed"),
        # Being refused is the more useful answer when the text also names the driver.
        (PermissionError("the npcap driver refused"), "capture_permission_denied"),
    ],
)
def test_capture_errors_map_to_the_modules_error_codes(error: BaseException, code: str) -> None:
    assert classify_capture_error(error) == code


# --- The Scapy-facing pieces, against a fake scapy module -------------------------------------


def interface(
    identity: str,
    *,
    name: str | None = None,
    description: str = "",
    ips: Any = None,
    ip: str | None = None,
    dummy: bool = False,
    invalid: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        network_name=identity,
        name=name if name is not None else identity,
        description=description,
        ips=ips if ips is not None else {},
        ip=ip,
        dummy=dummy,
        invalid=invalid,
    )


class FakeInterfaces(dict):
    """Scapy's ``conf.ifaces``: a mapping that can be reloaded from the system."""

    def __init__(self, items: Any = ()) -> None:
        super().__init__({(item.network_name or item.name): item for item in items})
        self.reads = 0
        self.reloads = 0
        self.appear_on_reload: list[SimpleNamespace] = []
        self.reload_error: Exception | None = None

    def values(self) -> Any:
        self.reads += 1
        return super().values()

    def reload(self) -> None:
        self.reloads += 1
        if self.reload_error is not None:
            raise self.reload_error
        for item in self.appear_on_reload:
            self[item.network_name or item.name] = item
        self.appear_on_reload = []


class FakeSniffer:
    """Just enough of ``AsyncSniffer``: a thread that reports in once its interface is open."""

    def __init__(self, options: dict[str, Any], *, opens: bool, fails_with: Exception | None):
        self.options = options
        self.fails_with = fails_with
        self.thread: threading.Thread | None = None
        self.running = False
        self.exception: Exception | None = None
        self.stop_requests = 0
        self.ignored_stops = 0
        self.stop_error: Exception | None = None
        self.opened = threading.Event()
        self.finished = threading.Event()
        if opens:
            self.opened.set()

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, name="test-fake-sniffer", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        self.running = True
        if self.fails_with is not None:
            self.exception = self.fails_with
            self.running = False
            return
        self.opened.wait(5)
        self.options["started_callback"]()
        self.finished.wait(5)
        self.running = False

    def stop(self, join: bool = True) -> None:
        self.stop_requests += 1
        if self.stop_error is not None:
            raise self.stop_error
        # Scapy ignores a request made before the interface is open.
        if not self.opened.is_set():
            self.ignored_stops += 1
            return
        self.finished.set()

    def release(self) -> None:
        self.opened.set()
        self.finished.set()
        if self.thread is not None:
            self.thread.join(2)


class SnifferFactory:
    """``scapy.AsyncSniffer``: records the options it was built with."""

    def __init__(self, *, opens: bool = True, fails_with: Exception | None = None) -> None:
        self.opens = opens
        self.fails_with = fails_with
        self.created: list[FakeSniffer] = []

    def __call__(self, **options: Any) -> FakeSniffer:
        sniffer = FakeSniffer(options, opens=self.opens, fails_with=self.fails_with)
        self.created.append(sniffer)
        return sniffer

    def release(self) -> None:
        for sniffer in self.created:
            sniffer.release()


@dataclass
class ScapyEnv:
    scapy: SimpleNamespace
    ifaces: FakeInterfaces
    sniffers: SnifferFactory


@pytest.fixture
def scapy_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[..., ScapyEnv]]:
    """Install a fake ``scapy`` module in the capture code."""
    built: list[SnifferFactory] = []

    def install(
        *interfaces: SimpleNamespace,
        platform: str = "linux",
        use_pcap: bool = True,
        sniffers: SnifferFactory | None = None,
    ) -> ScapyEnv:
        ifaces = FakeInterfaces(interfaces)
        factory = sniffers if sniffers is not None else SnifferFactory()
        built.append(factory)
        scapy = SimpleNamespace(
            conf=SimpleNamespace(ifaces=ifaces, use_pcap=use_pcap, use_npcap=True),
            AsyncSniffer=factory,
        )
        monkeypatch.setattr(capture_module, "load_scapy", lambda: scapy)
        monkeypatch.setattr(capture_module, "sys", SimpleNamespace(platform=platform))
        return ScapyEnv(scapy, ifaces, factory)

    yield install
    for factory in built:
        factory.release()


@pytest.mark.parametrize(
    ("platform", "use_pcap", "expected"),
    [
        ("win32", True, BackendInfo("npcap", True)),
        ("win32", False, BackendInfo("none", False)),
        ("linux", True, BackendInfo("libpcap", True)),
        ("linux", False, BackendInfo("native", True)),
        ("darwin", True, BackendInfo("libpcap", True)),
    ],
)
def test_the_backend_is_named_after_the_driver_scapy_uses(
    scapy_env: Callable[..., ScapyEnv], platform: str, use_pcap: bool, expected: BackendInfo
) -> None:
    scapy_env(platform=platform, use_pcap=use_pcap)

    assert probe_backend() == expected


def test_an_older_windows_driver_is_reported_as_winpcap(
    scapy_env: Callable[..., ScapyEnv],
) -> None:
    env = scapy_env(platform="win32", use_pcap=True)
    env.scapy.conf.use_npcap = False

    assert probe_backend() == BackendInfo("winpcap", True)


def test_a_missing_scapy_means_no_capture_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing() -> Any:
        raise CaptureLibraryMissingError("Scapy is not installed.")

    monkeypatch.setattr(capture_module, "load_scapy", missing)

    assert probe_backend() == BackendInfo("none", False)
    catalog = InterfaceCatalog()
    assert catalog.backend() == BackendInfo("none", False)
    assert catalog.interfaces() == []
    assert catalog.interfaces(refresh=True) == []
    assert catalog.resolve("anything") is None


def test_a_catalog_without_a_backend_never_reads_interfaces(
    scapy_env: Callable[..., ScapyEnv],
) -> None:
    env = scapy_env(interface("eth0"), platform="win32", use_pcap=False)
    catalog = InterfaceCatalog()

    assert catalog.backend().available is False
    assert catalog.interfaces() == []
    assert catalog.resolve("eth0") is None
    assert (env.ifaces.reads, env.ifaces.reloads) == (0, 0)


def test_the_backend_is_probed_once(
    scapy_env: Callable[..., ScapyEnv], monkeypatch: pytest.MonkeyPatch
) -> None:
    scapy_env(interface("eth0"))
    probes: list[int] = []
    real_probe = capture_module.probe_backend
    monkeypatch.setattr(capture_module, "probe_backend", lambda: probes.append(1) or real_probe())
    catalog = InterfaceCatalog()

    for _ in range(3):
        catalog.backend()
        catalog.interfaces()

    assert probes == [1]


def test_interfaces_with_addresses_come_first_then_by_name(
    scapy_env: Callable[..., ScapyEnv],
) -> None:
    scapy_env(
        interface("zeta", ips={4: ["192.0.2.3"]}),
        interface("Beta"),
        interface("alpha", ips={4: ["192.0.2.1"]}),
        interface("Gamma"),
    )

    found = InterfaceCatalog().interfaces()

    assert [info.id for info in found] == ["alpha", "zeta", "Beta", "Gamma"]


def test_the_network_name_is_the_id_and_the_friendly_name_is_shown(
    scapy_env: Callable[..., ScapyEnv],
) -> None:
    scapy_env(
        interface(
            "NPF_{TEST-GUID}",
            name="Test Wi-Fi",
            description="Synthetic wireless adapter",
            ips={4: ["192.0.2.9"]},
        ),
        SimpleNamespace(
            network_name="",
            name="eth9",
            description=None,
            ips=None,
            ip=None,
            dummy=False,
            invalid=False,
        ),
    )

    wifi, wired = InterfaceCatalog().interfaces()

    assert (wifi.id, wifi.name, wifi.description) == (
        "NPF_{TEST-GUID}",
        "Test Wi-Fi",
        "Synthetic wireless adapter",
    )
    assert wifi.addresses == ("192.0.2.9",)
    assert (wired.id, wired.name, wired.description, wired.addresses) == ("eth9", "eth9", "", ())


def test_dummy_invalid_nameless_and_repeated_interfaces_are_left_out(
    scapy_env: Callable[..., ScapyEnv],
) -> None:
    env = scapy_env(
        interface("real"),
        interface("dummy0", dummy=True),
        interface("broken0", invalid=True),
    )
    env.ifaces["nameless"] = SimpleNamespace(network_name="", name="", ips={}, ip=None)
    env.ifaces["alias"] = interface("real", name="same id, another entry")

    found = InterfaceCatalog().interfaces()

    assert [info.id for info in found] == ["real"]
    assert found[0].name == "real"


def test_addresses_are_cleaned_up_and_limited(scapy_env: Callable[..., ScapyEnv]) -> None:
    scapy_env(
        interface(
            "messy",
            ips={
                4: ["192.0.2.1", "192.0.2.1", "0.0.0.0", "not an address"],  # noqa: S104
                6: ("2001:db8::1", "::", "2001:db8::2"),
                0: "198.51.100.1",
            },
            ip="198.51.100.2",
        ),
        interface("sets", ips={4: {"203.0.113.1"}}),
        interface("none-of-them", ips={4: ["bogus"]}, ip="also bogus"),
    )

    by_id = {info.id: info for info in InterfaceCatalog().interfaces()}

    assert by_id["messy"].addresses == ("192.0.2.1", "2001:db8::1", "2001:db8::2", "198.51.100.1")
    assert by_id["sets"].addresses == ("203.0.113.1",)
    assert by_id["none-of-them"].addresses == ()


def test_overlong_names_are_cut_to_the_documented_sizes(
    scapy_env: Callable[..., ScapyEnv],
) -> None:
    scapy_env(interface("i" * 400, name="n" * 400, description="d" * 400))

    (info,) = InterfaceCatalog().interfaces()

    assert (len(info.id), len(info.name), len(info.description)) == (256, 128, 256)


def test_interfaces_are_kept_until_the_ttl_has_passed(scapy_env: Callable[..., ScapyEnv]) -> None:
    env = scapy_env(interface("eth0"))
    clock = FakeClock(100.0)
    catalog = InterfaceCatalog(ttl=30.0, clock=clock)

    catalog.interfaces()
    clock.advance(30.0)
    catalog.interfaces()
    assert env.ifaces.reads == 1

    clock.advance(0.5)
    catalog.interfaces()
    assert env.ifaces.reads == 2
    # An ordinary expiry rereads what Scapy already knows; only a refresh asks the system again.
    assert env.ifaces.reloads == 0


def test_a_refresh_asks_the_system_again_and_sees_new_interfaces(
    scapy_env: Callable[..., ScapyEnv],
) -> None:
    env = scapy_env(interface("eth0"))
    catalog = InterfaceCatalog(clock=FakeClock())
    assert [info.id for info in catalog.interfaces()] == ["eth0"]
    env.ifaces.appear_on_reload = [interface("usb0")]

    assert [info.id for info in catalog.interfaces()] == ["eth0"]
    assert sorted(info.id for info in catalog.interfaces(refresh=True)) == ["eth0", "usb0"]
    assert env.ifaces.reloads == 1


def test_a_failed_reload_keeps_the_interfaces_that_are_known(
    scapy_env: Callable[..., ScapyEnv], caplog: pytest.LogCaptureFixture
) -> None:
    env = scapy_env(interface("eth0"))
    env.ifaces.reload_error = RuntimeError("secret reload detail")
    catalog = InterfaceCatalog(clock=FakeClock())

    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        found = catalog.interfaces(refresh=True)

    assert [info.id for info in found] == ["eth0"]
    [record] = [r for r in caplog.records if r.getMessage() == "interface_reload_failed"]
    assert record.__dict__["error"] == "RuntimeError"
    assert "secret reload detail" not in caplog.text


def test_the_returned_list_cannot_change_the_catalog(scapy_env: Callable[..., ScapyEnv]) -> None:
    scapy_env(interface("eth0"))
    catalog = InterfaceCatalog(clock=FakeClock())

    catalog.interfaces().clear()

    assert [info.id for info in catalog.interfaces()] == ["eth0"]


def test_resolve_finds_an_interface_without_asking_the_system(
    scapy_env: Callable[..., ScapyEnv],
) -> None:
    env = scapy_env(interface("eth0", ips={4: ["192.0.2.1"]}), interface("eth1"))
    catalog = InterfaceCatalog(clock=FakeClock())

    info = catalog.resolve("eth1")

    assert info is not None and info.id == "eth1"
    assert env.ifaces.reloads == 0


def test_resolve_refreshes_once_before_giving_up_on_an_unknown_id(
    scapy_env: Callable[..., ScapyEnv],
) -> None:
    env = scapy_env(interface("eth0"))
    catalog = InterfaceCatalog(clock=FakeClock())

    assert catalog.resolve("no-such-interface") is None
    assert env.ifaces.reloads == 1

    env.ifaces.appear_on_reload = [interface("usb0")]
    found = catalog.resolve("usb0")
    assert found is not None and found.id == "usb0"
    assert env.ifaces.reloads == 2


@pytest.mark.parametrize("wanted", ["", " eth0", "ETH0", "eth0 ", "eth0\x00", "eth"])
def test_resolve_matches_the_id_exactly(scapy_env: Callable[..., ScapyEnv], wanted: str) -> None:
    scapy_env(interface("eth0"))

    assert InterfaceCatalog(clock=FakeClock()).resolve(wanted) is None


def test_concurrent_callers_load_the_interfaces_once(scapy_env: Callable[..., ScapyEnv]) -> None:
    env = scapy_env(interface("eth0"))
    catalog = InterfaceCatalog(clock=FakeClock())
    barrier = threading.Barrier(8)
    results: list[int] = []

    def ask() -> None:
        barrier.wait(5)
        results.append(len(catalog.interfaces()))

    threads = [threading.Thread(target=ask, name="test-catalog-caller") for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)

    assert results == [1] * 8
    assert env.ifaces.reads == 1


# --- The Scapy source ------------------------------------------------------------------------


def test_the_source_sniffs_the_interface_it_was_asked_for(
    scapy_env: Callable[..., ScapyEnv],
) -> None:
    wanted = interface("eth1", ips={4: ["192.0.2.1"]})
    env = scapy_env(interface("eth0"), wanted)
    source = ScapyLiveSource("eth1")
    received: list[Any] = []

    source.start(received.append)

    assert source.wait_started(5) is True
    (sniffer,) = env.sniffers.created
    options = sniffer.options
    assert options["iface"] is wanted
    # Packets are passed on, not stored, and only traffic to or from this machine is captured.
    assert (options["store"], options["promisc"]) == (False, False)
    options["prn"]("a packet")
    assert received == ["a packet"]
    assert source.alive is True
    assert source.error is None

    source.stop()

    assert source.alive is False
    assert sniffer.finished.is_set()


def test_an_unknown_interface_is_unavailable_and_nothing_is_started(
    scapy_env: Callable[..., ScapyEnv],
) -> None:
    env = scapy_env(interface("eth0"))
    source = ScapyLiveSource("gone0")

    with pytest.raises(CaptureFailure) as raised:
        source.start(lambda raw: None)

    assert raised.value.code == "interface_unavailable"
    assert env.sniffers.created == []
    assert source.alive is False
    source.stop()


def test_a_source_that_never_started_can_be_stopped_and_has_nothing_to_report() -> None:
    source = ScapyLiveSource("eth0")

    assert (source.alive, source.error) == (False, None)
    source.stop()
    assert source.wait_started(0) is False


def test_a_sniffer_that_dies_while_opening_reports_its_error(
    scapy_env: Callable[..., ScapyEnv],
) -> None:
    refusal = PermissionError(1, "Operation not permitted")
    env = scapy_env(interface("eth0"), sniffers=SnifferFactory(fails_with=refusal))
    source = ScapyLiveSource("eth0")

    source.start(lambda raw: None)

    assert source.wait_started(5) is False
    assert source.error is refusal
    assert source.alive is False
    assert len(env.sniffers.created) == 1


def test_wait_started_gives_up_after_the_timeout_while_the_interface_is_still_opening(
    scapy_env: Callable[..., ScapyEnv],
) -> None:
    scapy_env(interface("eth0"), sniffers=SnifferFactory(opens=False))
    source = ScapyLiveSource("eth0")
    source.start(lambda raw: None)

    began = time.monotonic()
    assert source.wait_started(0.1) is False

    assert 0.05 <= time.monotonic() - began < 2
    assert source.alive is True


def test_a_stop_request_made_while_the_interface_opens_is_repeated(
    scapy_env: Callable[..., ScapyEnv],
) -> None:
    env = scapy_env(interface("eth0"), sniffers=SnifferFactory(opens=False))
    source = ScapyLiveSource("eth0")
    source.start(lambda raw: None)
    (sniffer,) = env.sniffers.created
    wait_until(lambda: sniffer.running, what="the sniffer thread to run")
    stopper = threading.Thread(target=source.stop, name="test-stopper")

    stopper.start()
    wait_until(lambda: sniffer.ignored_stops >= 1, what="the first stop request to be ignored")
    sniffer.opened.set()
    stopper.join(5)

    assert not stopper.is_alive()
    assert source.alive is False
    assert sniffer.stop_requests >= 2


def test_stopping_gives_up_on_a_sniffer_thread_that_will_not_end(
    scapy_env: Callable[..., ScapyEnv],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    env = scapy_env(interface("eth0"))
    source = ScapyLiveSource("eth0")
    source.start(lambda raw: None)
    assert source.wait_started(5)
    (sniffer,) = env.sniffers.created
    sniffer.stop_error = RuntimeError("secret sniffer detail")
    monkeypatch.setattr(capture_module, "STOP_TIMEOUT_SECONDS", 0.3)

    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        began = time.monotonic()
        source.stop()

    assert time.monotonic() - began < 3
    assert source.alive is True
    messages = [record.getMessage() for record in caplog.records]
    assert "sniffer_thread_did_not_stop" in messages
    assert "secret sniffer detail" not in caplog.text


def test_a_handler_may_stop_the_source_from_the_sniffer_thread(
    scapy_env: Callable[..., ScapyEnv],
) -> None:
    env = scapy_env(interface("eth0"))
    source = ScapyLiveSource("eth0")
    stopped = threading.Event()

    def handler(raw: Any) -> None:
        source.stop()  # would wait for its own thread forever without the guard
        stopped.set()

    source.start(handler)
    assert source.wait_started(5)
    (sniffer,) = env.sniffers.created
    caller = threading.Thread(
        target=lambda: sniffer.options["prn"]("a packet"), name="test-handler-thread"
    )
    caller.start()
    caller.join(5)

    assert stopped.is_set()
    assert not caller.is_alive()


# --- A capture, with a source driven by the test ---------------------------------------------


def packets(count: int, *, start: int = 0) -> list[Any]:
    return [packet(T0 + start + n, dport=1000 + start + n) for n in range(count)]


def test_a_started_capture_runs_until_it_is_stopped(make_run: Callable[..., Run]) -> None:
    run = make_run()
    capture = run.capture

    assert (capture.state, capture.active, capture.error_code) == (
        CaptureStatus.RUNNING,
        True,
        None,
    )
    assert run.source.handler == capture._on_packet
    sent = packets(5)
    run.source.emit(*sent)
    wait_until(lambda: len(run.monitor.processed) == 5, what="the packets to be processed")

    assert capture.stop(timeout=5) is True

    assert run.monitor.processed == sent
    assert (capture.state, capture.active) == (CaptureStatus.STOPPED, False)
    assert run.monitor.statuses == [CaptureStatus.RUNNING, CaptureStatus.STOPPING]
    assert finished_without_error(run)
    assert run.source.stop_calls >= 1
    assert capture._thread.is_alive() is False


def test_packets_are_analysed_in_order_in_bounded_batches(make_run: Callable[..., Run]) -> None:
    gate = threading.Event()
    run = make_run(monitor=RecordingMonitor(gate=gate))
    sent = packets(600)
    run.source.emit(sent[0])
    assert run.monitor.entered.wait(5)
    # The consumer is busy with the first packet, so the rest queue up behind it.
    run.source.emit(*sent[1:])

    gate.set()
    assert run.capture.stop(timeout=5) is True

    assert [len(batch) for batch in run.monitor.batches] == [1, 256, 256, 87]
    assert run.monitor.processed == sent
    assert run.monitor.dropped == 0


def test_a_full_queue_drops_packets_and_counts_them(make_run: Callable[..., Run]) -> None:
    gate = threading.Event()
    run = make_run(monitor=RecordingMonitor(gate=gate), buffer_size=3)
    sent = packets(10)
    run.source.emit(sent[0])
    assert run.monitor.entered.wait(5)

    began = time.monotonic()
    run.source.emit(*sent[1:])
    # The thread of the capture library is never made to wait for the consumer.
    assert time.monotonic() - began < 2
    assert run.monitor.dropped == 6

    gate.set()
    assert run.capture.stop(timeout=5) is True

    assert run.monitor.processed == sent[:4]
    assert finished_without_error(run)


def test_packets_that_cannot_be_used_are_counted_and_never_queued(
    make_run: Callable[..., Run],
) -> None:
    run = make_run()
    good = packets(2)

    run.source.emit(good[0], NON_IP, UNREADABLE, NON_IP, good[1], UNREADABLE, UNREADABLE)
    assert run.capture.stop(timeout=5) is True

    assert run.monitor.processed == good
    assert (run.monitor.non_ip, run.monitor.malformed, run.monitor.dropped) == (2, 3, 0)


def test_real_frames_are_reduced_to_metadata_before_they_are_queued(
    make_run: Callable[..., Run], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(capture_module, "extract_packet", real_extract_packet)
    run = make_run()

    run.source.emit(*scan_traffic(ports=3), scapy_arp(T0), object())
    assert run.capture.stop(timeout=5) is True

    assert [(p.src_ip, p.dst_ip, p.protocol) for p in run.monitor.processed] == [
        ("45.33.32.156", "10.0.0.9", "tcp"),
        ("45.33.32.156", "10.0.0.9", "tcp"),
        ("45.33.32.156", "10.0.0.9", "tcp"),
        ("10.0.0.5", "8.8.8.8", "udp"),
        ("10.0.0.5", "192.0.2.77", "tcp"),
        ("10.0.0.5", "10.0.0.9", "tcp"),
    ]
    assert (run.monitor.non_ip, run.monitor.malformed) == (2, 1)
    # Only metadata reaches the analysis: no payload, no Scapy object.
    assert all(type(item).__name__ == "PacketMeta" for item in run.monitor.processed)


def test_stopping_waits_for_every_queued_packet_to_be_analysed(
    make_run: Callable[..., Run],
) -> None:
    gate = threading.Event()
    run = make_run(monitor=RecordingMonitor(gate=gate))
    sent = packets(40)
    run.source.emit(sent[0])
    assert run.monitor.entered.wait(5)
    run.source.emit(*sent[1:])

    assert run.capture.stop(timeout=0.1) is False
    assert run.capture.state is CaptureStatus.STOPPING
    assert run.capture.active is True
    gate.set()
    wait_until(lambda: not run.capture.active, what="the capture to finish")

    assert run.capture.stop(timeout=5) is True
    assert run.monitor.processed == sent
    assert run.capture.state is CaptureStatus.STOPPED
    assert run.monitor.finished == [(CaptureStatus.STOPPED, None)]


def test_stopping_twice_is_harmless(make_run: Callable[..., Run]) -> None:
    run = make_run()

    assert run.capture.stop(timeout=5) is True
    assert run.capture.stop(timeout=5) is True

    assert run.monitor.finished == [(CaptureStatus.STOPPED, None)]
    assert run.monitor.statuses == [CaptureStatus.RUNNING, CaptureStatus.STOPPING]
    assert run.capture.state is CaptureStatus.STOPPED


def test_starting_twice_is_refused_and_leaves_the_capture_alone(
    make_run: Callable[..., Run],
) -> None:
    run = make_run()

    with pytest.raises(RuntimeError):
        run.capture.start()

    assert run.source.start_calls == 1
    assert run.capture.state is CaptureStatus.RUNNING
    assert run.capture.stop(timeout=5) is True


def test_a_capture_that_was_never_started_can_be_stopped(make_run: Callable[..., Run]) -> None:
    run = make_run(start=False)

    assert run.capture.stop(timeout=1) is True
    assert run.source.stop_calls == 1


# --- Starting ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (
            PermissionError(1, "Operation not permitted"),
            CaptureStatus.PERMISSION_DENIED,
            "capture_permission_denied",
        ),
        (
            RuntimeError("Access is denied"),
            CaptureStatus.PERMISSION_DENIED,
            "capture_permission_denied",
        ),
        (
            CaptureLibraryMissingError("Scapy is not installed."),
            CaptureStatus.FAILED,
            "capture_backend_missing",
        ),
        (CaptureFailure("interface_unavailable"), CaptureStatus.FAILED, "interface_unavailable"),
        (OSError("No such device"), CaptureStatus.FAILED, "interface_unavailable"),
        (RuntimeError("boom"), CaptureStatus.FAILED, "capture_failed"),
    ],
)
def test_a_source_that_fails_to_start_ends_the_session_with_the_matching_code(
    make_run: Callable[..., Run], error: Exception, status: CaptureStatus, code: str
) -> None:
    run = make_run(FakeSource(start_error=error), start=False)

    with pytest.raises(CaptureFailure) as raised:
        run.capture.start()

    assert raised.value.code == code
    assert run.monitor.finished == [(status, code)]
    assert (run.capture.state, run.capture.error_code, run.capture.active) == (status, code, False)
    assert run.monitor.statuses == []
    assert run.source.stop_calls >= 1


def test_a_source_that_dies_before_it_reports_in_fails_the_start(
    make_run: Callable[..., Run],
) -> None:
    class Stillborn(FakeSource):
        def start(self, handler: Callable[[Any], None]) -> None:
            super().start(handler)
            self.die(PermissionError(1, "Operation not permitted"))

    run = make_run(Stillborn(autostart=False), start_timeout=0.05, start=False)

    with pytest.raises(CaptureFailure) as raised:
        run.capture.start()

    assert raised.value.code == "capture_permission_denied"
    assert run.monitor.finished == [(CaptureStatus.PERMISSION_DENIED, "capture_permission_denied")]


def test_a_source_that_dies_silently_before_it_reports_in_is_a_plain_failure(
    make_run: Callable[..., Run],
) -> None:
    class Stillborn(FakeSource):
        def start(self, handler: Callable[[Any], None]) -> None:
            super().start(handler)
            self.die()

    run = make_run(Stillborn(autostart=False), start_timeout=0.05, start=False)

    with pytest.raises(CaptureFailure) as raised:
        run.capture.start()

    assert raised.value.code == "capture_failed"
    assert run.monitor.finished == [(CaptureStatus.FAILED, "capture_failed")]


def test_start_returns_while_the_interface_is_still_opening(make_run: Callable[..., Run]) -> None:
    source = FakeSource(autostart=False)
    run = make_run(source, start_timeout=0.05)

    # The sniffer is alive but has not reported in: the capture is still starting, not failed.
    assert run.capture.state is CaptureStatus.STARTING
    assert run.capture.active is True
    assert run.monitor.statuses == []

    source.become_ready()
    wait_until(lambda: run.capture.state is CaptureStatus.RUNNING, what="the capture to run")

    assert run.monitor.statuses == [CaptureStatus.RUNNING]
    assert run.capture.stop(timeout=5) is True


def test_a_sniffer_that_never_reports_in_can_still_be_stopped(make_run: Callable[..., Run]) -> None:
    run = make_run(FakeSource(autostart=False), start_timeout=0.05)

    assert run.capture.stop(timeout=5) is True

    assert run.monitor.statuses == [CaptureStatus.STOPPING]
    assert run.monitor.finished == [(CaptureStatus.STOPPED, None)]


def test_a_sniffer_that_dies_while_the_interface_is_opening_fails_the_session(
    make_run: Callable[..., Run],
) -> None:
    source = FakeSource(autostart=False)
    run = make_run(source, start_timeout=0.05)
    assert run.capture.state is CaptureStatus.STARTING

    source.die(PermissionError(1, "Operation not permitted"))
    wait_until(lambda: not run.capture.active, what="the capture to finish")

    assert run.capture.state is CaptureStatus.PERMISSION_DENIED
    assert run.capture.error_code == "capture_permission_denied"
    assert run.monitor.finished == [(CaptureStatus.PERMISSION_DENIED, "capture_permission_denied")]


def test_a_slow_start_is_not_mistaken_for_a_dead_source(make_run: Callable[..., Run]) -> None:
    monitor = RecordingMonitor()

    def slow_start(_source: FakeSource) -> None:
        # The consumer thread is already polling the source while start() is still opening it.
        deadline = time.monotonic() + 1.0
        while monitor.ticks < 3 and time.monotonic() < deadline:
            time.sleep(0.005)

    run = make_run(FakeSource(start_hook=slow_start), monitor)

    assert run.capture.error_code is None
    assert run.capture.state is CaptureStatus.RUNNING
    assert run.monitor.finished == []
    assert run.capture.stop(timeout=5) is True
    assert finished_without_error(run)


# --- A capture that goes wrong while it runs --------------------------------------------------


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (None, CaptureStatus.FAILED, "capture_failed"),
        (OSError("The network is down"), CaptureStatus.FAILED, "interface_unavailable"),
        (RuntimeError("boom"), CaptureStatus.FAILED, "capture_failed"),
        (
            PermissionError(1, "Operation not permitted"),
            CaptureStatus.PERMISSION_DENIED,
            "capture_permission_denied",
        ),
    ],
)
def test_a_source_that_dies_mid_capture_fails_the_session_and_keeps_what_it_saw(
    make_run: Callable[..., Run], error: Exception | None, status: CaptureStatus, code: str
) -> None:
    run = make_run()
    sent = packets(3)
    run.source.emit(*sent)
    wait_until(lambda: len(run.monitor.processed) == 3, what="the packets to be processed")

    run.source.die(error)
    wait_until(lambda: not run.capture.active, what="the capture to finish")

    assert run.monitor.processed == sent
    assert run.monitor.finished == [(status, code)]
    assert (run.capture.state, run.capture.error_code) == (status, code)
    assert run.source.stop_calls >= 1
    # Stopping afterwards changes nothing.
    assert run.capture.stop(timeout=5) is True
    assert run.monitor.finished == [(status, code)]


def test_packets_still_queued_when_the_source_dies_are_analysed(
    make_run: Callable[..., Run],
) -> None:
    gate = threading.Event()
    run = make_run(monitor=RecordingMonitor(gate=gate))
    sent = packets(6)
    run.source.emit(sent[0])
    assert run.monitor.entered.wait(5)
    run.source.emit(*sent[1:])

    run.source.die(OSError("The network is down"))
    gate.set()
    wait_until(lambda: not run.capture.active, what="the capture to finish")

    assert run.monitor.processed == sent
    assert run.monitor.finished == [(CaptureStatus.FAILED, "interface_unavailable")]


def test_a_session_deleted_during_the_capture_ends_the_capture(
    make_run: Callable[..., Run],
) -> None:
    run = make_run()

    run.monitor.gone = True
    wait_until(lambda: not run.capture.active, what="the capture to end")

    assert run.source.stop_calls >= 1
    assert run.capture.state is CaptureStatus.STOPPED
    assert run.capture.error_code is None


def test_a_crash_in_the_analysis_ends_the_session_cleanly(
    make_run: Callable[..., Run], caplog: pytest.LogCaptureFixture
) -> None:
    class Exploding(RecordingMonitor):
        def process_batch(self, packets: Any) -> None:
            raise RuntimeError("secret analysis detail")

    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        run = make_run(monitor=Exploding())
        run.source.emit(*packets(2))
        wait_until(lambda: not run.capture.active, what="the capture to end")

    assert run.monitor.finished == [(CaptureStatus.FAILED, "capture_failed")]
    assert run.capture.state is CaptureStatus.FAILED
    assert run.source.stop_calls >= 1
    [record] = [r for r in caplog.records if r.getMessage() == "capture_consumer_failed"]
    assert record.__dict__["error"] == "RuntimeError"
    assert "secret analysis detail" not in caplog.text


def test_a_failure_to_store_the_final_results_does_not_hang_the_stop(
    make_run: Callable[..., Run], caplog: pytest.LogCaptureFixture
) -> None:
    monitor = RecordingMonitor()
    monitor.finish_error = RuntimeError("secret finish detail")
    run = make_run(monitor=monitor)

    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        assert run.capture.stop(timeout=5) is True

    assert run.capture.active is False
    assert "capture_finish_failed" in [record.getMessage() for record in caplog.records]
    assert "secret finish detail" not in caplog.text


def test_a_source_that_fails_to_stop_does_not_lose_the_results(
    make_run: Callable[..., Run], caplog: pytest.LogCaptureFixture
) -> None:
    run = make_run(FakeSource(stop_error=RuntimeError("secret stop detail")))
    run.source.emit(*packets(3))

    with caplog.at_level(logging.DEBUG, logger="cipherforge.network"):
        stopped = run.capture.stop(timeout=5)

    assert stopped is True
    assert run.monitor.processed == packets(3)
    assert finished_without_error(run)
    assert "secret stop detail" not in caplog.text


# --- A real session, the real source and a fake scapy -----------------------------------------


@pytest.fixture
def factory(make_settings: Callable[..., Settings], db_url: str) -> Iterator[Any]:
    engine = build_engine(make_settings(database_url=db_url))
    yield build_session_factory(engine)
    engine.dispose()


def test_a_capture_over_the_real_monitor_records_its_session(
    make_run: Callable[..., Run],
    factory: Any,
    make_settings: Callable[..., Settings],
    db_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(capture_module, "extract_packet", real_extract_packet)
    rig = build_rig(factory, make_settings(database_url=db_url))
    run = make_run(monitor=rig.monitor, buffer_size=1000)

    run.source.emit(*scan_traffic())
    assert run.capture.stop(timeout=10) is True

    row = rig.row()
    assert row.status == "stopped"
    assert row.error_code is None
    assert row.ended_at is not None and row.ended_at >= row.started_at
    assert (row.packets_total, row.flows_total, row.alerts_total) == (
        SCAN_FRAMES - 1,
        SCAN_FLOWS,
        1,
    )
    assert row.stats["non_ip_packets"] == 1
    assert row.packets_dropped == 0
    assert [(alert.rule_id, alert.src_ip) for alert in rig.alerts()] == [
        ("NET-001", "45.33.32.156")
    ]


def test_a_refused_capture_leaves_a_permission_denied_session(
    make_run: Callable[..., Run], factory: Any, make_settings: Callable[..., Settings], db_url: str
) -> None:
    rig = build_rig(factory, make_settings(database_url=db_url))
    refusal = PermissionError(1, "Operation not permitted")
    run = make_run(FakeSource(start_error=refusal), rig.monitor, start=False)

    with pytest.raises(CaptureFailure) as raised:
        run.capture.start()

    assert raised.value.code == "capture_permission_denied"
    row = rig.row()
    assert (row.status, row.error_code) == ("permission_denied", "capture_permission_denied")
    assert row.ended_at is not None and row.ended_at >= row.started_at


def test_the_scapy_source_and_the_capture_work_together(
    make_run: Callable[..., Run], scapy_env: Callable[..., ScapyEnv]
) -> None:
    env = scapy_env(interface("eth0", ips={4: ["192.0.2.1"]}))
    run = make_run(source=ScapyLiveSource("eth0"))
    (sniffer,) = env.sniffers.created
    sent = packets(4)

    for item in sent:
        sniffer.options["prn"](item)
    wait_until(lambda: len(run.monitor.processed) == 4, what="the packets to be processed")

    assert run.capture.state is CaptureStatus.RUNNING
    assert run.capture.stop(timeout=5) is True
    assert run.monitor.processed == sent
    assert sniffer.finished.is_set()
    assert finished_without_error(run)


def test_a_refusal_from_the_scapy_source_is_reported_as_permission_denied(
    make_run: Callable[..., Run], scapy_env: Callable[..., ScapyEnv]
) -> None:
    refusal = PermissionError(1, "Operation not permitted")
    scapy_env(interface("eth0"), sniffers=SnifferFactory(fails_with=refusal))
    run = make_run(source=ScapyLiveSource("eth0"), start=False)

    with pytest.raises(CaptureFailure) as raised:
        run.capture.start()

    assert raised.value.code == "capture_permission_denied"
    assert run.monitor.finished == [(CaptureStatus.PERMISSION_DENIED, "capture_permission_denied")]


def test_an_interface_that_vanished_fails_the_start_through_the_scapy_source(
    make_run: Callable[..., Run], scapy_env: Callable[..., ScapyEnv]
) -> None:
    scapy_env(interface("eth0"))
    run = make_run(source=ScapyLiveSource("gone0"), start=False)

    with pytest.raises(CaptureFailure) as raised:
        run.capture.start()

    assert raised.value.code == "interface_unavailable"
    assert run.monitor.finished == [(CaptureStatus.FAILED, "interface_unavailable")]
