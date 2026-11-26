"""Synthetic network traffic for the demo server, the browser tests and the sample capture.

Nothing here is a capture of a real network. Every address is private, reserved for documentation
or one invented "attacker": an IPv6 address from space IANA has not allocated, taken from the demo
catalogue, which the simulated providers rate as critical. ``devtools`` is not part of the
container image, so none of this can run in production.

One scenario feeds every consumer:

* ``write_sample_capture`` writes the capture file the browser tests upload
  (``python -m devtools.synthetic_network`` regenerates the committed copy);
* ``SimulatedCatalog`` and ``SimulatedSource`` let the demo server run a "live" capture that is
  labelled as simulated everywhere it is shown;
* the tests read the frames directly.
"""

import itertools
import sys
import threading
import time
from collections.abc import Callable, Iterator
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.models.enums import IndicatorType
from app.network.capture import BackendInfo, InterfaceCatalog, InterfaceInfo
from app.network.scapy_support import load_scapy
from devtools.demo_data import build_catalogue
from devtools.simulated_providers import Tier

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_PATH = REPO_ROOT / "frontend" / "e2e" / "data" / "synthetic-network.pcap"
# 2025-06-11 10:30:00 UTC, 16:00:00 IST: a fixed start keeps the sample byte-for-byte repeatable.
SAMPLE_START = 1_749_637_800.0

LAN_HOST = "10.20.30.40"
LAN_PEER = "10.20.30.50"
LAN_SERVER_V6 = "fd00:cf::10"
PUBLIC_RESOLVER = "8.8.8.8"
PUBLIC_ECHO_TARGET = "1.1.1.1"
DOCUMENTATION_SCANNER = "203.0.113.77"

ATTACKER_SCAN_PORTS = 30
DOCUMENTATION_SCAN_PORTS = 22
ATTACKER_FIRST_PORT = 2000
DOCUMENTATION_FIRST_PORT = 3000
DNS_EXCHANGES = 5

# Locally administered MAC addresses: they belong to no manufacturer.
_MAC_CLIENT = "02:00:00:00:00:01"
_MAC_GATEWAY = "02:00:00:00:00:02"

LAN_INTERFACE = InterfaceInfo(
    id="simulated-lan",
    name="Simulated office LAN",
    description=(
        "Synthetic traffic made up by the demo server. Nothing is captured from this machine."
    ),
    addresses=(LAN_HOST,),
)
QUIET_INTERFACE = InterfaceInfo(
    id="simulated-quiet",
    name="Simulated quiet link",
    description="Synthetic link with almost no traffic. Nothing is captured from this machine.",
    addresses=("10.20.40.2",),
)
SIMULATED_BACKEND = "simulated"
_TRICKLE_SECONDS = {LAN_INTERFACE.id: 2.0, QUIET_INTERFACE.id: 4.0}


@lru_cache(maxsize=1)
def attacker_address() -> str:
    """The invented public attacker: the first IPv6 address the demo catalogue rates critical."""
    for entry in build_catalogue():
        if entry.indicator_type is IndicatorType.IPV6 and entry.tier is Tier.CRITICAL:
            return entry.value
    raise LookupError("the demo catalogue has no critical IPv6 address")


# --- Frames ---------------------------------------------------------------------------------


def _ip(src: str, dst: str) -> Any:
    scapy = load_scapy()
    return scapy.IPv6(src=src, dst=dst) if ":" in src else scapy.IP(src=src, dst=dst)


def _frame(src: str, dst: str, transport: Any, at: float) -> Any:
    scapy = load_scapy()
    built = scapy.Ether(src=_MAC_CLIENT, dst=_MAC_GATEWAY) / _ip(src, dst) / transport
    built.time = at
    return built


def _tcp(src: str, dst: str, sport: int, dport: int, flags: str, at: float) -> Any:
    return _frame(src, dst, load_scapy().TCP(sport=sport, dport=dport, flags=flags), at)


def _udp(src: str, dst: str, sport: int, dport: int, size: int, at: float) -> Any:
    # The payload is filler: the monitor never reads past the headers.
    return _frame(src, dst, load_scapy().UDP(sport=sport, dport=dport) / (b"\x00" * size), at)


def _icmp(src: str, dst: str, kind: str, at: float) -> Any:
    scapy = load_scapy()
    return _frame(src, dst, scapy.ICMP(type=kind, id=7, seq=1), at)


def _arp(at: float) -> Any:
    scapy = load_scapy()
    built = scapy.Ether(src=_MAC_CLIENT, dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(
        psrc=LAN_HOST, pdst=LAN_PEER
    )
    built.time = at
    return built


def dns_exchange(number: int, at: float) -> list[Any]:
    """A DNS question from the LAN host to the public resolver, and the answer."""
    port = 40000 + number
    return [
        _udp(LAN_HOST, PUBLIC_RESOLVER, port, 53, 29, at),
        _udp(PUBLIC_RESOLVER, LAN_HOST, 53, port, 45, at + 0.04),
    ]


def scenario(start: float = SAMPLE_START) -> list[Any]:
    """Every frame of the sample, in time order, stamped relative to ``start``.

    * An invented public attacker (IPv6) probes ``ATTACKER_SCAN_PORTS`` ports of a private server:
      one port scan alert, and an address the demo providers know as malicious.
    * A documentation-range IPv4 address probes ``DOCUMENTATION_SCAN_PORTS`` ports of the LAN
      host: a second scan alert for an address that is never looked up, being no public host.
    * The LAN host asks a public resolver five DNS questions and pings a second public address:
      ordinary traffic to addresses the providers know as clean.
    * The LAN host and its private neighbour hold a short TCP conversation, and one ARP frame
      is not IP traffic at all. Neither private address may ever reach a provider.
    """
    attacker = attacker_address()
    frames: list[Any] = []

    for number in range(DNS_EXCHANGES):
        frames.extend(dns_exchange(number, start + 0.05 + number))

    for at, src, dst, sport, dport, flags in (
        (0.50, LAN_HOST, LAN_PEER, 50000, 8080, "S"),
        (0.52, LAN_PEER, LAN_HOST, 8080, 50000, "SA"),
        (0.54, LAN_HOST, LAN_PEER, 50000, 8080, "A"),
        (0.60, LAN_HOST, LAN_PEER, 50000, 8080, "PA"),
        (0.62, LAN_PEER, LAN_HOST, 8080, 50000, "A"),
        (0.70, LAN_PEER, LAN_HOST, 8080, 50000, "PA"),
        (0.90, LAN_HOST, LAN_PEER, 50000, 8080, "FA"),
        (0.92, LAN_PEER, LAN_HOST, 8080, 50000, "FA"),
    ):
        frames.append(_tcp(src, dst, sport, dport, flags, start + at))

    for index in range(ATTACKER_SCAN_PORTS):
        at = start + 1.0 + 0.1 * index
        frames.append(_tcp(attacker, LAN_SERVER_V6, 41000, ATTACKER_FIRST_PORT + index, "S", at))
    for index in range(DOCUMENTATION_SCAN_PORTS):
        at = start + 2.0 + 0.1 * index
        port = DOCUMENTATION_FIRST_PORT + index
        frames.append(_tcp(DOCUMENTATION_SCANNER, LAN_HOST, 42000, port, "S", at))

    frames.append(_icmp(LAN_HOST, PUBLIC_ECHO_TARGET, "echo-request", start + 4.5))
    frames.append(_icmp(PUBLIC_ECHO_TARGET, LAN_HOST, "echo-reply", start + 4.52))
    frames.append(_arp(start + 5.0))
    frames.sort(key=lambda frame: float(frame.time))
    return frames


def write_sample_capture(path: Path, *, ng: bool = False, start: float = SAMPLE_START) -> Path:
    """Write the sample scenario to a capture file. ``ng`` chooses PCAPNG over classic PCAP."""
    scapy = load_scapy()
    writer = scapy.PcapNgWriter if ng else scapy.PcapWriter
    with writer(str(path)) as out:
        for frame in scenario(start):
            out.write(frame)
    return path


# --- A simulated live capture -------------------------------------------------------------------


class SimulatedCatalog(InterfaceCatalog):
    """Two imaginary interfaces, so the demo can show a capture without capturing anything."""

    def backend(self) -> BackendInfo:
        return BackendInfo(SIMULATED_BACKEND, True)

    def interfaces(self, *, refresh: bool = False) -> list[InterfaceInfo]:
        return [LAN_INTERFACE, QUIET_INTERFACE]

    def resolve(self, interface_id: str) -> InterfaceInfo | None:
        return next((item for item in self.interfaces() if item.id == interface_id), None)


def _gaps(frames: list[Any], first_gap: float = 0.0) -> Iterator[tuple[float, Any]]:
    """The frames paired with how long to wait before each, going by their own timestamps."""
    previous = float(frames[0].time) - first_gap
    for frame in frames:
        moment = float(frame.time)
        yield moment - previous, frame
        previous = moment


class SimulatedSource:
    """Plays the sample scenario, then a slow trickle of DNS, from a thread of its own.

    It hands real Scapy frames, re-stamped with the time they are delivered, to the same handler a
    live sniffer would use, so everything downstream of the packet source runs unchanged.
    """

    def __init__(self, interface_id: str, *, trickle_seconds: float | None = None) -> None:
        self._interface_id = interface_id
        self._trickle_seconds = (
            _TRICKLE_SECONDS.get(interface_id, 4.0) if trickle_seconds is None else trickle_seconds
        )
        self._started = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def error(self) -> BaseException | None:
        return None

    def start(self, handler: Callable[[Any], None]) -> None:
        if self._thread is not None:
            raise RuntimeError("the simulated source was already started")
        self._thread = threading.Thread(
            target=self._run, args=(handler,), name="cipherforge-simulated-capture", daemon=True
        )
        self._thread.start()

    def wait_started(self, timeout: float) -> bool:
        return self._started.wait(timeout)

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(5.0)

    def _schedule(self) -> Iterator[tuple[float, Any]]:
        """(seconds to wait, frame) pairs, without end."""
        if self._interface_id == LAN_INTERFACE.id:
            yield from _gaps(scenario(0.0))
        for number in itertools.count():
            yield from _gaps(dns_exchange(number % 1000, 0.0), first_gap=self._trickle_seconds)

    def _run(self, handler: Callable[[Any], None]) -> None:
        self._started.set()
        for delay, frame in self._schedule():
            if self._stop.wait(delay):
                return
            frame.time = time.time()
            handler(frame)


def main(argv: list[str]) -> int:
    """``python -m devtools.synthetic_network [output]`` rewrites the committed sample capture."""
    if len(argv) > 1:
        print("usage: python -m devtools.synthetic_network [output.pcap]", file=sys.stderr)
        return 2
    target = Path(argv[0]) if argv else SAMPLE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    write_sample_capture(target)
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
