"""A real capture on this machine's own network stack. Off unless asked for.

Run with ``CIPHERFORGE_LIVE_CAPTURE_TESTS=1``. It needs a capture driver (Npcap on Windows,
libpcap elsewhere) and the privileges capture needs; without them the test skips.

The test sends a few small UDP datagrams to an address from the documentation range
(192.0.2.0/24, RFC 5737), which is not routable on the Internet, and checks that the capture saw
them. Nothing about the interface it used is printed.
"""

import os
import socket
import time

import pytest

from app.models.enums import CaptureStatus
from app.network.capture import InterfaceCatalog, LiveCapture, ScapyLiveSource
from app.network.errors import CaptureFailure
from tests.network_helpers import RecordingMonitor, assert_no_module_threads, wait_until

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("CIPHERFORGE_LIVE_CAPTURE_TESTS") != "1",
        reason="Set CIPHERFORGE_LIVE_CAPTURE_TESTS=1 to capture real packets.",
    ),
]

DESTINATION = "192.0.2.1"
DISCARD_PORT = 9
DATAGRAMS = 5


def outgoing_address() -> str:
    """The local address this machine would send to ``DESTINATION`` from.

    Connecting a UDP socket only chooses a route; nothing is sent.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect((DESTINATION, DISCARD_PORT))
        except OSError:
            pytest.skip("This machine has no route to send a datagram on.")
        return probe.getsockname()[0]


def test_a_real_capture_sees_the_datagrams_this_machine_sends() -> None:
    catalog = InterfaceCatalog()
    if not catalog.backend().available:
        pytest.skip("No packet-capture driver (Npcap or libpcap) is available.")
    local = outgoing_address()
    interface = next((item for item in catalog.interfaces() if local in item.addresses), None)
    if interface is None:
        pytest.skip("No capture interface carries the address used to reach the network.")

    monitor = RecordingMonitor()
    capture = LiveCapture(
        monitor, ScapyLiveSource(interface.id), buffer_size=1000, start_timeout=15.0
    )
    try:
        capture.start()
    except CaptureFailure as failure:
        if failure.code in {"capture_permission_denied", "capture_backend_missing"}:
            pytest.skip("Packet capture is not permitted or not installed here.")
        raise
    try:
        wait_until(
            lambda: capture.state is CaptureStatus.RUNNING,
            timeout=15.0,
            what="the capture to be running",
        )

        def datagrams_seen() -> int:
            return sum(
                1
                for item in monitor.processed
                if (item.dst_ip, item.dst_port, item.protocol) == (DESTINATION, DISCARD_PORT, "udp")
            )

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.bind((local, 0))
            for _ in range(DATAGRAMS):
                sender.sendto(b"cipherforge live capture test", (DESTINATION, DISCARD_PORT))
                time.sleep(0.05)
        wait_until(lambda: datagrams_seen() >= 1, timeout=15.0, what="a datagram to be captured")
    finally:
        stopped = capture.stop(timeout=15.0)

    assert stopped is True
    assert capture.state is CaptureStatus.STOPPED
    assert monitor.finished == [(CaptureStatus.STOPPED, None)]
    assert datagrams_seen() >= 1
    assert monitor.dropped == 0
    assert_no_module_threads()
