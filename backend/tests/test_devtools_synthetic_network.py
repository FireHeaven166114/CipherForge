"""The synthetic network scenario, its committed sample capture and the demo server's simulated
capture and encrypted file sharing."""

import ipaddress
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import Settings
from app.models.enums import IndicatorType
from app.models.threat import ThreatIndicator
from app.network.capture import BackendInfo
from app.network.packets import extract_packet
from app.services.normalization import is_public_address
from devtools import demo_server
from devtools.demo_data import build_catalogue, tiers_of
from devtools.demo_server import (
    create_demo_app,
    demo_key_path,
    demo_master_key,
    demo_settings,
    demo_storage_dir,
    prepare_database,
)
from devtools.simulated_providers import Tier
from devtools.synthetic_network import (
    ATTACKER_SCAN_PORTS,
    DNS_EXCHANGES,
    DOCUMENTATION_SCAN_PORTS,
    DOCUMENTATION_SCANNER,
    LAN_HOST,
    LAN_INTERFACE,
    LAN_PEER,
    LAN_SERVER_V6,
    PUBLIC_ECHO_TARGET,
    PUBLIC_RESOLVER,
    QUIET_INTERFACE,
    SAMPLE_PATH,
    SimulatedCatalog,
    SimulatedSource,
    attacker_address,
    scenario,
    write_sample_capture,
)
from tests.network_helpers import read_pcap, wait_until

REGENERATE = (
    "frontend/e2e/data/synthetic-network.pcap is out of date: run "
    "`python -m devtools.synthetic_network` from backend/ and commit the result"
)
FIXED_NOW = datetime(2025, 6, 11, 15, 20, tzinfo=UTC)
CAPTURE_THREADS = {"cipherforge-capture-consumer", "cipherforge-simulated-capture"}
FILE_BODY = b"synthetic file for the demo round trip\n" * 40


def _frames_as_tuples(frames: list[Any]) -> list[tuple[float, bytes]]:
    return [(round(float(frame.time), 6), bytes(frame)) for frame in frames]


# --- The scenario and the sample capture -------------------------------------------------


def test_the_committed_sample_capture_is_what_the_generator_writes() -> None:
    assert SAMPLE_PATH.is_file(), REGENERATE
    assert _frames_as_tuples(read_pcap(SAMPLE_PATH)) == _frames_as_tuples(scenario()), REGENERATE


def test_writing_the_sample_is_repeatable_and_readable_in_both_formats(tmp_path: Path) -> None:
    first = write_sample_capture(tmp_path / "first.pcap")
    second = write_sample_capture(tmp_path / "second.pcap")
    assert first.read_bytes() == second.read_bytes()

    ng = write_sample_capture(tmp_path / "sample.pcapng", ng=True)
    assert _frames_as_tuples(read_pcap(ng)) == _frames_as_tuples(scenario())


def test_the_scenario_plays_in_time_order_over_a_few_seconds() -> None:
    times = [float(frame.time) for frame in scenario(0.0)]
    assert times == sorted(times)
    assert 0 <= times[0] < 1
    assert 4 < times[-1] < 6


def test_the_only_public_addresses_are_the_made_up_attacker_and_two_clean_resolvers() -> None:
    packets = [extract_packet(frame) for frame in scenario()]
    addresses = {
        address
        for packet in packets
        if packet is not None
        for address in (packet.src_ip, packet.dst_ip)
    }
    attacker = attacker_address()

    assert {address for address in addresses if is_public_address(address)} == {
        attacker,
        PUBLIC_RESOLVER,
        PUBLIC_ECHO_TARGET,
    }
    # The ones that must never reach a provider: private or reserved for documentation.
    for address in (LAN_HOST, LAN_PEER, LAN_SERVER_V6, DOCUMENTATION_SCANNER):
        assert address in addresses
        assert not is_public_address(address)

    tiers = tiers_of(build_catalogue())
    assert tiers[(IndicatorType.IPV6, attacker)] is Tier.CRITICAL
    assert ipaddress.ip_address(attacker) in ipaddress.ip_network("2100::/16")
    assert tiers[(IndicatorType.IPV4, PUBLIC_RESOLVER)] is Tier.CLEAN
    assert tiers[(IndicatorType.IPV4, PUBLIC_ECHO_TARGET)] is Tier.CLEAN


# --- The simulated catalogue and source --------------------------------------------------


def test_the_simulated_catalogue_says_it_is_simulated() -> None:
    catalog = SimulatedCatalog()
    assert catalog.backend() == BackendInfo("simulated", True)
    assert catalog.interfaces() == [LAN_INTERFACE, QUIET_INTERFACE]
    assert catalog.resolve(LAN_INTERFACE.id) is LAN_INTERFACE
    assert catalog.resolve("eth0") is None
    for interface in catalog.interfaces():
        assert "Nothing is captured from this machine" in interface.description


def _collect(source: SimulatedSource, *, frames: int) -> tuple[list[Any], set[str]]:
    received: list[Any] = []
    delivered_by: set[str] = set()

    def handler(frame: Any) -> None:
        received.append(frame)
        delivered_by.add(threading.current_thread().name)

    assert not source.alive
    source.start(handler)
    assert source.wait_started(2.0)
    wait_until(lambda: len(received) >= frames, timeout=10, what="the first frames")
    assert source.alive
    assert source.error is None
    source.stop()
    assert not source.alive
    return received, delivered_by


def test_the_simulated_source_delivers_stamped_frames_from_its_own_thread_until_stopped() -> None:
    source = SimulatedSource(LAN_INTERFACE.id)
    received, delivered_by = _collect(source, frames=8)

    assert delivered_by == {"cipherforge-simulated-capture"}
    # Re-stamped on delivery: the scenario's own offsets start at zero.
    assert all(abs(float(frame.time) - time.time()) < 60 for frame in received)
    delivered = len(received)
    time.sleep(0.3)
    assert len(received) == delivered
    source.stop()  # a second stop changes nothing
    with pytest.raises(RuntimeError, match="already started"):
        source.start(lambda frame: None)


def test_the_quiet_interface_only_trickles_dns() -> None:
    source = SimulatedSource(QUIET_INTERFACE.id, trickle_seconds=0.01)
    received, _ = _collect(source, frames=6)

    packets = [extract_packet(frame) for frame in received]
    assert all(packet is not None and packet.protocol == "udp" for packet in packets)
    assert all(53 in (packet.src_port, packet.dst_port) for packet in packets if packet)
    assert attacker_address() not in {packet.src_ip for packet in packets if packet}


# --- The demo server ---------------------------------------------------------------------


@dataclass(frozen=True)
class Demo:
    client: TestClient
    directory: Path
    storage: Path


@pytest.fixture(scope="module")
def demo(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Demo]:
    directory = tmp_path_factory.mktemp("synthetic-demo") / ".demo"
    directory.mkdir()
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(demo_server, "DEMO_DIR", directory)
        patch.setenv("CIPHERFORGE_DEMO_DB", str(directory / "synthetic.db"))
        with TestClient(create_demo_app()) as client:
            yield Demo(client, directory, demo_storage_dir(directory / "synthetic.db"))


def _session(demo: Demo, session_id: str) -> dict[str, Any]:
    return demo.client.get(f"/api/v1/network/sessions/{session_id}").json()


def _alerts(demo: Demo, session_id: str) -> list[dict[str, Any]]:
    return demo.client.get(f"/api/v1/network/sessions/{session_id}/alerts").json()["items"]


def test_the_demo_labels_its_capture_backend_and_interfaces_as_simulated(demo: Demo) -> None:
    status = demo.client.get("/api/v1/network/status").json()
    assert status["backend"] == {"name": "simulated", "available": True}
    listing = demo.client.get("/api/v1/network/interfaces").json()
    assert listing["backend"]["name"] == "simulated"
    assert [item["id"] for item in listing["interfaces"]] == [
        LAN_INTERFACE.id,
        QUIET_INTERFACE.id,
    ]


def test_the_sample_capture_is_analysed_into_scan_alerts_and_only_public_addresses_are_looked_up(
    demo: Demo,
) -> None:
    uploaded = demo.client.post(
        "/api/v1/network/pcap",
        content=SAMPLE_PATH.read_bytes(),
        headers={"Content-Type": "application/octet-stream", "X-File-Name": SAMPLE_PATH.name},
    )
    assert uploaded.status_code == 202
    session_id = uploaded.json()["id"]
    wait_until(lambda: _session(demo, session_id)["status"] != "running", what="the analysis")

    session = _session(demo, session_id)
    assert session["status"] == "completed"
    assert session["source_kind"] == "pcap"
    assert session["non_ip_packets"] == 1
    # Every conversation is one flow: a DNS exchange per question, the private TCP conversation,
    # one flow per probed port and the ping.
    assert session["flows_total"] == (
        DNS_EXCHANGES + 1 + ATTACKER_SCAN_PORTS + DOCUMENTATION_SCAN_PORTS + 1
    )

    # The attacker and the two resolvers are public, so they are looked up on their own.
    wait_until(
        lambda: _session(demo, session_id)["enrichment"]["completed"] == 3,
        timeout=15,
        what="the enrichment of the three public addresses",
    )
    alerts = _alerts(demo, session_id)
    attacker = attacker_address()
    by_rule = sorted((alert["rule_id"], alert["src_ip"]) for alert in alerts)
    assert by_rule == sorted(
        [("NET-001", attacker), ("NET-001", DOCUMENTATION_SCANNER), ("NET-005", attacker)]
    )
    states = {
        alert["src_ip"]: alert["enrichment"]["status"]
        for alert in alerts
        if alert["rule_id"] == "NET-001"
    }
    assert states == {attacker: "completed", DOCUMENTATION_SCANNER: "not_applicable"}

    with demo.client.app.state.session_factory() as db:
        looked_up = set(db.scalars(select(ThreatIndicator.indicator_value)))
    assert attacker in looked_up
    assert not looked_up & {LAN_HOST, LAN_PEER, LAN_SERVER_V6, DOCUMENTATION_SCANNER}


def test_a_simulated_capture_alerts_stops_and_leaves_no_capture_thread(demo: Demo) -> None:
    started = demo.client.post(
        "/api/v1/network/capture/start", json={"interface": LAN_INTERFACE.id}
    )
    assert started.status_code == 200
    assert started.json()["state"] == "running"
    session_id = started.json()["session_id"]

    wait_until(
        lambda: {"NET-001", "NET-005"} <= {alert["rule_id"] for alert in _alerts(demo, session_id)},
        timeout=20,
        what="the scan alerts of the simulated capture",
    )
    stopped = demo.client.post("/api/v1/network/capture/stop")
    assert stopped.status_code == 200
    assert stopped.json()["state"] == "stopped"

    session = _session(demo, session_id)
    assert session["status"] == "stopped"
    assert session["source_kind"] == "live"
    assert session["interface"] == LAN_INTERFACE.name
    assert session["packets_total"] > 0
    wait_until(
        lambda: not CAPTURE_THREADS & {thread.name for thread in threading.enumerate()},
        what="the capture threads to exit",
    )
    again = demo.client.post("/api/v1/network/capture/stop")
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "capture_not_running"


def test_the_demo_encrypts_files_with_its_own_key_and_shares_them(demo: Demo) -> None:
    assert demo.client.get("/api/v1/files/status").json()["configured"] is True

    uploaded = demo.client.post(
        "/api/v1/files",
        content=FILE_BODY,
        headers={"Content-Type": "application/octet-stream", "X-File-Name": "demo-notes.txt"},
    )
    assert uploaded.status_code == 201
    file_id = uploaded.json()["id"]

    stored = list(demo.storage.glob("*.bin"))
    assert len(stored) == 1
    assert FILE_BODY[:30] not in stored[0].read_bytes()

    share = demo.client.post(f"/api/v1/files/{file_id}/shares", json={"max_downloads": 2})
    assert share.status_code == 201
    downloaded = demo.client.get(f"/api/v1/shares/{share.json()['token']}/download")
    assert downloaded.status_code == 200
    assert downloaded.content == FILE_BODY


# --- The demo key and files follow the demo database ---------------------------------------


def test_the_demo_key_is_random_stable_valid_and_removed_with_a_rebuild(tmp_path: Path) -> None:
    path = tmp_path / "demo.db"
    assert prepare_database(path, reset=False, now=FIXED_NOW) is True

    key = demo_master_key(path)
    assert demo_master_key(path) == key
    assert demo_key_path(path).read_text(encoding="ascii") == key
    assert len(demo_settings(path, master_key=key).master_key or b"") == 32
    assert demo_settings(path).master_key is None
    assert demo_settings(path).encrypted_file_storage_path == demo_storage_dir(path)

    storage = demo_storage_dir(path)
    storage.mkdir()
    (storage / "left-behind.bin").write_bytes(b"ciphertext")
    assert prepare_database(path, reset=True, now=FIXED_NOW) is True
    assert not storage.exists()
    assert not demo_key_path(path).exists()
    assert demo_master_key(path) != key


def test_each_demo_database_gets_its_own_key_and_storage_folder(tmp_path: Path) -> None:
    first, second = tmp_path / "first.db", tmp_path / "second.db"
    assert demo_storage_dir(first) != demo_storage_dir(second)
    assert demo_key_path(first) != demo_key_path(second)
    assert demo_master_key(first) != demo_master_key(second)
    assert isinstance(demo_settings(first), Settings)
