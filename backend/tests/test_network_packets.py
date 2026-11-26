"""Packet metadata extraction, tested on packets Scapy builds and a capture file returns."""

import contextlib
import hashlib

import pytest

from app.network.packets import (
    TCP_ACK,
    TCP_SYN,
    MalformedPacketError,
    PacketMeta,
    extract_packet,
    protocol_name,
)
from app.network.scapy_support import load_scapy
from tests.network_helpers import T0, read_pcap, scapy_syn, write_pcap, write_raw_pcap

scapy = load_scapy()
ETHER = scapy.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def _dissected(layers, ts: float = T0):
    built = layers
    built.time = ts
    # Dissect from the raw bytes, which is what a capture does.
    parsed = scapy.Ether(bytes(built))
    parsed.time = ts
    return parsed


def test_tcp_syn_keeps_addresses_ports_flags_and_time():
    meta = extract_packet(_dissected(scapy_syn(T0, "10.1.1.1", "10.2.2.2", 443, 51000)))
    assert meta == PacketMeta(
        timestamp=T0,
        src_ip="10.1.1.1",
        dst_ip="10.2.2.2",
        protocol="tcp",
        length=meta.length,
        src_port=51000,
        dst_port=443,
        tcp_flags=TCP_SYN,
    )
    assert meta.is_pure_syn
    assert meta.opens_connection


def test_syn_ack_is_not_a_pure_syn_and_does_not_open_a_connection():
    packet = ETHER / scapy.IP(src="10.0.0.2", dst="10.0.0.1") / scapy.TCP(flags="SA")
    meta = extract_packet(_dissected(packet))
    assert meta.tcp_flags == TCP_SYN | TCP_ACK
    assert not meta.is_pure_syn
    assert not meta.opens_connection


@pytest.mark.parametrize("flags", ["", "F", "FPU"])
def test_scan_probes_without_ack_open_a_connection(flags):
    packet = ETHER / scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.TCP(flags=flags)
    meta = extract_packet(_dissected(packet))
    assert meta.opens_connection
    assert not meta.is_pure_syn


def test_udp_ports_and_no_flags():
    packet = ETHER / scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.UDP(sport=5353, dport=53)
    meta = extract_packet(_dissected(packet))
    assert (meta.protocol, meta.src_port, meta.dst_port, meta.tcp_flags) == (
        "udp",
        5353,
        53,
        None,
    )
    assert meta.opens_connection


def test_icmp_has_no_ports():
    packet = ETHER / scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.ICMP()
    meta = extract_packet(_dissected(packet))
    assert (meta.protocol, meta.src_port, meta.dst_port) == ("icmp", None, None)


def test_ipv6_addresses_are_canonical_and_ports_are_read():
    packet = (
        ETHER
        / scapy.IPv6(src="2001:0db8:0000:0000:0000:0000:0000:0001", dst="2001:db8::2")
        / scapy.TCP(sport=1234, dport=22, flags="S")
    )
    meta = extract_packet(_dissected(packet))
    assert (meta.src_ip, meta.dst_ip) == ("2001:db8::1", "2001:db8::2")
    assert (meta.protocol, meta.src_port, meta.dst_port) == ("tcp", 1234, 22)


def test_ipv6_extension_headers_are_walked():
    packet = (
        ETHER
        / scapy.IPv6(src="2001:db8::1", dst="2001:db8::2")
        / scapy.IPv6ExtHdrHopByHop()
        / scapy.UDP(sport=1000, dport=2000)
    )
    meta = extract_packet(_dissected(packet))
    assert (meta.protocol, meta.src_port, meta.dst_port) == ("udp", 1000, 2000)


def test_arp_is_not_ip_traffic():
    assert extract_packet(_dissected(ETHER / scapy.ARP())) is None


def test_vlan_tagged_frames_are_read():
    meta = extract_packet(_dissected(scapy_syn(T0, "10.0.0.1", "10.0.0.2", 80, vlan=True)))
    assert meta.protocol == "tcp"
    assert meta.dst_port == 80


def test_unknown_protocol_is_named_by_number():
    packet = ETHER / scapy.IP(src="10.0.0.1", dst="10.0.0.2", proto=253) / scapy.Raw(b"x")
    meta = extract_packet(_dissected(packet))
    assert meta.protocol == "proto-253"
    assert meta.src_port is None


def test_non_first_fragment_has_no_ports():
    packet = (
        ETHER / scapy.IP(src="10.0.0.1", dst="10.0.0.2", proto=6, frag=5) / scapy.Raw(b"x" * 40)
    )
    meta = extract_packet(_dissected(packet))
    assert meta.protocol == "tcp"
    assert (meta.src_port, meta.dst_port, meta.tcp_flags) == (None, None, None)


def test_a_tunnelled_packet_is_attributed_to_the_outer_header():
    packet = (
        ETHER
        / scapy.IPv6(src="2001:db8::1", dst="2001:db8::2", nh=47)
        / scapy.GRE()
        / scapy.IP(src="192.0.2.1", dst="192.0.2.2")
        / scapy.TCP(sport=1, dport=2)
    )
    meta = extract_packet(_dissected(packet))
    assert (meta.src_ip, meta.dst_ip, meta.protocol) == ("2001:db8::1", "2001:db8::2", "gre")
    assert meta.src_port is None


def test_truncated_transport_header_still_yields_a_packet_without_ports():
    raw = bytes(ETHER / scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.TCP(sport=1, dport=2))
    truncated = scapy.Ether(raw[: 14 + 20 + 6])
    truncated.time = T0
    meta = extract_packet(truncated)
    assert meta is not None
    assert meta.protocol == "tcp"
    assert meta.src_port is None


def test_truncated_ip_header_is_not_ip_traffic():
    raw = bytes(ETHER / scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.TCP())[: 14 + 8]
    truncated = scapy.Ether(raw)
    truncated.time = T0
    assert extract_packet(truncated) is None


def _noise(seed: int, length: int) -> bytes:
    """Reproducible junk, so a failure can be replayed."""
    return hashlib.shake_128(seed.to_bytes(4, "big")).digest(length)


def test_hostile_frames_in_a_capture_file_never_escape_as_other_exceptions(tmp_path):
    frames = [b"", b"\x00", bytes(range(256)), b"\xff" * 1500]
    frames += [_noise(seed, 1 + seed % 199) for seed in range(300)]
    # Valid headers followed by damage, so the deeper layers see bad input too.
    good = bytes(scapy_syn(T0, "10.0.0.1", "10.0.0.2", 80))
    for cut in range(1, len(good)):
        frames.append(good[:cut])
        frames.append(good[:cut] + _noise(cut, 8))
    path = write_raw_pcap(tmp_path / "hostile.pcap", [(T0 + i, f) for i, f in enumerate(frames)])
    read = list(read_pcap(path))
    assert len(read) == len(frames)
    for frame in read:
        with contextlib.suppress(MalformedPacketError):
            result = extract_packet(frame)
            assert result is None or isinstance(result, PacketMeta)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1.0, 4_102_444_801.0])
def test_a_timestamp_outside_1970_to_2100_is_malformed(value):
    packet = _dissected(scapy_syn(T0, "10.0.0.1", "10.0.0.2", 80))
    packet.time = value
    with pytest.raises(MalformedPacketError):
        extract_packet(packet)


def test_an_object_that_is_not_a_packet_is_malformed():
    with pytest.raises(MalformedPacketError):
        extract_packet(object())


def test_length_is_the_wire_length_from_a_capture_file(tmp_path):
    big = ETHER / scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.UDP() / scapy.Raw(b"a" * 1000)
    big.time = T0
    path = write_pcap(tmp_path / "one.pcap", [big])
    (read_back,) = read_pcap(path)
    meta = extract_packet(read_back)
    assert meta.length == len(bytes(big))
    assert meta.timestamp == pytest.approx(T0, abs=1e-5)


def test_pcapng_files_round_trip_the_same_way(tmp_path):
    path = write_pcap(tmp_path / "one.pcapng", [scapy_syn(T0, "10.0.0.1", "10.0.0.2", 22)], ng=True)
    (read_back,) = read_pcap(path)
    meta = extract_packet(read_back)
    assert (meta.src_ip, meta.dst_port, meta.is_pure_syn) == ("10.0.0.1", 22, True)


def test_payload_is_never_kept():
    secret = b"password=hunter2"
    packet = (
        ETHER / scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.TCP(dport=80) / scapy.Raw(secret)
    )
    meta = extract_packet(_dissected(packet))
    assert secret.decode() not in repr(meta)
    assert not hasattr(meta, "payload")


@pytest.mark.parametrize(
    ("number", "name"),
    [(1, "icmp"), (6, "tcp"), (17, "udp"), (47, "gre"), (58, "icmpv6"), (200, "proto-200")],
)
def test_protocol_names(number, name):
    assert protocol_name(number) == name
