"""Reduce a captured packet to the metadata the monitor works with.

Only addresses, ports, protocol, length, timestamp and TCP flags are kept. The payload is never
copied, stored or logged. This module does not import Scapy: it reads the layers of whatever
dissected packet it is given, which keeps the analysis code importable (and unit-testable)
without a capture library.
"""

import ipaddress
import math
from dataclasses import dataclass
from typing import Any

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10

_PROTOCOL_NAMES = {
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "icmpv6",
    89: "ospf",
    132: "sctp",
}
# The IPv6 headers that sit between the fixed header and the transport header: hop-by-hop options,
# routing, fragment and destination options.
_IPV6_EXTENSIONS = frozenset({0, 43, 44, 60})
_IPV6_FRAGMENT = 44
_MAX_EXTENSION_HEADERS = 8
_PORT_LAYERS = frozenset({"TCP", "UDP", "SCTP"})
_NETWORK_LAYERS = frozenset({"IP", "IPv6"})
# Ethernet, a few VLAN tags, LLC/SNAP: how many layers may sit in front of the IP header.
_MAX_LINK_LAYERS = 8
# Capture files can carry any timestamp; anything outside 1970..2100 is treated as corrupt rather
# than stored.
_MAX_TIMESTAMP = 4_102_444_800.0


class MalformedPacketError(Exception):
    """A packet could not be read. The caller counts it and carries on."""


@dataclass(frozen=True, slots=True)
class PacketMeta:
    """What the monitor keeps of one IP packet. ``timestamp`` is seconds since the Unix epoch."""

    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int | None = None

    @property
    def is_pure_syn(self) -> bool:
        """A TCP SYN that is not part of an acknowledgement: the first packet of a handshake."""
        return self.tcp_flags is not None and self.tcp_flags & (TCP_SYN | TCP_ACK) == TCP_SYN

    @property
    def opens_connection(self) -> bool:
        """Whether this packet can be the first of a connection attempt.

        A TCP packet carrying ACK belongs to a connection that is already under way (a capture that
        starts mid-connection, or a reply), so it is not an attempt. SYN, and the flag-less, FIN and
        other probes port scanners send, are. Protocols without a handshake count their first
        packet.
        """
        return self.tcp_flags is None or not self.tcp_flags & TCP_ACK


def protocol_name(number: int) -> str:
    """The lower-case name of an IP protocol number, or ``proto-<n>`` when it has no common name."""
    return _PROTOCOL_NAMES.get(number, f"proto-{number}")


def extract_packet(packet: Any) -> PacketMeta | None:
    """The metadata of a dissected packet, or None when it carries no IP traffic (ARP, STP, ...).

    Raises ``MalformedPacketError`` when the packet is IP but cannot be read.
    """
    try:
        return _extract(packet)
    except Exception as exc:
        # Scapy raises a variety of exception types on hostile or truncated input.
        raise MalformedPacketError(type(exc).__name__) from exc


def _extract(packet: Any) -> PacketMeta | None:
    network = _network_layer(packet)
    if network is None:
        return None
    if type(network).__name__ == "IP":
        src_ip, dst_ip = _address(network.src), _address(network.dst)
        protocol_number = int(network.proto)
        transport = network.payload
        fragment_offset = int(network.frag)
    else:
        src_ip, dst_ip = _address(network.src), _address(network.dst)
        protocol_number, transport, fragment_offset = _walk_ipv6_headers(network)

    src_port = dst_port = tcp_flags = None
    # Only the first fragment of a datagram carries the transport header.
    if fragment_offset == 0 and type(transport).__name__ in _PORT_LAYERS:
        src_port, dst_port = int(transport.sport), int(transport.dport)
        if protocol_number == 6:
            tcp_flags = int(transport.flags) & 0xFF

    return PacketMeta(
        timestamp=_timestamp(packet),
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol_name(protocol_number),
        length=_length(packet),
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
    )


def _network_layer(packet: Any) -> Any | None:
    """The outermost IPv4 or IPv6 layer, so a tunnelled inner packet is never mistaken for it."""
    layer = packet
    for _ in range(_MAX_LINK_LAYERS):
        if type(layer).__name__ in _NETWORK_LAYERS:
            return layer
        layer = layer.payload
    return None


def _walk_ipv6_headers(ipv6: Any) -> tuple[int, Any, int]:
    """The upper-layer protocol number, its layer and the fragment offset behind the IPv6 header."""
    next_header = int(ipv6.nh)
    layer = ipv6.payload
    fragment_offset = 0
    for _ in range(_MAX_EXTENSION_HEADERS):
        if next_header not in _IPV6_EXTENSIONS:
            break
        if next_header == _IPV6_FRAGMENT:
            fragment_offset = int(layer.offset)
        next_header = int(layer.nh)
        layer = layer.payload
    return next_header, layer, fragment_offset


def _address(value: Any) -> str:
    text = str(value)
    if ":" in text:
        # One spelling per address, so a flow key is the same whichever way a packet wrote it.
        return str(ipaddress.IPv6Address(text))
    return text


def _timestamp(packet: Any) -> float:
    value = float(packet.time)
    if not math.isfinite(value) or not 0.0 <= value <= _MAX_TIMESTAMP:
        raise ValueError("timestamp out of range")
    return value


def _length(packet: Any) -> int:
    wire_length = getattr(packet, "wirelen", None)
    if wire_length:
        return int(wire_length)
    original = getattr(packet, "original", None)
    return len(original) if original else len(packet)
