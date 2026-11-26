"""One monitoring session's analysis: flows, detection rules, traffic statistics, external peers.

``Analyzer`` is pure in-memory state with no threads and no database, so it behaves the same for a
live capture and for a capture file, and it can be tested by feeding it packets.
"""

from collections.abc import Collection
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from app.detection.network_rules import NetworkRuleConfig, RawAlert, RuleEngine
from app.network.flows import Flow, FlowTable
from app.network.packets import PacketMeta
from app.network.windows import LruMap
from app.services.normalization import is_public_address

_TOP_COUNT = 10
_MAX_PEER_DETAIL = 5
_MAX_TRACKED_PEERS = 2000
_MAX_TALKERS = 5000

_is_public = lru_cache(maxsize=16_384)(is_public_address)


def _iso(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat()


def subject_address(src_ip: str | None, dst_ip: str | None) -> str | None:
    """The public address a finding between these two addresses is about, if there is one.

    The source is preferred, so an outside host that scans the network is the subject, and a
    local host reaching out to a public server makes that server the subject.
    """
    for address in (src_ip, dst_ip):
        if address and _is_public(address):
            return address
    return None


@dataclass(frozen=True, slots=True)
class TrafficStat:
    key: str
    packets: int
    bytes: int


class _Talkers:
    """Packet and byte counts per address, bounded: the lightest 25% go when the limit is hit."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._counts: dict[str, list[int]] = {}
        self.truncated = False

    def add(self, key: str, size: int) -> None:
        entry = self._counts.get(key)
        if entry is None:
            if len(self._counts) >= self._limit:
                self._shrink()
            entry = self._counts[key] = [0, 0]
        entry[0] += 1
        entry[1] += size

    def top(self, count: int) -> list[TrafficStat]:
        ranked = sorted(self._counts.items(), key=lambda item: (-item[1][1], item[0]))[:count]
        return [TrafficStat(key, values[0], values[1]) for key, values in ranked]

    def _shrink(self) -> None:
        heaviest = sorted(self._counts.items(), key=lambda item: item[1][1], reverse=True)
        self._counts = dict(heaviest[: self._limit * 3 // 4])
        self.truncated = True


@dataclass(slots=True)
class ExternalPeer:
    """A public address seen in the traffic, with what is needed to look it up and explain it."""

    address: str
    first_seen: float
    last_seen: float
    packets: int = 0
    bytes: int = 0
    # Whether something sent traffic to this address (rather than only receiving from it).
    sent_to: bool = False
    alerted: bool = False
    peers: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)

    def copy(self) -> "ExternalPeer":
        return replace(
            self, peers=list(self.peers), ports=list(self.ports), protocols=list(self.protocols)
        )

    def as_facts(self) -> dict[str, Any]:
        """The JSON form kept with the session and handed to the enrichment worker."""
        return {
            "address": self.address,
            "first_seen": _iso(self.first_seen),
            "last_seen": _iso(self.last_seen),
            "packets": self.packets,
            "bytes": self.bytes,
            "sent_to": self.sent_to,
            "alerted": self.alerted,
            "peers": list(self.peers),
            "ports": list(self.ports),
            "protocols": list(self.protocols),
        }


def _remember(items: list, value: Any) -> None:
    if value is not None and value not in items and len(items) < _MAX_PEER_DETAIL:
        items.append(value)


@dataclass(frozen=True, slots=True)
class AnalyzerOutput:
    alerts: list[RawAlert]
    flows: list[Flow]


@dataclass(frozen=True, slots=True)
class AnalyzerSnapshot:
    packets: int
    bytes: int
    flows_total: int
    active_flows: int
    flows_evicted: int
    alerts_total: int
    alerts_suppressed: int
    alerts_by_rule: dict[str, int]
    non_ip_packets: int
    malformed_packets: int
    first_packet_at: float | None
    last_packet_at: float | None
    protocols: list[tuple[str, int, int]]
    top_sources: list[TrafficStat]
    top_destinations: list[TrafficStat]
    talkers_truncated: bool

    def as_stats(self) -> dict[str, Any]:
        """The part of the snapshot kept in ``capture_sessions.stats`` (counts live in columns)."""

        def talkers(items: list[TrafficStat]) -> list[dict[str, Any]]:
            return [
                {"address": item.key, "packets": item.packets, "bytes": item.bytes}
                for item in items
            ]

        return {
            "first_packet_at": _iso(self.first_packet_at),
            "last_packet_at": _iso(self.last_packet_at),
            "protocols": [
                {"protocol": name, "packets": packets, "bytes": size}
                for name, packets, size in self.protocols
            ],
            "top_sources": talkers(self.top_sources),
            "top_destinations": talkers(self.top_destinations),
            "active_flows": self.active_flows,
            "flows_evicted": self.flows_evicted,
            "non_ip_packets": self.non_ip_packets,
            "malformed_packets": self.malformed_packets,
            "alerts_by_rule": dict(self.alerts_by_rule),
            "alerts_suppressed": self.alerts_suppressed,
            "talkers_truncated": self.talkers_truncated,
        }


class Analyzer:
    def __init__(
        self,
        config: NetworkRuleConfig,
        *,
        idle_timeout: float,
        max_flows: int,
        max_peers: int = _MAX_TRACKED_PEERS,
        max_talkers: int = _MAX_TALKERS,
    ) -> None:
        self._flows = FlowTable(idle_timeout=idle_timeout, max_flows=max_flows)
        self._rules = RuleEngine(config)
        self._peers: LruMap[str, ExternalPeer] = LruMap(max_peers)
        self._sources = _Talkers(max_talkers)
        self._destinations = _Talkers(max_talkers)
        self._protocols: dict[str, list[int]] = {}
        self._alerts: list[RawAlert] = []
        self.packets = 0
        self.bytes = 0
        self.non_ip_packets = 0
        self.malformed_packets = 0
        self.first_packet_at: float | None = None
        self.last_packet_at: float | None = None

    @property
    def active_flows(self) -> int:
        return self._flows.active_count

    def note_non_ip(self, count: int = 1) -> None:
        self.non_ip_packets += count

    def note_malformed(self, count: int = 1) -> None:
        self.malformed_packets += count

    def process(self, packet: PacketMeta) -> None:
        self.packets += 1
        self.bytes += packet.length
        timestamp = packet.timestamp
        if self.first_packet_at is None or timestamp < self.first_packet_at:
            self.first_packet_at = timestamp
        if self.last_packet_at is None or timestamp > self.last_packet_at:
            self.last_packet_at = timestamp
        counts = self._protocols.setdefault(packet.protocol, [0, 0])
        counts[0] += 1
        counts[1] += packet.length
        self._sources.add(packet.src_ip, packet.length)
        self._destinations.add(packet.dst_ip, packet.length)

        is_new = self._flows.observe(packet)
        alerts = self._rules.observe(packet, new_flow=is_new)

        if _is_public(packet.src_ip):
            self._note_peer(packet.src_ip, packet.dst_ip, packet.src_port, packet, outbound=False)
        if _is_public(packet.dst_ip):
            self._note_peer(packet.dst_ip, packet.src_ip, packet.dst_port, packet, outbound=True)
        for alert in alerts:
            self._alerts.append(alert)
            subject = self.alert_subject(alert)
            peer = self._peers.peek(subject) if subject else None
            if peer is not None:
                peer.alerted = True

    @staticmethod
    def alert_subject(alert: RawAlert) -> str | None:
        """The public address an alert is about: its source if public, else its destination."""
        return subject_address(alert.src_ip, alert.dst_ip)

    def advance(self, now: float) -> None:
        """Finish flows that have been quiet too long, as of ``now`` (stream or wall time)."""
        self._flows.sweep(now)

    def finish(self) -> None:
        """The session is over: finish every flow that is still open."""
        self._flows.flush()

    def take_output(self) -> AnalyzerOutput:
        alerts, self._alerts = self._alerts, []
        return AnalyzerOutput(alerts=alerts, flows=self._flows.take_finished())

    def snapshot(self) -> AnalyzerSnapshot:
        protocols = sorted(
            ((name, counts[0], counts[1]) for name, counts in self._protocols.items()),
            key=lambda item: (-item[2], item[0]),
        )
        return AnalyzerSnapshot(
            packets=self.packets,
            bytes=self.bytes,
            flows_total=self._flows.flows_seen,
            active_flows=self._flows.active_count,
            flows_evicted=self._flows.flows_evicted,
            alerts_total=self._rules.alerts_raised,
            alerts_suppressed=self._rules.alerts_suppressed,
            alerts_by_rule=self._rules.alerts_by_rule,
            non_ip_packets=self.non_ip_packets,
            malformed_packets=self.malformed_packets,
            first_packet_at=self.first_packet_at,
            last_packet_at=self.last_packet_at,
            protocols=protocols,
            top_sources=self._sources.top(_TOP_COUNT),
            top_destinations=self._destinations.top(_TOP_COUNT),
            talkers_truncated=self._sources.truncated or self._destinations.truncated,
        )

    def peer(self, address: str) -> ExternalPeer | None:
        found = self._peers.peek(address)
        return found.copy() if found is not None else None

    def enrichment_candidates(self, limit: int, exclude: Collection[str]) -> list[ExternalPeer]:
        """Public addresses worth looking up, alert-involved first, then heaviest traffic."""
        eligible = [peer for peer in self._peers.values() if peer.address not in exclude]
        eligible.sort(key=lambda peer: (not peer.alerted, -peer.bytes, peer.address))
        return [peer.copy() for peer in eligible[: max(limit, 0)]]

    def _note_peer(
        self, address: str, other: str, port: int | None, packet: PacketMeta, *, outbound: bool
    ) -> None:
        peer = self._peers.get(address)
        if peer is None:
            peer = ExternalPeer(address, packet.timestamp, packet.timestamp)
            self._peers.set(address, peer)
        peer.packets += 1
        peer.bytes += packet.length
        peer.first_seen = min(peer.first_seen, packet.timestamp)
        peer.last_seen = max(peer.last_seen, packet.timestamp)
        peer.sent_to = peer.sent_to or outbound
        _remember(peer.peers, other)
        _remember(peer.ports, port)
        _remember(peer.protocols, packet.protocol)
