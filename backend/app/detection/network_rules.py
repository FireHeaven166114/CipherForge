"""Network detection rules, NET-001 to NET-007.

Each rule watches one kind of behaviour by one source address over a sliding time window and
compares it with a configured threshold. An alert records what was measured, the threshold, the
window and the addresses involved, so an analyst can see why it fired and how far past the
threshold the activity went.

The default thresholds are starting points for a lab or a demonstration, not universal security
standards; every real network needs them tuned (see docs/network-monitoring.md).

Time is the packet's own timestamp, so replaying a capture file raises the same alerts every time.
"""

from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core.config import DEFAULT_EXPECTED_PROTOCOLS, DEFAULT_SUSPICIOUS_PORTS, Settings
from app.core.timeutil import format_ist
from app.models.enums import AlertSeverity
from app.network.packets import PacketMeta
from app.network.windows import LruMap, SlidingWindow

_MB = 1024 * 1024
_MAX_SAMPLES = 5
_MAX_SAMPLE_PORTS = 20
# An alert is raised at the threshold; observed/threshold decides how severe it is.
_STEP_RATIOS = (3.0, 10.0)
_SEVERITY_RANK = {
    AlertSeverity.LOW: 0,
    AlertSeverity.MEDIUM: 1,
    AlertSeverity.HIGH: 2,
    AlertSeverity.CRITICAL: 3,
}


@dataclass(frozen=True, slots=True)
class RuleInfo:
    rule_id: str
    name: str
    title: str
    # What ``observed_value`` and ``threshold`` count for this rule.
    unit: str
    description: str
    # The severity at 1x, 3x and 10x the threshold. Rules that are not threshold-based keep one.
    severities: tuple[AlertSeverity, AlertSeverity, AlertSeverity]
    needs_enrichment: bool = False


PORT_SCAN = RuleInfo(
    "NET-001",
    "port_scan",
    "Port scan",
    "ports",
    "One source tried connections to many different destination ports within the window.",
    (AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL),
)
CONNECTION_RATE = RuleInfo(
    "NET-002",
    "connection_rate",
    "High connection rate",
    "connections",
    "One source opened an unusually high number of new connections within the window.",
    (AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH),
)
SYN_RATE = RuleInfo(
    "NET-003",
    "syn_rate",
    "Abnormal SYN rate",
    "SYN packets",
    "One source sent an unusually high number of TCP SYN packets within the window, the pattern "
    "of a SYN flood or a fast scan.",
    (AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL),
)
HIGH_VOLUME = RuleInfo(
    "NET-004",
    "high_volume",
    "High traffic volume",
    "MB",
    "One source sent an unusually large amount of data within the window.",
    (AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH),
)
KNOWN_MALICIOUS_IP = RuleInfo(
    "NET-005",
    "known_malicious_ip",
    "Communication with a known malicious address",
    "risk score",
    "Traffic involved a public address whose CipherForge threat-intelligence risk score is at or "
    "above the configured minimum. Raised only once the address has been looked up.",
    (AlertSeverity.HIGH, AlertSeverity.HIGH, AlertSeverity.CRITICAL),
    needs_enrichment=True,
)
SUSPICIOUS_PORT = RuleInfo(
    "NET-006",
    "suspicious_port",
    "Repeated connections to suspicious ports",
    "attempts",
    "One source repeatedly tried to connect to ports on the configured suspicious-port list.",
    (AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.HIGH),
)
UNEXPECTED_PROTOCOL = RuleInfo(
    "NET-007",
    "unexpected_protocol",
    "Unexpected protocol",
    "packets",
    "Traffic used an IP protocol that is not on the expected-protocol list.",
    (AlertSeverity.LOW, AlertSeverity.LOW, AlertSeverity.LOW),
)

ALL_RULES = (
    PORT_SCAN,
    CONNECTION_RATE,
    SYN_RATE,
    HIGH_VOLUME,
    KNOWN_MALICIOUS_IP,
    SUSPICIOUS_PORT,
    UNEXPECTED_PROTOCOL,
)


@dataclass(frozen=True, slots=True)
class NetworkRuleConfig:
    """Every threshold and window the rules use; ``from_settings`` reads them from ``Settings``."""

    port_scan_threshold: int = 20
    port_scan_window_seconds: int = 60
    connection_rate_threshold: int = 100
    connection_rate_window_seconds: int = 60
    syn_rate_threshold: int = 200
    syn_rate_window_seconds: int = 10
    suspicious_port_threshold: int = 25
    suspicious_port_window_seconds: int = 60
    suspicious_ports: frozenset[int] = frozenset(DEFAULT_SUSPICIOUS_PORTS)
    high_volume_threshold_mb: int = 50
    high_volume_window_seconds: int = 60
    expected_protocols: frozenset[str] = frozenset(DEFAULT_EXPECTED_PROTOCOLS)
    known_malicious_min_score: int = 61
    # How many sources the rules remember at once; the least recently active are forgotten first.
    max_tracked_sources: int = 10_000
    max_alerts_per_session: int = 500
    max_alerts_per_rule: int = 200

    @classmethod
    def from_settings(cls, settings: Settings) -> "NetworkRuleConfig":
        return cls(
            port_scan_threshold=settings.port_scan_threshold,
            port_scan_window_seconds=settings.port_scan_window_seconds,
            connection_rate_threshold=settings.connection_rate_threshold,
            connection_rate_window_seconds=settings.connection_rate_window_seconds,
            syn_rate_threshold=settings.syn_rate_threshold,
            syn_rate_window_seconds=settings.syn_rate_window_seconds,
            suspicious_port_threshold=settings.suspicious_port_threshold,
            suspicious_port_window_seconds=settings.suspicious_port_window_seconds,
            suspicious_ports=frozenset(settings.suspicious_ports),
            high_volume_threshold_mb=settings.high_volume_threshold_mb,
            high_volume_window_seconds=settings.high_volume_window_seconds,
            expected_protocols=frozenset(settings.expected_protocols),
            known_malicious_min_score=settings.known_malicious_min_score,
            max_tracked_sources=max(1000, settings.max_active_flows),
        )


@dataclass(frozen=True, slots=True)
class RuleSetting:
    """One rule's configured threshold and window, for display."""

    info: RuleInfo
    threshold: float
    window_seconds: int | None
    detail: str | None = None


def describe_rules(config: NetworkRuleConfig) -> list[RuleSetting]:
    return [
        RuleSetting(PORT_SCAN, config.port_scan_threshold, config.port_scan_window_seconds),
        RuleSetting(
            CONNECTION_RATE, config.connection_rate_threshold, config.connection_rate_window_seconds
        ),
        RuleSetting(SYN_RATE, config.syn_rate_threshold, config.syn_rate_window_seconds),
        RuleSetting(
            HIGH_VOLUME, config.high_volume_threshold_mb, config.high_volume_window_seconds
        ),
        RuleSetting(
            KNOWN_MALICIOUS_IP,
            config.known_malicious_min_score,
            None,
            "Needs external enrichment: only addresses that were looked up can raise it.",
        ),
        RuleSetting(
            SUSPICIOUS_PORT,
            config.suspicious_port_threshold,
            config.suspicious_port_window_seconds,
            "Ports: " + ", ".join(str(port) for port in sorted(config.suspicious_ports)),
        ),
        RuleSetting(
            UNEXPECTED_PROTOCOL,
            1,
            None,
            "Expected: " + ", ".join(sorted(config.expected_protocols)),
        ),
    ]


@dataclass(frozen=True, slots=True)
class RawAlert:
    """A finding before it is stored. Times are seconds since the Unix epoch."""

    rule_id: str
    rule_name: str
    severity: AlertSeverity
    explanation: str
    observed_value: float
    threshold: float
    window_seconds: int | None
    first_observed: float
    last_observed: float
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class _Cooldown:
    until: float
    rank: int


@dataclass(slots=True)
class _ScanState:
    ports: SlidingWindow
    targets: SlidingWindow


def severity_for(rule: RuleInfo, observed: float, threshold: float) -> AlertSeverity:
    """The rule's severity for ``observed`` against ``threshold`` (see ``RuleInfo.severities``)."""
    ratio = observed / threshold if threshold > 0 else _STEP_RATIOS[-1]
    if ratio >= _STEP_RATIOS[1]:
        return rule.severities[2]
    if ratio >= _STEP_RATIOS[0]:
        return rule.severities[1]
    return rule.severities[0]


def _ist(timestamp: float) -> str:
    return format_ist(datetime.fromtimestamp(timestamp, tz=UTC))


def _span(first: float, last: float) -> str:
    return f"between {_ist(first)} and {_ist(last)}"


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else plural or singular + 's'}"


def _top(window: SlidingWindow, label: str, count: int = _MAX_SAMPLES) -> list[dict[str, Any]]:
    return [{"address": key, label: weight} for key, weight in window.top(count)]


def _observed_range(window: SlidingWindow, timestamp: float) -> tuple[float, float]:
    """First and last event time in the window, widened to include the packet that fired."""
    first = window.first_at if window.first_at is not None else timestamp
    last = window.last_at if window.last_at is not None else timestamp
    return min(first, timestamp), max(last, timestamp)


def _entries_cap(threshold: int) -> int:
    # Enough that a count can reach ten times its threshold (the top severity step) accurately.
    return max(2048, threshold * 12)


class RuleEngine:
    """Feeds packets to the rules and returns the alerts they raise.

    An alert is raised when a measurement first reaches its threshold. The same rule and source then
    stays quiet for one window, except that a worse severity step (3x, 10x the threshold) raises a
    further alert, so a growing attack is not hidden behind its first alert. At most
    ``max_alerts_per_session`` alerts (``max_alerts_per_rule`` for one rule) are raised; the
    rest are counted in ``alerts_suppressed``.
    """

    def __init__(self, config: NetworkRuleConfig) -> None:
        self._config = config
        tracked = max(config.max_tracked_sources, 1)
        self._scans: LruMap[str, _ScanState] = LruMap(tracked)
        self._connections: LruMap[str, SlidingWindow] = LruMap(tracked)
        self._syns: LruMap[str, SlidingWindow] = LruMap(tracked)
        self._volumes: LruMap[str, SlidingWindow] = LruMap(tracked)
        self._suspicious: LruMap[str, SlidingWindow] = LruMap(tracked)
        self._protocols_seen: LruMap[tuple[str, str, str], bool] = LruMap(tracked)
        self._cooldowns: LruMap[tuple[str, str], _Cooldown] = LruMap(tracked * 4)
        self._by_rule: Counter[str] = Counter()
        self.alerts_raised = 0
        self.alerts_suppressed = 0

    @property
    def alerts_by_rule(self) -> dict[str, int]:
        return dict(self._by_rule)

    def observe(self, packet: PacketMeta, *, new_flow: bool) -> list[RawAlert]:
        """Run every rule over one packet. ``new_flow`` says it started a flow."""
        found = [
            self._unexpected_protocol(packet)
            if packet.protocol not in self._config.expected_protocols
            else None,
            self._syn_rate(packet) if packet.is_pure_syn else None,
        ]
        if new_flow and packet.opens_connection:
            found.append(self._connection_rate(packet))
            if packet.dst_port is not None:
                found.append(self._port_scan(packet))
                if packet.dst_port in self._config.suspicious_ports:
                    found.append(self._suspicious_port(packet))
        found.append(self._high_volume(packet))
        return [alert for alert in found if alert is not None]

    # --- Rules --------------------------------------------------------------------

    def _port_scan(self, packet: PacketMeta) -> RawAlert | None:
        config = self._config
        threshold, window = config.port_scan_threshold, config.port_scan_window_seconds
        state = self._scans.get(packet.src_ip)
        if state is None:
            cap = _entries_cap(threshold)
            state = _ScanState(
                SlidingWindow(window, max_entries=cap), SlidingWindow(window, max_entries=cap)
            )
            self._scans.set(packet.src_ip, state)
        state.ports.add(packet.timestamp, packet.dst_port)
        state.targets.add(packet.timestamp, packet.dst_ip)
        unique_ports = state.ports.unique
        if unique_ports < threshold:
            return None
        severity = severity_for(PORT_SCAN, unique_ports, threshold)
        if not self._admit(PORT_SCAN, packet.src_ip, packet.timestamp, window, severity):
            return None
        targets = state.targets.unique
        first, last = _observed_range(state.ports, packet.timestamp)
        ports = sorted(port for port in state.ports if isinstance(port, int))
        return RawAlert(
            rule_id=PORT_SCAN.rule_id,
            rule_name=PORT_SCAN.name,
            severity=severity,
            explanation=(
                f"{packet.src_ip} tried {_plural(unique_ports, 'different destination port')} on "
                f"{_plural(targets, 'host')} within {window} seconds (threshold: {threshold} "
                f"ports), {_span(first, last)}."
            ),
            observed_value=unique_ports,
            threshold=threshold,
            window_seconds=window,
            first_observed=first,
            last_observed=last,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip if targets == 1 else None,
            dst_port=ports[0] if unique_ports == 1 and ports else None,
            protocol=packet.protocol,
            evidence={
                "unique_ports": unique_ports,
                "sample_ports": ports[:_MAX_SAMPLE_PORTS],
                "unique_targets": targets,
                "top_targets": _top(state.targets, "count"),
                "truncated": state.ports.truncated,
            },
        )

    def _connection_rate(self, packet: PacketMeta) -> RawAlert | None:
        config = self._config
        threshold, window = config.connection_rate_threshold, config.connection_rate_window_seconds
        tracker = self._tracker(self._connections, packet.src_ip, window, threshold)
        tracker.add(packet.timestamp, packet.dst_ip)
        count = tracker.total
        if count < threshold:
            return None
        severity = severity_for(CONNECTION_RATE, count, threshold)
        if not self._admit(CONNECTION_RATE, packet.src_ip, packet.timestamp, window, severity):
            return None
        first, last = _observed_range(tracker, packet.timestamp)
        destinations = tracker.unique
        return RawAlert(
            rule_id=CONNECTION_RATE.rule_id,
            rule_name=CONNECTION_RATE.name,
            severity=severity,
            explanation=(
                f"{packet.src_ip} opened {_plural(count, 'new connection')} to "
                f"{_plural(destinations, 'destination')} within {window} seconds (threshold: "
                f"{threshold}), {_span(first, last)}."
            ),
            observed_value=count,
            threshold=threshold,
            window_seconds=window,
            first_observed=first,
            last_observed=last,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip if destinations == 1 else None,
            protocol=packet.protocol,
            evidence={
                "new_flows": count,
                "unique_destinations": destinations,
                "top_destinations": _top(tracker, "count"),
                "truncated": tracker.truncated,
            },
        )

    def _syn_rate(self, packet: PacketMeta) -> RawAlert | None:
        config = self._config
        threshold, window = config.syn_rate_threshold, config.syn_rate_window_seconds
        tracker = self._tracker(self._syns, packet.src_ip, window, threshold)
        tracker.add(packet.timestamp, packet.dst_ip)
        count = tracker.total
        if count < threshold:
            return None
        severity = severity_for(SYN_RATE, count, threshold)
        if not self._admit(SYN_RATE, packet.src_ip, packet.timestamp, window, severity):
            return None
        first, last = _observed_range(tracker, packet.timestamp)
        destinations = tracker.unique
        return RawAlert(
            rule_id=SYN_RATE.rule_id,
            rule_name=SYN_RATE.name,
            severity=severity,
            explanation=(
                f"{packet.src_ip} sent {_plural(count, 'TCP SYN packet')} to "
                f"{_plural(destinations, 'destination')} within {window} seconds (threshold: "
                f"{threshold}), {_span(first, last)}."
            ),
            observed_value=count,
            threshold=threshold,
            window_seconds=window,
            first_observed=first,
            last_observed=last,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip if destinations == 1 else None,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
            evidence={
                "syn_packets": count,
                "unique_destinations": destinations,
                "top_destinations": _top(tracker, "count"),
                "truncated": tracker.truncated,
            },
        )

    def _high_volume(self, packet: PacketMeta) -> RawAlert | None:
        config = self._config
        threshold_bytes = config.high_volume_threshold_mb * _MB
        window = config.high_volume_window_seconds
        tracker = self._volumes.get(packet.src_ip)
        if tracker is None:
            tracker = SlidingWindow(window, max_entries=_entries_cap(window))
            self._volumes.set(packet.src_ip, tracker)
        tracker.add(packet.timestamp, packet.dst_ip, packet.length)
        sent = tracker.total
        if sent < threshold_bytes:
            return None
        severity = severity_for(HIGH_VOLUME, sent, threshold_bytes)
        if not self._admit(HIGH_VOLUME, packet.src_ip, packet.timestamp, window, severity):
            return None
        first, last = _observed_range(tracker, packet.timestamp)
        megabytes = round(sent / _MB, 2)
        destinations = tracker.unique
        return RawAlert(
            rule_id=HIGH_VOLUME.rule_id,
            rule_name=HIGH_VOLUME.name,
            severity=severity,
            explanation=(
                f"{packet.src_ip} sent {megabytes} MB to {_plural(destinations, 'destination')} "
                f"within {window} seconds (threshold: {config.high_volume_threshold_mb} MB), "
                f"{_span(first, last)}."
            ),
            observed_value=megabytes,
            threshold=config.high_volume_threshold_mb,
            window_seconds=window,
            first_observed=first,
            last_observed=last,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip if destinations == 1 else None,
            protocol=packet.protocol,
            evidence={
                "bytes": sent,
                "unique_destinations": destinations,
                "top_destinations": _top(tracker, "bytes"),
                "truncated": tracker.truncated,
            },
        )

    def _suspicious_port(self, packet: PacketMeta) -> RawAlert | None:
        config = self._config
        threshold, window = config.suspicious_port_threshold, config.suspicious_port_window_seconds
        tracker = self._tracker(self._suspicious, packet.src_ip, window, threshold)
        tracker.add(packet.timestamp, packet.dst_port)
        attempts = tracker.total
        if attempts < threshold:
            return None
        severity = severity_for(SUSPICIOUS_PORT, attempts, threshold)
        if not self._admit(SUSPICIOUS_PORT, packet.src_ip, packet.timestamp, window, severity):
            return None
        first, last = _observed_range(tracker, packet.timestamp)
        by_port = tracker.top(10)
        main_port = by_port[0][0] if by_port else packet.dst_port
        ports = tracker.unique
        return RawAlert(
            rule_id=SUSPICIOUS_PORT.rule_id,
            rule_name=SUSPICIOUS_PORT.name,
            severity=severity,
            explanation=(
                f"{packet.src_ip} made {_plural(attempts, 'connection attempt')} to "
                f"{_plural(ports, 'suspicious port')} within {window} seconds (threshold: "
                f"{threshold}), {_span(first, last)}."
            ),
            observed_value=attempts,
            threshold=threshold,
            window_seconds=window,
            first_observed=first,
            last_observed=last,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            dst_port=main_port if isinstance(main_port, int) else packet.dst_port,
            protocol=packet.protocol,
            evidence={
                "attempts": attempts,
                "unique_ports": ports,
                "by_port": [{"port": port, "attempts": weight} for port, weight in by_port],
                "truncated": tracker.truncated,
            },
        )

    def _unexpected_protocol(self, packet: PacketMeta) -> RawAlert | None:
        key = (packet.protocol, packet.src_ip, packet.dst_ip)
        # One alert per protocol and address pair for the session.
        if key in self._protocols_seen:
            return None
        self._protocols_seen.set(key, True)
        if not self._admit(UNEXPECTED_PROTOCOL, "|".join(key), packet.timestamp, None, None):
            return None
        expected = sorted(self._config.expected_protocols)
        name = packet.protocol.upper()
        return RawAlert(
            rule_id=UNEXPECTED_PROTOCOL.rule_id,
            rule_name=UNEXPECTED_PROTOCOL.name,
            severity=UNEXPECTED_PROTOCOL.severities[0],
            explanation=(
                f"{packet.src_ip} sent {name} traffic to {packet.dst_ip} at "
                f"{_ist(packet.timestamp)}. {name} is not on the expected protocol list "
                f"({', '.join(expected)})."
            ),
            observed_value=1,
            threshold=1,
            window_seconds=None,
            first_observed=packet.timestamp,
            last_observed=packet.timestamp,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
            evidence={"protocol": packet.protocol, "expected_protocols": expected},
        )

    # --- Support ------------------------------------------------------------------

    @staticmethod
    def _tracker(
        trackers: LruMap[str, SlidingWindow], source: str, window: int, threshold: int
    ) -> SlidingWindow:
        tracker = trackers.get(source)
        if tracker is None:
            tracker = SlidingWindow(window, max_entries=_entries_cap(threshold))
            trackers.set(source, tracker)
        return tracker

    def _admit(
        self,
        rule: RuleInfo,
        key: str,
        now: float,
        window: int | None,
        severity: AlertSeverity | None,
    ) -> bool:
        """Whether this measurement raises an alert: cooldown and escalation first, then caps."""
        if window is not None and severity is not None:
            rank = _SEVERITY_RANK[severity]
            cooldown = self._cooldowns.get((rule.rule_id, key))
            if cooldown is not None and now < cooldown.until and rank <= cooldown.rank:
                return False
            self._cooldowns.set((rule.rule_id, key), _Cooldown(now + window, rank))
        config = self._config
        if (
            self.alerts_raised >= config.max_alerts_per_session
            or self._by_rule[rule.rule_id] >= config.max_alerts_per_rule
        ):
            self.alerts_suppressed += 1
            return False
        self._by_rule[rule.rule_id] += 1
        self.alerts_raised += 1
        return True


def known_malicious_alert(
    *,
    address: str,
    risk_score: int,
    classification: str,
    minimum_score: int,
    providers: list[dict[str, Any]],
    peers: list[str],
    sent_to: bool,
    protocols: list[str],
    ports: list[int],
    packets: int,
    total_bytes: int,
    first_seen: float,
    last_seen: float,
) -> RawAlert:
    """NET-005: traffic involved ``address``, whose threat-intelligence score is high.

    ``sent_to`` says the monitored hosts sent traffic to the address, not only received from it.
    """
    severity = AlertSeverity.CRITICAL if classification == "critical" else AlertSeverity.HIGH
    peer = peers[0] if peers else None
    names = ", ".join(str(item.get("display_name") or item.get("provider")) for item in providers)
    direction = "sent traffic to" if sent_to else "received traffic from"
    return RawAlert(
        rule_id=KNOWN_MALICIOUS_IP.rule_id,
        rule_name=KNOWN_MALICIOUS_IP.name,
        severity=severity,
        explanation=(
            f"Monitored hosts {direction} {address}, which has a CipherForge risk score of "
            f"{risk_score}/100 ({classification}), at or above the configured minimum of "
            f"{minimum_score}. Providers that returned data: {names or 'none'}. "
            f"Traffic seen {_span(first_seen, last_seen)}."
        ),
        observed_value=risk_score,
        threshold=minimum_score,
        window_seconds=None,
        first_observed=min(first_seen, last_seen),
        last_observed=max(first_seen, last_seen),
        src_ip=peer if sent_to else address,
        dst_ip=address if sent_to else peer,
        dst_port=ports[0] if sent_to and ports else None,
        protocol=protocols[0] if protocols else None,
        evidence={
            "address": address,
            "risk_score": risk_score,
            "classification": classification,
            "providers": providers,
            "peers": peers,
            "ports": ports,
            "protocols": protocols,
            "packets": packets,
            "bytes": total_bytes,
        },
    )
