"""NET-001 to NET-007: thresholds, boundaries, severity steps, cooldowns, caps and evidence."""

import pytest

from app.detection.network_rules import (
    ALL_RULES,
    HIGH_VOLUME,
    PORT_SCAN,
    NetworkRuleConfig,
    RawAlert,
    RuleEngine,
    describe_rules,
    known_malicious_alert,
    severity_for,
)
from app.models.enums import AlertSeverity
from app.network.analyzer import Analyzer
from app.network.packets import TCP_ACK
from tests.network_helpers import T0, packet, syn

ATTACKER = "198.51.100.7"
VICTIM = "10.0.0.9"
MB = 1024 * 1024


def run(config: NetworkRuleConfig, packets) -> list[RawAlert]:
    analyzer = Analyzer(config, idle_timeout=60, max_flows=100_000)
    for item in packets:
        analyzer.process(item)
    return analyzer.take_output().alerts


def only(alerts: list[RawAlert], rule_id: str) -> list[RawAlert]:
    return [alert for alert in alerts if alert.rule_id == rule_id]


def scan(
    count: int, *, start: float = T0, gap: float = 0.1, src: str = ATTACKER, dst: str = VICTIM
):
    return [syn(start + index * gap, src, dst, 1000 + index) for index in range(count)]


class TestPortScan:
    def test_alerts_at_the_threshold_with_evidence(self):
        alerts = only(run(NetworkRuleConfig(), scan(20)), "NET-001")
        (alert,) = alerts
        assert alert.severity == AlertSeverity.MEDIUM
        assert (alert.observed_value, alert.threshold, alert.window_seconds) == (20, 20, 60)
        assert (alert.src_ip, alert.dst_ip, alert.protocol) == (ATTACKER, VICTIM, "tcp")
        assert alert.evidence["unique_ports"] == 20
        assert alert.evidence["sample_ports"][:3] == [1000, 1001, 1002]
        assert alert.evidence["unique_targets"] == 1
        assert alert.evidence["truncated"] is False
        assert "20 different destination ports" in alert.explanation
        assert "threshold: 20 ports" in alert.explanation
        assert "IST" in alert.explanation
        assert alert.first_observed <= alert.last_observed

    def test_one_port_below_the_threshold_is_quiet(self):
        assert only(run(NetworkRuleConfig(), scan(19)), "NET-001") == []

    def test_the_same_port_again_and_again_is_not_a_scan(self):
        repeated = [syn(T0 + i * 0.1, ATTACKER, VICTIM, 80, 40000 + i) for i in range(100)]
        assert only(run(NetworkRuleConfig(), repeated), "NET-001") == []

    def test_connections_that_are_already_established_are_not_counted(self):
        acks = [
            packet(T0 + i * 0.1, ATTACKER, VICTIM, sport=40000, dport=1000 + i, flags=TCP_ACK)
            for i in range(40)
        ]
        assert only(run(NetworkRuleConfig(), acks), "NET-001") == []

    def test_slow_scans_outside_the_window_are_not_flagged(self):
        slow = scan(30, gap=5.0)  # 30 ports over 145 s: never 20 inside 60 s
        assert only(run(NetworkRuleConfig(), slow), "NET-001") == []

    def test_udp_probes_count_too(self):
        probes = [
            packet(T0 + i * 0.1, ATTACKER, VICTIM, protocol="udp", sport=5000, dport=2000 + i)
            for i in range(20)
        ]
        (alert,) = only(run(NetworkRuleConfig(), probes), "NET-001")
        assert alert.protocol == "udp"

    def test_probes_without_the_ack_bit_count(self):
        probes = [
            packet(T0 + i * 0.1, ATTACKER, VICTIM, sport=5000, dport=2000 + i, flags=0x01)
            for i in range(20)
        ]
        assert len(only(run(NetworkRuleConfig(), probes), "NET-001")) == 1

    def test_one_alert_per_window_but_a_worse_step_escalates(self):
        alerts = only(run(NetworkRuleConfig(), scan(200)), "NET-001")
        assert [a.severity for a in alerts] == [
            AlertSeverity.MEDIUM,
            AlertSeverity.HIGH,
            AlertSeverity.CRITICAL,
        ]
        assert [a.observed_value for a in alerts] == [20, 60, 200]

    def test_a_sustained_scan_alerts_again_after_the_window(self):
        first = scan(20, start=T0)
        later = scan(20, start=T0 + 100)
        alerts = only(run(NetworkRuleConfig(), first + later), "NET-001")
        assert len(alerts) == 2

    def test_each_source_is_judged_alone(self):
        packets = scan(12, src="198.51.100.1") + scan(12, src="198.51.100.2", start=T0 + 0.05)
        assert only(run(NetworkRuleConfig(), packets), "NET-001") == []

    def test_a_scan_of_several_hosts_reports_no_single_target(self):
        packets = [syn(T0 + i * 0.1, ATTACKER, f"10.0.0.{10 + i % 4}", 1000 + i) for i in range(20)]
        (alert,) = only(run(NetworkRuleConfig(), packets), "NET-001")
        assert alert.dst_ip is None
        assert alert.evidence["unique_targets"] == 4

    def test_replaying_the_same_traffic_gives_identical_alerts(self):
        packets = scan(80)
        assert run(NetworkRuleConfig(), packets) == run(NetworkRuleConfig(), packets)

    def test_thresholds_come_from_the_configuration(self):
        config = NetworkRuleConfig(port_scan_threshold=5, port_scan_window_seconds=10)
        (alert,) = only(run(config, scan(5)), "NET-001")
        assert (alert.threshold, alert.window_seconds) == (5, 10)


class TestConnectionRate:
    def test_alerts_at_the_threshold(self):
        packets = [syn(T0 + i * 0.1, ATTACKER, VICTIM, 80, 20000 + i) for i in range(100)]
        (alert,) = only(run(NetworkRuleConfig(), packets), "NET-002")
        assert alert.severity == AlertSeverity.LOW
        assert alert.observed_value == 100
        assert alert.evidence["new_flows"] == 100
        assert alert.evidence["top_destinations"] == [{"address": VICTIM, "count": 100}]

    def test_one_connection_below_the_threshold_is_quiet(self):
        packets = [syn(T0 + i * 0.1, ATTACKER, VICTIM, 80, 20000 + i) for i in range(99)]
        assert only(run(NetworkRuleConfig(), packets), "NET-002") == []

    def test_packets_of_one_connection_are_not_new_connections(self):
        packets = [syn(T0 + i * 0.01, ATTACKER, VICTIM, 80, 20000) for i in range(500)]
        assert only(run(NetworkRuleConfig(), packets), "NET-002") == []

    def test_severity_steps_up(self):
        packets = [syn(T0 + i * 0.01, ATTACKER, VICTIM, 80, 20000 + i) for i in range(1000)]
        alerts = only(run(NetworkRuleConfig(), packets), "NET-002")
        assert [a.severity for a in alerts] == [
            AlertSeverity.LOW,
            AlertSeverity.MEDIUM,
            AlertSeverity.HIGH,
        ]


class TestSynRate:
    def test_counts_pure_syns_including_retransmissions(self):
        packets = [syn(T0 + i * 0.01, ATTACKER, VICTIM, 80, 30000) for i in range(200)]
        (alert,) = only(run(NetworkRuleConfig(), packets), "NET-003")
        assert alert.severity == AlertSeverity.MEDIUM
        assert (alert.observed_value, alert.window_seconds) == (200, 10)
        assert alert.dst_port == 80

    def test_one_below_the_threshold_is_quiet(self):
        packets = [syn(T0 + i * 0.01, ATTACKER, VICTIM, 80, 30000) for i in range(199)]
        assert only(run(NetworkRuleConfig(), packets), "NET-003") == []

    def test_a_slow_trickle_stays_under_the_threshold(self):
        packets = [syn(T0 + i * 0.1, ATTACKER, VICTIM, 80, 30000 + i) for i in range(300)]
        assert only(run(NetworkRuleConfig(), packets), "NET-003") == []

    def test_syn_acks_from_a_busy_server_are_not_counted(self):
        packets = [
            packet(T0 + i * 0.001, VICTIM, ATTACKER, sport=80, dport=30000 + i, flags=0x12)
            for i in range(1000)
        ]
        assert only(run(NetworkRuleConfig(), packets), "NET-003") == []


class TestHighVolume:
    def test_alerts_when_a_source_sends_the_threshold_within_the_window(self):
        packets = [packet(T0 + i, ATTACKER, VICTIM, flags=TCP_ACK, length=MB) for i in range(50)]
        (alert,) = only(run(NetworkRuleConfig(), packets), "NET-004")
        assert alert.severity == AlertSeverity.LOW
        assert alert.observed_value == 50.0
        assert alert.threshold == 50
        assert alert.evidence["bytes"] == 50 * MB
        assert alert.evidence["top_destinations"] == [{"address": VICTIM, "bytes": 50 * MB}]
        assert "50.0 MB" in alert.explanation

    def test_one_byte_under_is_quiet(self):
        packets = [packet(T0 + i, ATTACKER, VICTIM, flags=TCP_ACK, length=MB) for i in range(49)]
        packets.append(packet(T0 + 49, ATTACKER, VICTIM, flags=TCP_ACK, length=MB - 1))
        assert only(run(NetworkRuleConfig(), packets), "NET-004") == []

    def test_the_same_data_spread_over_a_longer_time_is_quiet(self):
        packets = [
            packet(T0 + i * 2, ATTACKER, VICTIM, flags=TCP_ACK, length=MB) for i in range(50)
        ]
        assert only(run(NetworkRuleConfig(), packets), "NET-004") == []

    def test_data_received_does_not_count_against_a_host(self):
        packets = [packet(T0 + i, VICTIM, ATTACKER, flags=TCP_ACK, length=MB) for i in range(60)]
        alerts = only(run(NetworkRuleConfig(), packets), "NET-004")
        assert {a.src_ip for a in alerts} == {VICTIM}

    def test_ten_times_the_threshold_is_high(self):
        packets = [
            packet(T0 + i, ATTACKER, VICTIM, flags=TCP_ACK, length=10 * MB) for i in range(50)
        ]
        alerts = only(run(NetworkRuleConfig(), packets), "NET-004")
        assert alerts[-1].severity == AlertSeverity.HIGH


class TestSuspiciousPort:
    def test_alerts_after_repeated_attempts_to_listed_ports(self):
        packets = [syn(T0 + i * 0.1, ATTACKER, VICTIM, 3389, 20000 + i) for i in range(25)]
        (alert,) = only(run(NetworkRuleConfig(), packets), "NET-006")
        assert alert.severity == AlertSeverity.MEDIUM
        assert (alert.observed_value, alert.threshold) == (25, 25)
        assert alert.dst_port == 3389
        assert alert.evidence["by_port"] == [{"port": 3389, "attempts": 25}]

    def test_attempts_are_summed_over_the_listed_ports(self):
        ports = [23, 445, 3389, 4444, 5900]
        packets = [syn(T0 + i * 0.1, ATTACKER, VICTIM, ports[i % 5], 20000 + i) for i in range(25)]
        (alert,) = only(run(NetworkRuleConfig(), packets), "NET-006")
        assert alert.evidence["unique_ports"] == 5

    def test_ordinary_ports_are_ignored(self):
        packets = [syn(T0 + i * 0.1, ATTACKER, VICTIM, 8080, 20000 + i) for i in range(60)]
        assert only(run(NetworkRuleConfig(), packets), "NET-006") == []

    def test_the_list_is_configurable(self):
        config = NetworkRuleConfig(suspicious_ports=frozenset({8080}), suspicious_port_threshold=3)
        packets = [syn(T0 + i * 0.1, ATTACKER, VICTIM, 8080, 20000 + i) for i in range(3)]
        assert len(only(run(config, packets), "NET-006")) == 1

    def test_severity_is_capped_at_high(self):
        packets = [syn(T0 + i * 0.01, ATTACKER, VICTIM, 445, 20000 + i) for i in range(600)]
        severities = {a.severity for a in only(run(NetworkRuleConfig(), packets), "NET-006")}
        assert severities == {AlertSeverity.MEDIUM, AlertSeverity.HIGH}


class TestUnexpectedProtocol:
    def test_alerts_once_per_protocol_and_address_pair(self):
        packets = [packet(T0 + i, ATTACKER, VICTIM, protocol="gre") for i in range(10)]
        (alert,) = only(run(NetworkRuleConfig(), packets), "NET-007")
        assert alert.severity == AlertSeverity.LOW
        assert alert.protocol == "gre"
        assert alert.window_seconds is None
        assert "GRE" in alert.explanation
        assert alert.evidence["expected_protocols"] == ["icmp", "icmpv6", "igmp", "tcp", "udp"]

    def test_another_pair_alerts_separately(self):
        packets = [
            packet(T0, ATTACKER, VICTIM, protocol="gre"),
            packet(T0 + 1, ATTACKER, "10.0.0.10", protocol="gre"),
            packet(T0 + 2, ATTACKER, VICTIM, protocol="esp"),
        ]
        assert len(only(run(NetworkRuleConfig(), packets), "NET-007")) == 3

    def test_expected_protocols_are_quiet(self):
        packets = [
            packet(T0, protocol="tcp"),
            packet(T0, protocol="udp"),
            packet(T0, protocol="icmp"),
        ]
        assert only(run(NetworkRuleConfig(), packets), "NET-007") == []

    def test_adding_a_protocol_to_the_expected_list_silences_it(self):
        config = NetworkRuleConfig(expected_protocols=frozenset({"tcp", "gre"}))
        assert only(run(config, [packet(T0, protocol="gre")]), "NET-007") == []


class TestCaps:
    def test_alerts_per_rule_are_capped_and_the_rest_counted(self):
        config = NetworkRuleConfig(max_alerts_per_rule=3, max_alerts_per_session=100)
        engine = RuleEngine(config)
        raised = []
        for index in range(10):
            flow_packet = packet(T0 + index, f"198.51.100.{index}", VICTIM, protocol="gre")
            raised += engine.observe(flow_packet, new_flow=True)
        assert len(raised) == 3
        assert engine.alerts_suppressed == 7
        assert engine.alerts_by_rule == {"NET-007": 3}

    def test_alerts_per_session_are_capped(self):
        config = NetworkRuleConfig(max_alerts_per_rule=100, max_alerts_per_session=4)
        engine = RuleEngine(config)
        total = 0
        for index in range(10):
            total += len(
                engine.observe(
                    packet(T0 + index, f"198.51.100.{index}", VICTIM, protocol="gre"),
                    new_flow=True,
                )
            )
        assert total == 4
        assert engine.alerts_suppressed == 6

    def test_a_suppressed_burst_is_counted_once_per_window_not_per_packet(self):
        config = NetworkRuleConfig(max_alerts_per_session=0)
        engine = RuleEngine(config)
        for packet_ in scan(100):
            engine.observe(packet_, new_flow=True)
        assert engine.alerts_raised == 0
        assert engine.alerts_suppressed < 20

    def test_tracked_sources_are_bounded(self):
        engine = RuleEngine(NetworkRuleConfig(max_tracked_sources=50))
        for index in range(500):
            engine.observe(
                syn(T0 + index * 0.01, f"203.0.113.{index % 250}", VICTIM, 80, index), new_flow=True
            )
        assert len(engine._scans) <= 50


class TestSeverityAndMetadata:
    @pytest.mark.parametrize(
        ("observed", "expected"),
        [
            (20, AlertSeverity.MEDIUM),
            (59, AlertSeverity.MEDIUM),
            (60, AlertSeverity.HIGH),
            (199, AlertSeverity.HIGH),
            (200, AlertSeverity.CRITICAL),
        ],
    )
    def test_port_scan_steps_at_3x_and_10x(self, observed, expected):
        assert severity_for(PORT_SCAN, observed, 20) == expected

    def test_volume_never_exceeds_high(self):
        assert severity_for(HIGH_VOLUME, 10_000, 50) == AlertSeverity.HIGH

    def test_every_rule_is_described_with_its_configured_threshold(self):
        settings = describe_rules(NetworkRuleConfig(port_scan_threshold=7))
        assert [item.info.rule_id for item in settings] == [r.rule_id for r in ALL_RULES]
        assert [item.info.rule_id for item in settings] == [f"NET-00{n}" for n in range(1, 8)]
        assert settings[0].threshold == 7
        assert next(s for s in settings if s.info.rule_id == "NET-005").info.needs_enrichment


class TestKnownMaliciousAlert:
    def _alert(self, **overrides) -> RawAlert:
        base = {
            "address": "203.0.113.50",
            "risk_score": 88,
            "classification": "high",
            "minimum_score": 61,
            "providers": [{"provider": "abuseipdb", "display_name": "AbuseIPDB"}],
            "peers": ["10.0.0.5"],
            "sent_to": True,
            "protocols": ["tcp"],
            "ports": [443],
            "packets": 12,
            "total_bytes": 4096,
            "first_seen": T0,
            "last_seen": T0 + 30,
        }
        return known_malicious_alert(**{**base, **overrides})

    def test_outbound_traffic_orients_source_and_destination(self):
        alert = self._alert()
        assert (alert.src_ip, alert.dst_ip, alert.dst_port) == ("10.0.0.5", "203.0.113.50", 443)
        assert alert.rule_id == "NET-005"
        assert alert.severity == AlertSeverity.HIGH
        assert (alert.observed_value, alert.threshold) == (88, 61)
        assert "88/100" in alert.explanation
        assert "AbuseIPDB" in alert.explanation

    def test_inbound_traffic_makes_the_address_the_source(self):
        alert = self._alert(sent_to=False)
        assert (alert.src_ip, alert.dst_ip, alert.dst_port) == ("203.0.113.50", "10.0.0.5", None)

    def test_a_critical_score_is_critical(self):
        assert self._alert(classification="critical").severity == AlertSeverity.CRITICAL

    def test_the_evidence_is_json_friendly(self):
        import json

        json.dumps(self._alert().evidence)
