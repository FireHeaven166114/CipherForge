"""The per-session analyzer: statistics, external peers, bounds and the flow/alert hand-over."""

import json

from app.detection.network_rules import NetworkRuleConfig
from app.models.enums import FlowCloseReason
from app.network.analyzer import Analyzer
from tests.network_helpers import T0, packet, syn

PUBLIC = "8.8.8.8"
OTHER_PUBLIC = "1.1.1.1"
LAN = "10.0.0.5"
LAN_2 = "10.0.0.9"


def make(**overrides) -> Analyzer:
    options = {"idle_timeout": 60, "max_flows": 1000, **overrides}
    return Analyzer(NetworkRuleConfig(), **options)


class TestStatistics:
    def test_totals_protocols_and_talkers(self):
        analyzer = make()
        analyzer.process(packet(T0 + 2, LAN, LAN_2, length=100))
        analyzer.process(packet(T0, LAN, LAN_2, protocol="udp", length=900))
        analyzer.process(packet(T0 + 1, LAN_2, LAN, length=500))
        snapshot = analyzer.snapshot()

        assert (snapshot.packets, snapshot.bytes) == (3, 1500)
        assert (snapshot.first_packet_at, snapshot.last_packet_at) == (T0, T0 + 2)
        assert snapshot.protocols == [("udp", 1, 900), ("tcp", 2, 600)]
        assert [(s.key, s.packets, s.bytes) for s in snapshot.top_sources] == [
            (LAN, 2, 1000),
            (LAN_2, 1, 500),
        ]
        assert [(s.key, s.bytes) for s in snapshot.top_destinations] == [(LAN_2, 1000), (LAN, 500)]
        assert snapshot.flows_total == 3
        assert snapshot.active_flows == 3

    def test_packets_that_were_not_analysed_are_counted_separately(self):
        analyzer = make()
        analyzer.note_non_ip(3)
        analyzer.note_malformed()
        analyzer.process(packet(T0))
        snapshot = analyzer.snapshot()
        assert (snapshot.non_ip_packets, snapshot.malformed_packets, snapshot.packets) == (3, 1, 1)

    def test_only_the_ten_heaviest_talkers_are_listed(self):
        analyzer = make()
        for index in range(25):
            analyzer.process(
                packet(T0 + index, f"10.1.0.{index + 1}", LAN_2, length=100 + index, sport=1000)
            )
        top = analyzer.snapshot().top_sources
        assert len(top) == 10
        assert top[0].key == "10.1.0.25"
        assert [item.bytes for item in top] == sorted((item.bytes for item in top), reverse=True)

    def test_the_stored_statistics_are_plain_json_with_utc_iso_timestamps(self):
        analyzer = make()
        analyzer.process(packet(T0, PUBLIC, LAN))
        stats = analyzer.snapshot().as_stats()
        assert json.loads(json.dumps(stats)) == stats
        assert stats["first_packet_at"] == "2026-01-15T10:00:00+00:00"
        assert stats["protocols"] == [{"protocol": "tcp", "packets": 1, "bytes": 60}]
        assert stats["top_sources"] == [{"address": PUBLIC, "packets": 1, "bytes": 60}]
        assert stats["alerts_by_rule"] == {}

    def test_an_empty_session_has_empty_statistics(self):
        stats = make().snapshot().as_stats()
        assert stats["first_packet_at"] is None
        assert stats["protocols"] == []
        assert stats["top_sources"] == []

    def test_the_talker_tables_are_bounded_and_keep_the_heaviest(self):
        analyzer = make(max_talkers=8)
        for index in range(60):
            analyzer.process(packet(T0 + index * 0.01, f"10.2.0.{index + 1}", LAN_2, length=100))
        analyzer.process(packet(T0 + 1, "10.3.0.1", LAN_2, length=100_000))
        snapshot = analyzer.snapshot()
        assert snapshot.talkers_truncated is True
        assert snapshot.top_sources[0].key == "10.3.0.1"
        assert analyzer.snapshot().as_stats()["talkers_truncated"] is True


class TestExternalPeers:
    def test_private_traffic_has_no_external_peers(self):
        analyzer = make()
        analyzer.process(packet(T0, LAN, LAN_2))
        assert analyzer.enrichment_candidates(10, ()) == []
        assert analyzer.peer(LAN) is None

    def test_direction_is_remembered(self):
        analyzer = make()
        analyzer.process(packet(T0, LAN, PUBLIC, dport=443))
        analyzer.process(packet(T0 + 1, OTHER_PUBLIC, LAN, sport=22, dport=50000))
        sent_to = analyzer.peer(PUBLIC)
        received_from = analyzer.peer(OTHER_PUBLIC)
        assert sent_to is not None
        assert received_from is not None
        assert sent_to.sent_to is True
        assert received_from.sent_to is False
        assert sent_to.peers == [LAN]
        assert sent_to.ports == [443]
        assert received_from.ports == [22]
        assert (sent_to.packets, sent_to.bytes) == (1, 60)

    def test_what_is_remembered_about_a_peer_is_small_and_without_duplicates(self):
        analyzer = make()
        for index in range(12):
            analyzer.process(
                packet(T0 + index, f"10.0.1.{index + 1}", PUBLIC, dport=400 + index % 8)
            )
            analyzer.process(packet(T0 + index, "10.0.1.1", PUBLIC, dport=400, protocol="udp"))
        peer = analyzer.peer(PUBLIC)
        assert peer is not None
        assert len(peer.peers) == 5
        assert len(peer.ports) == 5
        assert sorted(peer.protocols) == ["tcp", "udp"]
        assert len(set(peer.peers)) == 5

    def test_the_caller_gets_a_copy(self):
        analyzer = make()
        analyzer.process(packet(T0, LAN, PUBLIC))
        analyzer.peer(PUBLIC).peers.append("tampered")
        analyzer.enrichment_candidates(5, ())[0].ports.append(1)
        fresh = analyzer.peer(PUBLIC)
        assert fresh is not None
        assert fresh.peers == [LAN]
        assert fresh.ports == [80]

    def test_the_peer_table_is_bounded_and_forgets_the_least_recent(self):
        analyzer = make(max_peers=3)
        for index in range(10):
            analyzer.process(packet(T0 + index, LAN, f"9.9.9.{index + 1}"))
        assert analyzer.peer("9.9.9.1") is None
        assert analyzer.peer("9.9.9.10") is not None
        assert len(analyzer.enrichment_candidates(100, ())) == 3

    def test_candidates_are_ranked_by_traffic_and_can_exclude_what_is_done(self):
        analyzer = make()
        analyzer.process(packet(T0, LAN, "9.9.9.1", length=100))
        analyzer.process(packet(T0, LAN, "9.9.9.2", length=900))
        analyzer.process(packet(T0, LAN, "9.9.9.3", length=500))
        ranked = [peer.address for peer in analyzer.enrichment_candidates(10, ())]
        assert ranked == ["9.9.9.2", "9.9.9.3", "9.9.9.1"]
        assert [p.address for p in analyzer.enrichment_candidates(2, ())] == ranked[:2]
        assert [p.address for p in analyzer.enrichment_candidates(10, {"9.9.9.2"})] == [
            "9.9.9.3",
            "9.9.9.1",
        ]
        assert analyzer.enrichment_candidates(0, ()) == []
        assert analyzer.enrichment_candidates(-3, ()) == []

    def test_an_address_in_an_alert_goes_to_the_front_of_the_queue(self):
        analyzer = make()
        analyzer.process(packet(T0, LAN, "9.9.9.1", length=9000))
        for index in range(25):
            analyzer.process(syn(T0 + 1 + index * 0.1, PUBLIC, LAN, 1000 + index))
        (first, second) = analyzer.enrichment_candidates(2, ())
        assert first.address == PUBLIC
        assert first.alerted is True
        assert second.alerted is False

    def test_the_subject_of_an_alert_is_its_public_end(self):
        from app.detection.network_rules import known_malicious_alert

        analyzer = make()

        def alert(**overrides):
            base = {
                "address": PUBLIC,
                "risk_score": 90,
                "classification": "high",
                "minimum_score": 61,
                "providers": [],
                "peers": [LAN],
                "sent_to": True,
                "protocols": ["tcp"],
                "ports": [443],
                "packets": 1,
                "total_bytes": 60,
                "first_seen": T0,
                "last_seen": T0,
            }
            return known_malicious_alert(**{**base, **overrides})

        assert analyzer.alert_subject(alert()) == PUBLIC
        assert analyzer.alert_subject(alert(sent_to=False)) == PUBLIC
        assert analyzer.alert_subject(alert(address=LAN, peers=[LAN_2])) is None


class TestHandOver:
    def test_flows_and_alerts_are_handed_over_once(self):
        analyzer = make()
        for index in range(20):
            analyzer.process(syn(T0 + index * 0.1, PUBLIC, LAN, 1000 + index))
        analyzer.finish()
        output = analyzer.take_output()
        assert [alert.rule_id for alert in output.alerts] == ["NET-001"]
        assert len(output.flows) == 20
        assert {flow.close_reason for flow in output.flows} == {FlowCloseReason.ENDED}
        again = analyzer.take_output()
        assert (again.alerts, again.flows) == ([], [])

    def test_the_alert_count_survives_the_hand_over(self):
        analyzer = make()
        for index in range(20):
            analyzer.process(syn(T0 + index * 0.1, PUBLIC, LAN, 1000 + index))
        analyzer.take_output()
        snapshot = analyzer.snapshot()
        assert snapshot.alerts_total == 1
        assert snapshot.alerts_by_rule == {"NET-001": 1}

    def test_advancing_time_finishes_idle_flows_only(self):
        analyzer = make(idle_timeout=30)
        analyzer.process(syn(T0, LAN, LAN_2, 80, 5000))
        analyzer.process(syn(T0 + 40, LAN, LAN_2, 81, 5001))
        analyzer.advance(T0 + 45)
        output = analyzer.take_output()
        assert [flow.dst_port for flow in output.flows] == [80]
        assert output.flows[0].close_reason == FlowCloseReason.IDLE
        assert analyzer.active_flows == 1

    def test_the_flow_limit_is_reported(self):
        analyzer = make(max_flows=5)
        for index in range(20):
            analyzer.process(syn(T0 + index, LAN, LAN_2, 80, 5000 + index))
        snapshot = analyzer.snapshot()
        assert snapshot.active_flows == 5
        assert snapshot.flows_evicted == 15
        assert snapshot.flows_total == 20
