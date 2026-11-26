"""Sliding windows, the LRU map and the flow table."""

import pytest

from app.models.enums import FlowCloseReason
from app.network.flows import FlowTable, flow_key
from app.network.packets import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN
from app.network.windows import LruMap, SlidingWindow
from tests.network_helpers import T0, packet, syn


class TestSlidingWindow:
    def test_counts_only_the_events_inside_the_window(self):
        window = SlidingWindow(10)
        for second in range(15):
            window.add(T0 + second)
        assert window.total == 10

    def test_unique_keys_and_weights(self):
        window = SlidingWindow(60)
        window.add(T0, "a", 5)
        window.add(T0 + 1, "b", 2)
        window.add(T0 + 2, "a", 1)
        assert (window.total, window.unique) == (8, 2)
        assert window.top(1) == [("a", 6)]
        assert sorted(window) == ["a", "b"]

    def test_a_key_leaves_when_its_last_event_expires(self):
        window = SlidingWindow(5)
        window.add(T0, "old")
        window.add(T0 + 10, "new")
        assert sorted(window) == ["new"]
        assert window.unique == 1

    def test_expire_forgets_everything_after_a_quiet_spell(self):
        window = SlidingWindow(5)
        window.add(T0, "x")
        window.expire(T0 + 100)
        assert (window.total, window.unique, window.first_at) == (0, 0, None)

    def test_the_edge_is_accurate_to_one_second(self):
        window = SlidingWindow(10)
        window.add(T0)
        window.add(T0 + 9.9)
        assert window.total == 2
        window.add(T0 + 10.0)
        assert window.total == 2

    def test_a_late_event_is_counted_in_the_newest_second(self):
        window = SlidingWindow(10)
        window.add(T0 + 5, "now")
        window.add(T0 + 2, "late")
        assert window.total == 2
        assert window.first_at == T0 + 2

    def test_an_event_older_than_the_window_is_ignored(self):
        window = SlidingWindow(10)
        window.add(T0 + 50, "now")
        window.add(T0, "ancient")
        assert (window.total, window.unique) == (1, 1)

    def test_first_and_last_event_times(self):
        window = SlidingWindow(30)
        window.add(T0 + 1.25)
        window.add(T0 + 4.75)
        assert (window.first_at, window.last_at) == (T0 + 1.25, T0 + 4.75)

    def test_memory_is_bounded_and_the_oldest_seconds_go_first(self):
        window = SlidingWindow(1000, max_entries=50)
        for index in range(200):
            window.add(T0 + index, f"key-{index}")
        assert window.truncated
        assert window.unique <= 50
        assert "key-199" in set(window)
        assert "key-0" not in set(window)

    def test_one_second_with_many_keys_is_not_dropped_entirely(self):
        window = SlidingWindow(60, max_entries=10)
        for index in range(100):
            window.add(T0, index)
        assert window.total == 100

    def test_a_window_must_be_at_least_one_second(self):
        with pytest.raises(ValueError, match="at least 1"):
            SlidingWindow(0)


class TestLruMap:
    def test_the_least_recently_used_entry_goes_first(self):
        cache: LruMap[str, int] = LruMap(2)
        cache.set("a", 1)
        cache.set("b", 2)
        assert cache.get("a") == 1
        cache.set("c", 3)
        assert "b" not in cache
        assert (cache.peek("a"), cache.peek("c")) == (1, 3)
        assert len(cache) == 2

    def test_peek_does_not_refresh(self):
        cache: LruMap[str, int] = LruMap(2)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.peek("a")
        cache.set("c", 3)
        assert "a" not in cache

    def test_pop_and_listing(self):
        cache: LruMap[str, int] = LruMap(3)
        cache.set("a", 1)
        cache.set("b", 2)
        assert cache.pop("a") == 1
        assert cache.pop("a") is None
        assert cache.items() == [("b", 2)]
        assert cache.values() == [2]

    def test_size_must_be_positive(self):
        with pytest.raises(ValueError, match="at least 1"):
            LruMap(0)


def _table(idle: float = 60, max_flows: int = 100) -> FlowTable:
    return FlowTable(idle_timeout=idle, max_flows=max_flows)


class TestFlowKey:
    def test_both_directions_share_a_key(self):
        forward = packet(T0, "10.0.0.1", "10.0.0.2", sport=1111, dport=80)
        reverse = packet(T0, "10.0.0.2", "10.0.0.1", sport=80, dport=1111)
        assert flow_key(forward) == flow_key(reverse)

    def test_different_ports_are_different_flows(self):
        one = packet(T0, sport=1111, dport=80)
        other = packet(T0, sport=1112, dport=80)
        assert flow_key(one) != flow_key(other)

    def test_protocol_is_part_of_the_key(self):
        assert flow_key(packet(T0, protocol="tcp")) != flow_key(
            packet(T0, protocol="udp", sport=40000, dport=80)
        )


class TestFlowTable:
    def test_a_conversation_is_one_flow_oriented_by_its_first_packet(self):
        table = _table()
        assert table.observe(syn(T0, "10.0.0.1", "10.0.0.2", 80, 5000)) is True
        reply = packet(
            T0 + 0.1, "10.0.0.2", "10.0.0.1", sport=80, dport=5000, flags=TCP_SYN | TCP_ACK
        )
        assert table.observe(reply) is False
        table.flush()
        (flow,) = table.take_finished()
        assert (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port) == (
            "10.0.0.1",
            5000,
            "10.0.0.2",
            80,
        )
        assert (flow.packets_out, flow.packets_in) == (1, 1)
        assert (flow.bytes_out, flow.bytes_in) == (60, 60)
        assert flow.tcp_flags == TCP_SYN | TCP_ACK
        assert flow.close_reason == FlowCloseReason.ENDED
        assert table.flows_seen == 1

    def test_non_tcp_flows_have_no_flags(self):
        table = _table()
        table.observe(packet(T0, protocol="icmp"))
        table.flush()
        (flow,) = table.take_finished()
        assert flow.tcp_flags is None
        assert flow.src_port is None

    def test_fins_in_both_directions_close_the_connection(self):
        table = _table()
        table.observe(syn(T0, "10.0.0.1", "10.0.0.2", 80, 5000))
        table.observe(
            packet(T0 + 1, "10.0.0.1", "10.0.0.2", sport=5000, dport=80, flags=TCP_FIN | TCP_ACK)
        )
        assert table.active_count == 1
        table.observe(
            packet(T0 + 2, "10.0.0.2", "10.0.0.1", sport=80, dport=5000, flags=TCP_FIN | TCP_ACK)
        )
        assert table.active_count == 0
        assert len(table) == 1

    def test_a_reset_closes_the_connection(self):
        table = _table()
        table.observe(syn(T0, "10.0.0.1", "10.0.0.2", 80, 5000))
        table.observe(packet(T0 + 1, "10.0.0.2", "10.0.0.1", sport=80, dport=5000, flags=TCP_RST))
        assert table.active_count == 0

    def test_trailing_acks_after_a_close_do_not_start_a_new_flow(self):
        table = _table()
        table.observe(syn(T0, "10.0.0.1", "10.0.0.2", 80, 5000))
        table.observe(packet(T0 + 1, "10.0.0.1", "10.0.0.2", sport=5000, dport=80, flags=TCP_RST))
        started = table.observe(
            packet(T0 + 2, "10.0.0.2", "10.0.0.1", sport=80, dport=5000, flags=TCP_ACK)
        )
        assert started is False
        assert table.flows_seen == 1

    def test_a_new_handshake_on_a_closed_pair_is_a_new_flow(self):
        table = _table()
        table.observe(syn(T0, "10.0.0.1", "10.0.0.2", 80, 5000))
        table.observe(packet(T0 + 1, "10.0.0.1", "10.0.0.2", sport=5000, dport=80, flags=TCP_RST))
        assert table.observe(syn(T0 + 5, "10.0.0.1", "10.0.0.2", 80, 5000)) is True
        (old,) = table.take_finished()
        assert old.close_reason == FlowCloseReason.CLOSED
        assert table.flows_seen == 2

    def test_a_repeated_syn_on_an_open_flow_is_not_a_new_flow(self):
        table = _table()
        table.observe(syn(T0, "10.0.0.1", "10.0.0.2", 80, 5000))
        assert table.observe(syn(T0 + 3, "10.0.0.1", "10.0.0.2", 80, 5000)) is False

    def test_idle_flows_are_finished_by_a_sweep(self):
        table = _table(idle=30)
        table.observe(syn(T0, "10.0.0.1", "10.0.0.2", 80))
        table.sweep(T0 + 29)
        assert table.take_finished() == []
        table.sweep(T0 + 31)
        (flow,) = table.take_finished()
        assert flow.close_reason == FlowCloseReason.IDLE
        assert len(table) == 0

    def test_activity_keeps_a_flow_alive(self):
        table = _table(idle=30)
        table.observe(syn(T0, "10.0.0.1", "10.0.0.2", 80, 5000))
        table.observe(packet(T0 + 25, "10.0.0.2", "10.0.0.1", sport=80, dport=5000, flags=TCP_ACK))
        table.sweep(T0 + 40)
        assert table.take_finished() == []

    def test_a_closed_flow_leaves_with_reason_closed_at_the_idle_timeout(self):
        table = _table(idle=30)
        table.observe(syn(T0, "10.0.0.1", "10.0.0.2", 80, 5000))
        table.observe(packet(T0 + 1, "10.0.0.2", "10.0.0.1", sport=80, dport=5000, flags=TCP_RST))
        table.sweep(T0 + 60)
        (flow,) = table.take_finished()
        assert flow.close_reason == FlowCloseReason.CLOSED

    def test_a_packet_after_the_idle_timeout_starts_a_new_flow_even_without_a_sweep(self):
        table = _table(idle=30)
        assert table.observe(syn(T0, "10.0.0.1", "10.0.0.2", 80, 5000)) is True
        assert table.observe(syn(T0 + 30, "10.0.0.1", "10.0.0.2", 80, 5000)) is False
        assert table.observe(syn(T0 + 61, "10.0.0.1", "10.0.0.2", 80, 5000)) is True
        (stale,) = table.take_finished()
        assert stale.close_reason == FlowCloseReason.IDLE
        assert (stale.first_seen, stale.last_seen, stale.packets) == (T0, T0 + 30, 2)
        assert table.flows_seen == 2
        assert len(table) == 1

    def test_the_stale_flow_that_is_replaced_keeps_the_reason_closed_if_it_had_ended(self):
        table = _table(idle=30)
        table.observe(syn(T0, "10.0.0.1", "10.0.0.2", 80, 5000))
        table.observe(packet(T0 + 1, "10.0.0.2", "10.0.0.1", sport=80, dport=5000, flags=TCP_RST))
        assert table.observe(packet(T0 + 90, "10.0.0.2", "10.0.0.1", sport=80, dport=5000)) is True
        (old,) = table.take_finished()
        assert old.close_reason == FlowCloseReason.CLOSED
        assert table.active_count == 1

    def test_an_out_of_order_packet_does_not_expire_a_flow(self):
        table = _table(idle=30)
        table.observe(syn(T0 + 100, "10.0.0.1", "10.0.0.2", 80, 5000))
        assert table.observe(syn(T0, "10.0.0.1", "10.0.0.2", 80, 5000)) is False
        assert table.take_finished() == []

    def test_the_table_is_bounded_and_evicts_the_least_recent_open_flow(self):
        table = _table(max_flows=3)
        for index in range(5):
            table.observe(syn(T0 + index, "10.0.0.1", "10.0.0.2", 1000 + index))
        assert len(table) == 3
        assert table.flows_evicted == 2
        finished = table.take_finished()
        assert [flow.dst_port for flow in finished] == [1000, 1001]
        assert {flow.close_reason for flow in finished} == {FlowCloseReason.EVICTED}

    def test_evicting_a_closed_flow_is_not_counted_as_losing_data(self):
        table = _table(max_flows=1)
        table.observe(syn(T0, "10.0.0.1", "10.0.0.2", 80, 5000))
        table.observe(packet(T0 + 1, "10.0.0.1", "10.0.0.2", sport=5000, dport=80, flags=TCP_RST))
        table.observe(syn(T0 + 2, "10.0.0.1", "10.0.0.3", 80))
        assert table.flows_evicted == 0
        assert table.take_finished()[0].close_reason == FlowCloseReason.CLOSED

    def test_taking_finished_flows_empties_the_list(self):
        table = _table()
        table.observe(syn(T0, "10.0.0.1", "10.0.0.2", 80))
        table.flush()
        assert len(table.take_finished()) == 1
        assert table.take_finished() == []

    def test_out_of_order_timestamps_never_make_last_seen_precede_first_seen(self):
        table = _table()
        table.observe(syn(T0 + 10, "10.0.0.1", "10.0.0.2", 80, 5000))
        table.observe(packet(T0 + 2, "10.0.0.2", "10.0.0.1", sport=80, dport=5000, flags=TCP_ACK))
        table.flush()
        (flow,) = table.take_finished()
        assert flow.first_seen == T0 + 2
        assert flow.last_seen == T0 + 10
