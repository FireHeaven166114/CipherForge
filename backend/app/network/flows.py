"""Bidirectional flow aggregation with expiry and a size limit."""

from collections import OrderedDict
from dataclasses import dataclass

from app.models.enums import FlowCloseReason
from app.network.packets import TCP_FIN, TCP_RST, PacketMeta

# (address, port) of both ends in a fixed order, then the protocol. A missing port is -1.
FlowKey = tuple[tuple[str, int], tuple[str, int], str]


def flow_key(packet: PacketMeta) -> FlowKey:
    """The same key for both directions of a conversation."""
    one = (packet.src_ip, -1 if packet.src_port is None else packet.src_port)
    other = (packet.dst_ip, -1 if packet.dst_port is None else packet.dst_port)
    return (one, other, packet.protocol) if one <= other else (other, one, packet.protocol)


@dataclass(slots=True)
class Flow:
    """One conversation. ``src`` is the end that sent the first packet the monitor saw."""

    protocol: str
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    first_seen: float
    last_seen: float
    packets_out: int = 0
    packets_in: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    tcp_flags: int | None = None
    fin_out: bool = False
    fin_in: bool = False
    closed: bool = False
    close_reason: FlowCloseReason | None = None

    @property
    def packets(self) -> int:
        return self.packets_out + self.packets_in

    @property
    def total_bytes(self) -> int:
        return self.bytes_out + self.bytes_in

    def add(self, packet: PacketMeta) -> bool:
        """Count the packet. Returns True when it ended the connection (a reset, or both FINs)."""
        outgoing = (packet.src_ip, packet.src_port) == (self.src_ip, self.src_port)
        if outgoing:
            self.packets_out += 1
            self.bytes_out += packet.length
        else:
            self.packets_in += 1
            self.bytes_in += packet.length
        self.first_seen = min(self.first_seen, packet.timestamp)
        self.last_seen = max(self.last_seen, packet.timestamp)

        flags = packet.tcp_flags
        if flags is None:
            return False
        self.tcp_flags = flags if self.tcp_flags is None else self.tcp_flags | flags
        if flags & TCP_FIN:
            if outgoing:
                self.fin_out = True
            else:
                self.fin_in = True
        was_closed = self.closed
        if flags & TCP_RST or (self.fin_out and self.fin_in):
            self.closed = True
        return self.closed and not was_closed


class FlowTable:
    """The conversations currently open, bounded in number and in time.

    A flow leaves the table when it has been quiet for ``idle_timeout`` seconds, when the table is
    full and it is the least recently active, when a closed connection's address pair is reused
    for a new handshake, or when the session ends. Finished flows are handed over through
    :meth:`take_finished`. A connection that has closed stays until the idle timeout so that its
    trailing ACKs do not appear as flows of their own.

    Time is whatever the caller says it is (packet timestamps for a capture file), so replaying a
    file gives the same flows every time.
    """

    def __init__(self, *, idle_timeout: float, max_flows: int) -> None:
        self._idle_timeout = idle_timeout
        self._max_flows = max_flows
        # Least recently active first.
        self._flows: OrderedDict[FlowKey, Flow] = OrderedDict()
        self._finished: list[Flow] = []
        self._closed = 0
        self.flows_seen = 0
        self.flows_evicted = 0

    def __len__(self) -> int:
        return len(self._flows)

    @property
    def active_count(self) -> int:
        """Flows whose connection has not ended."""
        return len(self._flows) - self._closed

    def observe(self, packet: PacketMeta) -> bool:
        """Account for one packet. Returns True when it started a new flow."""
        key = flow_key(packet)
        flow = self._flows.get(key)
        if flow is not None:
            # Expiry must not depend on how often the caller sweeps: a packet that turns up after
            # the idle timeout belongs to a new conversation, whether or not the old one was swept.
            if packet.timestamp - flow.last_seen > self._idle_timeout:
                self._remove(
                    key, flow, FlowCloseReason.CLOSED if flow.closed else FlowCloseReason.IDLE
                )
                flow = None
            elif flow.closed and packet.is_pure_syn:
                self._remove(key, flow, FlowCloseReason.CLOSED)
                flow = None
        is_new = flow is None
        if flow is None:
            if len(self._flows) >= self._max_flows:
                self._evict_least_recent()
            flow = Flow(
                protocol=packet.protocol,
                src_ip=packet.src_ip,
                src_port=packet.src_port,
                dst_ip=packet.dst_ip,
                dst_port=packet.dst_port,
                first_seen=packet.timestamp,
                last_seen=packet.timestamp,
            )
            self._flows[key] = flow
            self.flows_seen += 1
        else:
            self._flows.move_to_end(key)
        if flow.add(packet):
            self._closed += 1
        return is_new

    def sweep(self, now: float) -> None:
        """Finish the flows that have been quiet for longer than the idle timeout."""
        cutoff = now - self._idle_timeout
        while self._flows:
            key, flow = next(iter(self._flows.items()))
            if flow.last_seen >= cutoff:
                break
            reason = FlowCloseReason.CLOSED if flow.closed else FlowCloseReason.IDLE
            self._remove(key, flow, reason)

    def flush(self) -> None:
        """Finish every remaining flow (the session is over)."""
        while self._flows:
            key, flow = next(iter(self._flows.items()))
            reason = FlowCloseReason.CLOSED if flow.closed else FlowCloseReason.ENDED
            self._remove(key, flow, reason)

    def take_finished(self) -> list[Flow]:
        """The flows that finished since the last call, oldest first."""
        finished, self._finished = self._finished, []
        return finished

    def _evict_least_recent(self) -> None:
        key, flow = next(iter(self._flows.items()))
        if flow.closed:
            self._remove(key, flow, FlowCloseReason.CLOSED)
        else:
            # An open connection cut short: later packets of it will start a second flow.
            self.flows_evicted += 1
            self._remove(key, flow, FlowCloseReason.EVICTED)

    def _remove(self, key: FlowKey, flow: Flow, reason: FlowCloseReason) -> None:
        del self._flows[key]
        if flow.closed:
            self._closed -= 1
        flow.close_reason = reason
        self._finished.append(flow)
