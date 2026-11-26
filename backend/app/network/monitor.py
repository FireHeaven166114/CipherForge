"""The running state of one monitoring session.

A ``SessionMonitor`` joins the parts of a session: the in-memory :class:`Analyzer`, the
:class:`SessionRecorder` that stores results every couple of seconds, and the hand-over of public
addresses to the enrichment worker. Whatever feeds a session (the live capture thread, or the
offline capture-file analysis) only calls ``process_batch``, ``tick`` and ``finish``.

The monitor never blocks on the network: it queues lookups and moves on.
"""

import logging
import threading
import time
import uuid
from collections.abc import Callable, Sequence
from typing import Any

from app.core.config import Settings
from app.detection.network_rules import NetworkRuleConfig, RawAlert
from app.models.enums import CaptureStatus
from app.network.analyzer import Analyzer, AnalyzerSnapshot, ExternalPeer
from app.network.enrichment import (
    PRIORITY_ALERT,
    PRIORITY_TALKER,
    EnrichmentRequest,
    EnrichmentWorker,
)
from app.network.packets import PacketMeta
from app.network.recorder import EnrichmentStatus, SessionRecorder

logger = logging.getLogger("cipherforge.network")

FLUSH_INTERVAL_SECONDS = 2.0
SWEEP_INTERVAL_SECONDS = 1.0
# How many public addresses the session keeps traffic details for, whatever the lookup budget.
MIN_PEER_LIST = 25
_FINAL_FLUSH_ATTEMPTS = 3
_FINAL_FLUSH_DELAY = 0.2


class SessionMonitor:
    """Everything one capture session needs while it runs.

    ``stream_time`` selects the clock that retires idle flows: for a capture file it is the time
    of the packets themselves (the file can be years old), for a live capture it is the wall clock.
    """

    def __init__(
        self,
        session_id: uuid.UUID,
        *,
        settings: Settings,
        recorder: SessionRecorder,
        enrichment: EnrichmentWorker | None,
        stream_time: bool,
        clock: Callable[[], float] = time.time,
        flush_interval: float = FLUSH_INTERVAL_SECONDS,
    ) -> None:
        self.session_id = session_id
        self._settings = settings
        self._recorder = recorder
        self._enrichment = enrichment if settings.external_enrichment_enabled else None
        self._stream_time = stream_time
        self._clock = clock
        self._flush_interval = flush_interval
        self._analyzer = Analyzer(
            NetworkRuleConfig.from_settings(settings),
            idle_timeout=settings.flow_idle_timeout_seconds,
            max_flows=settings.max_active_flows,
        )
        # Lock order: _flush_lock, then _lock, then _counter_lock. The packet callback of a live
        # capture only ever takes _counter_lock, so it is never held up by the analysis.
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._counter_lock = threading.Lock()
        self._dropped = 0
        self._pending_non_ip = 0
        self._pending_malformed = 0
        self._latest = 0.0
        self._last_sweep = 0.0
        self._last_flush = 0.0
        self._last_written: tuple[AnalyzerSnapshot, int] | None = None
        # Enrichment bookkeeping (touched only while flushing).
        self._submitted: set[str] = set()
        self._talkers = 0
        self._skipped: set[str] = set()

    # --- Counters from the capture thread -----------------------------------------

    def note_dropped(self, count: int = 1) -> None:
        with self._counter_lock:
            self._dropped += count

    def note_non_ip(self, count: int = 1) -> None:
        with self._counter_lock:
            self._pending_non_ip += count

    def note_malformed(self, count: int = 1) -> None:
        with self._counter_lock:
            self._pending_malformed += count

    @property
    def packets_dropped(self) -> int:
        with self._counter_lock:
            return self._dropped

    @property
    def gone(self) -> bool:
        """The session row was removed while the session was running."""
        return self._recorder.gone

    @property
    def packets_processed(self) -> int:
        with self._lock:
            return self._analyzer.packets

    def set_status(self, status: CaptureStatus, error_code: str | None = None) -> bool:
        """Record a lifecycle change (starting, running, stopping) in the session row."""
        return self._recorder.set_status(status, error_code=error_code)

    # --- Feeding -------------------------------------------------------------------

    def process_batch(self, packets: Sequence[PacketMeta]) -> None:
        with self._lock:
            self._drain_counters()
            for packet in packets:
                self._analyzer.process(packet)
                if packet.timestamp > self._latest:
                    self._latest = packet.timestamp
        self.tick()

    def tick(self) -> None:
        """Retire idle flows and store results when they are due. Cheap when nothing is."""
        now = self._now()
        if now > 0 and now - self._last_sweep >= SWEEP_INTERVAL_SECONDS:
            with self._lock:
                self._drain_counters()
                self._analyzer.advance(now)
            self._last_sweep = now
        if self._clock() - self._last_flush >= self._flush_interval:
            self.flush()

    def flush(self, *, force: bool = False) -> bool:
        """Store what has been learned since the last flush. False if it could not be stored."""
        with self._flush_lock:
            with self._lock:
                self._drain_counters()
                output = self._analyzer.take_output()
                snapshot = self._analyzer.snapshot()
                peers = self._peer_details()
            dropped = self.packets_dropped
            self._last_flush = self._clock()
            if (
                not force
                and not output.alerts
                and not output.flows
                and not self._recorder.pending
                and self._last_written == (snapshot, dropped)
            ):
                return True
            stats = snapshot.as_stats()
            stats["external_peers"] = [peer.as_facts() for peer in peers]
            stored = self._recorder.write(output, snapshot, stats=stats, packets_dropped=dropped)
            if stored:
                self._last_written = (snapshot, dropped)
                self._hand_over(output.alerts)
            return stored

    def finish(self, status: CaptureStatus, error_code: str | None = None) -> None:
        """End the session: store everything that is left, then record the final status."""
        with self._lock:
            self._drain_counters()
            self._analyzer.finish()
        stored = False
        for attempt in range(_FINAL_FLUSH_ATTEMPTS):
            stored = self.flush(force=True)
            if stored or self._recorder.gone:
                break
            if attempt + 1 < _FINAL_FLUSH_ATTEMPTS:
                time.sleep(_FINAL_FLUSH_DELAY)
        if self._enrichment is not None:
            waiting = {
                address
                for address in self._submitted
                if self._enrichment.is_pending(self.session_id, address)
            }
            self._enrichment.settle(self.session_id, waiting)
        if not stored and not self._recorder.gone and error_code is None:
            error_code = "results_incomplete"
        self._recorder.set_status(status, error_code=error_code, ended=True)

    # --- Internals -------------------------------------------------------------------

    def _now(self) -> float:
        if self._stream_time:
            return self._latest
        return max(self._latest, self._clock())

    def _drain_counters(self) -> None:
        """Move counts noted by the capture thread into the analyzer. Call with ``_lock`` held."""
        with self._counter_lock:
            non_ip, self._pending_non_ip = self._pending_non_ip, 0
            malformed, self._pending_malformed = self._pending_malformed, 0
        if non_ip:
            self._analyzer.note_non_ip(non_ip)
        if malformed:
            self._analyzer.note_malformed(malformed)

    def _peer_details(self) -> list[ExternalPeer]:
        """The public addresses whose traffic details are kept with the session.

        Addresses that were sent for lookup come first, so a result never loses its traffic
        details when busier peers appear later. Call with ``_lock`` held.
        """
        budget = self._settings.network_enrichment_max_ips
        limit = max(budget, MIN_PEER_LIST)
        sent = [
            peer
            for address in self._submitted
            if (peer := self._analyzer.peer(address)) is not None
        ]
        sent.sort(key=lambda peer: (not peer.alerted, -peer.bytes, peer.address))
        others = self._analyzer.enrichment_candidates(limit, self._submitted)
        return sent + others[: max(limit - len(sent), 0)]

    def _hand_over(self, alerts: Sequence[RawAlert]) -> None:
        """Queue public addresses for lookup, alert-involved ones first, within the budget."""
        worker = self._enrichment
        if worker is None:
            return
        requests, over_budget = self._plan_enrichment(alerts)
        if over_budget:
            worker.mark(self.session_id, over_budget, EnrichmentStatus.SKIPPED_BUDGET)
        if requests:
            rejected = worker.submit(self.session_id, requests)
            if rejected:
                worker.mark(
                    self.session_id,
                    {request.address for request in rejected},
                    EnrichmentStatus.FAILED,
                    error_code="queue_full",
                )

    def _plan_enrichment(
        self, alerts: Sequence[RawAlert]
    ) -> tuple[list[EnrichmentRequest], list[str]]:
        budget = self._settings.network_enrichment_max_ips
        # Addresses that were never alert-involved may use all but a fifth of the budget, so a
        # session full of busy servers still has room to look up the address that raised an alert.
        talker_cap = budget - budget // 5
        requests: list[EnrichmentRequest] = []
        over_budget: list[str] = []
        with self._lock:
            new_subjects = {
                subject
                for alert in alerts
                if (subject := Analyzer.alert_subject(alert)) is not None
            }
            candidates = self._analyzer.enrichment_candidates(budget, self._submitted)
            alerted: dict[str, ExternalPeer | None] = {
                subject: self._analyzer.peer(subject)
                for subject in sorted(new_subjects - self._submitted)
            }
            for peer in candidates:
                if peer.alerted:
                    alerted.setdefault(peer.address, peer)
            for address, peer in alerted.items():
                if len(self._submitted) < budget:
                    self._submitted.add(address)
                    requests.append(_request(address, peer, PRIORITY_ALERT))
                elif address in new_subjects or address not in self._skipped:
                    over_budget.append(address)
                    self._skipped.add(address)
            for peer in candidates:
                if peer.alerted or peer.address in self._submitted:
                    continue
                if len(self._submitted) >= budget or self._talkers >= talker_cap:
                    break
                self._submitted.add(peer.address)
                self._talkers += 1
                requests.append(_request(peer.address, peer, PRIORITY_TALKER))
        return requests, over_budget


def _request(address: str, peer: ExternalPeer | None, priority: int) -> EnrichmentRequest:
    facts: dict[str, Any] = peer.as_facts() if peer is not None else {"address": address}
    return EnrichmentRequest(address=address, priority=priority, facts=facts)
