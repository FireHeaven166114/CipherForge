"""Writes one monitoring session's results to the database in small batches.

The analyzer works in memory; this is the only part of a live session that touches the database
on the packet path, and it does so a couple of seconds at a time rather than per packet. A batch
that fails to write is kept (up to a limit) and retried with the next one, so a locked database
slows recording down instead of losing it or stopping the capture.
"""

import logging
import threading
import time
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.detection.network_rules import RawAlert
from app.models.enums import CaptureStatus, FlowCloseReason
from app.models.network import CaptureSession, NetworkAlert, NetworkFlow
from app.models.types import utcnow
from app.network.analyzer import Analyzer, AnalyzerOutput, AnalyzerSnapshot
from app.network.flows import Flow

logger = logging.getLogger("cipherforge.network")

# Bounds on what is held back while the database is unavailable.
MAX_PENDING_FLOWS = 50_000
MAX_PENDING_ALERTS = 2_000
_STATUS_ATTEMPTS = 3


class EnrichmentStatus(StrEnum):
    """Where an alert's (or an address's) threat-intelligence lookup stands."""

    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"
    SKIPPED_BUDGET = "skipped_budget"
    NOT_APPLICABLE = "not_applicable"


def as_datetime(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=UTC)


def initial_enrichment(
    alert: RawAlert, *, enabled: bool, known: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """The enrichment state a new alert starts in.

    ``known`` holds the answers already recorded for the session, so an alert about an address
    that was looked up before the alert existed starts with that answer instead of waiting.
    """
    subject = Analyzer.alert_subject(alert)
    if subject is None:
        return {"status": EnrichmentStatus.NOT_APPLICABLE.value}
    if not enabled:
        return {"status": EnrichmentStatus.DISABLED.value, "address": subject}
    answer = known.get(subject) if known else None
    if isinstance(answer, dict) and answer.get("status"):
        return dict(answer)
    return {"status": EnrichmentStatus.PENDING.value, "address": subject}


def alert_row(session_id: uuid.UUID, alert: RawAlert, enrichment: dict[str, Any]) -> NetworkAlert:
    return NetworkAlert(
        session_id=session_id,
        rule_id=alert.rule_id,
        rule_name=alert.rule_name,
        severity=alert.severity.value,
        explanation=alert.explanation,
        observed_value=float(alert.observed_value),
        threshold=float(alert.threshold),
        window_seconds=alert.window_seconds,
        src_ip=alert.src_ip,
        dst_ip=alert.dst_ip,
        dst_port=alert.dst_port,
        protocol=alert.protocol,
        first_observed=as_datetime(alert.first_observed),
        last_observed=as_datetime(max(alert.last_observed, alert.first_observed)),
        evidence=alert.evidence,
        enrichment=enrichment,
    )


def flow_row(session_id: uuid.UUID, flow: Flow) -> NetworkFlow:
    reason = flow.close_reason or FlowCloseReason.ENDED
    return NetworkFlow(
        session_id=session_id,
        protocol=flow.protocol,
        src_ip=flow.src_ip,
        src_port=flow.src_port,
        dst_ip=flow.dst_ip,
        dst_port=flow.dst_port,
        first_seen=as_datetime(flow.first_seen),
        last_seen=as_datetime(max(flow.last_seen, flow.first_seen)),
        packets_out=flow.packets_out,
        packets_in=flow.packets_in,
        bytes_out=flow.bytes_out,
        bytes_in=flow.bytes_in,
        tcp_flags=flow.tcp_flags,
        close_reason=reason.value,
    )


class SessionRecorder:
    """Persists flows, alerts, counters and statistics for one capture session.

    ``stats_lock`` is shared with the enrichment worker. Between them they own disjoint keys of
    ``capture_sessions.stats`` (this class everything except ``enrichment`` and
    ``enrichment_alerts``, the count of alerts the worker raised), and both read, change and write
    that JSON value while holding the lock, so neither overwrites the other.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        session_id: uuid.UUID,
        *,
        max_stored_flows: int,
        enrichment_enabled: bool,
        stats_lock: threading.Lock,
        retry_delay: float = 0.2,
    ) -> None:
        self._session_factory = session_factory
        self._session_id = session_id
        self._max_stored_flows = max_stored_flows
        self._enrichment_enabled = enrichment_enabled
        self._stats_lock = stats_lock
        self._retry_delay = retry_delay
        self._pending_alerts: list[RawAlert] = []
        self._pending_flows: list[Flow] = []
        self.flows_stored = 0
        self.flows_not_stored = 0
        self.alerts_lost = 0
        self.write_failures = 0
        # The session row no longer exists (deleted underneath a running session).
        self.gone = False

    @property
    def pending(self) -> int:
        return len(self._pending_flows) + len(self._pending_alerts)

    def write(
        self,
        output: AnalyzerOutput,
        snapshot: AnalyzerSnapshot,
        *,
        stats: dict[str, Any],
        packets_dropped: int,
    ) -> bool:
        """Store a batch together with the latest totals. Returns False if it was not stored."""
        if self.gone:
            return False
        self._pending_alerts.extend(output.alerts)
        self._pending_flows.extend(output.flows)
        self._bound_pending()

        room = max(self._max_stored_flows - self.flows_stored, 0)
        flows, overflow = self._pending_flows[:room], self._pending_flows[room:]
        alerts = self._pending_alerts
        try:
            with self._session_factory() as db, self._stats_lock:
                existing = db.execute(
                    select(CaptureSession.stats).where(CaptureSession.id == self._session_id)
                ).first()
                if existing is None:
                    self.gone = True
                    self._pending_flows.clear()
                    self._pending_alerts.clear()
                    return False
                known = (existing[0] or {}).get("enrichment")
                db.add_all([flow_row(self._session_id, flow) for flow in flows])
                db.add_all(
                    [
                        alert_row(
                            self._session_id,
                            alert,
                            initial_enrichment(
                                alert, enabled=self._enrichment_enabled, known=known
                            ),
                        )
                        for alert in alerts
                    ]
                )
                merged = dict(existing[0] or {})
                merged.update(stats)
                merged["flows_stored"] = self.flows_stored + len(flows)
                merged["flows_not_stored"] = self.flows_not_stored + len(overflow)
                merged["alerts_lost"] = self.alerts_lost
                merged["write_failures"] = self.write_failures
                if known is not None:
                    merged["enrichment"] = known
                db.execute(
                    update(CaptureSession)
                    .where(CaptureSession.id == self._session_id)
                    .values(
                        packets_total=snapshot.packets,
                        bytes_total=snapshot.bytes,
                        flows_total=snapshot.flows_total,
                        packets_dropped=packets_dropped,
                        # Added to, not set: the enrichment worker can add alerts of its own.
                        alerts_total=CaptureSession.alerts_total + len(alerts),
                        stats=merged,
                    )
                )
                db.commit()
        except SQLAlchemyError as exc:
            self.write_failures += 1
            logger.warning(
                "network_persist_failed",
                extra={
                    "session_id": str(self._session_id),
                    "error": type(exc).__name__,
                    "pending": self.pending,
                },
            )
            return False
        self.flows_stored += len(flows)
        self.flows_not_stored += len(overflow)
        self._pending_flows.clear()
        self._pending_alerts.clear()
        return True

    def set_status(
        self, status: CaptureStatus, *, error_code: str | None = None, ended: bool = False
    ) -> bool:
        """Record a lifecycle change, retrying briefly: a final status must not be lost."""
        for attempt in range(_STATUS_ATTEMPTS):
            try:
                with self._session_factory() as db:
                    values: dict[str, Any] = {"status": status.value}
                    if error_code is not None:
                        values["error_code"] = error_code
                    if ended:
                        started = db.scalar(
                            select(CaptureSession.started_at).where(
                                CaptureSession.id == self._session_id
                            )
                        )
                        if started is None:
                            self.gone = True
                            return False
                        values["ended_at"] = max(utcnow(), started)
                    db.execute(
                        update(CaptureSession)
                        .where(CaptureSession.id == self._session_id)
                        .values(**values)
                    )
                    db.commit()
                    return True
            except SQLAlchemyError as exc:
                logger.warning(
                    "network_status_failed",
                    extra={
                        "session_id": str(self._session_id),
                        "status": status.value,
                        "error": type(exc).__name__,
                    },
                )
                if attempt + 1 < _STATUS_ATTEMPTS:
                    time.sleep(self._retry_delay)
        return False

    def _bound_pending(self) -> None:
        excess = len(self._pending_flows) - MAX_PENDING_FLOWS
        if excess > 0:
            del self._pending_flows[:excess]
            self.flows_not_stored += excess
        excess = len(self._pending_alerts) - MAX_PENDING_ALERTS
        if excess > 0:
            del self._pending_alerts[:excess]
            self.alerts_lost += excess
