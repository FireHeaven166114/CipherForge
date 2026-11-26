"""Looks up the public addresses a monitoring session saw, away from the packet path.

One worker thread serves every session. It takes addresses from a priority queue (addresses that
are part of an alert first, then the heaviest talkers), asks the configured threat-intelligence
providers through the same :class:`IntelService` the Investigate page uses, and writes the answer
back onto the session and onto the alerts that name the address.

Nothing here runs on, or waits for, the packet path. The worker spaces out the lookups that
actually reach a provider (``NETWORK_ENRICHMENT_MAX_PER_MINUTE``), because the free provider tiers
are small: answers that come from the intelligence cache cost nothing and are not delayed.
"""

import contextlib
import itertools
import logging
import queue
import threading
import time
import uuid
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import or_, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.detection.network_rules import RawAlert, known_malicious_alert
from app.models.network import CaptureSession, NetworkAlert
from app.models.types import utcnow
from app.network.recorder import EnrichmentStatus, alert_row
from app.schemas.intel import InvestigationResponse
from app.services.intel_service import IndicatorDeletedError, IntelService, RequestContext
from app.services.normalization import InvalidIndicatorError, is_public_address

logger = logging.getLogger("cipherforge.network")

# The actor recorded in the audit trail for lookups the monitor makes on its own.
SYSTEM_ACTOR = "system:network-monitor"
KNOWN_MALICIOUS_RULE = "NET-005"

PRIORITY_ALERT = 0
PRIORITY_TALKER = 1

_MAX_QUEUE = 2_000
_POLL_SECONDS = 0.5
# A provider that answered (with data or without), or was reached and failed, used up quota.
_CONTACTED = frozenset({"ok", "no_data", "rate_limited", "error"})
_ANSWERED = frozenset({"ok", "no_data"})


@dataclass(frozen=True, slots=True)
class EnrichmentRequest:
    address: str
    priority: int
    # What the monitor knows about the address, in the form kept in ``stats["external_peers"]``.
    facts: dict[str, Any]


def _value(item: Any) -> Any:
    return getattr(item, "value", item)


def summarize(address: str, response: InvestigationResponse) -> dict[str, Any]:
    """The part of an investigation that is kept with a capture session.

    The score is only kept when a provider returned evidence (``ok``). A provider that answered
    "no data" leaves the lookup ``completed`` but not ``assessed``, and the score that follows
    from no evidence is 0, which says nothing about the address: "no data" is never a statement
    that it is safe.
    """
    providers = [
        {
            "provider": view.provider,
            "display_name": view.display_name,
            "status": view.status,
            "verdict": _value(view.verdict),
        }
        for view in response.providers
    ]
    statuses = {view.status for view in response.providers}
    error_code: str | None = None
    if statuses & _ANSWERED:
        status = EnrichmentStatus.COMPLETED
    elif "rate_limited" in statuses:
        status, error_code = EnrichmentStatus.FAILED, "rate_limited"
    elif "error" in statuses:
        status, error_code = EnrichmentStatus.FAILED, "provider_error"
    else:
        status, error_code = EnrichmentStatus.UNAVAILABLE, "no_provider_available"
    summary: dict[str, Any] = {
        "status": status.value,
        "address": address,
        "indicator_id": str(response.indicator.indicator_id),
        "providers": providers,
        "completed_at": utcnow().isoformat(),
        "assessed": "ok" in statuses,
    }
    if error_code is not None:
        summary["error_code"] = error_code
    if summary["assessed"]:
        summary["risk_score"] = response.indicator.risk_score
        summary["classification"] = _value(response.indicator.classification)
    return summary


def _plain(status: EnrichmentStatus, address: str, error_code: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": status.value, "address": address}
    if error_code is not None:
        result["error_code"] = error_code
    return result


class EnrichmentWorker:
    def __init__(
        self,
        *,
        intel_service: IntelService,
        session_factory: sessionmaker[Session],
        settings: Settings,
        stats_lock: threading.Lock,
        pacing_interval: float | None = None,
    ) -> None:
        self._intel = intel_service
        self._session_factory = session_factory
        self._settings = settings
        self._stats_lock = stats_lock
        self._interval = (
            60.0 / settings.network_enrichment_max_per_minute
            if pacing_interval is None
            else pacing_interval
        )
        self._queue: queue.PriorityQueue[tuple[int, int, uuid.UUID, EnrichmentRequest]] = (
            queue.PriorityQueue(maxsize=_MAX_QUEUE)
        )
        self._sequence = itertools.count()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._queued: dict[uuid.UUID, set[str]] = {}
        self._discarded: set[uuid.UUID] = set()
        self._next_provider_call = 0.0

    # --- Queue -------------------------------------------------------------------

    def submit(
        self, session_id: uuid.UUID, requests: Sequence[EnrichmentRequest]
    ) -> list[EnrichmentRequest]:
        """Queue addresses for lookup; returns the ones that could not be queued.

        An address already queued for the session is not queued twice (and is not rejected).
        """
        rejected: list[EnrichmentRequest] = []
        with self._lock:
            if self._stop.is_set():
                return list(requests)
            queued = self._queued.setdefault(session_id, set())
            for request in requests:
                if request.address in queued:
                    continue
                try:
                    self._queue.put_nowait(
                        (request.priority, next(self._sequence), session_id, request)
                    )
                except queue.Full:
                    rejected.append(request)
                    continue
                queued.add(request.address)
            if queued:
                self._ensure_thread()
            else:
                del self._queued[session_id]
        return rejected

    def is_pending(self, session_id: uuid.UUID, address: str) -> bool:
        with self._lock:
            return address in self._queued.get(session_id, ())

    def pending_count(self) -> int:
        with self._lock:
            return sum(len(addresses) for addresses in self._queued.values())

    def discard(self, session_id: uuid.UUID) -> None:
        """The session was deleted: its queued lookups are dropped when they come up."""
        with self._lock:
            if self._queued.get(session_id):
                self._discarded.add(session_id)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _ensure_thread(self) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(
                target=self._run, name="cipherforge-network-enrichment", daemon=True
            )
            self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                _, _, session_id, request = self._queue.get(timeout=_POLL_SECONDS)
            except queue.Empty:
                continue
            try:
                if not self._is_discarded(session_id):
                    self._handle(session_id, request)
            except Exception as exc:  # a failed lookup must never end the worker
                logger.warning("network_enrichment_error", extra={"error": type(exc).__name__})
            finally:
                self._done(session_id, request.address)

    def _is_discarded(self, session_id: uuid.UUID) -> bool:
        with self._lock:
            return session_id in self._discarded

    def _done(self, session_id: uuid.UUID, address: str) -> None:
        with self._lock:
            queued = self._queued.get(session_id)
            if queued is not None:
                queued.discard(address)
                if not queued:
                    del self._queued[session_id]
                    self._discarded.discard(session_id)

    # --- Lookups -----------------------------------------------------------------

    def _handle(self, session_id: uuid.UUID, request: EnrichmentRequest) -> None:
        if not self._wait_for_turn():
            return
        summary, contacted = self.lookup(request.address)
        if contacted:
            self._next_provider_call = time.monotonic() + self._interval
        self.apply(session_id, request.address, summary, facts=request.facts)

    def _wait_for_turn(self) -> bool:
        """Space out lookups that reach a provider. False when the worker was asked to stop."""
        remaining = self._next_provider_call - time.monotonic()
        if remaining > 0:
            return not self._stop.wait(remaining)
        return not self._stop.is_set()

    def lookup(
        self, address: str, *, context: RequestContext | None = None
    ) -> tuple[dict[str, Any], bool]:
        """Ask the providers about one address: (what to record, whether a provider was reached).

        ``context`` names who asked, for the audit trail; lookups the monitor makes on its own
        are recorded under the system actor.
        """
        if not self._settings.external_enrichment_enabled:
            return _plain(EnrichmentStatus.DISABLED, address), False
        if not is_public_address(address):
            return _plain(EnrichmentStatus.NOT_APPLICABLE, address), False
        context = context or RequestContext(actor=SYSTEM_ACTOR)
        try:
            with self._session_factory() as db:
                response = self._intel.investigate(db, context, address)
        except InvalidIndicatorError:
            return _plain(EnrichmentStatus.NOT_APPLICABLE, address), False
        except IndicatorDeletedError:
            return _plain(EnrichmentStatus.UNAVAILABLE, address, "indicator_deleted"), False
        except Exception as exc:  # providers and the database can fail in many ways
            logger.warning("network_enrichment_failed", extra={"error": type(exc).__name__})
            return _plain(EnrichmentStatus.FAILED, address, "lookup_failed"), True
        contacted = any(
            view.status in _CONTACTED and not view.from_cache for view in response.providers
        )
        return summarize(address, response), contacted

    def refresh(
        self, session_id: uuid.UUID, address: str, context: RequestContext
    ) -> dict[str, Any]:
        """Look the address up now, for the caller's own request, and record the answer."""
        summary, _ = self.lookup(address, context=context)
        self.apply(session_id, address, summary, facts=None)
        return summary

    # --- Recording ---------------------------------------------------------------

    def apply(
        self,
        session_id: uuid.UUID,
        address: str,
        summary: dict[str, Any],
        *,
        facts: dict[str, Any] | None,
    ) -> None:
        """Record an answer on the session, on its alerts for the address, and raise NET-005."""
        try:
            with self._session_factory() as db, self._stats_lock:
                existing = db.execute(
                    select(CaptureSession.stats).where(CaptureSession.id == session_id)
                ).first()
                if existing is None:
                    return
                stats = dict(existing[0] or {})
                enrichment = dict(stats.get("enrichment") or {})
                enrichment[address] = summary
                stats["enrichment"] = enrichment

                alerts = self._alerts_for(db, session_id, {address})
                for alert in alerts:
                    if (alert.enrichment or {}).get("address") == address:
                        alert.enrichment = dict(summary)

                raised = 0
                if self._should_raise(summary, alerts, address):
                    facts = facts or _stored_facts(stats, address)
                    if facts is not None:
                        db.add(
                            alert_row(session_id, self._known_malicious(summary, facts), summary)
                        )
                        raised = 1
                        counted = dict(stats.get("enrichment_alerts") or {})
                        counted[KNOWN_MALICIOUS_RULE] = counted.get(KNOWN_MALICIOUS_RULE, 0) + 1
                        stats["enrichment_alerts"] = counted
                db.execute(
                    update(CaptureSession)
                    .where(CaptureSession.id == session_id)
                    .values(stats=stats, alerts_total=CaptureSession.alerts_total + raised)
                )
                db.commit()
        except SQLAlchemyError as exc:
            logger.warning("network_enrichment_store_failed", extra={"error": type(exc).__name__})

    def mark(
        self,
        session_id: uuid.UUID,
        addresses: Collection[str],
        status: EnrichmentStatus,
        *,
        error_code: str | None = None,
    ) -> int:
        """Give the session's still-waiting alerts for these addresses a final status."""
        return self._mark_pending(
            session_id, lambda address: address in addresses, status, error_code
        )

    def settle(self, session_id: uuid.UUID, keep: Collection[str]) -> int:
        """The session is over: alerts still waiting on an address nobody queued will not be
        looked up, so they are marked as such rather than left pending."""
        return self._mark_pending(
            session_id, lambda address: address not in keep, EnrichmentStatus.SKIPPED_BUDGET, None
        )

    def _mark_pending(
        self,
        session_id: uuid.UUID,
        applies: Callable[[str], bool],
        status: EnrichmentStatus,
        error_code: str | None,
    ) -> int:
        changed = 0
        try:
            with self._session_factory() as db:
                rows = db.scalars(
                    select(NetworkAlert).where(NetworkAlert.session_id == session_id)
                ).all()
                for row in rows:
                    state = row.enrichment or {}
                    address = state.get("address")
                    waiting = state.get("status") == EnrichmentStatus.PENDING.value
                    if waiting and address and applies(address):
                        row.enrichment = _plain(status, address, error_code)
                        changed += 1
                if changed:
                    db.commit()
        except SQLAlchemyError as exc:
            logger.warning("network_enrichment_mark_failed", extra={"error": type(exc).__name__})
            return 0
        return changed

    def _should_raise(
        self, summary: dict[str, Any], alerts: Sequence[NetworkAlert], address: str
    ) -> bool:
        score = summary.get("risk_score")
        if summary.get("status") != EnrichmentStatus.COMPLETED.value or not summary.get("assessed"):
            return False
        if not isinstance(score, int) or score < self._settings.known_malicious_min_score:
            return False
        return not any(
            alert.rule_id == KNOWN_MALICIOUS_RULE
            and (alert.enrichment or {}).get("address") == address
            for alert in alerts
        )

    def _known_malicious(self, summary: dict[str, Any], facts: dict[str, Any]) -> RawAlert:
        answered = [item for item in summary["providers"] if item["status"] == "ok"]
        return known_malicious_alert(
            address=summary["address"],
            risk_score=summary["risk_score"],
            classification=str(summary["classification"]),
            minimum_score=self._settings.known_malicious_min_score,
            providers=answered,
            peers=list(facts.get("peers") or []),
            sent_to=bool(facts.get("sent_to")),
            protocols=list(facts.get("protocols") or []),
            ports=list(facts.get("ports") or []),
            packets=int(facts.get("packets") or 0),
            total_bytes=int(facts.get("bytes") or 0),
            first_seen=_epoch(facts.get("first_seen")),
            last_seen=_epoch(facts.get("last_seen")),
        )

    @staticmethod
    def _alerts_for(
        db: Session, session_id: uuid.UUID, addresses: Collection[str]
    ) -> Sequence[NetworkAlert]:
        return db.scalars(
            select(NetworkAlert).where(
                NetworkAlert.session_id == session_id,
                or_(NetworkAlert.src_ip.in_(addresses), NetworkAlert.dst_ip.in_(addresses)),
            )
        ).all()


def _epoch(value: Any) -> float:
    if isinstance(value, str):
        with contextlib.suppress(ValueError):
            return datetime.fromisoformat(value).timestamp()
    return time.time()


def _stored_facts(stats: dict[str, Any], address: str) -> dict[str, Any] | None:
    for entry in stats.get("external_peers") or ():
        if isinstance(entry, dict) and entry.get("address") == address:
            return entry
    return None
