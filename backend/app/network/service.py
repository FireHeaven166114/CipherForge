"""The network-monitoring use cases behind ``/api/v1/network``.

``NetworkService`` owns what requests share: the single live capture, the single capture-file
analysis, the enrichment worker and the upload spool. Everything it returns is scoped to the
caller. A session, flow or alert belongs to whoever started the capture or uploaded the file;
for anyone else, administrators included, it does not exist.

Construction is cheap and touches neither the database nor the capture library. Scapy is imported
the first time a capture backend or interface list is asked for.
"""

import logging
import threading
import time
import uuid
from collections.abc import Callable, Collection
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.errors import ApiError
from app.detection.network_rules import NetworkRuleConfig, describe_rules
from app.models.enums import CaptureSource, CaptureStatus
from app.models.network import CaptureSession
from app.models.types import utcnow
from app.network import repository, views
from app.network.analyzer import subject_address
from app.network.capture import (
    STOP_TIMEOUT_SECONDS,
    InterfaceCatalog,
    InterfaceInfo,
    LiveCapture,
    PacketSource,
    ScapyLiveSource,
)
from app.network.enrichment import EnrichmentWorker
from app.network.errors import ERRORS, CaptureFailure, message_for
from app.network.monitor import SessionMonitor
from app.network.pcap import (
    AnalysisOutcome,
    InvalidCaptureError,
    PcapRunner,
    ReceivedUpload,
    UploadSpool,
    analyze_file,
    inspect_capture,
)
from app.network.recorder import SessionRecorder
from app.schemas.network import (
    AlertOut,
    AlertPage,
    AnalysisStatus,
    BackendOut,
    FlowPage,
    InterfaceList,
    InterfaceOut,
    NetworkStatus,
    RuleOut,
    SessionDetail,
    SessionPage,
)
from app.services.audit import RESULT_PARTIAL, RESULT_REJECTED, RESULT_SUCCESS, record_audit
from app.services.intel_service import IntelService, RequestContext

logger = logging.getLogger("cipherforge.network")

NETWORK_CAPTURE_START = "NETWORK_CAPTURE_START"
NETWORK_CAPTURE_STOP = "NETWORK_CAPTURE_STOP"
NETWORK_PCAP_ANALYZE = "NETWORK_PCAP_ANALYZE"
NETWORK_SESSION_DELETE = "NETWORK_SESSION_DELETE"
NETWORK_ENRICH = "NETWORK_ENRICH"

PURGE_INTERVAL_SECONDS = 600.0
SHUTDOWN_TIMEOUT_SECONDS = 10.0
_PURGE_BATCH = 200
_MAX_PURGE_ROUNDS = 50
# What the status of the caller's last live capture says once it is over.
_ENDED_STATES = {
    CaptureStatus.STOPPED.value: "stopped",
    CaptureStatus.COMPLETED.value: "stopped",
    CaptureStatus.FAILED.value: "failed",
    CaptureStatus.PERMISSION_DENIED.value: "permission_denied",
}
_ACTIVE_VALUES = {status.value for status in repository.ACTIVE_STATUSES}


def _target(session_id: uuid.UUID) -> str:
    return f"network-session:{session_id}"


def _capture_error(code: str) -> ApiError:
    known = code in ERRORS
    info = ERRORS[code if known else "capture_failed"]
    return ApiError(info.status, code if known else "capture_failed", info.message)


@dataclass(slots=True)
class _LiveRun:
    """The live capture that holds the capture slot. ``capture`` is set once it is built."""

    session_id: uuid.UUID
    owner: str
    interface: str
    capture: LiveCapture | None = None

    @property
    def active(self) -> bool:
        return self.capture is None or self.capture.active


class NetworkService:
    def __init__(
        self,
        settings: Settings,
        session_factory: sessionmaker[Session],
        *,
        intel_service: IntelService,
        catalog: InterfaceCatalog | None = None,
        source_factory: Callable[[str], PacketSource] = ScapyLiveSource,
        spool: UploadSpool | None = None,
        pacing_interval: float | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._catalog = catalog or InterfaceCatalog()
        self._source_factory = source_factory
        self._spool = spool or UploadSpool()
        self._clock = clock
        # Shared by the recorders and the enrichment worker, which write different keys of the
        # same JSON column and must not overwrite each other.
        self._stats_lock = threading.Lock()
        self._enrichment = EnrichmentWorker(
            intel_service=intel_service,
            session_factory=session_factory,
            settings=settings,
            stats_lock=self._stats_lock,
            pacing_interval=pacing_interval,
        )
        self._runner = PcapRunner()
        self._live: _LiveRun | None = None
        self._live_lock = threading.Lock()
        self._purge_lock = threading.Lock()
        self._last_purge = float("-inf")

    @property
    def spool(self) -> UploadSpool:
        return self._spool

    # --- Status, interfaces, rules ------------------------------------------------------

    def status(self, db: Session, owner: str) -> NetworkStatus:
        backend = self._catalog.backend()
        with self._live_lock:
            run = self._current_live_locked()
        common: dict[str, Any] = {
            "backend": BackendOut(name=backend.name, available=backend.available),
            "busy": run is not None and run.owner != owner,
            "analysis": self._analysis_status(db, owner),
            "enrichment_enabled": self._settings.external_enrichment_enabled,
        }
        if not backend.available:
            return NetworkStatus(
                state="not_configured",
                interface=None,
                session_id=None,
                error_code="capture_backend_missing",
                message=message_for("capture_backend_missing"),
                **common,
            )
        if run is not None and run.owner == owner:
            state = run.capture.state.value if run.capture is not None else "starting"
            return NetworkStatus(
                state=state,
                interface=run.interface,
                session_id=run.session_id,
                error_code=None,
                message=None,
                **common,
            )
        last = repository.latest_live_session(db, owner)
        ended = _ENDED_STATES.get(last.status) if last is not None else None
        if last is not None and ended is not None:
            return NetworkStatus(
                state=ended,
                interface=last.interface,
                session_id=last.id,
                error_code=last.error_code,
                message=message_for(last.error_code),
                **common,
            )
        return NetworkStatus(
            state="ready", interface=None, session_id=None, error_code=None, message=None, **common
        )

    def interfaces(self, *, refresh: bool = False) -> InterfaceList:
        backend = self._catalog.backend()
        found: list[InterfaceInfo] = []
        if backend.available:
            try:
                found = self._catalog.interfaces(refresh=refresh)
            except Exception as exc:  # the operating system's interface listing can fail
                logger.warning("interface_listing_failed", extra={"error": type(exc).__name__})
        return InterfaceList(
            backend=BackendOut(name=backend.name, available=backend.available),
            interfaces=[
                InterfaceOut(
                    id=item.id,
                    name=item.name,
                    description=item.description,
                    addresses=list(item.addresses),
                )
                for item in found
            ],
        )

    def rules(self) -> list[RuleOut]:
        settings = describe_rules(NetworkRuleConfig.from_settings(self._settings))
        return [
            views.rule_out(item, enrichment_enabled=self._settings.external_enrichment_enabled)
            for item in settings
        ]

    # --- Live capture --------------------------------------------------------------------

    def start_live(self, db: Session, context: RequestContext, interface_id: str) -> NetworkStatus:
        backend = self._catalog.backend()
        if not backend.available:
            self._reject(db, context, NETWORK_CAPTURE_START, "capture_backend_missing")
            raise _capture_error("capture_backend_missing")
        info = self._resolve_interface(interface_id)
        if info is None:
            self._reject(db, context, NETWORK_CAPTURE_START, "interface_not_found")
            raise ApiError(
                404,
                "interface_not_found",
                "That network interface was not found. Choose one from the list.",
            )

        session_id = uuid.uuid4()
        run = _LiveRun(session_id, context.actor, info.name)
        with self._live_lock:
            taken = self._current_live_locked() is not None
            if not taken:
                self._live = run
        if taken:
            self._reject(db, context, NETWORK_CAPTURE_START, "capture_already_running")
            raise ApiError(
                409,
                "capture_already_running",
                "A capture is already running. Only one capture can run at a time.",
            )

        recorder: SessionRecorder | None = None
        try:
            # Built before the session row exists, so a failure leaves no "starting" row behind.
            built = self._build(session_id, stream_time=False)
            repository.new_session(
                db,
                session_id=session_id,
                owner=context.actor,
                source_kind=CaptureSource.LIVE,
                status=CaptureStatus.STARTING,
                interface=info.name,
            )
            db.commit()
            recorder, monitor = built
            capture = LiveCapture(
                monitor,
                self._source_factory(info.id),
                buffer_size=self._settings.monitoring_buffer_size,
            )
            run.capture = capture
            capture.start()
        except CaptureFailure as failure:
            self._release(run)
            self._reject(
                db, context, NETWORK_CAPTURE_START, failure.code, target=_target(session_id)
            )
            raise _capture_error(failure.code) from None
        except BaseException:
            self._release(run)
            if recorder is not None:
                recorder.set_status(CaptureStatus.FAILED, error_code="capture_failed", ended=True)
            raise

        try:
            self._audit(
                db,
                context,
                NETWORK_CAPTURE_START,
                RESULT_SUCCESS,
                target=_target(session_id),
                details={"interface": info.name},
            )
        except BaseException:
            # An action is not left running without its audit record.
            capture.stop(STOP_TIMEOUT_SECONDS)
            raise
        return self.status(db, context.actor)

    def stop_live(self, db: Session, context: RequestContext) -> NetworkStatus:
        with self._live_lock:
            run = self._current_live_locked()
        if run is None or run.owner != context.actor or run.capture is None:
            raise ApiError(409, "capture_not_running", "You have no capture running.")
        finished = run.capture.stop(STOP_TIMEOUT_SECONDS)
        self._audit(
            db,
            context,
            NETWORK_CAPTURE_STOP,
            RESULT_SUCCESS if finished else RESULT_PARTIAL,
            target=_target(run.session_id),
            details={"finished": finished},
        )
        return self.status(db, context.actor)

    # --- Capture files -------------------------------------------------------------------

    def ensure_analysis_idle(self) -> None:
        """Refuse early, before an upload is read, when the analysis slot is taken."""
        if self._runner.busy:
            raise ApiError(
                409,
                "analysis_already_running",
                "Another capture file is being analysed. Wait for it to finish.",
            )

    def analyze_pcap(
        self, db: Session, context: RequestContext, *, upload: ReceivedUpload, name: str
    ) -> SessionDetail:
        """Check an uploaded capture and start analysing it. The file is removed in every case."""
        path = upload.path
        try:
            info = inspect_capture(path)
        except InvalidCaptureError:
            self._spool.remove(path)
            self._reject(
                db,
                context,
                NETWORK_PCAP_ANALYZE,
                "invalid_capture_file",
                details={"size_bytes": upload.size},
            )
            raise _capture_error("invalid_capture_file") from None

        session_id = uuid.uuid4()
        if not self._runner.reserve(session_id):
            self._spool.remove(path)
            self._reject(db, context, NETWORK_PCAP_ANALYZE, "analysis_already_running")
            raise ApiError(
                409,
                "analysis_already_running",
                "Another capture file is being analysed. Wait for it to finish.",
            )
        try:
            # Built before the session row exists, so a failure leaves no "running" row behind.
            recorder, monitor = self._build(session_id, stream_time=True)
            row = repository.new_session(
                db,
                session_id=session_id,
                owner=context.actor,
                source_kind=CaptureSource.PCAP,
                status=CaptureStatus.RUNNING,
                source_label=name,
            )
            record_audit(
                db,
                actor=context.actor,
                action=NETWORK_PCAP_ANALYZE,
                result=RESULT_SUCCESS,
                target=_target(session_id),
                source_ip=context.source_ip,
                details={
                    "size_bytes": upload.size,
                    "format": info.format,
                    "packets": info.packets,
                    "truncated": info.truncated,
                },
            )
            db.commit()
        except BaseException:
            self._runner.release()
            self._spool.remove(path)
            raise

        cancel = self._runner.cancel

        def job() -> None:
            outcome = AnalysisOutcome(CaptureStatus.FAILED, "analysis_failed", 0)
            try:
                outcome = analyze_file(path, info, monitor, cancel=cancel)
            except Exception as exc:
                logger.error("pcap_analysis_failed", extra={"error": type(exc).__name__})
            finally:
                try:
                    monitor.finish(outcome.status, outcome.error_code)
                finally:
                    self._spool.remove(path)

        try:
            self._runner.launch(job)
        except Exception as exc:  # the analysis thread could not be started
            logger.error("pcap_launch_failed", extra={"error": type(exc).__name__})
            self._runner.release()
            self._spool.remove(path)
            recorder.set_status(CaptureStatus.FAILED, error_code="analysis_failed", ended=True)
            raise _capture_error("analysis_failed") from None
        return self._detail(row)

    # --- Sessions, flows, alerts ---------------------------------------------------------

    def list_sessions(self, db: Session, owner: str, *, limit: int, offset: int) -> SessionPage:
        self._purge_when_due()
        rows, total = repository.list_sessions(db, owner, limit=limit, offset=offset)
        now = utcnow()
        return SessionPage(
            items=[views.session_out(row, now=now) for row in rows],
            total=total,
            limit=limit,
            offset=offset,
        )

    def get_session(self, db: Session, owner: str, session_id: uuid.UUID) -> SessionDetail:
        return self._detail(self._owned(db, owner, session_id))

    def list_flows(
        self, db: Session, owner: str, session_id: uuid.UUID, *, limit: int, offset: int
    ) -> FlowPage:
        self._owned(db, owner, session_id)
        rows, total = repository.list_flows(db, session_id, limit=limit, offset=offset)
        return FlowPage(
            items=[views.flow_out(row) for row in rows], total=total, limit=limit, offset=offset
        )

    def list_alerts(
        self,
        db: Session,
        owner: str,
        session_id: uuid.UUID,
        *,
        severities: Collection[str],
        rule_id: str | None,
        limit: int,
        offset: int,
    ) -> AlertPage:
        self._owned(db, owner, session_id)
        rows, total = repository.list_alerts(
            db, session_id, severities=severities, rule_id=rule_id, limit=limit, offset=offset
        )
        return AlertPage(
            items=[views.alert_out(row) for row in rows], total=total, limit=limit, offset=offset
        )

    def delete_session(self, db: Session, context: RequestContext, session_id: uuid.UUID) -> None:
        row = self._owned(db, context.actor, session_id)
        if row.status in _ACTIVE_VALUES:
            raise ApiError(
                409,
                "session_running",
                "The session is still running. Stop it before deleting it.",
            )
        details = {
            "source": row.source_kind,
            "flows": row.flows_total,
            "alerts": row.alerts_total,
        }
        self._enrichment.discard(session_id)
        repository.delete_session(db, session_id)
        record_audit(
            db,
            actor=context.actor,
            action=NETWORK_SESSION_DELETE,
            result=RESULT_SUCCESS,
            target=_target(session_id),
            source_ip=context.source_ip,
            details=details,
        )
        db.commit()

    def enrich_alert(self, db: Session, context: RequestContext, alert_id: uuid.UUID) -> AlertOut:
        """Look up the public address of an alert now, for the caller, and return the alert."""
        alert = repository.get_owned_alert(db, context.actor, alert_id)
        if alert is None:
            raise ApiError(404, "alert_not_found", "Alert not found.")
        if not self._settings.external_enrichment_enabled:
            raise ApiError(
                409,
                "enrichment_disabled",
                "External enrichment is switched off on this server.",
            )
        address = subject_address(alert.src_ip, alert.dst_ip)
        if address is None:
            raise ApiError(
                422,
                "address_not_public",
                "The alert involves no public address, so there is nothing to look up.",
            )
        summary = self._enrichment.refresh(alert.session_id, address, context)
        self._audit(
            db,
            context,
            NETWORK_ENRICH,
            RESULT_SUCCESS if summary.get("status") == "completed" else RESULT_PARTIAL,
            target=f"network-alert:{alert_id}",
            details={"status": summary.get("status"), "error_code": summary.get("error_code")},
        )
        db.refresh(alert)
        return views.alert_out(alert)

    # --- Maintenance ---------------------------------------------------------------------

    def startup(self) -> None:
        """Clean up after the previous run. Tolerates a database that is not migrated yet."""
        ended = lookups = purged = 0
        try:
            with self._session_factory() as db:
                ended = repository.interrupt_unfinished_sessions(db)
                lookups = repository.interrupt_pending_lookups(db)
            purged = self.purge_expired()
        except SQLAlchemyError as exc:
            logger.warning("network_startup_skipped", extra={"error": type(exc).__name__})
        # Uploads left in the spool by a crash are cleared whatever state the database is in.
        stale = self._spool.purge_stale()
        if ended or lookups or purged or stale:
            logger.info(
                "network_startup_cleanup",
                extra={
                    "sessions_interrupted": ended,
                    "lookups_interrupted": lookups,
                    "sessions_purged": purged,
                    "stale_uploads_removed": stale,
                },
            )

    def purge_expired(self) -> int:
        """Delete finished sessions older than the retention period. Returns how many."""
        cutoff = utcnow() - timedelta(hours=self._settings.network_retention_hours)
        total = 0
        try:
            with self._session_factory() as db:
                for _ in range(_MAX_PURGE_ROUNDS):
                    removed = repository.purge_finished_before(db, cutoff, batch=_PURGE_BATCH)
                    total += removed
                    if removed < _PURGE_BATCH:
                        break
        except SQLAlchemyError as exc:
            logger.warning("network_purge_failed", extra={"error": type(exc).__name__})
        return total

    def shutdown(self) -> None:
        """Stop everything this service started. Safe to call more than once."""
        with self._live_lock:
            run = self._live
        if run is not None and run.capture is not None:
            run.capture.stop(SHUTDOWN_TIMEOUT_SECONDS)
        self._runner.shutdown(SHUTDOWN_TIMEOUT_SECONDS)
        self._enrichment.stop()
        try:
            with self._session_factory() as db:
                repository.interrupt_pending_lookups(db)
        except SQLAlchemyError as exc:
            logger.warning("network_shutdown_cleanup_failed", extra={"error": type(exc).__name__})
        self._spool.close()

    # --- Internals ------------------------------------------------------------------------

    def _current_live_locked(self) -> _LiveRun | None:
        """The capture holding the slot, forgetting one that has ended. Hold ``_live_lock``."""
        run = self._live
        if run is not None and not run.active:
            self._live = None
            return None
        return run

    def _release(self, run: _LiveRun) -> None:
        with self._live_lock:
            if self._live is run:
                self._live = None

    def _resolve_interface(self, interface_id: str) -> InterfaceInfo | None:
        try:
            return self._catalog.resolve(interface_id)
        except Exception as exc:  # the operating system's interface listing can fail
            logger.warning("interface_listing_failed", extra={"error": type(exc).__name__})
            return None

    def _build(
        self, session_id: uuid.UUID, *, stream_time: bool
    ) -> tuple[SessionRecorder, SessionMonitor]:
        recorder = SessionRecorder(
            self._session_factory,
            session_id,
            max_stored_flows=self._settings.network_max_stored_flows,
            enrichment_enabled=self._settings.external_enrichment_enabled,
            stats_lock=self._stats_lock,
        )
        monitor = SessionMonitor(
            session_id,
            settings=self._settings,
            recorder=recorder,
            enrichment=self._enrichment,
            stream_time=stream_time,
            clock=self._clock,
        )
        return recorder, monitor

    def _owned(self, db: Session, owner: str, session_id: uuid.UUID) -> CaptureSession:
        row = repository.get_session(db, owner, session_id)
        if row is None:
            raise ApiError(404, "session_not_found", "Monitoring session not found.")
        return row

    def _detail(self, row: CaptureSession) -> SessionDetail:
        session_id = row.id
        return views.session_detail(
            row,
            now=utcnow(),
            enrichment_enabled=self._settings.external_enrichment_enabled,
            is_pending=lambda address: self._enrichment.is_pending(session_id, address),
        )

    def _analysis_status(self, db: Session, owner: str) -> AnalysisStatus:
        running = self._runner.session_id
        own = None
        if running is not None and repository.get_session(db, owner, running) is not None:
            own = running
        return AnalysisStatus(
            running=running is not None,
            session_id=own,
            max_upload_mb=self._settings.network_max_pcap_size_mb,
        )

    def _purge_when_due(self) -> None:
        now = time.monotonic()
        if now - self._last_purge < PURGE_INTERVAL_SECONDS:
            return
        if not self._purge_lock.acquire(blocking=False):
            return
        try:
            self._last_purge = now
            self.purge_expired()
        finally:
            self._purge_lock.release()

    def _audit(
        self,
        db: Session,
        context: RequestContext,
        action: str,
        result: str,
        *,
        target: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        record_audit(
            db,
            actor=context.actor,
            action=action,
            result=result,
            target=target,
            source_ip=context.source_ip,
            details=details,
        )
        db.commit()

    def _reject(
        self,
        db: Session,
        context: RequestContext,
        action: str,
        reason: str,
        *,
        target: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self._audit(
            db,
            context,
            action,
            RESULT_REJECTED,
            target=target,
            details={"reason": reason, **(details or {})},
        )
