"""Database access for network monitoring.

Everything that reads or removes capture sessions, flows and alerts goes through here. Reads for
the API are always scoped to one owner; the maintenance functions (retention, crash recovery) are
the only ones that look across owners.
"""

import uuid
from collections.abc import Collection, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import String, cast, delete, func, select
from sqlalchemy.orm import Session

from app.models.enums import CaptureSource, CaptureStatus
from app.models.network import CaptureSession, NetworkAlert, NetworkFlow
from app.models.types import utcnow

ACTIVE_STATUSES = (CaptureStatus.STARTING, CaptureStatus.RUNNING, CaptureStatus.STOPPING)
FINISHED_STATUSES = (
    CaptureStatus.STOPPED,
    CaptureStatus.COMPLETED,
    CaptureStatus.FAILED,
    CaptureStatus.PERMISSION_DENIED,
)
_ACTIVE_VALUES = [status.value for status in ACTIVE_STATUSES]
_FINISHED_VALUES = [status.value for status in FINISHED_STATUSES]
_PENDING = "pending"


def new_session(
    db: Session,
    *,
    session_id: uuid.UUID,
    owner: str,
    source_kind: CaptureSource,
    status: CaptureStatus,
    interface: str | None = None,
    source_label: str | None = None,
) -> CaptureSession:
    row = CaptureSession(
        id=session_id,
        owner=owner,
        source_kind=source_kind.value,
        status=status.value,
        interface=interface[:256] if interface else None,
        source_label=source_label[:128] if source_label else None,
        started_at=utcnow(),
    )
    db.add(row)
    return row


def get_session(db: Session, owner: str, session_id: uuid.UUID) -> CaptureSession | None:
    """The owner's session, or None. Someone else's session is the same as one that is not there."""
    return db.scalar(
        select(CaptureSession).where(CaptureSession.id == session_id, CaptureSession.owner == owner)
    )


def latest_live_session(db: Session, owner: str) -> CaptureSession | None:
    return db.scalar(
        select(CaptureSession)
        .where(CaptureSession.owner == owner, CaptureSession.source_kind == CaptureSource.LIVE)
        .order_by(CaptureSession.started_at.desc(), CaptureSession.id)
        .limit(1)
    )


def list_sessions(
    db: Session, owner: str, *, limit: int, offset: int
) -> tuple[Sequence[CaptureSession], int]:
    total = db.scalar(
        select(func.count()).select_from(CaptureSession).where(CaptureSession.owner == owner)
    )
    rows = db.scalars(
        select(CaptureSession)
        .where(CaptureSession.owner == owner)
        .order_by(CaptureSession.started_at.desc(), CaptureSession.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return rows, int(total or 0)


def list_flows(
    db: Session, session_id: uuid.UUID, *, limit: int, offset: int
) -> tuple[Sequence[NetworkFlow], int]:
    total = db.scalar(
        select(func.count()).select_from(NetworkFlow).where(NetworkFlow.session_id == session_id)
    )
    rows = db.scalars(
        select(NetworkFlow)
        .where(NetworkFlow.session_id == session_id)
        .order_by(NetworkFlow.first_seen.desc(), NetworkFlow.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return rows, int(total or 0)


def list_alerts(
    db: Session,
    session_id: uuid.UUID,
    *,
    severities: Collection[str] = (),
    rule_id: str | None = None,
    limit: int,
    offset: int,
) -> tuple[Sequence[NetworkAlert], int]:
    conditions: list[Any] = [NetworkAlert.session_id == session_id]
    if severities:
        conditions.append(NetworkAlert.severity.in_(list(severities)))
    if rule_id:
        conditions.append(NetworkAlert.rule_id == rule_id)
    total = db.scalar(select(func.count()).select_from(NetworkAlert).where(*conditions))
    rows = db.scalars(
        select(NetworkAlert)
        .where(*conditions)
        .order_by(NetworkAlert.created_at.desc(), NetworkAlert.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return rows, int(total or 0)


def get_owned_alert(db: Session, owner: str, alert_id: uuid.UUID) -> NetworkAlert | None:
    """The alert, if it belongs to one of the owner's sessions."""
    return db.scalar(
        select(NetworkAlert)
        .join(CaptureSession, CaptureSession.id == NetworkAlert.session_id)
        .where(NetworkAlert.id == alert_id, CaptureSession.owner == owner)
    )


def delete_session(db: Session, session_id: uuid.UUID) -> None:
    """Remove a session with its flows and alerts. The caller commits."""
    db.execute(delete(NetworkAlert).where(NetworkAlert.session_id == session_id))
    db.execute(delete(NetworkFlow).where(NetworkFlow.session_id == session_id))
    db.execute(delete(CaptureSession).where(CaptureSession.id == session_id))


# --- Maintenance ---------------------------------------------------------------------------


def purge_finished_before(db: Session, cutoff: datetime, *, batch: int = 200) -> int:
    """Delete finished sessions that ended before ``cutoff`` (at most ``batch`` of them).

    A session that is still running is never touched. Returns how many were deleted.
    """
    ids = list(
        db.scalars(
            select(CaptureSession.id)
            .where(
                CaptureSession.status.in_(_FINISHED_VALUES),
                func.coalesce(CaptureSession.ended_at, CaptureSession.started_at) < cutoff,
            )
            .order_by(CaptureSession.started_at)
            .limit(batch)
        )
    )
    if not ids:
        return 0
    db.execute(delete(NetworkAlert).where(NetworkAlert.session_id.in_(ids)))
    db.execute(delete(NetworkFlow).where(NetworkFlow.session_id.in_(ids)))
    db.execute(delete(CaptureSession).where(CaptureSession.id.in_(ids)))
    db.commit()
    return len(ids)


def interrupt_unfinished_sessions(db: Session) -> int:
    """End sessions the previous process left running.

    Capture state lives in the process, so at start-up a session still marked starting, running
    or stopping can only be one the process died on. Returns how many were ended.
    """
    rows = db.scalars(select(CaptureSession).where(CaptureSession.status.in_(_ACTIVE_VALUES))).all()
    now = utcnow()
    for row in rows:
        row.status = CaptureStatus.FAILED.value
        row.error_code = "interrupted"
        row.ended_at = max(now, row.started_at)
    if rows:
        db.commit()
    return len(rows)


def interrupt_pending_lookups(db: Session) -> int:
    """Give alerts whose lookup was still waiting a final answer, since nothing will finish it.

    The text match only narrows the scan; the status itself is checked on the decoded value.
    """
    rows = db.scalars(
        select(NetworkAlert).where(cast(NetworkAlert.enrichment, String).like(f"%{_PENDING}%"))
    ).all()
    changed = 0
    for row in rows:
        state = row.enrichment
        if not isinstance(state, dict) or state.get("status") != _PENDING:
            continue
        row.enrichment = {
            "status": "unavailable",
            "address": state.get("address"),
            "error_code": "interrupted",
        }
        changed += 1
    if changed:
        db.commit()
    return changed
