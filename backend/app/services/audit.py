"""Writer for the append-only audit trail (spec section 19).

Callers add the row to their own session and commit it together with the work it describes, so
an action and its audit record succeed or fail as one. If the audit insert fails, the request
fails: it is better to refuse an action than to perform it without a record.
"""

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.core.context import correlation_id_var
from app.models.audit import AuditLog

IOC_LOOKUP = "IOC_LOOKUP"

RESULT_SUCCESS = "success"
RESULT_PARTIAL = "partial"
RESULT_REJECTED = "rejected"

# Column widths of audit_logs; longer values are truncated rather than failing the insert.
_ACTOR_MAX = 256
_ACTION_MAX = 64
_TARGET_MAX = 2100
_RESULT_MAX = 32
_SOURCE_IP_MAX = 64
_CORRELATION_ID_MAX = 64


def record_audit(
    session: Session,
    *,
    actor: str,
    action: str,
    result: str,
    target: str | None = None,
    source_ip: str | None = None,
    correlation_id: str | None = None,
    details: dict[str, Any] | None = None,
    timestamp: datetime | None = None,
) -> AuditLog:
    """Add one audit row to ``session`` (the caller commits).

    ``actor`` is the authenticated principal's stable subject. Never put passwords, tokens,
    API keys or raw user input in ``details``. ``timestamp`` defaults to the current UTC time;
    services pass their own clock so one investigation has one notion of "now".
    """
    correlation = correlation_id if correlation_id is not None else correlation_id_var.get()
    entry = AuditLog(
        actor=actor[:_ACTOR_MAX],
        action=action[:_ACTION_MAX],
        target=target[:_TARGET_MAX] if target is not None else None,
        result=result[:_RESULT_MAX],
        source_ip=source_ip[:_SOURCE_IP_MAX] if source_ip is not None else None,
        correlation_id=correlation[:_CORRELATION_ID_MAX] if correlation is not None else None,
        details=details,
    )
    if timestamp is not None:
        entry.timestamp = timestamp
    session.add(entry)
    return entry
