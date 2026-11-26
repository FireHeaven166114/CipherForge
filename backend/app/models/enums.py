"""Closed vocabularies shared by the ORM models, normalizer, collectors and API.

Kept free of SQLAlchemy imports so pure modules (normalization, scoring) can use them.
"""

from enum import StrEnum


class IndicatorType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class IndicatorStatus(StrEnum):
    """Evidence state of an indicator as of its last check.

    ``active``: at least one provider answered freshly. ``stale``: no fresh provider evidence.
    """

    ACTIVE = "active"
    STALE = "stale"


class ObservationStatus(StrEnum):
    """Stored observation outcomes. Failures (errors, rate limits) are never stored."""

    OK = "ok"
    NO_DATA = "no_data"


class CaptureSource(StrEnum):
    """Where a monitoring session's packets came from."""

    LIVE = "live"
    PCAP = "pcap"


class CaptureStatus(StrEnum):
    """Lifecycle of one monitoring session.

    A live capture goes ``starting`` -> ``running`` -> ``stopping`` -> ``stopped``. An uploaded
    capture file goes ``running`` -> ``completed``. ``failed`` and ``permission_denied`` end either.
    """

    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    COMPLETED = "completed"
    FAILED = "failed"
    PERMISSION_DENIED = "permission_denied"


class AlertSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FlowCloseReason(StrEnum):
    """Why a flow left the active table: it went quiet, was pushed out by the size limit, the
    connection ended (TCP reset, or a FIN seen both ways), or the session ended with it open."""

    IDLE = "idle"
    EVICTED = "evicted"
    CLOSED = "closed"
    ENDED = "ended"


class FileStatus(StrEnum):
    """``corrupt`` is set when the stored ciphertext failed authentication; the file is then
    refused for every download until its owner deletes it."""

    ACTIVE = "active"
    CORRUPT = "corrupt"
