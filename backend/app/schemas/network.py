"""Request and response models for the network-monitoring API.

Timestamps are timezone-aware UTC, like everywhere else in the API; the interface shows them in
Indian Standard Time.
"""

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

CaptureState = Literal[
    "not_configured",
    "ready",
    "starting",
    "running",
    "stopping",
    "stopped",
    "failed",
    "permission_denied",
]
SessionStatus = Literal[
    "starting", "running", "stopping", "stopped", "completed", "failed", "permission_denied"
]
SourceKind = Literal["live", "pcap"]
Severity = Literal["low", "medium", "high", "critical"]
EnrichmentState = Literal[
    "pending",
    "completed",
    "failed",
    "unavailable",
    "disabled",
    "skipped_budget",
    "not_applicable",
    "not_looked_up",
]

MAX_INTERFACE_ID = 512


class StartCaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # An id from GET /network/interfaces. It is checked against the interfaces that exist.
    interface: str = Field(min_length=1, max_length=MAX_INTERFACE_ID)


class BackendOut(BaseModel):
    # "npcap", "winpcap", "libpcap", "native" (the kernel's packet socket) or "none".
    name: str
    available: bool


class AnalysisStatus(BaseModel):
    running: bool
    # Set only for the caller's own analysis.
    session_id: uuid.UUID | None
    max_upload_mb: int


class NetworkStatus(BaseModel):
    state: CaptureState
    backend: BackendOut
    # The caller's live capture: the one running now, or the latest that ended.
    interface: str | None
    session_id: uuid.UUID | None
    error_code: str | None
    message: str | None
    # Someone else's live capture holds the single capture slot.
    busy: bool
    analysis: AnalysisStatus
    enrichment_enabled: bool


class InterfaceOut(BaseModel):
    id: str
    name: str
    description: str
    addresses: list[str]


class InterfaceList(BaseModel):
    backend: BackendOut
    interfaces: list[InterfaceOut]


class RuleOut(BaseModel):
    rule_id: str
    name: str
    title: str
    description: str
    # What ``threshold`` counts: ports, connections, SYN packets, MB, risk score ...
    unit: str
    threshold: float
    window_seconds: int | None
    detail: str | None
    # False when the rule cannot fire in the current configuration (external lookups are off).
    active: bool
    # The severity at 1x, 3x and 10x the threshold.
    severities: list[Severity]


class EnrichmentProviderOut(BaseModel):
    provider: str
    display_name: str
    # "ok", "no_data", "not_configured", "unsupported", "rate_limited", "error" or "not_queried".
    status: str
    verdict: str | None


class EnrichmentOut(BaseModel):
    """What the threat-intelligence providers said about one public address."""

    status: EnrichmentState
    address: str | None = None
    # Only present when a provider returned evidence (``assessed`` is true). "No data" never means
    # "safe", so an answer of "nothing known" carries no score and no classification.
    risk_score: int | None = None
    classification: str | None = None
    # True when a provider returned evidence, not only a "nothing known".
    assessed: bool | None = None
    indicator_id: uuid.UUID | None = None
    completed_at: datetime | None = None
    error_code: str | None = None
    message: str | None = None
    providers: list[EnrichmentProviderOut] = Field(default_factory=list)


class ProtocolStat(BaseModel):
    protocol: str
    packets: int
    bytes: int


class TalkerStat(BaseModel):
    address: str
    packets: int
    bytes: int


class ExternalIpOut(BaseModel):
    """A public address the session's traffic involved, with its lookup result."""

    address: str
    first_seen: datetime | None
    last_seen: datetime | None
    packets: int | None
    bytes: int | None
    # Whether anything on the monitored side sent traffic to it.
    sent_to: bool
    alerted: bool
    peers: list[str]
    ports: list[int]
    protocols: list[str]
    enrichment: EnrichmentOut


class EnrichmentSummary(BaseModel):
    enabled: bool
    total: int
    completed: int
    pending: int
    failed: int
    unavailable: int
    skipped: int


class SessionOut(BaseModel):
    id: uuid.UUID
    source_kind: SourceKind
    status: SessionStatus
    interface: str | None
    # For a capture file: the name it was uploaded under (display only).
    source_label: str | None
    started_at: datetime
    ended_at: datetime | None
    duration_seconds: float
    packets_total: int
    bytes_total: int
    flows_total: int
    active_flows: int
    alerts_total: int
    packets_dropped: int
    error_code: str | None
    message: str | None


class SessionPage(BaseModel):
    items: list[SessionOut]
    total: int
    limit: int
    offset: int


class SessionDetail(SessionOut):
    first_packet_at: datetime | None
    last_packet_at: datetime | None
    protocols: list[ProtocolStat]
    top_sources: list[TalkerStat]
    top_destinations: list[TalkerStat]
    non_ip_packets: int
    malformed_packets: int
    flows_evicted: int
    flows_stored: int
    # Finished flows beyond the per-session storage limit. They are counted, not stored.
    flows_not_stored: int
    alerts_by_rule: dict[str, int]
    alerts_suppressed: int
    alerts_lost: int
    talkers_truncated: bool
    external_ips: list[ExternalIpOut]
    enrichment: EnrichmentSummary


class FlowOut(BaseModel):
    id: int
    protocol: str
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    first_seen: datetime
    last_seen: datetime
    duration_seconds: float
    packets_out: int
    packets_in: int
    bytes_out: int
    bytes_in: int
    tcp_flags: int | None
    tcp_flag_names: list[str]
    close_reason: str


class FlowPage(BaseModel):
    items: list[FlowOut]
    total: int
    limit: int
    offset: int


class AlertOut(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    rule_id: str
    rule_name: str
    title: str
    severity: Severity
    explanation: str
    observed_value: float
    threshold: float
    unit: str
    window_seconds: int | None
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None
    first_observed: datetime
    last_observed: datetime
    created_at: datetime
    evidence: dict[str, Any]
    enrichment: EnrichmentOut


class AlertPage(BaseModel):
    items: list[AlertOut]
    total: int
    limit: int
    offset: int
