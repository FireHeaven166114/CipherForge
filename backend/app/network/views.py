"""Turns stored rows into API response models.

Capture statistics and enrichment answers are kept as JSON on the session and its alerts, written
by two threads at different times. They are read defensively here: a missing or malformed value
becomes a neutral default instead of an error, so one odd row never breaks a whole page.
"""

import math
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any, get_args

from app.core.timeutil import parse_timestamp
from app.detection.network_rules import ALL_RULES, RuleSetting
from app.models.network import CaptureSession, NetworkAlert, NetworkFlow
from app.network.errors import message_for
from app.network.repository import ACTIVE_STATUSES
from app.schemas.network import (
    AlertOut,
    EnrichmentOut,
    EnrichmentProviderOut,
    EnrichmentState,
    EnrichmentSummary,
    ExternalIpOut,
    FlowOut,
    ProtocolStat,
    RuleOut,
    SessionDetail,
    SessionOut,
    TalkerStat,
)

_ACTIVE = {status.value for status in ACTIVE_STATUSES}
_STATES = set(get_args(EnrichmentState))
_MAX_EXTERNAL_IPS = 100
_MAX_PROVIDERS = 10
_TCP_FLAGS = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
)
_RULES_BY_ID = {rule.rule_id: rule for rule in ALL_RULES}

ENRICHMENT_MESSAGES: dict[str, str] = {
    "rate_limited": "A provider's rate limit was reached. Try again later.",
    "provider_error": "A provider returned an error.",
    "no_provider_available": "No configured provider could answer for this address.",
    "queue_full": "The lookup queue was full, so this address was not looked up.",
    "lookup_failed": "The lookup failed.",
    "indicator_deleted": "The indicator was deleted while it was being looked up.",
    "interrupted": "The application stopped before the lookup finished.",
}
_STATE_MESSAGES: dict[str, str] = {
    "pending": "Waiting for the lookup.",
    "disabled": "External enrichment is switched off.",
    "skipped_budget": "Not looked up: the session reached its limit on lookups.",
    "not_applicable": "The traffic involves no public address, so there is nothing to look up.",
    "not_looked_up": "Not looked up.",
}
_NO_EVIDENCE = "No provider returned evidence for this address. That does not mean it is safe."


# --- Small readers -------------------------------------------------------------------------


def _int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return default
    if isinstance(value, float) and not math.isfinite(value):
        return default
    return int(value)


def _rule_counts(*sources: Any) -> dict[str, int]:
    """Alerts per rule, added up over the stored maps. Anything that is not a map adds nothing."""
    counts: dict[str, int] = {}
    for source in sources:
        if isinstance(source, dict):
            for rule, count in source.items():
                counts[str(rule)] = counts.get(str(rule), 0) + _int(count)
    return counts


def _items(value: Any) -> list[Any]:
    """The elements of a stored list; anything else is no list at all."""
    return value if isinstance(value, list) else []


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _strings(value: Any, limit: int = 10) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)][:limit]


def _ports(value: Any, limit: int = 10) -> list[int]:
    if not isinstance(value, list):
        return []
    return [
        item
        for item in value
        if isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 65535
    ][:limit]


def _time(value: Any) -> datetime | None:
    return parse_timestamp(value)


def _uuid(value: Any) -> uuid.UUID | None:
    if not isinstance(value, str):
        return None
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


def tcp_flag_names(flags: int | None) -> list[str]:
    if flags is None:
        return []
    return [name for bit, name in _TCP_FLAGS if flags & bit]


# --- Enrichment ----------------------------------------------------------------------------


def parse_enrichment(raw: Mapping[str, Any] | None) -> EnrichmentOut:
    """The stored lookup state of an alert or an address as a response model."""
    state = raw if isinstance(raw, Mapping) else {}
    status = state.get("status")
    if not raw:
        status = "not_applicable"
    elif not isinstance(status, str) or status not in _STATES:
        status = "unavailable"
    providers: list[EnrichmentProviderOut] = []
    for item in _items(state.get("providers"))[:_MAX_PROVIDERS]:
        if not isinstance(item, dict):
            continue
        provider, display_name = _text(item.get("provider")), _text(item.get("display_name"))
        if provider is None:
            continue
        providers.append(
            EnrichmentProviderOut(
                provider=provider,
                display_name=display_name or provider,
                status=_text(item.get("status")) or "unknown",
                verdict=_text(item.get("verdict")),
            )
        )
    score = state.get("risk_score")
    classification = _text(state.get("classification"))
    error_code = _text(state.get("error_code"))
    assessed = state.get("assessed")
    message = ENRICHMENT_MESSAGES.get(error_code or "") or _STATE_MESSAGES.get(str(status))
    if status == "completed" and assessed is False:
        # No provider returned evidence: whatever score was kept with it is not a finding.
        message, score, classification = _NO_EVIDENCE, None, None
    return EnrichmentOut(
        status=status,
        address=_text(state.get("address")),
        risk_score=score if isinstance(score, int) and not isinstance(score, bool) else None,
        classification=classification,
        assessed=assessed if isinstance(assessed, bool) else None,
        indicator_id=_uuid(state.get("indicator_id")),
        completed_at=_time(state.get("completed_at")),
        error_code=error_code,
        message=message,
        providers=providers,
    )


def external_ips(
    stats: Mapping[str, Any],
    *,
    enabled: bool,
    is_pending: Callable[[str], bool],
) -> list[ExternalIpOut]:
    """The session's public addresses (those kept with traffic details) with their results."""
    results = stats.get("enrichment")
    results = results if isinstance(results, dict) else {}
    found: list[ExternalIpOut] = []
    seen: set[str] = set()
    for entry in _items(stats.get("external_peers")):
        if not isinstance(entry, dict):
            continue
        address = _text(entry.get("address"))
        if address is None or address in seen:
            continue
        seen.add(address)
        found.append(
            ExternalIpOut(
                address=address,
                first_seen=_time(entry.get("first_seen")),
                last_seen=_time(entry.get("last_seen")),
                packets=_int(entry.get("packets")),
                bytes=_int(entry.get("bytes")),
                sent_to=bool(entry.get("sent_to")),
                alerted=bool(entry.get("alerted")),
                peers=_strings(entry.get("peers")),
                ports=_ports(entry.get("ports")),
                protocols=_strings(entry.get("protocols")),
                enrichment=_lookup_state(address, results, enabled=enabled, is_pending=is_pending),
            )
        )
    # An address with an answer but no traffic details (they were evicted) is still worth showing.
    for address, answer in results.items():
        if address in seen or not isinstance(answer, dict):
            continue
        seen.add(address)
        found.append(
            ExternalIpOut(
                address=address,
                first_seen=None,
                last_seen=None,
                packets=None,
                bytes=None,
                sent_to=False,
                alerted=False,
                peers=[],
                ports=[],
                protocols=[],
                enrichment=parse_enrichment(answer),
            )
        )
    found.sort(key=lambda item: (not item.alerted, -(item.bytes or 0), item.address))
    return found[:_MAX_EXTERNAL_IPS]


def _lookup_state(
    address: str,
    results: Mapping[str, Any],
    *,
    enabled: bool,
    is_pending: Callable[[str], bool],
) -> EnrichmentOut:
    answer = results.get(address)
    if isinstance(answer, dict) and answer:
        return parse_enrichment(answer)
    if not enabled:
        status = "disabled"
    elif is_pending(address):
        status = "pending"
    else:
        status = "not_looked_up"
    return parse_enrichment({"status": status, "address": address})


def summarize_enrichment(items: list[ExternalIpOut], *, enabled: bool) -> EnrichmentSummary:
    counts: dict[str, int] = {}
    for item in items:
        counts[item.enrichment.status] = counts.get(item.enrichment.status, 0) + 1
    return EnrichmentSummary(
        enabled=enabled,
        total=len(items),
        completed=counts.get("completed", 0),
        pending=counts.get("pending", 0),
        failed=counts.get("failed", 0),
        unavailable=counts.get("unavailable", 0),
        skipped=sum(
            counts.get(name, 0) for name in ("skipped_budget", "not_looked_up", "disabled")
        ),
    )


# --- Sessions, flows, alerts ---------------------------------------------------------------


def session_out(row: CaptureSession, *, now: datetime) -> SessionOut:
    stats = row.stats if isinstance(row.stats, dict) else {}
    end = row.ended_at or now
    return SessionOut(
        id=row.id,
        source_kind=row.source_kind,
        status=row.status,
        interface=row.interface,
        source_label=row.source_label,
        started_at=row.started_at,
        ended_at=row.ended_at,
        duration_seconds=max((end - row.started_at).total_seconds(), 0.0),
        packets_total=row.packets_total,
        bytes_total=row.bytes_total,
        flows_total=row.flows_total,
        active_flows=_int(stats.get("active_flows")) if row.status in _ACTIVE else 0,
        alerts_total=row.alerts_total,
        packets_dropped=row.packets_dropped,
        error_code=row.error_code,
        message=message_for(row.error_code),
    )


def session_detail(
    row: CaptureSession,
    *,
    now: datetime,
    enrichment_enabled: bool,
    is_pending: Callable[[str], bool],
) -> SessionDetail:
    stats = row.stats if isinstance(row.stats, dict) else {}
    addresses = external_ips(stats, enabled=enrichment_enabled, is_pending=is_pending)
    return SessionDetail(
        **session_out(row, now=now).model_dump(),
        first_packet_at=_time(stats.get("first_packet_at")),
        last_packet_at=_time(stats.get("last_packet_at")),
        protocols=[
            ProtocolStat(
                protocol=str(item.get("protocol", "")),
                packets=_int(item.get("packets")),
                bytes=_int(item.get("bytes")),
            )
            for item in _items(stats.get("protocols"))
            if isinstance(item, dict) and item.get("protocol")
        ],
        top_sources=_talkers(stats.get("top_sources")),
        top_destinations=_talkers(stats.get("top_destinations")),
        non_ip_packets=_int(stats.get("non_ip_packets")),
        malformed_packets=_int(stats.get("malformed_packets")),
        flows_evicted=_int(stats.get("flows_evicted")),
        flows_stored=_int(stats.get("flows_stored")),
        flows_not_stored=_int(stats.get("flows_not_stored")),
        # The monitor counts the alerts its rules raise; the enrichment worker counts its own.
        alerts_by_rule=_rule_counts(stats.get("alerts_by_rule"), stats.get("enrichment_alerts")),
        alerts_suppressed=_int(stats.get("alerts_suppressed")),
        alerts_lost=_int(stats.get("alerts_lost")),
        talkers_truncated=bool(stats.get("talkers_truncated")),
        external_ips=addresses,
        enrichment=summarize_enrichment(addresses, enabled=enrichment_enabled),
    )


def _talkers(value: Any) -> list[TalkerStat]:
    return [
        TalkerStat(
            address=str(item["address"]),
            packets=_int(item.get("packets")),
            bytes=_int(item.get("bytes")),
        )
        for item in _items(value)
        if isinstance(item, dict) and item.get("address")
    ]


def flow_out(row: NetworkFlow) -> FlowOut:
    return FlowOut(
        id=row.id,
        protocol=row.protocol,
        src_ip=row.src_ip,
        src_port=row.src_port,
        dst_ip=row.dst_ip,
        dst_port=row.dst_port,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        duration_seconds=max((row.last_seen - row.first_seen).total_seconds(), 0.0),
        packets_out=row.packets_out,
        packets_in=row.packets_in,
        bytes_out=row.bytes_out,
        bytes_in=row.bytes_in,
        tcp_flags=row.tcp_flags,
        tcp_flag_names=tcp_flag_names(row.tcp_flags),
        close_reason=row.close_reason,
    )


def alert_out(row: NetworkAlert) -> AlertOut:
    rule = _RULES_BY_ID.get(row.rule_id)
    return AlertOut(
        id=row.id,
        session_id=row.session_id,
        rule_id=row.rule_id,
        rule_name=row.rule_name,
        title=rule.title if rule is not None else row.rule_name,
        severity=row.severity,
        explanation=row.explanation,
        observed_value=row.observed_value,
        threshold=row.threshold,
        unit=rule.unit if rule is not None else "",
        window_seconds=row.window_seconds,
        src_ip=row.src_ip,
        dst_ip=row.dst_ip,
        dst_port=row.dst_port,
        protocol=row.protocol,
        first_observed=row.first_observed,
        last_observed=row.last_observed,
        created_at=row.created_at,
        evidence=row.evidence if isinstance(row.evidence, dict) else {},
        enrichment=parse_enrichment(row.enrichment),
    )


def rule_out(setting: RuleSetting, *, enrichment_enabled: bool) -> RuleOut:
    info = setting.info
    return RuleOut(
        rule_id=info.rule_id,
        name=info.name,
        title=info.title,
        description=info.description,
        unit=info.unit,
        threshold=setting.threshold,
        window_seconds=setting.window_seconds,
        detail=setting.detail,
        active=enrichment_enabled or not info.needs_enrichment,
        severities=[severity.value for severity in info.severities],
    )
