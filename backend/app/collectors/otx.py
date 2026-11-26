"""AlienVault OTX adapter (IPs, domains, URLs and MD5, SHA-1 and SHA-256 file hashes).

Uses ``GET /api/v1/indicators/{type}/{value}/general`` and reads only the ``pulse_info`` and
``validation`` sections. A *pulse* is a community-submitted threat report, so the number of
pulses is a weak-to-moderate signal and every pulse title is untrusted text.

The response field names used here come from OTX's public examples and SDK, and a live lookup
has returned them. Parsing is still defensive: an unexpected shape becomes a provider error,
never a crash or a guess.
"""

import re
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, ClassVar
from urllib.parse import quote

from app.collectors.base import (
    Collector,
    ProviderFailure,
    ProviderResult,
    ProviderStatus,
    Reason,
)
from app.collectors.sanitize import bounded_int, clean_text, isoformat, parse_timestamp
from app.models.enums import IndicatorType
from app.services.normalization import NormalizedIndicator

BASE_URL = "https://otx.alienvault.com/api/v1/indicators"
MAX_PULSES = 100
TOP_PULSES = 5
TOP_ITEMS = 10
VALIDATION_DISCOUNT = 0.25
_BAD_SHAPE = "Unexpected response format from AlienVault OTX."
_MAX_COUNT = 1_000_000_000
_ATTACK_ID = re.compile(r"T\d{4}(?:\.\d{3})?")
_PULSE_ID = re.compile(r"[0-9a-fA-F]{24}")
_OLDEST = datetime.min.replace(tzinfo=UTC)


def _bad_shape() -> ProviderFailure:
    return ProviderFailure(ProviderStatus.ERROR, _BAD_SHAPE, Reason.MALFORMED_RESPONSE)


_SECTION_BY_TYPE = {
    IndicatorType.IPV4: "IPv4",
    IndicatorType.IPV6: "IPv6",
    IndicatorType.DOMAIN: "domain",
    IndicatorType.URL: "url",
    IndicatorType.MD5: "file",
    IndicatorType.SHA1: "file",
    IndicatorType.SHA256: "file",
}

# (minimum pulse count, signal). More independent community reports means stronger evidence,
# with diminishing returns; a single pulse is a lead, not a conclusion.
_PULSE_SIGNAL_STEPS = ((25, 1.0), (10, 0.85), (5, 0.7), (3, 0.55), (2, 0.4), (1, 0.25))


class OTXCollector(Collector):
    name: ClassVar[str] = "otx"
    display_name: ClassVar[str] = "AlienVault OTX"
    supported_types: ClassVar[frozenset[IndicatorType]] = frozenset(IndicatorType)

    def _query(self, indicator: NormalizedIndicator, api_key: str) -> ProviderResult:
        section = _SECTION_BY_TYPE[indicator.indicator_type]
        value = indicator.indicator_value
        if indicator.indicator_type is IndicatorType.URL:
            # OTX expects the whole URL as one path segment.
            value = quote(value, safe="")
        payload = self._get_json(
            f"{BASE_URL}/{section}/{value}/general",
            headers={"X-OTX-API-KEY": api_key, "Accept": "application/json"},
            not_found_is_none=True,
        )
        if payload is None:
            return ProviderResult(self.name, ProviderStatus.NO_DATA, summary={"pulse_count": 0})
        return parse_otx(payload)


def pulse_signal(pulse_count: int) -> float:
    for minimum, signal in _PULSE_SIGNAL_STEPS:
        if pulse_count >= minimum:
            return signal
    return 0.0


def parse_otx(payload: Any) -> ProviderResult:
    if not isinstance(payload, dict):
        raise _bad_shape()
    pulse_info = payload.get("pulse_info")
    if not isinstance(pulse_info, dict):
        raise _bad_shape()
    raw_pulses = pulse_info.get("pulses", [])
    if not isinstance(raw_pulses, list):
        raise _bad_shape()

    pulses = [pulse for pulse in raw_pulses[:MAX_PULSES] if isinstance(pulse, dict)]
    pulse_count = max(bounded_int(pulse_info.get("count"), 0, _MAX_COUNT) or 0, len(pulses))
    validation = _validation_entries(payload.get("validation"))

    created_times: list[datetime] = []
    modified_times: list[datetime] = []
    tag_counts: Counter[str] = Counter()
    family_counts: Counter[str] = Counter()
    attack_counts: Counter[str] = Counter()
    pulse_summaries: list[tuple[datetime | None, dict[str, Any]]] = []

    for pulse in pulses:
        created = parse_timestamp(pulse.get("created"))
        modified = parse_timestamp(pulse.get("modified")) or created
        if created:
            created_times.append(created)
        if modified:
            modified_times.append(modified)
        tag_counts.update(_names(pulse.get("tags"), key=None, lowercase=True, max_length=48))
        family_counts.update(
            _names(pulse.get("malware_families"), key="display_name", fallback="id", max_length=64)
        )
        attack_counts.update(
            attack_id
            for attack_id in _names(pulse.get("attack_ids"), key="id", max_length=16)
            if _ATTACK_ID.fullmatch(attack_id)
        )
        pulse_summaries.append((modified, _pulse_summary(pulse, created, modified)))

    signal = pulse_signal(pulse_count)
    notes: list[str] = []
    if signal > 0:
        notes.append(
            "OTX pulses are community-submitted reports; treat them as leads, not verdicts."
        )
        if validation:
            signal *= VALIDATION_DISCOUNT
            notes.append(
                "OTX attaches validation entries (such as known-good lists) to this indicator; "
                "the signal is reduced."
            )

    families = _top(family_counts)
    return ProviderResult(
        provider=OTXCollector.name,
        status=ProviderStatus.OK if pulse_count > 0 else ProviderStatus.NO_DATA,
        signal=round(signal, 4),
        evidence_at=max(modified_times, default=None),
        first_evidence_at=min(created_times, default=None),
        summary={
            "pulse_count": pulse_count,
            "pulses_analyzed": len(pulses),
            "top_pulses": _newest(pulse_summaries),
            "validation": validation,
            "malware_families": families,
            "attack_ids": _top(attack_counts),
            "notes": notes,
        },
        tags=_top(tag_counts),
    )


def _validation_entries(value: Any) -> list[dict[str, str | None]]:
    if not isinstance(value, list):
        return []
    entries: list[dict[str, str | None]] = []
    for item in value[:TOP_PULSES]:
        if not isinstance(item, dict):
            continue
        source = clean_text(item.get("source"), 48)
        message = clean_text(item.get("message") or item.get("name"), 160)
        if source or message:
            entries.append({"source": source, "message": message})
    return entries


def _pulse_summary(
    pulse: dict[str, Any], created: datetime | None, modified: datetime | None
) -> dict[str, Any]:
    pulse_id = pulse.get("id")
    return {
        "id": pulse_id.lower()
        if isinstance(pulse_id, str) and _PULSE_ID.fullmatch(pulse_id)
        else None,
        "name": clean_text(pulse.get("name"), 160) or "(unnamed pulse)",
        "created": isoformat(created),
        "modified": isoformat(modified),
    }


def _newest(
    pulse_summaries: list[tuple[datetime | None, dict[str, Any]]],
) -> list[dict[str, Any]]:
    ordered = sorted(pulse_summaries, key=lambda entry: entry[0] or _OLDEST, reverse=True)
    return [summary for _modified, summary in ordered[:TOP_PULSES]]


def _names(
    value: Any,
    *,
    key: str | None,
    fallback: str | None = None,
    lowercase: bool = False,
    max_length: int,
    limit: int = 50,
) -> Iterable[str]:
    """Extract short, clean strings from a list of strings or of dicts holding a name."""
    if not isinstance(value, list):
        return
    for item in value[:limit]:
        raw = item
        if isinstance(item, dict):
            raw = item.get(key) if key else None
            if raw is None and fallback:
                raw = item.get(fallback)
        cleaned = clean_text(raw, max_length)
        if cleaned:
            yield cleaned.lower() if lowercase else cleaned


def _top(counts: Counter[str]) -> list[str]:
    # Most frequent first, ties broken alphabetically so output is deterministic.
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [name for name, _count in ranked[:TOP_ITEMS]]
