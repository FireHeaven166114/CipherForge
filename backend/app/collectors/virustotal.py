"""VirusTotal adapter (API v3): IP addresses, domains, URLs and MD5, SHA-1 and SHA-256 hashes.

Uses the documented read-only lookups ``GET /ip_addresses/{ip}``, ``/domains/{domain}``,
``/urls/{id}`` and ``/files/{hash}`` with the ``x-apikey`` header. CipherForge never uploads a
file or submits a URL for scanning, so a lookup shares nothing beyond the indicator itself.

Interpretation choices:

* ``last_analysis_stats`` counts what each antivirus or reputation engine concluded. The
  verdict names the strongest category any engine reported and the counts always travel with
  it, so a lone detection reads as "1 of 70", not as a certainty.
* The signal weighs engines, not the verdict: a *malicious* answer counts twice a *suspicious*
  one, and one or two flagging engines are weak evidence because lone detections are often
  false positives.
* "No detections" is not proof of safety and a missing record (404) is not a clean result.
* Every string comes from VirusTotal or from whoever uploaded a sample, so it is cleaned and
  length-limited. The provider link is built from this module's constants and a validated id.
"""

import base64
import ipaddress
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import quote

import httpx2

from app.collectors.base import (
    Collector,
    ProviderFailure,
    ProviderResult,
    ProviderStatus,
    Reason,
    Verdict,
)
from app.collectors.sanitize import (
    bounded_int,
    clean_list,
    clean_text,
    country_code,
    isoformat,
    parse_epoch,
)
from app.models.enums import IndicatorType
from app.services.normalization import NormalizedIndicator

DEFAULT_BASE_URL = "https://www.virustotal.com/api/v3"
GUI_URL = "https://www.virustotal.com/gui"
MAX_LISTED_ITEMS = 5
MAX_TAGS = 10
MAX_FAMILIES = 3
# At most this many flagging engines is reported as a possible false positive.
LOW_DETECTION_ENGINES = 2
_BAD_SHAPE = "Unexpected response format from VirusTotal."
_MAX_ENGINES = 10_000
_MAX_COUNT = 1_000_000_000
_MAX_SCANNED_ITEMS = 1_000
_MAX_ASN = 4_294_967_295
_SHA256 = re.compile(r"[0-9a-f]{64}")

# (minimum weighted detections, signal). Weighted detections count each malicious engine twice
# and each suspicious engine once, so one malicious engine (2) is a lead and ten (20) is
# near-certain. The steps are deliberately coarse and documented in docs/threat-intelligence.md.
_DETECTION_STEPS = ((20, 1.0), (10, 0.85), (6, 0.7), (4, 0.5), (2, 0.25), (1, 0.1))


@dataclass(frozen=True, slots=True)
class _Route:
    collection: str  # path segment of the API collection
    data_type: str  # the "type" VirusTotal reports for it
    gui: str  # path segment on the website


_IP_ROUTE = _Route("ip_addresses", "ip_address", "ip-address")
_FILE_ROUTE = _Route("files", "file", "file")
_ROUTES = {
    IndicatorType.IPV4: _IP_ROUTE,
    IndicatorType.IPV6: _IP_ROUTE,
    IndicatorType.DOMAIN: _Route("domains", "domain", "domain"),
    IndicatorType.URL: _Route("urls", "url", "url"),
    IndicatorType.MD5: _FILE_ROUTE,
    IndicatorType.SHA1: _FILE_ROUTE,
    IndicatorType.SHA256: _FILE_ROUTE,
}


@dataclass(frozen=True, slots=True)
class _Stats:
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    timeout: int

    @property
    def engines(self) -> int:
        """Engines that reached a verdict. Timeouts did not, so they are not counted."""
        return self.malicious + self.suspicious + self.harmless + self.undetected


_NO_STATS = _Stats(0, 0, 0, 0, 0)


class VirusTotalCollector(Collector):
    name: ClassVar[str] = "virustotal"
    display_name: ClassVar[str] = "VirusTotal"
    supported_types: ClassVar[frozenset[IndicatorType]] = frozenset(IndicatorType)

    def __init__(
        self,
        *,
        api_key: str | None,
        client: httpx2.Client,
        cache_ttl_seconds: int,
        base_url: str = DEFAULT_BASE_URL,
        **options: Any,
    ) -> None:
        super().__init__(
            api_key=api_key, client=client, cache_ttl_seconds=cache_ttl_seconds, **options
        )
        self._base_url = base_url.rstrip("/")

    def _query(self, indicator: NormalizedIndicator, api_key: str) -> ProviderResult:
        route = _ROUTES[indicator.indicator_type]
        payload = self._get_json(
            f"{self._base_url}/{route.collection}/{_path_id(indicator)}",
            headers={"x-apikey": api_key, "Accept": "application/json"},
            not_found_is_none=True,
        )
        if payload is None:
            return _not_found()
        return parse_virustotal(payload, indicator)


def detection_signal(malicious: int, suspicious: int) -> float:
    """Evidence strength from the engine counts (see ``_DETECTION_STEPS``)."""
    weighted = 2 * malicious + suspicious
    for minimum, signal in _DETECTION_STEPS:
        if weighted >= minimum:
            return signal
    return 0.0


def _path_id(indicator: NormalizedIndicator) -> str:
    value = indicator.indicator_value
    if indicator.indicator_type is IndicatorType.URL:
        # A URL is addressed by its URL-safe base64 form without padding. Normalized URLs are
        # ASCII, so the encoding cannot fail.
        return base64.urlsafe_b64encode(value.encode("ascii")).decode("ascii").rstrip("=")
    return quote(value, safe=":")


def _not_found() -> ProviderResult:
    return ProviderResult(
        VirusTotalCollector.name,
        ProviderStatus.NO_DATA,
        summary={
            "verdict": Verdict.NOT_FOUND.value,
            "analysis_status": "not_found",
            "notes": [
                "VirusTotal has no record of this indicator. That does not mean it is safe: "
                "it may simply never have been submitted."
            ],
        },
    )


def _bad_shape() -> ProviderFailure:
    return ProviderFailure(ProviderStatus.ERROR, _BAD_SHAPE, Reason.MALFORMED_RESPONSE)


def parse_virustotal(payload: Any, indicator: NormalizedIndicator) -> ProviderResult:
    route = _ROUTES[indicator.indicator_type]
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict) or data.get("type") != route.data_type:
        raise _bad_shape()
    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        raise _bad_shape()

    stats = _read_stats(attributes.get("last_analysis_stats"))
    analysed = stats is not None and stats.engines > 0
    counts = stats or _NO_STATS
    verdict = _verdict(counts, analysed)
    signal = detection_signal(counts.malicious, counts.suspicious) if analysed else 0.0

    last_analysis = parse_epoch(attributes.get("last_analysis_date")) if analysed else None
    first_submission = parse_epoch(attributes.get("first_submission_date"))
    provider_id, provider_link = _reference(route, data.get("id"), indicator)

    classification = attributes.get("popular_threat_classification")
    classification = classification if isinstance(classification, dict) else {}
    popular = _ranked_names(classification.get("popular_threat_name"), limit=MAX_LISTED_ITEMS)
    threat_names = popular or clean_list(
        attributes.get("threat_names"), limit=MAX_LISTED_ITEMS, max_length=64
    )

    summary: dict[str, Any] = {
        "verdict": verdict.value,
        "analysis_status": "completed" if analysed else "no_analysis",
        "malicious": counts.malicious,
        "suspicious": counts.suspicious,
        "harmless": counts.harmless,
        "undetected": counts.undetected,
        "timeout": counts.timeout,
        "engines_total": counts.engines,
        "reputation": bounded_int(attributes.get("reputation"), -_MAX_COUNT, _MAX_COUNT),
        "last_analysis_at": isoformat(last_analysis),
        "first_submission_at": isoformat(first_submission),
        "times_submitted": bounded_int(attributes.get("times_submitted"), 0, _MAX_COUNT),
        "categories": _top_categories(attributes.get("categories")),
        "threat_label": clean_text(classification.get("suggested_threat_label"), 64),
        "threat_names": threat_names,
        "file_name": clean_text(attributes.get("meaningful_name"), 128),
        "file_type": clean_text(attributes.get("type_description"), 64),
        "country_code": country_code(attributes.get("country")),
        "asn": bounded_int(attributes.get("asn"), 0, _MAX_ASN),
        "as_owner": clean_text(attributes.get("as_owner"), 96),
        "provider_id": provider_id,
        "provider_link": provider_link,
        "malware_families": popular[:MAX_FAMILIES],
        "notes": _notes(verdict, counts),
    }
    return ProviderResult(
        provider=VirusTotalCollector.name,
        status=ProviderStatus.OK if analysed else ProviderStatus.NO_DATA,
        signal=signal,
        evidence_at=last_analysis,
        first_evidence_at=first_submission,
        summary=summary,
        tags=clean_list(attributes.get("tags"), limit=MAX_TAGS, max_length=48, lowercase=True),
    )


def _read_stats(raw: Any) -> _Stats | None:
    """The five engine counters, ``None`` when VirusTotal gave none. Bad values are an error."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise _bad_shape()
    values: dict[str, int] = {}
    for key in ("malicious", "suspicious", "harmless", "undetected", "timeout"):
        value = raw.get(key, 0)
        count = bounded_int(0 if value is None else value, 0, _MAX_ENGINES)
        if count is None:
            raise _bad_shape()
        values[key] = count
    return _Stats(**values)


def _verdict(stats: _Stats, analysed: bool) -> Verdict:
    if not analysed:
        return Verdict.UNKNOWN
    if stats.malicious > 0:
        return Verdict.MALICIOUS
    if stats.suspicious > 0:
        return Verdict.SUSPICIOUS
    return Verdict.HARMLESS


def _notes(verdict: Verdict, stats: _Stats) -> list[str]:
    flagged = stats.malicious + stats.suspicious
    if verdict is Verdict.UNKNOWN:
        return ["VirusTotal holds a record for this indicator but no engine results for it yet."]
    if verdict is Verdict.HARMLESS:
        return [
            "No engine flagged this indicator. That is the engines' opinion at the time of "
            "analysis, not proof that it is safe."
        ]
    if flagged <= LOW_DETECTION_ENGINES:
        return [
            f"Only {flagged} of {stats.engines} engines flagged this indicator; a lone "
            "detection is often a false positive, so the signal is low."
        ]
    return []


def _reference(
    route: _Route, data_id: Any, indicator: NormalizedIndicator
) -> tuple[str | None, str | None]:
    """The provider's id for the record and a link to its page, or ``(None, None)``.

    Addresses and domains use the indicator CipherForge itself validated. Files and URLs are
    addressed by a SHA-256 that only VirusTotal can compute, so that id must look like one.
    """
    if route is _IP_ROUTE or route.data_type == "domain":
        value = indicator.indicator_value
        if isinstance(data_id, str) and not _same_indicator(route, data_id, value):
            return None, None
        return value, _link(route, value)
    if isinstance(data_id, str) and _SHA256.fullmatch(data_id):
        return data_id, _link(route, data_id)
    return None, None


def _same_indicator(route: _Route, data_id: str, value: str) -> bool:
    if route is _IP_ROUTE:
        try:
            return ipaddress.ip_address(data_id) == ipaddress.ip_address(value)
        except ValueError:
            return False
    return data_id.lower() == value


def _link(route: _Route, identifier: str) -> str:
    return f"{GUI_URL}/{route.gui}/{quote(identifier, safe=':')}"


def _top_categories(raw: Any) -> list[str]:
    """Categories that engines assigned (domains and URLs), most common first."""
    if not isinstance(raw, dict):
        return []
    counts: Counter[str] = Counter()
    for value in list(raw.values())[:_MAX_SCANNED_ITEMS]:
        text = clean_text(value, 48)
        if text:
            counts[text.lower()] += 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [name for name, _ in ranked[:MAX_LISTED_ITEMS]]


def _ranked_names(raw: Any, *, limit: int) -> list[str]:
    """Names from ``[{"value": ..., "count": ...}]`` lists, most reported first."""
    if not isinstance(raw, list):
        return []
    ranked: list[tuple[int, str]] = []
    for item in raw[:_MAX_SCANNED_ITEMS]:
        if not isinstance(item, dict):
            continue
        name = clean_text(item.get("value"), 48)
        if name:
            ranked.append((bounded_int(item.get("count"), 0, _MAX_COUNT) or 0, name))
    ranked.sort(key=lambda entry: (-entry[0], entry[1].lower()))
    seen: dict[str, str] = {}
    for _, name in ranked:
        seen.setdefault(name.lower(), name)
    return list(seen.values())[:limit]
