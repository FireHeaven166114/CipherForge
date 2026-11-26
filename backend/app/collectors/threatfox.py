"""ThreatFox adapter (abuse.ch): IP addresses, domains, URLs and MD5 / SHA-256 hashes.

Uses the documented community API, ``POST {base}/`` with a JSON body and the ``Auth-Key`` header
(a free key from https://auth.abuse.ch/). ThreatFox has no SHA-1 search, so SHA-1 is reported
as unsupported instead of being converted or guessed.

How an indicator is searched:

* Domains and URLs use ``search_ioc`` with ``exact_match`` so only that exact IOC matches.
* IP addresses use ``search_ioc`` as a wildcard search, because ThreatFox stores them as
  ``ip:port``. A wildcard also returns unrelated IOCs that merely contain the text, so the
  answer is filtered to entries for exactly that address.
* Hashes use ``search_hash``, which returns the IOCs (usually command-and-control servers)
  that ThreatFox associates with that file. The file itself is not rated.

Interpretation choices:

* ``confidence_level`` is the *reporter's* confidence that the IOC is malicious (0-100). It is
  mapped to the signal and never presented as comparable to VirusTotal's detection counts.
* A match is a report that the indicator is malware infrastructure, so any match is at least
  "suspicious"; a reporter confidence of 75 or more is labelled "malicious".
* ThreatFox expires IOCs after six months and does not serve expired ones, so "no result" says
  nothing about older or never-reported activity.
* Reporter-supplied text and links are untrusted: they are cleaned, length-limited and links
  are kept only when they are plain http(s) URLs.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar
from urllib.parse import urlsplit

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
    isoformat,
    parse_timestamp,
)
from app.models.enums import IndicatorType
from app.services.normalization import NormalizedIndicator

DEFAULT_BASE_URL = "https://threatfox-api.abuse.ch/api/v1"
MALICIOUS_CONFIDENCE = 75
MAX_LISTED_MATCHES = 5
MAX_TAGS = 10
MAX_FAMILIES = 5
_BAD_SHAPE = "Unexpected response format from ThreatFox."
_MAX_SCANNED_ENTRIES = 1_000
_MAX_REFERENCE_LENGTH = 512
_MAX_ID = 10**12
_MALPEDIA_PREFIX = "https://malpedia.caad.fkie.fraunhofer.de/"
_HASH_TYPES = frozenset({IndicatorType.MD5, IndicatorType.SHA256})
_IP_TYPES = frozenset({IndicatorType.IPV4, IndicatorType.IPV6})
_STATUS_OK = "ok"
_STATUS_NO_RESULT = "no_result"
_STATUS_INVALID_PREFIX = "illegal_"
# The documentation does not say how a bad Auth-Key is reported (HTTP 401/403 are handled by the
# shared plumbing), so a 200 answer that says so in its query_status is recognised as well.
_AUTH_STATUS_MARKERS = ("unauthori", "forbidden")


@dataclass(frozen=True, slots=True)
class _Entry:
    ioc: str
    confidence: int
    first_seen: datetime | None
    last_seen: datetime | None
    malware: str | None
    threat_type: str | None
    tags: list[str]
    detail: dict[str, Any]

    @property
    def activity(self) -> datetime | None:
        return self.last_seen or self.first_seen


class ThreatFoxCollector(Collector):
    name: ClassVar[str] = "threatfox"
    display_name: ClassVar[str] = "ThreatFox"
    supported_types: ClassVar[frozenset[IndicatorType]] = frozenset(
        {
            IndicatorType.IPV4,
            IndicatorType.IPV6,
            IndicatorType.DOMAIN,
            IndicatorType.URL,
            IndicatorType.MD5,
            IndicatorType.SHA256,
        }
    )

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
        # A search is read-only, so it is safe to retry like a GET.
        payload = self._request_json(
            "POST",
            f"{self._base_url}/",
            headers={"Auth-Key": api_key, "Accept": "application/json"},
            json_body=request_body(indicator),
        )
        return parse_threatfox(payload, indicator)


def request_body(indicator: NormalizedIndicator) -> dict[str, Any]:
    kind = indicator.indicator_type
    value = indicator.indicator_value
    if kind in _HASH_TYPES:
        return {"query": "search_hash", "hash": value}
    return {"query": "search_ioc", "search_term": value, "exact_match": kind not in _IP_TYPES}


def _bad_shape() -> ProviderFailure:
    return ProviderFailure(ProviderStatus.ERROR, _BAD_SHAPE, Reason.MALFORMED_RESPONSE)


def _not_found() -> ProviderResult:
    return ProviderResult(
        ThreatFoxCollector.name,
        ProviderStatus.NO_DATA,
        summary={
            "verdict": Verdict.NOT_FOUND.value,
            "match_count": 0,
            "notes": [
                "ThreatFox has no current record of this indicator. That does not mean it is "
                "safe: IOCs older than six months are no longer served."
            ],
        },
    )


def parse_threatfox(payload: Any, indicator: NormalizedIndicator) -> ProviderResult:
    if not isinstance(payload, dict):
        raise _bad_shape()
    status = payload.get("query_status")
    if not isinstance(status, str):
        raise _bad_shape()
    if status == _STATUS_NO_RESULT:
        return _not_found()
    if status.startswith(_STATUS_INVALID_PREFIX):
        raise ProviderFailure(
            ProviderStatus.ERROR,
            "ThreatFox rejected the search term as invalid.",
            Reason.INVALID_INPUT,
        )
    if any(marker in status.lower() for marker in _AUTH_STATUS_MARKERS):
        # Classification only: the status text itself is never shown or stored.
        raise ProviderFailure(
            ProviderStatus.ERROR,
            "ThreatFox rejected the configured credentials.",
            Reason.AUTH_FAILED,
        )
    if status != _STATUS_OK:
        # Other statuses are free-form provider text; report that, not the text.
        raise ProviderFailure(
            ProviderStatus.ERROR,
            "ThreatFox returned an unexpected query status.",
            Reason.UNAVAILABLE,
        )
    data = payload.get("data")
    if not isinstance(data, list):
        raise _bad_shape()
    if not data:
        return _not_found()

    entries = [_read_entry(item) for item in data[:_MAX_SCANNED_ENTRIES]]
    readable = [entry for entry in entries if entry is not None]
    if not readable:
        raise _bad_shape()
    matches = [entry for entry in readable if _is_match(indicator, entry.ioc)]
    if not matches:
        return _not_found()

    matches.sort(key=lambda entry: (-entry.confidence, str(entry.detail["id"] or ""), entry.ioc))
    highest = matches[0].confidence
    verdict = Verdict.MALICIOUS if highest >= MALICIOUS_CONFIDENCE else Verdict.SUSPICIOUS
    first_seen = [entry.first_seen for entry in matches if entry.first_seen]
    activity = [entry.activity for entry in matches if entry.activity]
    listed = matches[:MAX_LISTED_MATCHES]

    return ProviderResult(
        provider=ThreatFoxCollector.name,
        status=ProviderStatus.OK,
        signal=highest / 100,
        evidence_at=max(activity, default=None),
        first_evidence_at=min(first_seen, default=None),
        summary={
            "verdict": verdict.value,
            "match_count": len(matches),
            "highest_confidence": highest,
            "association": "file_hash" if indicator.indicator_type in _HASH_TYPES else "indicator",
            "matches": [entry.detail for entry in listed],
            "threat_types": clean_list(
                [entry.threat_type for entry in matches], limit=MAX_LISTED_MATCHES, max_length=48
            ),
            "malware_families": clean_list(
                [entry.malware for entry in matches], limit=MAX_FAMILIES, max_length=64
            ),
            "first_seen_at": isoformat(min(first_seen, default=None)),
            "last_seen_at": isoformat(max(activity, default=None)),
            "notes": _notes(indicator, len(matches), len(listed)),
        },
        tags=clean_list(
            [tag for entry in matches for tag in entry.tags],
            limit=MAX_TAGS,
            max_length=48,
            lowercase=True,
        ),
    )


def _notes(indicator: NormalizedIndicator, total: int, listed: int) -> list[str]:
    notes: list[str] = []
    if indicator.indicator_type in _HASH_TYPES:
        notes.append(
            "ThreatFox lists IOCs associated with this file hash; it does not rate the file."
        )
    elif indicator.indicator_type in _IP_TYPES:
        notes.append("ThreatFox records ip:port pairs; matches are made on the address alone.")
    if total > listed:
        notes.append(f"{total - listed} further matching records are not listed.")
    return notes


def _is_match(indicator: NormalizedIndicator, ioc: str) -> bool:
    kind = indicator.indicator_type
    value = indicator.indicator_value
    if kind in _HASH_TYPES:
        return True  # every entry is, by ThreatFox's own search, associated with the hash
    if kind is IndicatorType.IPV4:
        return ioc == value or ioc.startswith(f"{value}:")
    if kind is IndicatorType.IPV6:
        lowered = ioc.lower()
        return lowered == value or lowered.startswith(f"[{value}]:")
    if kind is IndicatorType.DOMAIN:
        return ioc.lower() == value
    return ioc == value


def _read_entry(raw: Any) -> _Entry | None:
    if not isinstance(raw, dict):
        return None
    ioc = clean_text(raw.get("ioc"), 512)
    confidence = bounded_int(raw.get("confidence_level"), 0, 100)
    if ioc is None or confidence is None:
        return None
    first_seen = _parse_time(raw.get("first_seen"))
    last_seen = _parse_time(raw.get("last_seen"))
    malware = clean_text(raw.get("malware_printable") or raw.get("malware"), 64)
    threat_type = clean_text(raw.get("threat_type"), 48)
    tags = clean_list(raw.get("tags"), limit=8, max_length=48)
    return _Entry(
        ioc=ioc,
        confidence=confidence,
        first_seen=first_seen,
        last_seen=last_seen,
        malware=malware,
        threat_type=threat_type,
        tags=tags,
        detail={
            "id": _record_id(raw.get("id")),
            "ioc": ioc,
            "ioc_type": clean_text(raw.get("ioc_type"), 24),
            "threat_type": threat_type,
            "malware": malware,
            "malware_aliases": _aliases(raw.get("malware_alias")),
            "confidence_level": confidence,
            "first_seen": isoformat(first_seen),
            "last_seen": isoformat(last_seen),
            "reporter": clean_text(raw.get("reporter"), 64),
            "reference": _safe_url(raw.get("reference")),
            "malpedia_url": _safe_url(raw.get("malware_malpedia"), prefix=_MALPEDIA_PREFIX),
            "tags": tags,
        },
    )


def _parse_time(value: Any) -> datetime | None:
    """ThreatFox writes ``YYYY-MM-DD HH:MM:SS UTC``; ``last_seen`` is null for live IOCs."""
    if not isinstance(value, str):
        return None
    return parse_timestamp(value.strip().removesuffix(" UTC"))


def _record_id(value: Any) -> str | None:
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 12:
        return value
    number = bounded_int(value, 0, _MAX_ID)
    return str(number) if number is not None else None


def _aliases(value: Any) -> list[str]:
    """``malware_alias`` is one comma-separated string."""
    if not isinstance(value, str):
        return []
    return clean_list(value.split(",")[:20], limit=5, max_length=48)


def _safe_url(value: Any, *, prefix: str | None = None) -> str | None:
    """The URL when it is a plain http(s) link without credentials, otherwise ``None``."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > _MAX_REFERENCE_LENGTH or not text.isascii():
        return None
    if any(ord(char) <= 32 or ord(char) == 127 for char in text):
        return None
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"} or not host or parts.username or parts.password:
        return None
    if prefix is not None and not text.startswith(prefix):
        return None
    return text
