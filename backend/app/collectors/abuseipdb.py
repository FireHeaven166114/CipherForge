"""AbuseIPDB adapter (IP addresses only).

Uses the documented ``GET /api/v2/check`` endpoint without ``verbose``, so individual report
text (which is attacker-writable free text) is never requested.

Interpretation choices:

* ``abuseConfidenceScore`` is AbuseIPDB's own judgement; it is mapped to a 0..1 signal and
  never presented as CipherForge's verdict.
* ``isWhitelisted`` may be null when AbuseIPDB did not run a whitelist lookup, so only an
  explicit ``true`` counts.
* A confident score built on one or two reports is discounted: it is cheap to produce.
* Geolocation fields are context about where an address is registered, not where an
  attacker is.
"""

from typing import Any, ClassVar

from app.collectors.base import Collector, ProviderFailure, ProviderResult, ProviderStatus
from app.collectors.sanitize import (
    bounded_int,
    clean_text,
    country_code,
    isoformat,
    parse_timestamp,
)
from app.models.enums import IndicatorType
from app.services.normalization import NormalizedIndicator

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
WINDOW_DAYS = 90
MIN_RELIABLE_REPORTS = 3
LOW_REPORT_DISCOUNT = 0.5
_BAD_SHAPE = "Unexpected response format from AbuseIPDB."
_MAX_COUNT = 1_000_000_000


class AbuseIPDBCollector(Collector):
    name: ClassVar[str] = "abuseipdb"
    display_name: ClassVar[str] = "AbuseIPDB"
    supported_types: ClassVar[frozenset[IndicatorType]] = frozenset(
        {IndicatorType.IPV4, IndicatorType.IPV6}
    )

    def _query(self, indicator: NormalizedIndicator, api_key: str) -> ProviderResult:
        payload = self._get_json(
            CHECK_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": indicator.indicator_value, "maxAgeInDays": str(WINDOW_DAYS)},
        )
        return parse_abuseipdb(payload)


def parse_abuseipdb(payload: Any) -> ProviderResult:
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise ProviderFailure(ProviderStatus.ERROR, _BAD_SHAPE)
    confidence = bounded_int(data.get("abuseConfidenceScore"), 0, 100)
    if confidence is None:
        raise ProviderFailure(ProviderStatus.ERROR, _BAD_SHAPE)

    total_reports = bounded_int(data.get("totalReports"), 0, _MAX_COUNT) or 0
    distinct_reporters = bounded_int(data.get("numDistinctUsers"), 0, _MAX_COUNT) or 0
    last_reported = parse_timestamp(data.get("lastReportedAt"))
    is_whitelisted = data.get("isWhitelisted") is True
    is_tor = data.get("isTor") is True

    signal = confidence / 100
    notes: list[str] = []
    if is_whitelisted:
        signal = 0.0
        notes.append("AbuseIPDB lists this address as whitelisted; its abuse score is not counted.")
    elif signal > 0 and 0 < total_reports < MIN_RELIABLE_REPORTS:
        signal *= LOW_REPORT_DISCOUNT
        notes.append(
            f"Only {total_reports} report(s) in the last {WINDOW_DAYS} days; "
            "the abuse score is discounted."
        )

    has_data = total_reports > 0 or confidence > 0
    return ProviderResult(
        provider=AbuseIPDBCollector.name,
        status=ProviderStatus.OK if has_data else ProviderStatus.NO_DATA,
        signal=round(signal, 4),
        evidence_at=last_reported,
        summary={
            "confidence_score": confidence,
            "total_reports": total_reports,
            "distinct_reporters": distinct_reporters,
            "last_reported_at": isoformat(last_reported),
            "window_days": WINDOW_DAYS,
            "is_whitelisted": is_whitelisted,
            "is_tor": is_tor,
            "usage_type": clean_text(data.get("usageType"), 64),
            "isp": clean_text(data.get("isp"), 96),
            "domain": clean_text(data.get("domain"), 128),
            "country_code": country_code(data.get("countryCode")),
            "notes": notes,
        },
        tags=["tor"] if is_tor else [],
    )
