"""Simulated AbuseIPDB and AlienVault OTX services for the demo.

The real adapters run unchanged (request building, parsing, sanitising, scoring). Only the
network is replaced by an in-process ``httpx2.MockTransport`` that answers in each provider's
documented response shape. Every answer is synthetic and derived deterministically from the
indicator, and every adapter reports ``simulated = True`` so the dashboard labels the data.

Two marker words force failures, so error handling can be demonstrated and tested: a value that
contains ``rate-limit`` is answered with HTTP 429 and one that contains ``provider-error`` with
HTTP 500.
"""

import random
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from urllib.parse import unquote

import httpx2

from app.collectors.abuseipdb import AbuseIPDBCollector
from app.collectors.base import Collector
from app.collectors.otx import OTXCollector
from app.models.enums import IndicatorType
from app.models.types import utcnow

DEMO_API_KEY = "simulated-demo-key"
FAILURE_MARKERS = (("rate-limit", 429), ("provider-error", 500))
MAX_LISTED_PULSES = 12

_ABUSEIPDB_HOST = "api.abuseipdb.com"
_OTX_HOST = "otx.alienvault.com"
_OTX_PATH = re.compile(r"/api/v1/indicators/(?P<section>[A-Za-z0-9]+)/(?P<value>[^/]+)/general")
_OTX_SECTIONS = {
    "IPv4": IndicatorType.IPV4,
    "IPv6": IndicatorType.IPV6,
    "domain": IndicatorType.DOMAIN,
    "url": IndicatorType.URL,
    "file": IndicatorType.SHA256,
}
_IP_TYPES = (IndicatorType.IPV4, IndicatorType.IPV6)

Range = tuple[int, int]


class Tier(StrEnum):
    """How much evidence the simulated providers hold about an indicator."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    CLEAN = "clean"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class AbuseShape:
    confidence: Range
    reports: Range
    reporters: Range
    last_reported_hours: Range


_NONE = AbuseShape((0, 0), (0, 0), (0, 0), (0, 0))
_ABUSE_SHAPES: dict[Tier, AbuseShape] = {
    Tier.CRITICAL: AbuseShape((85, 100), (150, 900), (45, 220), (1, 20)),
    Tier.HIGH: AbuseShape((50, 75), (30, 140), (12, 45), (3, 60)),
    Tier.MEDIUM: AbuseShape((28, 52), (8, 30), (4, 14), (24, 200)),
    Tier.LOW: AbuseShape((12, 38), (3, 9), (2, 6), (120, 600)),
    Tier.CLEAN: _NONE,
    Tier.UNKNOWN: _NONE,
}

# Pulses OTX holds, per tier. Only two providers exist, so an indicator that is not an IP
# address can never be corroborated: its pulse counts stay modest and its score tops out.
_IP_PULSES: dict[Tier, Range] = {
    Tier.CRITICAL: (8, 45),
    Tier.HIGH: (3, 8),
    Tier.MEDIUM: (2, 4),
    Tier.LOW: (2, 3),
    Tier.CLEAN: (0, 0),
    Tier.UNKNOWN: (0, 0),
}
_OTHER_PULSES: dict[Tier, Range] = {
    Tier.CRITICAL: (26, 55),
    Tier.HIGH: (25, 55),
    Tier.MEDIUM: (4, 9),
    Tier.LOW: (3, 4),
    Tier.CLEAN: (0, 0),
    Tier.UNKNOWN: (0, 0),
}
# (newest, oldest) pulse age in days.
_PULSE_AGE_DAYS: dict[Tier, tuple[float, float]] = {
    Tier.CRITICAL: (1, 40),
    Tier.HIGH: (2, 60),
    Tier.MEDIUM: (6, 120),
    Tier.LOW: (12, 300),
    Tier.CLEAN: (0, 0),
    Tier.UNKNOWN: (0, 0),
}

_FALLBACK_WEIGHTS: dict[bool, tuple[tuple[Tier, int], ...]] = {
    True: (
        (Tier.CRITICAL, 6),
        (Tier.HIGH, 12),
        (Tier.MEDIUM, 18),
        (Tier.LOW, 14),
        (Tier.CLEAN, 20),
        (Tier.UNKNOWN, 30),
    ),
    False: (
        (Tier.HIGH, 12),
        (Tier.MEDIUM, 20),
        (Tier.LOW, 18),
        (Tier.CLEAN, 15),
        (Tier.UNKNOWN, 35),
    ),
}


@dataclass(frozen=True, slots=True)
class Theme:
    families: tuple[str, ...]
    techniques: tuple[tuple[str, str], ...]
    tags: tuple[str, ...]
    titles: tuple[str, ...]


THEMES: dict[str, Theme] = {
    "phishing": Theme(
        (),
        (
            ("T1566", "Phishing"),
            ("T1566.001", "Spearphishing Attachment"),
            ("T1204.002", "Malicious File"),
            ("T1598", "Phishing for Information"),
        ),
        ("phishing", "credential-harvesting", "lure"),
        (
            "Credential-harvesting kit cluster",
            "Fake sign-in page campaign",
            "Invoice-themed phishing lures",
        ),
    ),
    "botnet": Theme(
        ("Mirai", "Emotet", "Qakbot", "TrickBot"),
        (
            ("T1071", "Application Layer Protocol"),
            ("T1105", "Ingress Tool Transfer"),
            ("T1498", "Network Denial of Service"),
            ("T1059", "Command and Scripting Interpreter"),
        ),
        ("botnet", "c2", "loader"),
        (
            "{family} command-and-control infrastructure",
            "{family} campaign indicators",
            "{family} loader distribution",
        ),
    ),
    "ransomware": Theme(
        ("LockBit", "BlackCat", "Conti", "Akira"),
        (
            ("T1486", "Data Encrypted for Impact"),
            ("T1490", "Inhibit System Recovery"),
            ("T1059", "Command and Scripting Interpreter"),
            ("T1021.001", "Remote Desktop Protocol"),
        ),
        ("ransomware", "extortion", "staging"),
        (
            "{family} affiliate infrastructure",
            "{family} staging servers",
            "{family} payload delivery",
        ),
    ),
    "stealer": Theme(
        ("RedLine Stealer", "Raccoon Stealer", "Agent Tesla", "Lokibot", "FormBook"),
        (
            ("T1555", "Credentials from Password Stores"),
            ("T1056", "Input Capture"),
            ("T1041", "Exfiltration Over C2 Channel"),
            ("T1005", "Data from Local System"),
        ),
        ("infostealer", "credential-theft", "exfiltration"),
        (
            "{family} exfiltration endpoints",
            "{family} distribution wave",
            "{family} panel infrastructure",
        ),
    ),
    "scanner": Theme(
        (),
        (
            ("T1595", "Active Scanning"),
            ("T1190", "Exploit Public-Facing Application"),
            ("T1110", "Brute Force"),
        ),
        ("scanner", "brute-force", "ssh", "recon"),
        (
            "Mass SSH brute-force sources",
            "Opportunistic web scanning wave",
            "Exposed-service reconnaissance",
        ),
    ),
    "c2": Theme(
        ("Cobalt Strike", "Sliver", "AsyncRAT", "Remcos"),
        (
            ("T1071", "Application Layer Protocol"),
            ("T1573", "Encrypted Channel"),
            ("T1105", "Ingress Tool Transfer"),
            ("T1059", "Command and Scripting Interpreter"),
        ),
        ("c2", "rat", "beacon"),
        (
            "{family} team server infrastructure",
            "{family} beacon configuration",
            "{family} operator activity",
        ),
    ),
}
_THEMES_BY_TYPE: dict[IndicatorType, tuple[str, ...]] = {
    IndicatorType.IPV4: ("scanner", "botnet", "c2"),
    IndicatorType.IPV6: ("scanner", "botnet", "c2", "ransomware"),
    IndicatorType.DOMAIN: ("phishing", "c2", "stealer", "botnet"),
    IndicatorType.URL: ("phishing", "stealer", "botnet"),
    IndicatorType.SHA256: ("ransomware", "stealer", "botnet", "c2"),
}

# Fictional operators, so no real network is ever described.
_ISPS = (
    "Acme Datacenter",
    "Globex Telecom",
    "Initech Hosting",
    "Hooli Cloud",
    "Vandelay Networks",
    "Wonka Transit",
    "Soylent Broadband",
    "Cyberdyne Hosting",
    "Tyrell Telecom",
    "Aperture Hosting",
)
_USAGE_TYPES = (
    "Data Center/Web Hosting/Transit",
    "Fixed Line ISP",
    "Commercial",
    "Mobile ISP",
    "Content Delivery Network",
)
_COUNTRIES = (
    "NL", "DE", "US", "BR", "IN", "KR", "FR", "GB", "VN", "ID", "TR", "UA", "PL",
    "SG", "JP", "CA", "ZA", "MX", "AR", "TH", "RO", "IT", "ES", "SE", "AU", "EG",
)  # fmt: skip
_COUNTRY_WEIGHTS = (
    14, 9, 12, 6, 6, 4, 4, 4, 5, 3, 4, 3, 3, 4, 2, 2, 1, 2, 1, 1, 3, 1, 1, 1, 1, 1,
)  # fmt: skip

Clock = Callable[[], datetime]
Catalogue = Mapping[tuple[IndicatorType, str], Tier]


@dataclass(frozen=True, slots=True)
class World:
    """What the simulated providers know. Unlisted indicators get a profile from their hash."""

    clock: Clock
    tiers: Catalogue

    def tier(self, indicator_type: IndicatorType, value: str) -> Tier:
        listed = self.tiers.get((indicator_type, value))
        return listed if listed is not None else fallback_tier(indicator_type, value)


def fallback_tier(indicator_type: IndicatorType, value: str) -> Tier:
    rng = random.Random(f"tier|{indicator_type.value}|{value}")
    options = _FALLBACK_WEIGHTS[indicator_type in _IP_TYPES]
    return rng.choices([tier for tier, _ in options], [weight for _, weight in options])[0]


def theme_for(indicator_type: IndicatorType, value: str) -> Theme:
    rng = random.Random(f"theme|{indicator_type.value}|{value}")
    return THEMES[rng.choice(_THEMES_BY_TYPE[indicator_type])]


def _timestamp(moment: datetime) -> str:
    # OTX writes naive UTC timestamps; the adapter reads them as UTC.
    return moment.astimezone(UTC).replace(tzinfo=None).isoformat(timespec="seconds")


def abuseipdb_payload(world: World, ip: str) -> dict[str, Any]:
    indicator_type = IndicatorType.IPV6 if ":" in ip else IndicatorType.IPV4
    tier = world.tier(indicator_type, ip)
    rng = random.Random(f"abuseipdb|{ip}")
    shape = _ABUSE_SHAPES[tier]

    confidence = rng.randint(*shape.confidence)
    reports = rng.randint(*shape.reports)
    reporters = min(reports, rng.randint(*shape.reporters))
    hours_ago = rng.uniform(*shape.last_reported_hours)
    # The well-known resolvers in the catalogue are simulated as clean and US-based.
    country = "US" if tier is Tier.CLEAN else rng.choices(_COUNTRIES, _COUNTRY_WEIGHTS)[0]
    isp = rng.choice(_ISPS)
    usage_type = rng.choice(_USAGE_TYPES)
    is_tor = tier in (Tier.CRITICAL, Tier.HIGH) and rng.random() < 0.15
    whitelisted = tier is Tier.CLEAN and rng.random() < 0.7
    last_reported = None
    if reports:
        last_reported = world.clock() - timedelta(hours=hours_ago)

    return {
        "data": {
            "ipAddress": ip,
            "isPublic": True,
            "ipVersion": 6 if indicator_type is IndicatorType.IPV6 else 4,
            "isWhitelisted": whitelisted,
            "abuseConfidenceScore": confidence,
            "countryCode": country,
            "usageType": usage_type,
            "isp": isp,
            "domain": f"{isp.lower().replace(' ', '-')}.example",
            "hostnames": [],
            "isTor": is_tor,
            "totalReports": reports,
            "numDistinctUsers": reporters,
            "lastReportedAt": last_reported.astimezone(UTC).isoformat() if last_reported else None,
        }
    }


def otx_payload(world: World, indicator_type: IndicatorType, value: str) -> dict[str, Any]:
    tier = world.tier(indicator_type, value)
    rng = random.Random(f"otx|{indicator_type.value}|{value}")
    theme = theme_for(indicator_type, value)
    counts = _IP_PULSES if indicator_type in _IP_TYPES else _OTHER_PULSES
    count = rng.randint(*counts[tier])
    newest, oldest = _PULSE_AGE_DAYS[tier]
    primary = rng.choice(theme.families) if theme.families else None

    now = world.clock()
    pulses = [
        _pulse(rng, theme, primary, now, newest if index == 0 else rng.uniform(newest, oldest))
        for index in range(min(count, MAX_LISTED_PULSES))
    ]
    validation: list[dict[str, str]] = []
    if tier is Tier.CLEAN:
        kind = "domain" if indicator_type is IndicatorType.DOMAIN else "IP address"
        validation.append(
            {
                "source": "whitelist",
                "message": f"Whitelisted {kind} {value} (simulated)",
                "name": f"Whitelisted {kind}",
            }
        )
    return {"pulse_info": {"count": count, "pulses": pulses}, "validation": validation}


def _pulse(
    rng: random.Random, theme: Theme, primary: str | None, now: datetime, age_days: float
) -> dict[str, Any]:
    created = now - timedelta(days=age_days)
    modified = created + timedelta(days=rng.uniform(0, min(age_days, 10)))
    families = [primary] if primary and rng.random() < 0.85 else []
    if theme.families and rng.random() < 0.25:
        families.append(rng.choice(theme.families))
    families = list(dict.fromkeys(families))
    techniques = rng.sample(theme.techniques, k=rng.randint(1, min(3, len(theme.techniques))))
    title = rng.choice(theme.titles).format(family=primary or "Unattributed")
    # No pulse id: the dashboard would otherwise link to a pulse that does not exist on OTX.
    return {
        "name": f"{title} (simulated)",
        "created": _timestamp(created),
        "modified": _timestamp(modified),
        "tags": rng.sample(theme.tags, k=rng.randint(1, min(3, len(theme.tags)))),
        "malware_families": [{"id": name, "display_name": name} for name in families],
        "attack_ids": [
            {"id": technique, "name": name, "display_name": f"{technique} - {name}"}
            for technique, name in techniques
        ],
    }


def _forced_failure(value: str) -> httpx2.Response | None:
    lowered = value.lower()
    for marker, status in FAILURE_MARKERS:
        if marker in lowered:
            return httpx2.Response(status, json={"detail": "simulated failure"})
    return None


def build_handler(world: World) -> Callable[[httpx2.Request], httpx2.Response]:
    def handle(request: httpx2.Request) -> httpx2.Response:
        url = request.url
        if request.method == "GET" and url.host == _ABUSEIPDB_HOST and url.path == "/api/v2/check":
            ip = url.params.get("ipAddress", "")
            return _forced_failure(ip) or httpx2.Response(200, json=abuseipdb_payload(world, ip))
        if request.method == "GET" and url.host == _OTX_HOST:
            # The raw path keeps a percent-encoded URL indicator in one segment.
            match = _OTX_PATH.fullmatch(url.raw_path.split(b"?", 1)[0].decode("ascii"))
            indicator_type = _OTX_SECTIONS.get(match["section"]) if match else None
            if match and indicator_type:
                value = unquote(match["value"])
                return _forced_failure(value) or httpx2.Response(
                    200, json=otx_payload(world, indicator_type, value)
                )
        return httpx2.Response(404, json={"detail": "not found"})

    return handle


class SimulatedAbuseIPDB(AbuseIPDBCollector):
    simulated = True


class SimulatedOTX(OTXCollector):
    simulated = True


def build_simulated_collectors(
    clock: Clock = utcnow,
    *,
    tiers: Catalogue | None = None,
    abuseipdb_cache_ttl_seconds: int = 6 * 3600,
    otx_cache_ttl_seconds: int = 12 * 3600,
) -> tuple[tuple[Collector, ...], httpx2.Client]:
    """The two simulated adapters plus the in-process client they share (close it when done)."""
    world = World(clock, tiers or {})
    client = httpx2.Client(
        transport=httpx2.MockTransport(build_handler(world)), follow_redirects=False
    )
    collectors = (
        SimulatedAbuseIPDB(
            api_key=DEMO_API_KEY, client=client, cache_ttl_seconds=abuseipdb_cache_ttl_seconds
        ),
        SimulatedOTX(api_key=DEMO_API_KEY, client=client, cache_ttl_seconds=otx_cache_ttl_seconds),
    )
    return collectors, client
