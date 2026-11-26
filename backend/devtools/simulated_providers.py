"""Simulated AbuseIPDB, AlienVault OTX, VirusTotal and ThreatFox services for the demo.

The real adapters run unchanged (request building, parsing, sanitising, scoring). Only the
network is replaced by an in-process ``httpx2.MockTransport`` that answers in each provider's
documented response shape. Every answer is synthetic and derived deterministically from the
indicator, and every adapter reports ``simulated = True`` so the dashboard labels the data.

Simulated records carry no identifiers or links that would point at a real provider page: a
reader following one would find nothing that confirms the data.

Marker words force failures, so error handling can be demonstrated and tested: a value that
contains ``rate-limit`` is answered with HTTP 429 and one that contains ``provider-error`` with
HTTP 500, by every provider that takes the value. A value that contains ``otx-down``,
``virustotal-down`` or ``threatfox-down`` makes only that provider answer with HTTP 500, and the
others then describe it as a heavily reported indicator, so one failure can be shown next to
answers that still arrive.
"""

import base64
import ipaddress
import json
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
from app.collectors.threatfox import ThreatFoxCollector
from app.collectors.virustotal import VirusTotalCollector
from app.models.enums import IndicatorType
from app.models.types import utcnow

DEMO_API_KEY = "simulated-demo-key"
FAILURE_MARKERS = (("rate-limit", 429), ("provider-error", 500))
# AbuseIPDB takes only addresses, which cannot carry a marker word, so it has none.
PROVIDER_DOWN_MARKERS = {
    "otx": "otx-down",
    "virustotal": "virustotal-down",
    "threatfox": "threatfox-down",
}
MAX_LISTED_PULSES = 12

_ABUSEIPDB_HOST = "api.abuseipdb.com"
_OTX_HOST = "otx.alienvault.com"
_OTX_PATH = re.compile(r"/api/v1/indicators/(?P<section>[A-Za-z0-9]+)/(?P<value>[^/]+)/general")
_OTX_SECTIONS = {
    "IPv4": IndicatorType.IPV4,
    "IPv6": IndicatorType.IPV6,
    "domain": IndicatorType.DOMAIN,
    "url": IndicatorType.URL,
}
_VIRUSTOTAL_HOST = "www.virustotal.com"
_VIRUSTOTAL_PATH = re.compile(
    r"/api/v3/(?P<collection>ip_addresses|domains|urls|files)/(?P<identifier>[^/]+)"
)
_THREATFOX_HOST = "threatfox-api.abuse.ch"
_THREATFOX_PATH = "/api/v1/"
# OTX has one "file" section for every hash algorithm, so the digest length tells them apart.
_HASH_TYPE_BY_LENGTH = {
    32: IndicatorType.MD5,
    40: IndicatorType.SHA1,
    64: IndicatorType.SHA256,
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
    Tier.HIGH: AbuseShape((32, 48), (30, 140), (12, 45), (3, 60)),
    Tier.MEDIUM: AbuseShape((20, 38), (8, 30), (4, 14), (24, 200)),
    Tier.LOW: AbuseShape((6, 18), (3, 9), (2, 6), (120, 600)),
    Tier.CLEAN: _NONE,
    Tier.UNKNOWN: _NONE,
}

# Pulses OTX holds, per tier. An address is also judged by AbuseIPDB, so its pulse counts stay
# lower than those of the indicators OTX is the main source for.
_IP_PULSES: dict[Tier, Range] = {
    Tier.CRITICAL: (8, 45),
    Tier.HIGH: (2, 3),
    Tier.MEDIUM: (1, 3),
    Tier.LOW: (2, 3),
    Tier.CLEAN: (0, 0),
    Tier.UNKNOWN: (0, 0),
}
_OTHER_PULSES: dict[Tier, Range] = {
    Tier.CRITICAL: (26, 55),
    Tier.HIGH: (3, 4),
    Tier.MEDIUM: (2, 4),
    Tier.LOW: (2, 4),
    Tier.CLEAN: (0, 0),
    Tier.UNKNOWN: (0, 0),
}
# (newest, oldest) pulse age in days.
_PULSE_AGE_DAYS: dict[Tier, tuple[float, float]] = {
    Tier.CRITICAL: (1, 40),
    Tier.HIGH: (2, 60),
    Tier.MEDIUM: (9, 120),
    Tier.LOW: (45, 300),
    Tier.CLEAN: (0, 0),
    Tier.UNKNOWN: (0, 0),
}


@dataclass(frozen=True, slots=True)
class EngineShape:
    """What VirusTotal's engines concluded about an indicator, and how stale the analysis is."""

    malicious: Range
    suspicious: Range
    analysed_hours_ago: Range
    reputation: Range
    submissions: Range


_VIRUSTOTAL_QUIET = EngineShape((0, 0), (0, 0), (6, 96), (0, 120), (30, 4000))
_VIRUSTOTAL_SHAPES: dict[Tier, EngineShape] = {
    Tier.CRITICAL: EngineShape((24, 58), (0, 5), (1, 30), (-120, -40), (40, 400)),
    Tier.HIGH: EngineShape((2, 3), (0, 1), (2, 80), (-60, -10), (12, 120)),
    Tier.MEDIUM: EngineShape((1, 2), (0, 1), (12, 240), (-15, 0), (3, 30)),
    Tier.LOW: EngineShape((1, 1), (0, 1), (72, 600), (-4, 5), (1, 6)),
    Tier.CLEAN: _VIRUSTOTAL_QUIET,
    Tier.UNKNOWN: _VIRUSTOTAL_QUIET,  # never used: VirusTotal has no record of these
}
# Addresses are also judged by AbuseIPDB. A third and fourth source agreeing pushes a score up
# fast, so the engine counts for them stay lower to keep the demo's tiers apart.
_VIRUSTOTAL_IP_SHAPES: dict[Tier, EngineShape] = {
    **_VIRUSTOTAL_SHAPES,
    Tier.HIGH: EngineShape((1, 2), (0, 1), (2, 80), (-60, -10), (12, 120)),
    Tier.MEDIUM: EngineShape((1, 1), (0, 1), (12, 240), (-15, 0), (3, 30)),
}


@dataclass(frozen=True, slots=True)
class FoxShape:
    """What ThreatFox holds: whether it knows the indicator at all, and what it says."""

    coverage: float
    records: Range
    confidence: Range
    first_seen_days: Range


_THREATFOX_QUIET = FoxShape(0.0, (0, 0), (0, 0), (0, 0))
# ThreatFox only lists malware infrastructure and drops IOCs after six months, so it knows few
# of the indicators the other providers hold records about.
_THREATFOX_SHAPES: dict[Tier, FoxShape] = {
    Tier.CRITICAL: FoxShape(1.0, (1, 3), (90, 100), (2, 30)),
    Tier.HIGH: FoxShape(0.25, (1, 2), (60, 85), (3, 60)),
    Tier.MEDIUM: FoxShape(0.15, (1, 1), (40, 60), (10, 120)),
    Tier.LOW: FoxShape(0.06, (1, 1), (20, 40), (30, 150)),
    Tier.CLEAN: _THREATFOX_QUIET,
    Tier.UNKNOWN: _THREATFOX_QUIET,
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
    IndicatorType.MD5: ("ransomware", "stealer", "botnet", "c2"),
    IndicatorType.SHA1: ("ransomware", "stealer", "botnet", "c2"),
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
        if listed is not None:
            return listed
        if _names_a_provider_down(value):
            return Tier.CRITICAL
        return fallback_tier(indicator_type, value)


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


def _names_a_provider_down(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in PROVIDER_DOWN_MARKERS.values())


def _forced_failure(value: str, provider: str) -> httpx2.Response | None:
    lowered = value.lower()
    marker = PROVIDER_DOWN_MARKERS.get(provider)
    if marker is not None and marker in lowered:
        return httpx2.Response(500, json={"detail": "simulated failure"})
    for marker, status in FAILURE_MARKERS:
        if marker in lowered:
            return httpx2.Response(status, json={"detail": "simulated failure"})
    return None


# --- VirusTotal --------------------------------------------------------------------------

_FILE_TYPES = (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256)
_VIRUSTOTAL_TYPES = {
    IndicatorType.IPV4: "ip_address",
    IndicatorType.IPV6: "ip_address",
    IndicatorType.DOMAIN: "domain",
    IndicatorType.URL: "url",
    IndicatorType.MD5: "file",
    IndicatorType.SHA1: "file",
    IndicatorType.SHA256: "file",
}
_FILE_KINDS = (
    ("Win32 EXE", "exe"),
    ("Win32 DLL", "dll"),
    ("PowerShell", "ps1"),
    ("Office Open XML Document", "docm"),
    ("ELF", "elf"),
)
# Fictional category providers, so no real vendor is credited with a made-up verdict.
_CATEGORY_SOURCES = ("Acme Shield", "Globex Guard", "Initech Scan", "Hooli Defender")
_BAD_CATEGORIES = ("phishing", "malware", "malicious sites", "command and control")
_GOOD_CATEGORIES = ("technology", "search engines", "software downloads", "business")
# 64496-64511 is the range IANA reserves for documentation, so no real network is named.
_DOCUMENTATION_ASNS: Range = (64496, 64511)


def virustotal_payload(
    world: World, indicator_type: IndicatorType, value: str
) -> dict[str, Any] | None:
    """The record VirusTotal would return, or ``None`` when it has never seen the indicator."""
    tier = world.tier(indicator_type, value)
    if tier is Tier.UNKNOWN:
        return None
    rng = random.Random(f"virustotal|{indicator_type.value}|{value}")
    shape = (_VIRUSTOTAL_IP_SHAPES if indicator_type in _IP_TYPES else _VIRUSTOTAL_SHAPES)[tier]
    theme = theme_for(indicator_type, value)
    is_file = indicator_type in _FILE_TYPES

    malicious = rng.randint(*shape.malicious)
    suspicious = rng.randint(*shape.suspicious)
    flagged = malicious + suspicious
    engines = rng.randint(64, 76) if is_file else rng.randint(88, 94)
    stats = {"malicious": malicious, "suspicious": suspicious, "timeout": 0}
    if is_file:
        # File scans have no "harmless" opinion: engines either detect or stay silent.
        stats["harmless"] = 0
        stats["type-unsupported"] = rng.randint(4, 9)
        stats["undetected"] = max(engines - flagged - stats["type-unsupported"], 0)
    else:
        stats["undetected"] = min(rng.randint(8, 22), max(engines - flagged, 0))
        stats["harmless"] = max(engines - flagged - stats["undetected"], 0)

    analysed = world.clock() - timedelta(hours=rng.uniform(*shape.analysed_hours_ago))
    attributes: dict[str, Any] = {
        "last_analysis_stats": stats,
        "last_analysis_date": int(analysed.timestamp()),
        "reputation": rng.randint(*shape.reputation),
        "tags": _sample(rng, theme.tags) if flagged else [],
    }
    if indicator_type in _IP_TYPES:
        attributes["country"] = (
            "US" if tier is Tier.CLEAN else rng.choices(_COUNTRIES, _COUNTRY_WEIGHTS)[0]
        )
        attributes["asn"] = rng.randint(*_DOCUMENTATION_ASNS)
        attributes["as_owner"] = rng.choice(_ISPS)
    else:
        attributes["categories"] = _categories(rng, tier)
    if indicator_type is IndicatorType.URL or is_file:
        first_submitted = analysed - timedelta(days=rng.uniform(1, 60))
        attributes["first_submission_date"] = int(first_submitted.timestamp())
        attributes["times_submitted"] = rng.randint(*shape.submissions)
    if is_file:
        kind, extension = rng.choice(_FILE_KINDS)
        attributes["type_description"] = kind
        attributes["meaningful_name"] = f"sample-{value[:8]}.{extension} (simulated)"
        if malicious and theme.families:
            attributes["popular_threat_classification"] = _classification(rng, theme)

    # The id is not the real one, so the adapter builds no link to a VirusTotal page.
    return {
        "data": {
            "id": "simulated",
            "type": _VIRUSTOTAL_TYPES[indicator_type],
            "attributes": attributes,
        }
    }


def _sample(rng: random.Random, options: tuple[str, ...]) -> list[str]:
    return rng.sample(options, k=rng.randint(1, min(3, len(options))))


def _categories(rng: random.Random, tier: Tier) -> dict[str, str]:
    options = _GOOD_CATEGORIES if tier is Tier.CLEAN else _BAD_CATEGORIES
    return {source: rng.choice(options) for source in rng.sample(_CATEGORY_SOURCES, k=3)}


def _classification(rng: random.Random, theme: Theme) -> dict[str, Any]:
    names = rng.sample(theme.families, k=rng.randint(1, min(3, len(theme.families))))
    return {
        "suggested_threat_label": f"trojan.{names[0].lower().replace(' ', '')}",
        "popular_threat_name": [{"value": name, "count": rng.randint(3, 30)} for name in names],
    }


def _decode_url_id(identifier: str) -> str | None:
    """VirusTotal addresses a URL by its URL-safe base64 form, without padding."""
    try:
        padded = identifier + "=" * (-len(identifier) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii")).decode("ascii")
    except ValueError:
        return None


def _virustotal_subject(collection: str, identifier: str) -> tuple[IndicatorType, str] | None:
    value = unquote(identifier)
    match collection:
        case "ip_addresses":
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                return None
            return (IndicatorType.IPV6 if address.version == 6 else IndicatorType.IPV4), str(
                address
            )
        case "domains":
            return IndicatorType.DOMAIN, value.lower()
        case "urls":
            decoded = _decode_url_id(value)
            return None if decoded is None else (IndicatorType.URL, decoded)
        case _:
            kind = _HASH_TYPE_BY_LENGTH.get(len(value))
            return None if kind is None else (kind, value.lower())


def _virustotal_response(world: World, collection: str, identifier: str) -> httpx2.Response:
    subject = _virustotal_subject(collection, identifier)
    if subject is not None:
        indicator_type, value = subject
        failure = _forced_failure(value, "virustotal")
        if failure is not None:
            return failure
        payload = virustotal_payload(world, indicator_type, value)
        if payload is not None:
            return httpx2.Response(200, json=payload)
    return httpx2.Response(
        404, json={"error": {"code": "NotFoundError", "message": "Resource not found."}}
    )


# --- ThreatFox ---------------------------------------------------------------------------

_THREATFOX_PORTS = (80, 443, 8080, 8443, 4444, 1337, 5555, 9001)
_THREATFOX_NO_RESULT = {
    "query_status": "no_result",
    "data": "Your search did not yield any results",
}


def threatfox_payload(world: World, indicator_type: IndicatorType, value: str) -> dict[str, Any]:
    """ThreatFox's answer to a search. It holds records for only a few of the indicators."""
    tier = world.tier(indicator_type, value)
    rng = random.Random(f"threatfox|{indicator_type.value}|{value}")
    shape = _THREATFOX_SHAPES[tier]
    if rng.random() >= shape.coverage:
        return _THREATFOX_NO_RESULT

    theme = theme_for(indicator_type, value)
    if not theme.families:
        theme = THEMES["c2"]  # ThreatFox only lists indicators tied to a malware family
    family = rng.choice(theme.families)
    records = [
        _threatfox_record(rng, world.clock(), indicator_type, value, (theme, family), shape)
        for _ in range(rng.randint(*shape.records))
    ]
    return {"query_status": "ok", "data": records}


def _threatfox_record(
    rng: random.Random,
    now: datetime,
    indicator_type: IndicatorType,
    value: str,
    malware: tuple[Theme, str],
    shape: FoxShape,
) -> dict[str, Any]:
    theme, family = malware
    first_seen = now - timedelta(days=rng.uniform(*shape.first_seen_days))
    # Most IOCs are still live, and ThreatFox reports no end date for those.
    last_seen = None
    if rng.random() < 0.4:
        last_seen = min(now, first_seen + timedelta(days=rng.uniform(0, 10)))
    ioc, ioc_type = _threatfox_ioc(rng, indicator_type, value)
    aliases = [name for name in theme.families if name != family]
    # No record id: a made-up number would link to somebody else's real ThreatFox record.
    return {
        "id": None,
        "ioc": ioc,
        "ioc_type": ioc_type,
        "threat_type": "payload_delivery" if indicator_type is IndicatorType.URL else "botnet_cc",
        "malware": f"sim.{family.lower().replace(' ', '_')}",
        "malware_printable": family,
        "malware_alias": ",".join(rng.sample(aliases, k=min(len(aliases), rng.randint(0, 2)))),
        "malware_malpedia": None,
        "confidence_level": rng.randint(*shape.confidence),
        "first_seen": _threatfox_time(first_seen),
        "last_seen": _threatfox_time(last_seen) if last_seen else None,
        "reference": None,
        "reporter": "demo-reporter (simulated)",
        "tags": _sample(rng, theme.tags),
    }


def _threatfox_ioc(
    rng: random.Random, indicator_type: IndicatorType, value: str
) -> tuple[str, str]:
    port = rng.choice(_THREATFOX_PORTS)
    if indicator_type is IndicatorType.IPV4:
        return f"{value}:{port}", "ip:port"
    if indicator_type is IndicatorType.IPV6:
        return f"[{value}]:{port}", "ip:port"
    if indicator_type in (IndicatorType.DOMAIN, IndicatorType.URL):
        return value, indicator_type.value
    # A file hash is tied to the servers its malware talks to: documentation addresses only.
    return f"198.51.100.{rng.randint(1, 254)}:{port}", "ip:port"


def _threatfox_time(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _search_kind(query: str, term: str) -> IndicatorType | None:
    if query == "search_hash":
        return _HASH_TYPE_BY_LENGTH.get(len(term))
    try:
        return IndicatorType.IPV6 if ipaddress.ip_address(term).version == 6 else IndicatorType.IPV4
    except ValueError:
        return IndicatorType.URL if "://" in term else IndicatorType.DOMAIN


def _threatfox_response(world: World, request: httpx2.Request) -> httpx2.Response:
    try:
        body = json.loads(request.content)
    except ValueError:
        body = None
    query = body.get("query") if isinstance(body, dict) else None
    term = body.get("hash" if query == "search_hash" else "search_term") if body else None
    if query not in ("search_hash", "search_ioc") or not isinstance(term, str):
        return httpx2.Response(400, json={"detail": "simulated: unsupported request"})
    failure = _forced_failure(term, "threatfox")
    if failure is not None:
        return failure
    kind = _search_kind(query, term)
    if kind is None:
        return httpx2.Response(200, json={"query_status": "illegal_hash"})
    return httpx2.Response(200, json=threatfox_payload(world, kind, term))


def build_handler(world: World) -> Callable[[httpx2.Request], httpx2.Response]:
    def handle(request: httpx2.Request) -> httpx2.Response:
        url = request.url
        if request.method == "GET" and url.host == _ABUSEIPDB_HOST and url.path == "/api/v2/check":
            ip = url.params.get("ipAddress", "")
            return _forced_failure(ip, "abuseipdb") or httpx2.Response(
                200, json=abuseipdb_payload(world, ip)
            )
        if request.method == "GET" and url.host == _OTX_HOST:
            # The raw path keeps a percent-encoded URL indicator in one segment.
            match = _OTX_PATH.fullmatch(url.raw_path.split(b"?", 1)[0].decode("ascii"))
            if match:
                value = unquote(match["value"])
                if match["section"] == "file":
                    indicator_type = _HASH_TYPE_BY_LENGTH.get(len(value))
                else:
                    indicator_type = _OTX_SECTIONS.get(match["section"])
                if indicator_type:
                    return _forced_failure(value, "otx") or httpx2.Response(
                        200, json=otx_payload(world, indicator_type, value)
                    )
        if request.method == "GET" and url.host == _VIRUSTOTAL_HOST:
            match = _VIRUSTOTAL_PATH.fullmatch(url.raw_path.split(b"?", 1)[0].decode("ascii"))
            if match:
                return _virustotal_response(world, match["collection"], match["identifier"])
        if request.method == "POST" and url.host == _THREATFOX_HOST and url.path == _THREATFOX_PATH:
            return _threatfox_response(world, request)
        return httpx2.Response(404, json={"detail": "not found"})

    return handle


class SimulatedAbuseIPDB(AbuseIPDBCollector):
    simulated = True


class SimulatedOTX(OTXCollector):
    simulated = True


class SimulatedVirusTotal(VirusTotalCollector):
    simulated = True


class SimulatedThreatFox(ThreatFoxCollector):
    simulated = True


def build_simulated_collectors(
    clock: Clock = utcnow,
    *,
    tiers: Catalogue | None = None,
    abuseipdb_cache_ttl_seconds: int = 6 * 3600,
    otx_cache_ttl_seconds: int = 12 * 3600,
    virustotal_cache_ttl_seconds: int = 24 * 3600,
    threatfox_cache_ttl_seconds: int = 6 * 3600,
) -> tuple[tuple[Collector, ...], httpx2.Client]:
    """The four simulated adapters plus the in-process client they share (close it when done)."""
    world = World(clock, tiers or {})
    client = httpx2.Client(
        transport=httpx2.MockTransport(build_handler(world)), follow_redirects=False
    )
    collectors = (
        SimulatedAbuseIPDB(
            api_key=DEMO_API_KEY, client=client, cache_ttl_seconds=abuseipdb_cache_ttl_seconds
        ),
        SimulatedOTX(api_key=DEMO_API_KEY, client=client, cache_ttl_seconds=otx_cache_ttl_seconds),
        SimulatedVirusTotal(
            api_key=DEMO_API_KEY, client=client, cache_ttl_seconds=virustotal_cache_ttl_seconds
        ),
        SimulatedThreatFox(
            api_key=DEMO_API_KEY, client=client, cache_ttl_seconds=threatfox_cache_ttl_seconds
        ),
    )
    return collectors, client
