"""Synthetic indicators and a replayable two-week lookup history for the demo.

The catalogue only contains values that cannot accuse a real host (tests enforce this):

* domains and URLs sit under ``example.com``/``.org``/``.net``, the names IANA reserves for
  documentation, apart from a few household-name sites that are simulated as clean;
* the malicious-looking IP addresses are IPv6 addresses from space IANA has not allocated; the
  only IPv4 addresses are well-known public resolvers, simulated as clean;
* file hashes are SHA-256 digests of made-up strings.
"""

import hashlib
import ipaddress
import itertools
import math
import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.orm import Session, sessionmaker

from app.models.enums import IndicatorType
from app.models.types import utcnow
from app.services.intel_service import IntelService, RequestContext
from app.services.normalization import InvalidIndicatorError
from devtools.simulated_providers import Catalogue, Tier

SEED = 42
HISTORY_DAYS = 14  # the overview charts 14 UTC days

_IPV6_TIERS = {
    Tier.CRITICAL: 6,
    Tier.HIGH: 10,
    Tier.MEDIUM: 10,
    Tier.LOW: 6,
    Tier.CLEAN: 3,
    Tier.UNKNOWN: 5,
}
_DOMAIN_TIERS = {Tier.HIGH: 6, Tier.MEDIUM: 12, Tier.LOW: 9, Tier.UNKNOWN: 9}
_URL_TIERS = {Tier.HIGH: 4, Tier.MEDIUM: 6, Tier.LOW: 4, Tier.UNKNOWN: 4}
_HASH_TIERS = {Tier.HIGH: 5, Tier.MEDIUM: 8, Tier.LOW: 5, Tier.UNKNOWN: 6}

BENIGN_IPV4 = (
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
)
BENIGN_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    "github.com",
    "wikipedia.org",
    "mozilla.org",
    "python.org",
    "debian.org",
)
# Values the simulator answers with a forced failure: they show the "not assessed" state.
FAILURE_SAMPLES = ("rate-limit-sample.example.net", "provider-error-sample.example.net")
DOCUMENTATION_APEXES = ("example.com", "example.org", "example.net")
UNALLOCATED_IPV6_PREFIX = "2100"

_LABEL_WORDS = (
    "secure", "account", "login", "verify", "update", "billing", "invoice", "parcel", "support",
    "portal", "shared", "docs", "reset", "payroll", "wallet", "reward", "survey", "gateway",
    "webmail", "benefits",
)  # fmt: skip
_LABEL_SUFFIXES = (
    "check", "center", "desk", "notice", "review", "confirm", "access", "service", "online",
    "portal",
)  # fmt: skip
_URL_PATHS = (
    "login",
    "verify/account",
    "download/invoice.zip",
    "wp-content/uploads/update.exe",
    "gate.php?id=9",
    "secure/session",
    "files/shared.html",
    "admin/config.bak",
)
HASH_SAMPLE = "cipherforge-demo-sample-{number:03d}"

ANALYSTS = (
    ("ada.okafor", "198.51.100.14"),
    ("ravi.menon", "198.51.100.27"),
    ("mei.tanaka", "203.0.113.8"),
    ("lena.fischer", "203.0.113.41"),
    ("soc-lead", "198.51.100.90"),
)
REJECTED_INPUTS = ("192.168.1.10", "10.0.0.7", "router.local", "localhost")

# Lookup volume: a working-hours bump, quieter weekends, a few bursts and a busy recent window.
BASE_RATE = 0.2
PEAK_RATE = 1.3
PEAK_HOUR = 13
PEAK_SPREAD = 3.5
WEEKEND_FACTOR = 0.5
MIN_PER_DAY = 4
BURSTS = 3
RECENT_WINDOW = timedelta(hours=6)
RECENT_MINIMUM = 12
SPARE_LOOKUPS = 85  # lookups beyond one per catalogue entry are repeats
_REPEAT_WEIGHTS = {
    Tier.CRITICAL: 5,
    Tier.HIGH: 4,
    Tier.MEDIUM: 2,
    Tier.LOW: 1,
    Tier.CLEAN: 1,
    Tier.UNKNOWN: 1,
}


@dataclass(frozen=True, slots=True)
class DemoIndicator:
    indicator_type: IndicatorType
    value: str
    tier: Tier


@dataclass(frozen=True, slots=True)
class PlannedLookup:
    moment: datetime
    value: str
    actor: str
    source_ip: str


@dataclass(frozen=True, slots=True)
class SeedSummary:
    lookups: int
    rejected: int
    indicators: int


class DemoClock:
    """Real UTC time, except while the seeder replays history at pinned moments."""

    def __init__(self) -> None:
        self._pinned: datetime | None = None

    def __call__(self) -> datetime:
        return self._pinned if self._pinned is not None else utcnow()

    def pin(self, moment: datetime) -> None:
        self._pinned = moment

    def unpin(self) -> None:
        self._pinned = None


# --- Catalogue -------------------------------------------------------------------------


def build_catalogue() -> list[DemoIndicator]:
    rng = random.Random(SEED)
    sample_numbers = itertools.count(1)

    def ipv6() -> str:
        first, second = rng.randrange(0x10000), rng.randrange(0x10000)
        host = rng.randrange(1, 0x10000)
        return str(
            ipaddress.IPv6Address(f"{UNALLOCATED_IPV6_PREFIX}:{first:x}:{second:x}::{host:x}")
        )

    def domain() -> str:
        return f"{_label(rng)}.{rng.choice(DOCUMENTATION_APEXES)}"

    def url() -> str:
        return f"https://{domain()}/{rng.choice(_URL_PATHS)}"

    def sha256() -> str:
        sample = HASH_SAMPLE.format(number=next(sample_numbers))
        return hashlib.sha256(sample.encode()).hexdigest()

    entries = [DemoIndicator(IndicatorType.IPV4, ip, Tier.CLEAN) for ip in BENIGN_IPV4]
    entries += [DemoIndicator(IndicatorType.DOMAIN, name, Tier.CLEAN) for name in BENIGN_DOMAINS]
    entries += [DemoIndicator(IndicatorType.DOMAIN, name, Tier.UNKNOWN) for name in FAILURE_SAMPLES]
    entries += _generated(IndicatorType.IPV6, ipv6, rng, _IPV6_TIERS)
    entries += _generated(IndicatorType.DOMAIN, domain, rng, _DOMAIN_TIERS)
    entries += _generated(IndicatorType.URL, url, rng, _URL_TIERS)
    entries += _generated(IndicatorType.SHA256, sha256, rng, _HASH_TIERS)
    return entries


def tiers_of(catalogue: Sequence[DemoIndicator]) -> Catalogue:
    return {(entry.indicator_type, entry.value): entry.tier for entry in catalogue}


def _label(rng: random.Random) -> str:
    return f"{rng.choice(_LABEL_WORDS)}-{rng.choice(_LABEL_SUFFIXES)}-{rng.randrange(0x1000):03x}"


def _generated(
    indicator_type: IndicatorType,
    make_value: Callable[[], str],
    rng: random.Random,
    counts: dict[Tier, int],
) -> list[DemoIndicator]:
    """Unique values, each assigned one of the tiers in a shuffled, exactly counted order."""
    tiers = [tier for tier, count in counts.items() for _ in range(count)]
    rng.shuffle(tiers)
    values: dict[str, None] = {}
    while len(values) < len(tiers):
        values[make_value()] = None
    return [
        DemoIndicator(indicator_type, value, tier)
        for value, tier in zip(values, tiers, strict=True)
    ]


# --- History ---------------------------------------------------------------------------


def _poisson(rng: random.Random, rate: float) -> int:
    limit = math.exp(-rate)
    count = 0
    product = rng.random()
    while product > limit:
        count += 1
        product *= rng.random()
    return count


def lookup_moments(rng: random.Random, now: datetime, minimum: int) -> list[datetime]:
    """When lookups happen: oldest first, within the 14 UTC days the overview charts."""
    start = (now - timedelta(days=HISTORY_DAYS - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    end = now - timedelta(minutes=15)
    moments: list[datetime] = []

    def between(low: datetime, high: datetime) -> datetime:
        return low + (high - low) * rng.random()

    hour = start
    elapsed_hours: list[datetime] = []
    while hour < end:
        elapsed_hours.append(hour)
        rate = BASE_RATE + PEAK_RATE * math.exp(-0.5 * ((hour.hour - PEAK_HOUR) / PEAK_SPREAD) ** 2)
        if hour.weekday() >= 5:
            rate *= WEEKEND_FACTOR
        moments += [
            min(end, between(hour, hour + timedelta(hours=1))) for _ in range(_poisson(rng, rate))
        ]
        hour += timedelta(hours=1)

    quiet_enough = [h for h in elapsed_hours if end - h > timedelta(hours=8)]
    for burst_hour in rng.sample(quiet_enough, k=min(BURSTS, len(quiet_enough))):
        moments += [
            between(burst_hour, burst_hour + timedelta(minutes=40))
            for _ in range(rng.randint(6, 10))
        ]

    for day in range(HISTORY_DAYS):
        day_start = start + timedelta(days=day)
        day_end = min(day_start + timedelta(days=1), end)
        if day_end - day_start < timedelta(hours=6):
            continue
        present = sum(day_start <= moment < day_end for moment in moments)
        low = day_start + timedelta(hours=8)
        high = min(day_start + timedelta(hours=18), day_end)
        if high <= low:
            low, high = day_start, day_end
        moments += [between(low, high) for _ in range(max(0, MIN_PER_DAY - present))]

    recent_start = end - RECENT_WINDOW
    recent = sum(moment >= recent_start for moment in moments)
    moments += [between(recent_start, end) for _ in range(max(0, RECENT_MINIMUM - recent))]

    while len(moments) < minimum:
        moments.append(between(start, end))
    return sorted(moments)


def plan_history(
    catalogue: Sequence[DemoIndicator], now: datetime, *, seed: int = SEED
) -> list[PlannedLookup]:
    """Who looked up what and when. Every catalogue entry appears; the rest are repeats."""
    rng = random.Random(seed)
    moments = lookup_moments(rng, now, len(catalogue) + SPARE_LOOKUPS)
    pending = list(catalogue)
    rng.shuffle(pending)
    seen: list[DemoIndicator] = []
    plan: list[PlannedLookup] = []

    for index, moment in enumerate(moments):
        slots_left = len(moments) - index
        if pending and (not seen or rng.random() < len(pending) / slots_left):
            chosen = pending.pop()
            seen.append(chosen)
        else:
            chosen = rng.choices(seen, [_REPEAT_WEIGHTS[entry.tier] for entry in seen])[0]
        actor, source_ip = rng.choice(ANALYSTS)
        plan.append(PlannedLookup(moment, chosen.value, actor, source_ip))

    for value in REJECTED_INPUTS:
        actor, source_ip = rng.choice(ANALYSTS)
        plan.append(PlannedLookup(rng.choice(moments), value, actor, source_ip))
    return sorted(plan, key=lambda step: step.moment)


def seed_demo(
    service: IntelService,
    session_factory: sessionmaker[Session],
    clock: DemoClock,
    *,
    catalogue: Sequence[DemoIndicator] | None = None,
    now: datetime | None = None,
) -> SeedSummary:
    """Replay the planned history through the real service, with the clock pinned per lookup."""
    now = now or utcnow()
    plan = plan_history(catalogue if catalogue is not None else build_catalogue(), now)
    rejected = 0
    try:
        for step in plan:
            clock.pin(step.moment)
            with session_factory() as session:
                try:
                    service.investigate(
                        session,
                        RequestContext(actor=step.actor, source_ip=step.source_ip),
                        step.value,
                    )
                except InvalidIndicatorError:
                    rejected += 1
    finally:
        clock.unpin()
    return SeedSummary(
        lookups=len(plan) - rejected,
        rejected=rejected,
        indicators=len({step.value for step in plan} - set(REJECTED_INPUTS)),
    )
