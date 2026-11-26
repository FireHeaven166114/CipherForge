"""Helpers that turn untrusted provider JSON into safe, bounded values.

Provider payloads are attacker-influenceable (anyone can name an OTX pulse), so nothing from
them is stored or shown without passing through here first.
"""

import re
import unicodedata
from datetime import UTC, datetime, timedelta
from typing import Any

_MAX_TIMESTAMP_LENGTH = 64
_MAX_SCANNED_ITEMS = 1_000
_MAX_CLOCK_SKEW = timedelta(days=1)
_EARLIEST_YEAR = 1990
_COUNTRY_CODE = re.compile(r"[A-Za-z]{2}")


def clean_text(value: Any, max_length: int) -> str | None:
    """Collapse whitespace, drop control and invisible characters, and cap the length."""
    if not isinstance(value, str):
        return None
    visible = "".join(" " if unicodedata.category(char).startswith("C") else char for char in value)
    collapsed = " ".join(visible.split())
    if not collapsed:
        return None
    if len(collapsed) > max_length:
        return collapsed[: max_length - 1].rstrip() + "\u2026"
    return collapsed


def bounded_int(value: Any, low: int, high: int) -> int | None:
    """Return ``value`` when it is a real integer within range (booleans are not integers)."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if not low <= value <= high:
        return None
    return value


def clean_list(value: Any, *, limit: int, max_length: int, lowercase: bool = False) -> list[str]:
    """Distinct (ignoring case), cleaned strings from a provider list.

    The first spelling wins unless ``lowercase`` is set. Anything that is not a list is ignored.
    """
    if not isinstance(value, list):
        return []
    found: dict[str, str] = {}
    for item in value[:_MAX_SCANNED_ITEMS]:
        text = clean_text(item, max_length)
        if text is None:
            continue
        key = text.lower()
        found.setdefault(key, key if lowercase else text)
        if len(found) >= limit:
            break
    return list(found.values())


def parse_timestamp(value: Any) -> datetime | None:
    """Parse an ISO 8601 timestamp to aware UTC. Naive values are read as UTC.

    Implausible values (before 1990, or more than a day ahead) are treated as unknown so a
    bad provider clock cannot make old evidence look brand new.
    """
    if not isinstance(value, str) or not value or len(value) > _MAX_TIMESTAMP_LENGTH:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    parsed = parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    return parsed if _plausible(parsed) else None


def parse_epoch(value: Any) -> datetime | None:
    """Unix seconds to aware UTC, with the same plausibility limits as :func:`parse_timestamp`."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        parsed = datetime.fromtimestamp(value, UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return parsed if _plausible(parsed) else None


def _plausible(moment: datetime) -> bool:
    return moment.year >= _EARLIEST_YEAR and moment <= datetime.now(UTC) + _MAX_CLOCK_SKEW


def country_code(value: Any) -> str | None:
    if isinstance(value, str) and _COUNTRY_CODE.fullmatch(value):
        return value.upper()
    return None


def isoformat(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None
