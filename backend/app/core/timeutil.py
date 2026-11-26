"""Time handling shared by the whole backend.

Timestamps are stored and exchanged as timezone-aware UTC: the database columns, the JSON that
the API returns and the audit trail all stay UTC, because that is unambiguous and machine
friendly. Anything written for a person (explanations, exports, bucketed days) uses Indian
Standard Time through this module, and nowhere else. The conversion uses the IANA zone
``Asia/Kolkata`` and never adds an offset by hand, so it stays correct if the zone rules change.

The display format is ``DD-MM-YYYY hh:mm:ss A IST``, for example ``25-11-2026 09:49:00 AM IST``.
It is built from the date parts rather than ``strftime("%p")`` so the result does not depend on
the process locale.
"""

import math
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DISPLAY_TIMEZONE_NAME = "Asia/Kolkata"
DISPLAY_LABEL = "IST"

# Timestamps outside this range are treated as invalid rather than overflowing a conversion.
_EARLIEST = datetime(1970, 1, 1, tzinfo=UTC)
_LATEST = datetime(2200, 1, 1, tzinfo=UTC)
_MAX_TIMESTAMP_LENGTH = 64


def _load_zone() -> ZoneInfo:
    try:
        return ZoneInfo(DISPLAY_TIMEZONE_NAME)
    except ZoneInfoNotFoundError:
        raise RuntimeError(
            f"The {DISPLAY_TIMEZONE_NAME} time zone is not available. Install the 'tzdata' "
            "package (pip install tzdata); Windows has no system time-zone database."
        ) from None


IST = _load_zone()


def parse_timestamp(value: object) -> datetime | None:
    """Read a timestamp as aware UTC, or return None when it is missing or not valid.

    Accepts datetimes, ISO 8601 strings (``Z`` or an offset, ``T`` or a space between date and
    time, an optional trailing ``UTC``) and epoch seconds. A value without a zone is read as UTC,
    which is how the database and the providers report them.
    """
    parsed: datetime | None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = _parse_text(value)
    elif isinstance(value, int | float) and not isinstance(value, bool):
        parsed = _parse_epoch(value)
    else:
        return None
    if parsed is None:
        return None
    try:
        aware = parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    except (OverflowError, ValueError):
        return None
    return aware if _EARLIEST <= aware < _LATEST else None


def _parse_text(text: str) -> datetime | None:
    cleaned = text.strip()
    if not cleaned or len(cleaned) > _MAX_TIMESTAMP_LENGTH:
        return None
    if cleaned.upper().endswith(" UTC"):
        cleaned = cleaned[:-4].rstrip()
    try:
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None


def _parse_epoch(seconds: float) -> datetime | None:
    if not math.isfinite(seconds):
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def to_ist(value: object) -> datetime | None:
    """The moment in Indian Standard Time, or None when the value is missing or invalid."""
    moment = parse_timestamp(value)
    return moment.astimezone(IST) if moment is not None else None


def format_ist(value: object, *, fallback: str = "unknown") -> str:
    """``DD-MM-YYYY hh:mm:ss A IST``, or ``fallback`` when the value is missing or invalid."""
    moment = to_ist(value)
    if moment is None:
        return fallback
    hour12 = moment.hour % 12 or 12
    meridiem = "AM" if moment.hour < 12 else "PM"
    return (
        f"{moment.day:02d}-{moment.month:02d}-{moment.year:04d} "
        f"{hour12:02d}:{moment.minute:02d}:{moment.second:02d} {meridiem} {DISPLAY_LABEL}"
    )


def ist_date(value: object) -> date | None:
    """The calendar date in India at that moment."""
    moment = to_ist(value)
    return moment.date() if moment is not None else None


def ist_hour(value: object) -> int | None:
    """The hour of the day (0-23) in India at that moment."""
    moment = to_ist(value)
    return moment.hour if moment is not None else None


def today_ist(now: datetime) -> date:
    """The current calendar date in India. ``now`` must be a timezone-aware datetime."""
    return now.astimezone(IST).date()


def ist_day_start(day: date) -> datetime:
    """The UTC instant at which ``day`` begins in India (00:00 IST)."""
    return datetime.combine(day, time.min, tzinfo=IST).astimezone(UTC)


def ist_day_bounds(day: date) -> tuple[datetime, datetime]:
    """UTC bounds ``[start, end)`` of one Indian calendar day, for filtering stored UTC values."""
    return ist_day_start(day), ist_day_start(day + timedelta(days=1))


def ist_range_bounds(
    first: date | None, last: date | None
) -> tuple[datetime | None, datetime | None]:
    """UTC bounds ``[start, end)`` covering the Indian days ``first`` through ``last`` inclusive."""
    start = ist_day_start(first) if first is not None else None
    end = ist_day_start(last + timedelta(days=1)) if last is not None else None
    return start, end


def parse_ist_date(value: str) -> date | None:
    """Read a calendar date typed by a user, as ``YYYY-MM-DD``; None when it is not one."""
    try:
        return date.fromisoformat(value.strip())
    except (ValueError, AttributeError):
        return None
