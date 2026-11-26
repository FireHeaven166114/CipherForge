"""UTC-to-IST conversion and the helpers built on it."""

from datetime import UTC, date, datetime, timedelta, timezone

import pytest

from app.core import timeutil
from app.core.timeutil import (
    format_ist,
    ist_date,
    ist_day_bounds,
    ist_day_start,
    ist_hour,
    ist_range_bounds,
    parse_ist_date,
    parse_timestamp,
    to_ist,
    today_ist,
)


def test_a_known_utc_instant_is_displayed_in_the_documented_format() -> None:
    assert format_ist("2026-11-25T04:19:00Z") == "25-11-2026 09:49:00 AM IST"


def test_conversion_uses_the_zone_rules_not_a_hand_added_offset() -> None:
    converted = to_ist(datetime(2026, 1, 1, 0, 0, tzinfo=UTC))

    assert converted is not None
    assert converted.tzinfo is timeutil.IST
    assert converted.utcoffset() == timedelta(hours=5, minutes=30)
    assert converted.tzname() == "IST"


@pytest.mark.parametrize(
    ("utc_value", "expected"),
    [
        ("2025-06-10T18:29:59Z", "10-06-2025 11:59:59 PM IST"),
        ("2025-06-10T18:30:00Z", "11-06-2025 12:00:00 AM IST"),
        ("2025-06-10T06:30:00Z", "10-06-2025 12:00:00 PM IST"),
        ("2025-12-31T18:30:00Z", "01-01-2026 12:00:00 AM IST"),
        ("2024-02-29T10:00:00Z", "29-02-2024 03:30:00 PM IST"),
    ],
)
def test_twelve_hour_clock_and_date_rollover(utc_value: str, expected: str) -> None:
    assert format_ist(utc_value) == expected


def test_naive_timestamps_are_read_as_utc() -> None:
    assert format_ist("2026-11-25T04:19:00") == "25-11-2026 09:49:00 AM IST"
    assert format_ist(datetime(2026, 11, 25, 4, 19)) == "25-11-2026 09:49:00 AM IST"
    assert format_ist("2026-11-25 04:19:00 UTC") == "25-11-2026 09:49:00 AM IST"


def test_other_offsets_are_normalised_before_conversion() -> None:
    plus_two = timezone(timedelta(hours=2))

    assert (
        format_ist(datetime(2026, 11, 25, 6, 19, tzinfo=plus_two)) == "25-11-2026 09:49:00 AM IST"
    )
    assert format_ist("2026-11-25T06:19:00+02:00") == "25-11-2026 09:49:00 AM IST"


def test_epoch_seconds_are_accepted() -> None:
    assert format_ist(1_795_580_340) == format_ist(datetime.fromtimestamp(1_795_580_340, tz=UTC))


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "   ",
        "not a date",
        "2026-13-45T00:00:00Z",
        "x" * 200,
        float("nan"),
        float("inf"),
        True,
        object(),
        "0001-01-01T00:00:00Z",
        "9999-12-31T23:59:59Z",
        10**20,
    ],
)
def test_missing_or_invalid_values_never_raise(value: object) -> None:
    assert parse_timestamp(value) is None
    assert to_ist(value) is None
    assert format_ist(value) == "unknown"
    assert format_ist(value, fallback="n/a") == "n/a"
    assert ist_date(value) is None
    assert ist_hour(value) is None


def test_ist_date_and_hour_follow_the_indian_calendar() -> None:
    moment = datetime(2025, 6, 10, 19, 0, tzinfo=UTC)

    assert ist_date(moment) == date(2025, 6, 11)
    assert ist_hour(moment) == 0
    assert today_ist(moment) == date(2025, 6, 11)


def test_day_bounds_cover_exactly_one_indian_day_in_utc() -> None:
    start, end = ist_day_bounds(date(2025, 6, 11))

    assert start == datetime(2025, 6, 10, 18, 30, tzinfo=UTC)
    assert end == datetime(2025, 6, 11, 18, 30, tzinfo=UTC)
    assert ist_day_start(date(2025, 6, 11)) == start


def test_range_bounds_include_the_whole_last_day_and_allow_open_ends() -> None:
    start, end = ist_range_bounds(date(2025, 6, 11), date(2025, 6, 12))

    assert start == datetime(2025, 6, 10, 18, 30, tzinfo=UTC)
    assert end == datetime(2025, 6, 12, 18, 30, tzinfo=UTC)
    assert ist_range_bounds(None, None) == (None, None)
    # A filter that starts on an IST day boundary includes an instant 1 second after it.
    just_after = datetime(2025, 6, 10, 18, 30, 1, tzinfo=UTC)
    assert start <= just_after < end


@pytest.mark.parametrize(
    ("value", "expected"), [("2025-06-11", date(2025, 6, 11)), (" 2025-06-11 ", date(2025, 6, 11))]
)
def test_calendar_dates_typed_by_a_user_are_parsed(value: str, expected: date) -> None:
    assert parse_ist_date(value) == expected


@pytest.mark.parametrize("value", ["", "11-06-2025", "2025-02-30", "yesterday"])
def test_invalid_calendar_dates_are_rejected(value: str) -> None:
    assert parse_ist_date(value) is None
