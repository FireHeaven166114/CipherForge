"""Sanitising helpers for untrusted provider JSON."""

import math
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.collectors.sanitize import (
    bounded_int,
    clean_list,
    clean_text,
    country_code,
    isoformat,
    parse_epoch,
    parse_timestamp,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("  hello \n\t world  ", "hello world"),
        ("a\x00b\u202ec\u200bd", "a b c d"),
        ("", None),
        ("   \n ", None),
        ("\x00\x01", None),
        (None, None),
        (12, None),
        (["x"], None),
    ],
)
def test_clean_text_drops_control_characters_and_requires_a_string(
    raw: Any, expected: str | None
) -> None:
    assert clean_text(raw, 50) == expected


def test_clean_text_truncates_with_an_ellipsis_within_the_limit() -> None:
    cleaned = clean_text("word " * 40, 20)

    assert cleaned is not None
    assert len(cleaned) == 20 and cleaned.endswith("\u2026")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(5, 5), (0, 0), (100, 100), (101, None), (-1, None), (True, None), ("5", None), (5.0, None)],
)
def test_bounded_int_accepts_only_real_in_range_integers(raw: Any, expected: int | None) -> None:
    assert bounded_int(raw, 0, 100) == expected


def test_clean_list_removes_duplicates_ignoring_case_and_keeps_the_first_spelling() -> None:
    assert clean_list(["Emotet", "emotet", "EMOTET", "Qakbot"], limit=10, max_length=20) == [
        "Emotet",
        "Qakbot",
    ]


def test_clean_list_can_lowercase() -> None:
    assert clean_list(["Emotet", "QAKBOT", "emotet"], limit=10, max_length=20, lowercase=True) == [
        "emotet",
        "qakbot",
    ]


def test_clean_list_respects_the_limit_and_skips_unusable_items() -> None:
    raw = [None, 1, "", "  ", "a", {"b": 1}, "b", "c", "d"]

    assert clean_list(raw, limit=3, max_length=5) == ["a", "b", "c"]


@pytest.mark.parametrize("raw", ["not a list", None, {"a": 1}, ("a", "b"), 3])
def test_clean_list_ignores_anything_that_is_not_a_list(raw: Any) -> None:
    assert clean_list(raw, limit=5, max_length=5) == []


def test_clean_list_only_scans_a_bounded_number_of_items() -> None:
    raw = [None] * 5_000 + ["late"]

    assert clean_list(raw, limit=5, max_length=10) == []


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2025-03-04T05:06:07Z", datetime(2025, 3, 4, 5, 6, 7, tzinfo=UTC)),
        ("2025-03-04T05:06:07+05:30", datetime(2025, 3, 3, 23, 36, 7, tzinfo=UTC)),
        ("2025-03-04T05:06:07", datetime(2025, 3, 4, 5, 6, 7, tzinfo=UTC)),
        ("  2025-03-04  ", datetime(2025, 3, 4, tzinfo=UTC)),
        ("1989-12-31T00:00:00Z", None),
        ("not a date", None),
        ("", None),
        (None, None),
        (20250304, None),
        ("2" * 65, None),
    ],
)
def test_parse_timestamp_returns_aware_utc_or_none(raw: Any, expected: datetime | None) -> None:
    assert parse_timestamp(raw) == expected


def test_parse_timestamp_rejects_values_well_in_the_future() -> None:
    tomorrow_plus = datetime.now(UTC) + timedelta(days=3)

    assert parse_timestamp(tomorrow_plus.isoformat()) is None
    assert parse_timestamp((datetime.now(UTC) - timedelta(hours=1)).isoformat()) is not None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (0, None),
        (631_152_000, datetime(1990, 1, 1, tzinfo=UTC)),
        (1_735_689_600, datetime(2025, 1, 1, tzinfo=UTC)),
        (1_735_689_600.5, datetime(2025, 1, 1, 0, 0, 0, 500_000, tzinfo=UTC)),
        (631_151_999, None),
        (-1, None),
        (10**20, None),
        (-(10**20), None),
        (math.inf, None),
        (math.nan, None),
        (True, None),
        ("1735689600", None),
        (None, None),
    ],
)
def test_parse_epoch_returns_aware_utc_or_none(raw: Any, expected: datetime | None) -> None:
    assert parse_epoch(raw) == expected


def test_parse_epoch_rejects_values_well_in_the_future() -> None:
    assert parse_epoch((datetime.now(UTC) + timedelta(days=3)).timestamp()) is None
    assert parse_epoch((datetime.now(UTC) - timedelta(hours=1)).timestamp()) is not None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("us", "US"),
        ("DE", "DE"),
        ("U", None),
        ("USA", None),
        ("1A", None),
        ("", None),
        (None, None),
    ],
)
def test_country_code_must_be_two_letters(raw: Any, expected: str | None) -> None:
    assert country_code(raw) == expected


def test_isoformat_handles_none() -> None:
    assert isoformat(None) is None
    assert isoformat(datetime(2025, 1, 2, 3, 4, 5, tzinfo=UTC)) == "2025-01-02T03:04:05+00:00"
