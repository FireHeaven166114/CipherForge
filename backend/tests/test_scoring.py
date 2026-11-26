"""Scoring methodology ``intel-risk-v1``: bands, weights, caps and the invariants around them."""

import json
import math
from datetime import UTC, datetime, timedelta
from itertools import pairwise, product

import pytest

from app.correlation.scoring import (
    CONFIDENCE_MAX,
    MAX_PROVIDER_POINTS,
    METHODOLOGY,
    NO_EVIDENCE_ACTIONS,
    SINGLE_SOURCE_CAP,
    Classification,
    EvidenceState,
    ProviderEvidence,
    ScoreResult,
    classify,
    freshness_weight,
    provider_points,
    recommended_actions,
    score_indicator,
    score_range,
)

NOW = datetime(2025, 6, 1, 12, 0, tzinfo=UTC)
FRESH = EvidenceState.FRESH


def evidence(
    provider: str,
    display_name: str,
    *,
    signal: float = 0.0,
    age: float | None = 1.0,
    state: EvidenceState = FRESH,
    families: tuple[str, ...] = (),
    notes: tuple[str, ...] = (),
    fetched_days_ago: float | None = 0.0,
) -> ProviderEvidence:
    return ProviderEvidence(
        provider=provider,
        display_name=display_name,
        state=state,
        signal=signal,
        evidence_at=None if age is None else NOW - timedelta(days=age),
        fetched_at=None if fetched_days_ago is None else NOW - timedelta(days=fetched_days_ago),
        malware_families=families,
        notes=notes,
    )


def abuse(**kwargs: object) -> ProviderEvidence:
    return evidence("abuseipdb", "AbuseIPDB", **kwargs)  # type: ignore[arg-type]


def otx(**kwargs: object) -> ProviderEvidence:
    return evidence("otx", "AlienVault OTX", **kwargs)  # type: ignore[arg-type]


def third(**kwargs: object) -> ProviderEvidence:
    return evidence("third", "Third Feed", **kwargs)  # type: ignore[arg-type]


def score(*items: ProviderEvidence) -> ScoreResult:
    return score_indicator(items, now=NOW)


def codes(result: ScoreResult) -> list[str]:
    return [factor.code for factor in result.factors]


def points(result: ScoreResult, code: str) -> int:
    return next(factor.points for factor in result.factors if factor.code == code)


def has_note(result: ScoreResult, fragment: str) -> bool:
    return any(fragment in note for note in result.uncertainty)


# --- Bands -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, Classification.INFORMATIONAL),
        (20, Classification.INFORMATIONAL),
        (21, Classification.LOW),
        (40, Classification.LOW),
        (41, Classification.MEDIUM),
        (60, Classification.MEDIUM),
        (61, Classification.HIGH),
        (80, Classification.HIGH),
        (81, Classification.CRITICAL),
        (100, Classification.CRITICAL),
    ],
)
def test_classification_band_boundaries(value: int, expected: Classification) -> None:
    assert classify(value) is expected


@pytest.mark.parametrize("value", [-1, 101, 1000])
def test_classify_rejects_scores_outside_the_scale(value: int) -> None:
    with pytest.raises(ValueError, match="between 0 and 100"):
        classify(value)


def test_score_ranges_partition_the_scale_without_gaps_or_overlap() -> None:
    ranges = [score_range(band) for band in Classification]

    assert ranges[0][0] == 0
    assert ranges[-1][1] == 100
    for (_, previous_high), (low, _) in pairwise(ranges):
        assert low == previous_high + 1
    for value in range(101):
        low, high = score_range(classify(value))
        assert low <= value <= high


# --- Weights -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("age", "expected"),
    [
        (timedelta(0), 1000),
        (timedelta(days=7), 1000),
        (timedelta(days=7, seconds=1), 900),
        (timedelta(days=30), 900),
        (timedelta(days=30, seconds=1), 700),
        (timedelta(days=90), 700),
        (timedelta(days=90, seconds=1), 500),
        (timedelta(days=180), 500),
        (timedelta(days=180, seconds=1), 300),
        (timedelta(days=3650), 300),
        (timedelta(days=-3), 1000),
    ],
)
def test_freshness_weight_steps(age: timedelta, expected: int) -> None:
    assert freshness_weight(NOW - age, NOW) == expected


def test_unknown_evidence_date_gets_a_middling_weight() -> None:
    assert freshness_weight(None, NOW) == 600


@pytest.mark.parametrize(
    ("signal", "weight", "expected"),
    [
        (1.0, 1000, 45),
        (0.87, 1000, 39),
        (0.5, 1000, 23),
        (1.0, 300, 14),
        (0.0, 1000, 0),
        (2.5, 1000, 45),
        (-1.0, 1000, 0),
        (math.nan, 1000, 0),
        (math.inf, 1000, 0),
    ],
)
def test_provider_points_round_half_up_and_clamp(signal: float, weight: int, expected: int) -> None:
    assert provider_points(signal, weight) == expected
    assert MAX_PROVIDER_POINTS == 45


# --- Worked examples (these numbers appear in docs/threat-intelligence.md) ----------------


def test_a_single_strong_source_tops_out_at_medium_and_says_so() -> None:
    result = score(abuse(signal=1.0), otx(state=EvidenceState.NOT_CONFIGURED))

    assert result.score == 45
    assert result.classification is Classification.MEDIUM
    assert (result.answered_sources, result.contributing_sources, result.supporting_sources) == (
        1,
        1,
        1,
    )
    assert result.confidence == 35
    assert codes(result) == ["provider:abuseipdb"]
    assert has_note(result, "Only AbuseIPDB returned an answer")
    assert has_note(result, "AlienVault OTX is not configured")


def test_a_strong_source_with_a_moderate_one_is_high() -> None:
    result = score(abuse(signal=1.0), otx(signal=0.55))

    assert result.score == 78
    assert result.classification is Classification.HIGH
    assert points(result, "corroboration") == 8
    assert result.confidence == 90


def test_two_strong_independent_sources_are_critical() -> None:
    result = score(abuse(signal=1.0), otx(signal=1.0))

    assert result.score == 98
    assert result.classification is Classification.CRITICAL
    assert not has_note(result, "corroboration is missing")


def test_two_moderate_sources_stay_medium() -> None:
    result = score(abuse(signal=0.5), otx(signal=0.5))

    assert result.score == 54
    assert result.classification is Classification.MEDIUM


def test_the_total_never_exceeds_one_hundred_and_the_cap_is_a_visible_factor() -> None:
    result = score(abuse(signal=1.0), otx(signal=1.0, families=("Emotet", "TrickBot")))

    assert result.score == 100
    assert points(result, "malware_family") == 10
    assert points(result, "score_cap") == -8


def test_one_source_alone_can_never_reach_high_even_with_a_barely_unsupportive_second() -> None:
    result = score(abuse(signal=1.0), otx(signal=0.39))

    assert result.supporting_sources == 1
    assert points(result, "single_source_cap") == -3
    assert result.score == SINGLE_SOURCE_CAP == 60
    assert result.classification is Classification.MEDIUM
    assert has_note(result, "independent corroboration is missing")


def test_a_weak_second_source_adds_a_little_without_corroborating() -> None:
    result = score(abuse(signal=1.0), otx(signal=0.3))

    assert result.score == 45 + 14
    assert "corroboration" not in codes(result)


@pytest.mark.parametrize(
    ("signal", "age", "supports"),
    [
        (0.4, 1, True),
        (0.399, 1, False),
        (0.45, 20, True),
        (0.44, 20, False),
        (0.6, 60, True),
        (0.8, 100, True),
        (0.79, 100, False),
    ],
)
def test_support_threshold_is_signal_times_freshness_of_at_least_point_four(
    signal: float, age: float, supports: bool
) -> None:
    result = score(abuse(signal=signal, age=age))

    assert result.supporting_sources == (1 if supports else 0)


def test_three_supporting_sources_earn_the_larger_corroboration_bonus() -> None:
    result = score(abuse(signal=0.5), otx(signal=0.5), third(signal=0.5))

    assert points(result, "corroboration") == 16
    assert result.score == 23 * 3 + 16
    assert result.confidence == CONFIDENCE_MAX


# --- Evidence age ------------------------------------------------------------------------


def test_old_evidence_counts_less_and_can_stop_supporting() -> None:
    recent = score(abuse(signal=1.0, age=2))
    old = score(abuse(signal=1.0, age=100))
    ancient = score(abuse(signal=1.0, age=400))

    assert (recent.score, old.score, ancient.score) == (45, 23, 14)
    assert (recent.supporting_sources, old.supporting_sources, ancient.supporting_sources) == (
        1,
        1,
        0,
    )


def test_unknown_recency_is_weighted_moderately_and_noted() -> None:
    result = score(otx(signal=1.0, age=None))

    assert result.score == 27
    assert has_note(result, "AlienVault OTX did not say when the activity occurred")


# --- Malware families --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("families", "bonus"),
    [
        ((), 0),
        (("Emotet",), 5),
        (("Emotet", "emotet", "EMOTET"), 5),
        (("Emotet", "TrickBot"), 10),
        (("A", "B", "C", "D"), 10),
    ],
)
def test_malware_family_bonus_counts_distinct_names_up_to_ten(
    families: tuple[str, ...], bonus: int
) -> None:
    result = score(otx(signal=0.55, families=families))

    assert result.score == 25 + bonus
    assert ("malware_family" in codes(result)) == (bonus > 0)


def test_families_named_by_a_non_supporting_source_earn_nothing() -> None:
    result = score(otx(signal=0.25, families=("Emotet",)), abuse(signal=1.0))

    assert "malware_family" not in codes(result)


# --- No data, failures and staleness -----------------------------------------------------


def test_no_data_scores_zero_and_is_never_called_safe() -> None:
    result = score(abuse(signal=0.0, age=None), otx(signal=0.0, age=None))

    assert result.score == 0
    assert result.classification is Classification.INFORMATIONAL
    assert result.confidence == 70
    assert [factor.points for factor in result.factors] == [0, 0]
    assert result.factors[0].detail == "No malicious signal reported by this provider."
    assert has_note(result, "Absence of reports is not proof that an indicator is safe")


def test_providers_that_did_not_answer_contribute_nothing_and_are_explained() -> None:
    result = score(
        abuse(state=EvidenceState.NOT_CONFIGURED),
        otx(state=EvidenceState.UNAVAILABLE),
        third(state=EvidenceState.UNSUPPORTED),
    )

    assert result.score == 0
    assert result.confidence == 0
    assert result.factors == ()
    assert has_note(result, "No provider returned evidence")
    assert has_note(result, "AbuseIPDB is not configured")
    assert has_note(result, "AlienVault OTX could not be queried")
    assert not has_note(result, "Third Feed")


def test_a_score_with_no_answers_does_not_say_no_action_is_needed() -> None:
    result = score(abuse(state=EvidenceState.NOT_CONFIGURED), otx(state=EvidenceState.UNAVAILABLE))

    assert result.classification is Classification.INFORMATIONAL
    assert result.recommended_actions == NO_EVIDENCE_ACTIONS
    assert not any("No action is needed" in action for action in result.recommended_actions)
    assert any("cannot say whether it is safe" in action for action in result.recommended_actions)


def test_an_answer_with_no_data_keeps_the_advice_for_its_band() -> None:
    result = score(abuse(signal=0.0), otx(state=EvidenceState.NOT_CONFIGURED))

    assert result.answered_sources == 1
    assert result.recommended_actions == recommended_actions(Classification.INFORMATIONAL)


def test_a_stale_answer_still_counts_but_lowers_confidence_and_is_flagged() -> None:
    fresh = score(abuse(signal=1.0), otx(signal=1.0))
    stale = score(
        abuse(signal=1.0, state=EvidenceState.STALE, fetched_days_ago=3),
        otx(signal=1.0),
    )

    assert stale.score == fresh.score
    assert fresh.confidence == 90
    assert stale.confidence == 15 + 35 + 20
    assert has_note(
        stale,
        "AbuseIPDB's latest answer (29-05-2025 05:30:00 PM IST) is older than its cache window",
    )


def test_collector_notes_reach_the_uncertainty_list_verbatim() -> None:
    note = "AbuseIPDB lists this address as whitelisted; its abuse score is not counted."

    result = score(abuse(signal=0.0, notes=(note,)))

    assert note in result.uncertainty


def test_notes_from_providers_that_did_not_answer_are_not_used() -> None:
    result = score(abuse(state=EvidenceState.UNAVAILABLE, notes=("leftover note",)))

    assert not has_note(result, "leftover note")


def test_no_providers_at_all_is_a_valid_empty_assessment() -> None:
    result = score()

    assert (result.score, result.confidence, result.answered_sources) == (0, 0, 0)
    assert result.uncertainty[0].startswith("No internal telemetry")


# --- Invariants --------------------------------------------------------------------------

SIGNALS = (0.0, 0.1, 0.25, 0.4, 0.55, 0.7, 0.85, 1.0)
AGES: tuple[float | None, ...] = (None, 0, 6, 20, 60, 120, 400)


def test_invariants_hold_across_a_grid_of_evidence() -> None:
    for (signal_a, age_a), (signal_b, age_b), state_a, families in product(
        product(SIGNALS, AGES),
        product(SIGNALS, AGES),
        (FRESH, EvidenceState.STALE),
        ((), ("Emotet", "TrickBot")),
    ):
        items = (
            abuse(signal=signal_a, age=age_a, state=state_a),
            otx(signal=signal_b, age=age_b, families=families),
        )

        result = score(*items)

        assert sum(factor.points for factor in result.factors) == result.score
        assert 0 <= result.score <= 100
        assert result.classification is classify(result.score)
        if result.supporting_sources < 2:
            assert result.score <= SINGLE_SOURCE_CAP
        assert result.confidence <= CONFIDENCE_MAX
        assert result.supporting_sources <= result.answered_sources == 2
        assert result.contributing_sources <= result.answered_sources
        assert score(*items) == result


def test_the_score_never_falls_as_a_providers_signal_rises() -> None:
    other = otx(signal=0.55, age=10)

    scores = [score(abuse(signal=signal, age=3), other).score for signal in SIGNALS]

    assert scores == sorted(scores)
    assert scores[0] < scores[-1]


def test_the_score_never_rises_as_evidence_ages() -> None:
    ages = (0, 7, 8, 30, 31, 90, 91, 180, 181, 1000)
    other = otx(signal=0.7, age=10)

    scores = [score(abuse(signal=1.0, age=age), other).score for age in ages]

    assert scores == sorted(scores, reverse=True)
    assert scores[0] > scores[-1]


# --- Output ------------------------------------------------------------------------------


def test_result_serializes_to_plain_json_with_the_methodology() -> None:
    result = score(abuse(signal=1.0), otx(signal=0.55, families=("Emotet",)))

    payload = json.loads(json.dumps(result.to_dict()))

    assert payload["methodology"] == METHODOLOGY == "intel-risk-v1"
    assert payload["score"] == result.score
    assert payload["classification"] == result.classification.value == "critical"
    assert [factor["code"] for factor in payload["factors"]] == [
        "provider:abuseipdb",
        "provider:otx",
        "corroboration",
        "malware_family",
    ]
    assert set(payload["factors"][0]) == {"code", "label", "points", "detail"}
    assert payload["recommended_actions"] == list(result.recommended_actions)


@pytest.mark.parametrize("band", list(Classification))
def test_every_band_has_two_to_four_actions_that_advise_rather_than_act(
    band: Classification,
) -> None:
    actions = recommended_actions(band)

    assert 2 <= len(actions) <= 4
    assert all(action.strip() for action in actions)
    if band in (Classification.HIGH, Classification.CRITICAL):
        assert any("never" in action and "automatically" in action for action in actions)
