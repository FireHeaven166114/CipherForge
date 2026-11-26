"""Retry, back-off and time-budget behaviour shared by every adapter.

Each test drives the real ``Collector`` plumbing through a canned transport and a fake clock, so
nothing touches the network and nothing really sleeps.
"""

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from typing import Any, ClassVar

import httpx2
import pytest

from app.collectors.base import (
    MAX_RESPONSE_BYTES,
    Collector,
    ProviderResult,
    ProviderStatus,
    Reason,
)
from app.models.enums import IndicatorType
from app.services.normalization import NormalizedIndicator
from tests.provider_helpers import (
    KEY,
    FakeTime,
    Script,
    Wire,
    assert_nothing_sensitive_logged,
    build,
    indicator,
)

URL = "https://provider.example/api/lookup"
GOOD = {"signal": 0.5}
TARGET = "8.8.4.4"


class _Probe(Collector):
    """The smallest adapter: one GET that returns a signal, or nothing for a 404."""

    name: ClassVar[str] = "probe"
    display_name: ClassVar[str] = "Probe"
    supported_types: ClassVar[frozenset[IndicatorType]] = frozenset(IndicatorType)

    def _query(self, indicator: NormalizedIndicator, api_key: str) -> ProviderResult:
        body = self._get_json(URL, headers={"x-apikey": api_key}, not_found_is_none=True)
        if body is None:
            return ProviderResult(self.name, ProviderStatus.NO_DATA)
        return ProviderResult(self.name, ProviderStatus.OK, signal=body["signal"])


def lookup(wire: Any, clock: FakeTime, **options: Any) -> ProviderResult:
    options = {"timeout_seconds": 15, "max_retries": 2, **options}
    return build(_Probe, wire, **clock.options, **options).lookup(indicator(TARGET))


# --- What is retried ---------------------------------------------------------------------


@pytest.mark.parametrize("status", [502, 503, 504])
def test_transient_server_errors_are_retried_until_they_clear(status: int) -> None:
    clock, wire = FakeTime(), Script(Wire(status), Wire(status), Wire(body=GOOD))

    result = lookup(wire, clock)

    assert result.status is ProviderStatus.OK
    assert result.reason is None
    assert len(wire.calls) == 3
    assert clock.slept == [0.5, 1.0], "back-off doubles: 0.5 s, then 1 s"


def test_retries_stop_at_the_configured_maximum() -> None:
    clock, wire = FakeTime(), Wire(503)

    result = lookup(wire, clock)

    assert len(wire.calls) == 3, "one attempt plus two retries"
    assert result.status is ProviderStatus.ERROR
    assert result.reason is Reason.UNAVAILABLE
    assert result.message == "Probe returned an unexpected HTTP status (503)."


def test_backoff_is_capped() -> None:
    clock = FakeTime()

    lookup(Wire(503), clock, max_retries=5, timeout_seconds=30)

    assert clock.slept == [0.5, 1.0, 2.0, 4.0, 4.0]


def test_timeouts_and_connection_failures_are_retried() -> None:
    clock = FakeTime()
    wire = Script(
        Wire(error=httpx2.ReadTimeout("slow")),
        Wire(error=httpx2.ConnectError("down")),
        Wire(body=GOOD),
    )

    result = lookup(wire, clock)

    assert result.status is ProviderStatus.OK
    assert clock.slept == [0.5, 1.0]


@pytest.mark.parametrize(
    ("error", "message", "reason"),
    [
        (httpx2.ReadTimeout("slow"), "Probe did not respond in time.", Reason.TIMEOUT),
        (httpx2.ConnectTimeout("slow"), "Probe did not respond in time.", Reason.TIMEOUT),
        (httpx2.ConnectError("down"), "Could not reach Probe.", Reason.UNAVAILABLE),
    ],
)
def test_exhausted_network_failures_report_a_reason(
    error: Exception, message: str, reason: Reason
) -> None:
    clock = FakeTime()

    result = lookup(Wire(error=error), clock)

    assert (result.status, result.message, result.reason) == (ProviderStatus.ERROR, message, reason)
    assert str(error) not in (result.message or "")


def test_retries_are_off_unless_the_adapter_opts_in() -> None:
    clock, wire = FakeTime(), Wire(503)
    collector = build(_Probe, wire, **clock.options)

    result = collector.lookup(indicator(TARGET))

    assert len(wire.calls) == 1
    assert clock.slept == []
    assert result.reason is Reason.UNAVAILABLE


# --- What is final -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "provider_status", "reason", "message"),
    [
        (
            400,
            ProviderStatus.ERROR,
            Reason.INVALID_INPUT,
            "Probe rejected the request as invalid (400).",
        ),
        (
            422,
            ProviderStatus.ERROR,
            Reason.INVALID_INPUT,
            "Probe rejected the request as invalid (422).",
        ),
        (
            401,
            ProviderStatus.ERROR,
            Reason.AUTH_FAILED,
            "Probe rejected the configured credentials.",
        ),
        (
            403,
            ProviderStatus.ERROR,
            Reason.AUTH_FAILED,
            "Probe rejected the configured credentials.",
        ),
        (
            402,
            ProviderStatus.ERROR,
            Reason.UNAVAILABLE,
            "Probe returned an unexpected HTTP status (402).",
        ),
        (
            418,
            ProviderStatus.ERROR,
            Reason.UNAVAILABLE,
            "Probe returned an unexpected HTTP status (418).",
        ),
        (
            500,
            ProviderStatus.ERROR,
            Reason.UNAVAILABLE,
            "Probe returned an unexpected HTTP status (500).",
        ),
        (
            302,
            ProviderStatus.ERROR,
            Reason.UNAVAILABLE,
            "Probe returned an unexpected HTTP status (302).",
        ),
    ],
)
def test_other_statuses_are_final_and_never_retried(
    status: int, provider_status: ProviderStatus, reason: Reason, message: str
) -> None:
    clock, wire = FakeTime(), Wire(status, body={"error": "provider text with a secret"})

    result = lookup(wire, clock)

    assert len(wire.calls) == 1, "a retry cannot change this answer"
    assert clock.slept == []
    assert (result.status, result.reason, result.message) == (provider_status, reason, message)
    assert "secret" not in (result.message or "")


def test_not_found_is_an_answer_not_a_failure() -> None:
    clock, wire = FakeTime(), Wire(404, body={})

    result = lookup(wire, clock)

    assert result.status is ProviderStatus.NO_DATA
    assert len(wire.calls) == 1


def test_invalid_json_is_final() -> None:
    clock, wire = FakeTime(), Wire(content=b"<html>not json</html>")

    result = lookup(wire, clock)

    assert result.reason is Reason.MALFORMED_RESPONSE
    assert result.message == "Probe returned invalid JSON."
    assert len(wire.calls) == 1


def test_oversized_responses_are_final() -> None:
    clock, wire = FakeTime(), Wire(content=b"{" + b" " * MAX_RESPONSE_BYTES + b"}")

    result = lookup(wire, clock)

    assert result.reason is Reason.MALFORMED_RESPONSE
    assert len(wire.calls) == 1


def test_a_parser_bug_is_reported_as_a_malformed_response() -> None:
    clock = FakeTime()

    result = lookup(Wire(body={"unexpected": "shape"}), clock)  # no "signal" key

    assert result.status is ProviderStatus.ERROR
    assert result.reason is Reason.MALFORMED_RESPONSE
    assert "unexpected" not in (result.message or "")


# --- Rate limits and Retry-After ---------------------------------------------------------


def test_a_rate_limit_without_retry_after_is_reported_not_retried() -> None:
    clock, wire = FakeTime(), Wire(429)

    result = lookup(wire, clock)

    assert len(wire.calls) == 1
    assert result.status is ProviderStatus.RATE_LIMITED
    assert result.reason is Reason.RATE_LIMITED
    assert result.message == "Probe rate limit reached; try again later."


def test_a_short_retry_after_is_honoured() -> None:
    clock = FakeTime()
    wire = Script(Wire(429, headers={"Retry-After": "2"}), Wire(body=GOOD))

    result = lookup(wire, clock)

    assert result.status is ProviderStatus.OK
    assert clock.slept == [2.0], "the server's wait replaces the back-off"
    assert len(wire.calls) == 2


def test_a_retry_after_in_http_date_form_is_honoured() -> None:
    clock = FakeTime()
    when = format_datetime(datetime.now(UTC) + timedelta(seconds=4), usegmt=True)
    wire = Script(Wire(429, headers={"Retry-After": when}), Wire(body=GOOD))

    result = lookup(wire, clock)

    assert result.status is ProviderStatus.OK
    assert len(clock.slept) == 1
    assert 2.0 <= clock.slept[0] <= 4.0


def test_a_retry_after_beyond_the_cap_is_reported_to_the_analyst() -> None:
    clock, wire = FakeTime(), Wire(429, headers={"Retry-After": "120"})

    result = lookup(wire, clock)

    assert len(wire.calls) == 1, "a worker thread must not sleep for two minutes"
    assert clock.slept == []
    assert result.status is ProviderStatus.RATE_LIMITED
    assert result.message == "Probe rate limit reached; try again in about 120 seconds."


def test_a_retry_after_that_does_not_fit_the_budget_is_not_waited_for() -> None:
    clock, wire = FakeTime(), Wire(429, headers={"Retry-After": "8"})

    result = lookup(wire, clock, timeout_seconds=5)

    assert len(wire.calls) == 1
    assert result.reason is Reason.RATE_LIMITED


def test_a_503_with_retry_after_waits_as_told() -> None:
    clock = FakeTime()
    wire = Script(Wire(503, headers={"Retry-After": "3"}), Wire(body=GOOD))

    result = lookup(wire, clock)

    assert result.status is ProviderStatus.OK
    assert clock.slept == [3.0]


@pytest.mark.parametrize("header", ["soon", "-5", "1e3", "9999999", "", "Wed, 99 Foo 2020"])
def test_unusable_retry_after_values_are_ignored(header: str) -> None:
    clock, wire = FakeTime(), Wire(429, headers={"Retry-After": header})

    result = lookup(wire, clock)

    assert len(wire.calls) == 1
    assert result.message == "Probe rate limit reached; try again later."


def test_a_retry_after_in_the_past_means_retry_now() -> None:
    clock = FakeTime()
    past = format_datetime(datetime.now(UTC) - timedelta(minutes=5), usegmt=True)
    wire = Script(Wire(429, headers={"Retry-After": past}), Wire(body=GOOD))

    result = lookup(wire, clock)

    assert result.status is ProviderStatus.OK
    assert clock.slept == [0.0]


# --- The time budget ---------------------------------------------------------------------


def test_retries_stop_when_the_budget_cannot_cover_another_attempt() -> None:
    clock, wire = FakeTime(), Wire(503)

    result = lookup(wire, clock, timeout_seconds=2, max_retries=5)

    # t=0 fail, wait 0.5 (1.5 left); next wait 1.0 plus a 1 s attempt would not fit.
    assert len(wire.calls) == 2
    assert clock.slept == [0.5]
    assert result.reason is Reason.UNAVAILABLE


def test_each_attempt_is_given_only_the_time_that_is_left() -> None:
    clock, seen = FakeTime(), []

    def slow(request: httpx2.Request) -> httpx2.Response:
        seen.append(dict(request.extensions["timeout"]))
        clock.advance(4)  # this attempt itself used 4 seconds
        return httpx2.Response(503)

    lookup(slow, clock)

    assert [timeout["read"] for timeout in seen] == [15, 10.5, 5.5]
    assert {timeout["connect"] for timeout in seen} == {5}


def test_without_a_budget_the_shared_client_timeouts_apply() -> None:
    seen: list[dict[str, Any]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(dict(request.extensions["timeout"]))
        return httpx2.Response(200, json=GOOD)

    client = httpx2.Client(
        transport=httpx2.MockTransport(handler), timeout=httpx2.Timeout(7.0, connect=3.0)
    )
    _Probe(api_key=KEY, client=client, cache_ttl_seconds=60).lookup(indicator(TARGET))

    assert (seen[0]["read"], seen[0]["connect"]) == (7.0, 3.0)


def test_a_slow_trickle_is_cut_off_by_the_total_budget() -> None:
    clock = FakeTime()

    def trickle(request: httpx2.Request) -> httpx2.Response:
        def body() -> Any:
            clock.advance(10)
            yield b'{"signal":'
            clock.advance(10)
            yield b" 0.5}"

        return httpx2.Response(200, content=body())

    result = lookup(trickle, clock, max_retries=0)

    assert result.status is ProviderStatus.ERROR
    assert result.reason is Reason.TIMEOUT
    assert result.message == "Probe did not respond in time."


# --- Logging -----------------------------------------------------------------------------


@pytest.mark.usefixtures("production_logging")
def test_retries_are_logged_without_secrets(caplog: pytest.LogCaptureFixture) -> None:
    clock = FakeTime()
    wire = Script(Wire(503), Wire(429, headers={"Retry-After": "2"}), Wire(body=GOOD))

    lookup(wire, clock)

    retries = [record for record in caplog.records if record.getMessage() == "provider_retry"]
    assert [(r.attempt, r.cause, r.delay_seconds) for r in retries] == [
        (1, "http_503", 0.5),
        (2, "rate_limited", 2.0),
    ]
    assert all(r.provider == "probe" for r in retries)
    assert_nothing_sensitive_logged(caplog, TARGET)
