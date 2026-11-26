"""Provider adapter contract and the shared, hardened HTTP plumbing.

Every adapter turns one normalized indicator into a :class:`ProviderResult`. ``lookup`` never
raises: timeouts, bad credentials, rate limits and malformed payloads all become a status the
API can show, so one failing provider cannot fail an investigation.

Security properties enforced here for every provider:

* URLs are hard-coded constants; only validated, encoded indicator values are inserted.
* Redirects are never followed (an API key must not travel to another host).
* Responses are streamed and capped at 2 MiB *after* decompression.
* Logs carry the provider, indicator type, status and duration, never the indicator or keys.

Retries are opt-in per adapter (``max_retries``) and limited to failures that can heal on
their own: timeouts, connection failures, HTTP 502/503/504 and a 429 that names a short
``Retry-After``. Invalid requests, rejected credentials and every other status are final. All
attempts of one lookup share a single time budget (``timeout_seconds``).
"""

import json
import logging
import math
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from enum import StrEnum
from typing import Any, ClassVar

import httpx2

from app.models.enums import IndicatorType
from app.services.normalization import NormalizedIndicator

logger = logging.getLogger("cipherforge.collectors")

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
CONNECT_TIMEOUT_SECONDS = 5.0
# Waits between attempts: 0.5 s, 1 s, 2 s, then 4 s. A server-supplied Retry-After replaces
# the wait, but a hint longer than the cap is reported to the analyst instead of blocking a
# worker thread.
BACKOFF_BASE_SECONDS = 0.5
BACKOFF_MAX_SECONDS = 4.0
MAX_RETRY_AFTER_SECONDS = 10.0
# A retry is only worth starting when at least this much of the budget is left after waiting.
MIN_ATTEMPT_SECONDS = 1.0
_HTTP_OK = 200
_HTTP_NOT_FOUND = 404
_HTTP_RATE_LIMITED = 429
_HTTP_AUTH_FAILURES = (401, 403)
_HTTP_INVALID_REQUEST = (400, 422)
_HTTP_TRANSIENT = (502, 503, 504)


class ProviderStatus(StrEnum):
    OK = "ok"
    NO_DATA = "no_data"
    NOT_CONFIGURED = "not_configured"
    UNSUPPORTED = "unsupported"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


class Reason(StrEnum):
    """Why a provider could not answer, in a form the interface can name.

    The values never carry provider text: the message that goes with them is written here.
    """

    NOT_CONFIGURED = "not_configured"
    INVALID_INPUT = "invalid_input"
    AUTH_FAILED = "auth_failed"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    MALFORMED_RESPONSE = "malformed_response"


class Verdict(StrEnum):
    """What a provider reported about an indicator it answered for (``summary["verdict"]``).

    It labels the provider's own data; it is never a CipherForge risk verdict. "harmless" and
    "not_found" are not evidence that an indicator is safe.
    """

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    HARMLESS = "harmless"
    UNKNOWN = "unknown"
    NOT_FOUND = "not_found"


@dataclass(frozen=True, slots=True)
class ProviderResult:
    provider: str
    status: ProviderStatus
    # Strength of the provider's evidence on a 0..1 scale. Not a probability of malice.
    signal: float = 0.0
    # When the provider says the activity happened: latest and earliest, when it says so.
    evidence_at: datetime | None = None
    first_evidence_at: datetime | None = None
    # Whitelisted, length-limited facts. Never the raw response.
    summary: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    message: str | None = None
    # Set only when the provider could not answer (never for ok / no_data / unsupported).
    reason: Reason | None = None

    @property
    def is_answer(self) -> bool:
        """True for outcomes worth storing: the provider answered (with or without data)."""
        return self.status in (ProviderStatus.OK, ProviderStatus.NO_DATA)


class ProviderFailure(Exception):
    """Internal signal that maps a failure to a :class:`ProviderStatus` and a safe message."""

    def __init__(self, status: ProviderStatus, message: str, reason: Reason | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.reason = reason


class _AttemptFailed(Exception):
    """One HTTP attempt failed. ``retryable`` says whether another attempt could succeed."""

    def __init__(
        self,
        failure: ProviderFailure,
        *,
        retryable: bool,
        cause: str,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(failure.message)
        self.failure = failure
        self.retryable = retryable
        self.cause = cause
        self.retry_after = retry_after


class Collector(ABC):
    name: ClassVar[str]
    display_name: ClassVar[str]
    supported_types: ClassVar[frozenset[IndicatorType]]
    # Only the dev-only demo adapters (backend/devtools) set this; the UI then says so loudly.
    simulated: ClassVar[bool] = False

    def __init__(
        self,
        *,
        api_key: str | None,
        client: httpx2.Client,
        cache_ttl_seconds: int,
        timeout_seconds: float | None = None,
        max_retries: int = 0,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._api_key = api_key
        self._client = client
        self.cache_ttl_seconds = cache_ttl_seconds
        # Total time one lookup may take, retries and waits included. ``None`` keeps the shared
        # client's per-request timeouts and makes a single attempt.
        self.timeout_seconds = timeout_seconds
        self._max_retries = max(0, max_retries)
        self._sleep = sleep
        self._monotonic = monotonic

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type in self.supported_types

    def precheck(self, indicator: NormalizedIndicator) -> ProviderResult | None:
        """The result a lookup returns without calling out (unsupported type, no key), if any."""
        if not self.supports(indicator.indicator_type):
            return self._skipped(
                ProviderStatus.UNSUPPORTED,
                f"{self.display_name} does not accept {indicator.indicator_type.value} indicators.",
            )
        if not self._api_key:
            return self._skipped(
                ProviderStatus.NOT_CONFIGURED,
                f"{self.display_name} is not configured (no API key set).",
                Reason.NOT_CONFIGURED,
            )
        return None

    def lookup(self, indicator: NormalizedIndicator) -> ProviderResult:
        """Query the provider. Unsupported types and missing keys make no network call."""
        skipped = self.precheck(indicator)
        if skipped is not None:
            return skipped
        api_key = self._api_key
        if api_key is None:
            raise AssertionError("precheck guarantees a configured key")

        started = time.perf_counter()
        try:
            result = self._query(indicator, api_key)
        except ProviderFailure as failure:
            result = ProviderResult(
                self.name, failure.status, message=failure.message, reason=failure.reason
            )
        except Exception as exc:
            # A parser bug must degrade one provider, not the whole investigation. Only the
            # exception type is logged: its text could contain the indicator or a key.
            logger.warning(
                "provider_unexpected_error",
                extra={"provider": self.name, "error_type": type(exc).__name__},
            )
            result = ProviderResult(
                self.name,
                ProviderStatus.ERROR,
                message=f"Unexpected error while handling the {self.display_name} response.",
                reason=Reason.MALFORMED_RESPONSE,
            )
        logger.info(
            "provider_lookup",
            extra={
                "provider": self.name,
                "indicator_type": indicator.indicator_type.value,
                "status": result.status.value,
                "reason": result.reason.value if result.reason else None,
                "duration_ms": round((time.perf_counter() - started) * 1000),
            },
        )
        return result

    @abstractmethod
    def _query(self, indicator: NormalizedIndicator, api_key: str) -> ProviderResult:
        """Call the provider and parse the answer. Raise :class:`ProviderFailure` on failure."""

    def _skipped(
        self, status: ProviderStatus, message: str, reason: Reason | None = None
    ) -> ProviderResult:
        return ProviderResult(self.name, status, message=message, reason=reason)

    def _get_json(
        self,
        url: str,
        *,
        headers: dict[str, str],
        params: dict[str, str] | None = None,
        not_found_is_none: bool = False,
    ) -> Any:
        return self._request_json(
            "GET", url, headers=headers, params=params, not_found_is_none=not_found_is_none
        )

    def _request_json(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        params: dict[str, str] | None = None,
        json_body: Any = None,
        not_found_is_none: bool = False,
    ) -> Any:
        """Send the request, retry transient failures within the time budget, parse the JSON.

        Returns ``None`` for an HTTP 404 when ``not_found_is_none`` is set. Everything else
        that is not a valid JSON answer raises :class:`ProviderFailure`.
        """
        started = self._monotonic()
        attempt = 0
        while True:
            try:
                body = self._send_once(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    json_body=json_body,
                    not_found_is_none=not_found_is_none,
                    started=started,
                )
                break
            except _AttemptFailed as failed:
                delay = self._retry_delay(failed, attempt, started)
                if delay is None:
                    raise failed.failure from None
                logger.info(
                    "provider_retry",
                    extra={
                        "provider": self.name,
                        "attempt": attempt + 1,
                        "cause": failed.cause,
                        "delay_seconds": round(delay, 2),
                    },
                )
                self._sleep(delay)
                attempt += 1

        if body is None:
            return None
        try:
            return json.loads(body)
        except (ValueError, RecursionError):
            raise ProviderFailure(
                ProviderStatus.ERROR,
                f"{self.display_name} returned invalid JSON.",
                Reason.MALFORMED_RESPONSE,
            ) from None

    def _remaining(self, started: float) -> float | None:
        if self.timeout_seconds is None:
            return None
        return self.timeout_seconds - (self._monotonic() - started)

    def _retry_delay(self, failed: _AttemptFailed, attempt: int, started: float) -> float | None:
        """Seconds to wait before the next attempt, or ``None`` when the failure is final."""
        if not failed.retryable or attempt >= self._max_retries:
            return None
        delay = min(BACKOFF_BASE_SECONDS * 2**attempt, BACKOFF_MAX_SECONDS)
        if failed.retry_after is not None:
            if failed.retry_after > MAX_RETRY_AFTER_SECONDS:
                return None
            delay = failed.retry_after
        remaining = self._remaining(started)
        if remaining is not None and delay + MIN_ATTEMPT_SECONDS > remaining:
            return None
        return delay

    def _send_once(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        params: dict[str, str] | None,
        json_body: Any,
        not_found_is_none: bool,
        started: float,
    ) -> bytes | None:
        remaining = self._remaining(started)
        options: dict[str, Any] = {}
        if remaining is not None:
            budget = max(remaining, MIN_ATTEMPT_SECONDS / 2)
            options["timeout"] = httpx2.Timeout(
                budget, connect=min(CONNECT_TIMEOUT_SECONDS, budget)
            )
        try:
            with self._client.stream(
                method, url, headers=headers, params=params, json=json_body, **options
            ) as response:
                status = response.status_code
                if status == _HTTP_NOT_FOUND and not_found_is_none:
                    return None
                if status != _HTTP_OK:
                    raise self._status_failure(status, response.headers.get("retry-after"))
                return self._read_capped(response, started)
        except httpx2.TimeoutException:
            raise _AttemptFailed(
                ProviderFailure(
                    ProviderStatus.ERROR,
                    f"{self.display_name} did not respond in time.",
                    Reason.TIMEOUT,
                ),
                retryable=True,
                cause="timeout",
            ) from None
        except httpx2.HTTPError:
            raise _AttemptFailed(
                ProviderFailure(
                    ProviderStatus.ERROR,
                    f"Could not reach {self.display_name}.",
                    Reason.UNAVAILABLE,
                ),
                retryable=True,
                cause="connection",
            ) from None

    def _status_failure(self, status: int, retry_after_header: str | None) -> _AttemptFailed:
        """Classify a non-200 answer: what to tell the analyst and whether a retry can help."""
        name = self.display_name
        retry_after = _parse_retry_after(retry_after_header)
        if status == _HTTP_RATE_LIMITED:
            wait = "try again later."
            if retry_after:
                wait = f"try again in about {math.ceil(retry_after)} seconds."
            return _AttemptFailed(
                ProviderFailure(
                    ProviderStatus.RATE_LIMITED,
                    f"{name} rate limit reached; {wait}",
                    Reason.RATE_LIMITED,
                ),
                # Only a stated, short wait is worth honouring; otherwise the analyst decides.
                retryable=retry_after is not None,
                cause="rate_limited",
                retry_after=retry_after,
            )
        if status in _HTTP_AUTH_FAILURES:
            failure = ProviderFailure(
                ProviderStatus.ERROR,
                f"{name} rejected the configured credentials.",
                Reason.AUTH_FAILED,
            )
            return _AttemptFailed(failure, retryable=False, cause="auth_failed")
        if status in _HTTP_INVALID_REQUEST:
            failure = ProviderFailure(
                ProviderStatus.ERROR,
                f"{name} rejected the request as invalid ({status}).",
                Reason.INVALID_INPUT,
            )
            return _AttemptFailed(failure, retryable=False, cause="invalid_request")
        failure = ProviderFailure(
            ProviderStatus.ERROR,
            f"{name} returned an unexpected HTTP status ({status}).",
            Reason.UNAVAILABLE,
        )
        return _AttemptFailed(
            failure,
            retryable=status in _HTTP_TRANSIENT,
            cause=f"http_{status}",
            retry_after=retry_after,
        )

    def _read_capped(self, response: httpx2.Response, started: float) -> bytes:
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise ProviderFailure(
                    ProviderStatus.ERROR,
                    f"{self.display_name} response was too large to process.",
                    Reason.MALFORMED_RESPONSE,
                )
            chunks.append(chunk)
            remaining = self._remaining(started)
            # The client's timeouts apply per read, so a slow trickle is cut off here instead.
            if remaining is not None and remaining <= 0:
                raise httpx2.ReadTimeout("response did not finish within the time budget")
        return b"".join(chunks)


def _parse_retry_after(value: str | None) -> float | None:
    """``Retry-After`` as seconds from now: delta-seconds or an HTTP date. ``None`` if unusable."""
    if not value:
        return None
    text = value.strip()
    if text.isascii() and text.isdigit() and len(text) <= 6:
        return float(text)
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (when - datetime.now(UTC)).total_seconds())
