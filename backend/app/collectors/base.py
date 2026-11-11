"""Provider adapter contract and the shared, hardened HTTP plumbing.

Every adapter turns one normalized indicator into a :class:`ProviderResult`. ``lookup`` never
raises: timeouts, bad credentials, rate limits and malformed payloads all become a status the
API can show, so one failing provider cannot fail an investigation.

Security properties enforced here for every provider:

* URLs are hard-coded constants; only validated, encoded indicator values are inserted.
* Redirects are never followed (an API key must not travel to another host).
* Responses are streamed and capped at 2 MiB *after* decompression.
* Logs carry the provider, indicator type, status and duration, never the indicator or keys.
"""

import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, ClassVar

import httpx2

from app.models.enums import IndicatorType
from app.services.normalization import NormalizedIndicator

logger = logging.getLogger("cipherforge.collectors")

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_HTTP_OK = 200
_HTTP_NOT_FOUND = 404
_HTTP_RATE_LIMITED = 429
_HTTP_AUTH_FAILURES = (401, 403)


class ProviderStatus(StrEnum):
    OK = "ok"
    NO_DATA = "no_data"
    NOT_CONFIGURED = "not_configured"
    UNSUPPORTED = "unsupported"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


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

    @property
    def is_answer(self) -> bool:
        """True for outcomes worth storing: the provider answered (with or without data)."""
        return self.status in (ProviderStatus.OK, ProviderStatus.NO_DATA)


class ProviderFailure(Exception):
    """Internal signal that maps a failure to a :class:`ProviderStatus` and a safe message."""

    def __init__(self, status: ProviderStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class Collector(ABC):
    name: ClassVar[str]
    display_name: ClassVar[str]
    supported_types: ClassVar[frozenset[IndicatorType]]

    def __init__(
        self, *, api_key: str | None, client: httpx2.Client, cache_ttl_seconds: int
    ) -> None:
        self._api_key = api_key
        self._client = client
        self.cache_ttl_seconds = cache_ttl_seconds

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
            result = ProviderResult(self.name, failure.status, message=failure.message)
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
            )
        logger.info(
            "provider_lookup",
            extra={
                "provider": self.name,
                "indicator_type": indicator.indicator_type.value,
                "status": result.status.value,
                "duration_ms": round((time.perf_counter() - started) * 1000),
            },
        )
        return result

    @abstractmethod
    def _query(self, indicator: NormalizedIndicator, api_key: str) -> ProviderResult:
        """Call the provider and parse the answer. Raise :class:`ProviderFailure` on failure."""

    def _skipped(self, status: ProviderStatus, message: str) -> ProviderResult:
        return ProviderResult(self.name, status, message=message)

    def _get_json(
        self,
        url: str,
        *,
        headers: dict[str, str],
        params: dict[str, str] | None = None,
        not_found_is_none: bool = False,
    ) -> Any:
        try:
            with self._client.stream("GET", url, headers=headers, params=params) as response:
                status = response.status_code
                if status == _HTTP_NOT_FOUND and not_found_is_none:
                    return None
                if status == _HTTP_RATE_LIMITED:
                    raise ProviderFailure(
                        ProviderStatus.RATE_LIMITED,
                        f"{self.display_name} rate limit reached; try again later.",
                    )
                if status in _HTTP_AUTH_FAILURES:
                    raise ProviderFailure(
                        ProviderStatus.ERROR,
                        f"{self.display_name} rejected the configured credentials.",
                    )
                if status != _HTTP_OK:
                    raise ProviderFailure(
                        ProviderStatus.ERROR,
                        f"{self.display_name} returned an unexpected HTTP status ({status}).",
                    )
                body = _read_capped(response, self.display_name)
        except httpx2.TimeoutException:
            raise ProviderFailure(
                ProviderStatus.ERROR, f"{self.display_name} did not respond in time."
            ) from None
        except httpx2.HTTPError:
            raise ProviderFailure(
                ProviderStatus.ERROR, f"Could not reach {self.display_name}."
            ) from None

        try:
            return json.loads(body)
        except (ValueError, RecursionError):
            raise ProviderFailure(
                ProviderStatus.ERROR, f"{self.display_name} returned invalid JSON."
            ) from None


def _read_capped(response: httpx2.Response, display_name: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise ProviderFailure(
                ProviderStatus.ERROR, f"{display_name} response was too large to process."
            )
        chunks.append(chunk)
    return b"".join(chunks)
