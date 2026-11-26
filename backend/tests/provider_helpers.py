"""Shared pieces for the provider adapter tests: canned HTTP exchanges and collector builders.

Nothing here touches the network or needs an API key.
"""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2
import pytest

from app.collectors.base import Collector
from app.services.normalization import NormalizedIndicator, normalize_indicator

KEY = "unit-test-api-key-0123456789"

Handler = Callable[[httpx2.Request], httpx2.Response]


def iso(days_ago: float = 0.0) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago)).isoformat()


def indicator(value: str) -> NormalizedIndicator:
    return normalize_indicator(value)


class Wire:
    """A canned HTTP exchange that records every request it receives."""

    def __init__(
        self,
        status: int = 200,
        *,
        body: Any = None,
        content: Any = None,
        headers: dict[str, str] | None = None,
        error: Exception | None = None,
        before: Callable[[], None] | None = None,
    ) -> None:
        self.calls: list[httpx2.Request] = []
        self._status, self._body, self._content = status, body, content
        self._headers, self._error, self._before = headers, error, before

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.calls.append(request)
        if self._before is not None:
            self._before()
        if self._error is not None:
            raise self._error
        if self._content is not None:
            return httpx2.Response(self._status, content=self._content, headers=self._headers)
        return httpx2.Response(self._status, json=self._body, headers=self._headers)


class Script:
    """Plays one canned exchange per request and repeats the last one when they run out."""

    def __init__(self, *steps: Handler) -> None:
        self.calls: list[httpx2.Request] = []
        self._steps = steps

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.calls.append(request)
        return self._steps[min(len(self.calls), len(self._steps)) - 1](request)


class FakeTime:
    """Stands in for ``time.sleep`` and ``time.monotonic`` so retry tests take no real time."""

    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    @property
    def options(self) -> dict[str, Any]:
        return {"sleep": self.sleep, "monotonic": self.monotonic}


def build(
    cls: type[Collector], wire: Handler, *, key: str | None = KEY, **options: Any
) -> Collector:
    client = httpx2.Client(transport=httpx2.MockTransport(wire), follow_redirects=False)
    return cls(api_key=key, client=client, cache_ttl_seconds=3600, **options)


def assert_nothing_sensitive_logged(caplog: pytest.LogCaptureFixture, *needles: str) -> None:
    rendered = "\n".join(f"{record.getMessage()} {vars(record)}" for record in caplog.records)
    for needle in (KEY, *needles):
        assert needle not in rendered
