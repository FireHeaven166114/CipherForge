"""Test doubles for the threat-intelligence service and API."""

import threading
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from app.collectors.base import Collector, ProviderFailure, ProviderResult, ProviderStatus
from app.core.context import correlation_id_var
from app.models.enums import IndicatorType
from app.services.normalization import NormalizedIndicator

STRONG = 1.0
MODERATE = 0.55


class Clock:
    """A controllable clock. It starts at the real time so audit rows (stamped by the database
    layer with the real clock) stay inside the 24-hour statistics window."""

    def __init__(self) -> None:
        self.now = datetime.now(UTC).replace(microsecond=0)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta: float) -> None:
        self.now += timedelta(**delta)

    def ago(self, **delta: float) -> datetime:
        return self.now - timedelta(**delta)


def answer(
    provider: str,
    *,
    signal: float,
    evidence_at: datetime | None,
    first_evidence_at: datetime | None = None,
    tags: Sequence[str] = (),
    families: Sequence[str] = (),
    notes: Sequence[str] = (),
    summary: dict[str, Any] | None = None,
) -> ProviderResult:
    return ProviderResult(
        provider,
        ProviderStatus.OK,
        signal=signal,
        evidence_at=evidence_at,
        first_evidence_at=first_evidence_at,
        summary={"malware_families": list(families), "notes": list(notes), **(summary or {})},
        tags=list(tags),
    )


def no_data(provider: str) -> ProviderResult:
    return ProviderResult(
        provider,
        ProviderStatus.NO_DATA,
        summary={"notes": [f"{provider} has no reports for this indicator."]},
    )


def failure(status: ProviderStatus, message: str) -> ProviderFailure:
    return ProviderFailure(status, message)


class FakeCollector(Collector):
    """A provider that answers from a script instead of the network.

    ``answers`` maps an indicator target (``type:value``) to its answer. Otherwise each call
    consumes the next ``script`` step (the last one repeats); with neither, the provider has no
    data. A step is a ``ProviderResult`` to return or a ``ProviderFailure`` to raise.
    """

    name = "fake"
    display_name = "Fake"
    supported_types = frozenset(IndicatorType)

    def __init__(
        self,
        script: Sequence[ProviderResult | ProviderFailure] = (),
        *,
        answers: Mapping[str, ProviderResult | ProviderFailure] | None = None,
        api_key: str | None = "test-key",
        cache_ttl_seconds: int = 3600,
        block: threading.Event | None = None,
    ) -> None:
        super().__init__(
            api_key=api_key,
            client=None,  # type: ignore[arg-type]
            cache_ttl_seconds=cache_ttl_seconds,
        )
        self.script = list(script)
        self.answers = dict(answers or {})
        self.calls: list[str] = []
        self.correlation_ids: list[str | None] = []
        self._block = block

    def _query(self, indicator: NormalizedIndicator, api_key: str) -> ProviderResult:
        self.calls.append(indicator.target)
        self.correlation_ids.append(correlation_id_var.get())
        if self._block is not None:
            self._block.wait(5)
        step = self.answers.get(indicator.target)
        if step is None and self.script:
            step = self.script[min(len(self.calls), len(self.script)) - 1]
        if step is None:
            return no_data(self.name)
        if isinstance(step, ProviderFailure):
            raise step
        return step


class FakeAbuse(FakeCollector):
    name = "abuseipdb"
    display_name = "AbuseIPDB"
    supported_types = frozenset({IndicatorType.IPV4, IndicatorType.IPV6})


class FakeOtx(FakeCollector):
    name = "otx"
    display_name = "AlienVault OTX"


class ExplodingCollector(FakeOtx):
    """A provider whose lookup breaks the 'never raises' contract."""

    def lookup(self, indicator: NormalizedIndicator) -> ProviderResult:
        raise RuntimeError("boom")


class ActsWhenAsked(FakeOtx):
    """A provider that runs ``action`` the first time it is asked, the way another analyst's
    request can in the middle of an investigation (providers are asked on worker threads)."""

    def __init__(
        self, action: Callable[[], None], script: Sequence[ProviderResult | ProviderFailure] = ()
    ) -> None:
        super().__init__(script)
        self._action: Callable[[], None] | None = action

    def _query(self, indicator: NormalizedIndicator, api_key: str) -> ProviderResult:
        action, self._action = self._action, None
        if action is not None:
            action()
        return super()._query(indicator, api_key)
