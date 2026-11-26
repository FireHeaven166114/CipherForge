"""Bounded sliding-window counters for the detection rules."""

import heapq
import math
from collections import OrderedDict, deque
from collections.abc import Hashable, Iterator
from dataclasses import dataclass, field


@dataclass(slots=True)
class _Bucket:
    second: int
    first_at: float
    last_at: float
    total: int = 0
    by_key: dict[Hashable, int] = field(default_factory=dict)


class SlidingWindow:
    """Weights recorded per key over the last ``window_seconds`` seconds.

    Events are grouped into one-second buckets, so the window edge is accurate to one second and
    memory is bounded by the number of distinct (second, key) pairs, not by the number of events.
    A late event is counted in the newest second; an event older than the window is ignored.
    When the pairs exceed ``max_entries`` the oldest seconds are dropped and ``truncated`` is set,
    so a counter can under-count a flood but never grow without limit.
    """

    def __init__(self, window_seconds: int, *, max_entries: int = 50_000) -> None:
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")
        self._window = window_seconds
        self._max_entries = max_entries
        self._buckets: deque[_Bucket] = deque()
        self._by_key: dict[Hashable, int] = {}
        self._total = 0
        self._entries = 0
        self.truncated = False

    @property
    def window_seconds(self) -> int:
        return self._window

    @property
    def total(self) -> int:
        """The sum of the weights inside the window."""
        return self._total

    @property
    def unique(self) -> int:
        """How many distinct keys are inside the window."""
        return len(self._by_key)

    @property
    def first_at(self) -> float | None:
        """The earliest event time still inside the window."""
        return self._buckets[0].first_at if self._buckets else None

    @property
    def last_at(self) -> float | None:
        return self._buckets[-1].last_at if self._buckets else None

    def __iter__(self) -> Iterator[Hashable]:
        """The distinct keys inside the window."""
        return iter(self._by_key)

    def top(self, count: int) -> list[tuple[Hashable, int]]:
        """The ``count`` heaviest keys, heaviest first (ties in a stable but arbitrary order)."""
        return heapq.nlargest(count, self._by_key.items(), key=lambda item: item[1])

    def add(self, timestamp: float, key: Hashable = None, weight: int = 1) -> None:
        second = math.floor(timestamp)
        newest = self._buckets[-1].second if self._buckets else second
        if second <= newest - self._window:
            return
        if not self._buckets or second > newest:
            self._expire_before(second)
            self._buckets.append(_Bucket(second, timestamp, timestamp))
        bucket = self._buckets[-1]
        bucket.first_at = min(bucket.first_at, timestamp)
        bucket.last_at = max(bucket.last_at, timestamp)
        if key not in bucket.by_key:
            self._entries += 1
        bucket.by_key[key] = bucket.by_key.get(key, 0) + weight
        bucket.total += weight
        self._by_key[key] = self._by_key.get(key, 0) + weight
        self._total += weight
        while self._entries > self._max_entries and len(self._buckets) > 1:
            self._drop_oldest()
            self.truncated = True

    def expire(self, now: float) -> None:
        """Forget everything that is older than the window as of ``now``."""
        self._expire_before(math.floor(now))

    def _expire_before(self, second: int) -> None:
        while self._buckets and self._buckets[0].second <= second - self._window:
            self._drop_oldest()

    def _drop_oldest(self) -> None:
        bucket = self._buckets.popleft()
        self._total -= bucket.total
        self._entries -= len(bucket.by_key)
        for key, weight in bucket.by_key.items():
            remaining = self._by_key[key] - weight
            if remaining > 0:
                self._by_key[key] = remaining
            else:
                del self._by_key[key]


class LruMap[K, V]:
    """A mapping that forgets its least recently used entry once it holds ``max_size`` entries."""

    def __init__(self, max_size: int) -> None:
        if max_size < 1:
            raise ValueError("max_size must be at least 1")
        self._max_size = max_size
        self._items: OrderedDict[K, V] = OrderedDict()

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, key: object) -> bool:
        return key in self._items

    def get(self, key: K) -> V | None:
        """The value for ``key`` (marking it recently used), or None."""
        value = self._items.get(key)
        if value is not None:
            self._items.move_to_end(key)
        return value

    def peek(self, key: K) -> V | None:
        """The value for ``key`` without marking it recently used."""
        return self._items.get(key)

    def set(self, key: K, value: V) -> None:
        self._items[key] = value
        self._items.move_to_end(key)
        while len(self._items) > self._max_size:
            self._items.popitem(last=False)

    def pop(self, key: K) -> V | None:
        return self._items.pop(key, None)

    def values(self) -> list[V]:
        return list(self._items.values())

    def items(self) -> list[tuple[K, V]]:
        return list(self._items.items())
