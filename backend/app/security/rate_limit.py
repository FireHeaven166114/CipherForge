"""In-memory sliding-window rate limiter.

Limits are tracked per key (the authenticated subject) in the memory of one process. With
several API replicas each keeps its own counters, so the effective limit is ``limit x replicas``
and counters reset when a process restarts. Put a shared limiter (a reverse proxy or Redis) in
front when a hard global limit matters.
"""

import math
import threading
import time
from collections import deque
from collections.abc import Callable

DEFAULT_MAX_KEYS = 10_000


class SlidingWindowRateLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: float = 60.0,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = DEFAULT_MAX_KEYS,
    ) -> None:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if max_keys < 1:
            raise ValueError("max_keys must be at least 1")
        self.limit = limit
        self.window_seconds = window_seconds
        self._clock = clock
        self._max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> int | None:
        """Count one request for ``key``.

        Returns None when the request is allowed, or the whole seconds the caller should wait
        when the limit is reached. Denied requests are not counted, so waiting out the
        ``Retry-After`` always works.
        """
        now = self._clock()
        cutoff = now - self.window_seconds
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                if len(self._hits) >= self._max_keys:
                    self._make_room(cutoff)
                hits = self._hits[key] = deque()
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self.limit:
                return max(1, math.ceil(hits[0] + self.window_seconds - now))
            hits.append(now)
            return None

    def _make_room(self, cutoff: float) -> None:
        """Bound memory: drop idle keys, then the least recently active one if still full."""
        for key in [k for k, hits in self._hits.items() if not hits or hits[-1] <= cutoff]:
            del self._hits[key]
        if len(self._hits) >= self._max_keys:
            oldest = min(self._hits, key=lambda k: self._hits[k][-1])
            del self._hits[oldest]
