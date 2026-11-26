"""Wrong-password budget for password-protected shares.

A password share can be guessed at by anyone who holds the link, so wrong guesses are counted
per share *and* per client network, ``limit`` per 15 minutes each. When either budget is spent
the request is refused before the expensive key derivation runs.

An attempt is *reserved* (counted) before the derivation starts and handed back with
``release`` unless the password turned out to be wrong. That makes the budget safe against
parallel guesses: N simultaneous requests can never run more than ``limit`` derivations.

A correct password never clears earlier failures, otherwise an attacker holding one valid
password could keep resetting the per-network counter. A spent budget therefore stays spent
until its oldest failure leaves the window; the legitimate user waits out ``Retry-After``.
State is in process memory (see the note in ``app.security.rate_limit``).
"""

import ipaddress
import math
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

WINDOW_SECONDS = 900.0
DEFAULT_MAX_KEYS = 10_000


class AttemptLimitExceeded(Exception):
    def __init__(self, retry_after: int) -> None:
        super().__init__("Too many wrong passwords.")
        self.retry_after = retry_after


@dataclass(frozen=True, slots=True)
class Reservation:
    keys: tuple[str, str]
    timestamp: float


def client_bucket(address: str | None) -> str:
    """The rate-limit key of a client address.

    IPv6 clients are bucketed by their /64 (one subscriber controls a whole /64, so per-address
    limits would be free to evade) and IPv4-mapped IPv6 addresses count as the IPv4 address.
    Callers without a usable address share the ``unknown`` bucket.
    """
    if not address:
        return "unknown"
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return "unknown"
    if isinstance(parsed, ipaddress.IPv6Address):
        if parsed.ipv4_mapped is not None:
            return str(parsed.ipv4_mapped)
        return str(ipaddress.IPv6Network((parsed, 64), strict=False))
    return str(parsed)


class PasswordAttemptLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: float = WINDOW_SECONDS,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = DEFAULT_MAX_KEYS,
    ) -> None:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if max_keys < 2:
            raise ValueError("max_keys must be at least 2")
        self.limit = limit
        self.window_seconds = window_seconds
        self._clock = clock
        self._max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def reserve(self, share_key: str, client_key: str) -> Reservation:
        """Count one attempt against the share and the client, or raise AttemptLimitExceeded."""
        keys = (f"share:{share_key}", f"client:{client_key}")
        now = self._clock()
        cutoff = now - self.window_seconds
        with self._lock:
            windows = [self._window(key, cutoff, keep=keys) for key in keys]
            waits = [
                max(1, math.ceil(hits[0] + self.window_seconds - now))
                for hits in windows
                if len(hits) >= self.limit
            ]
            if waits:
                raise AttemptLimitExceeded(max(waits))
            for hits in windows:
                hits.append(now)
        return Reservation(keys=keys, timestamp=now)

    def release(self, reservation: Reservation) -> None:
        """Give an attempt back (the password was not tested, or it was right)."""
        with self._lock:
            for key in reservation.keys:
                hits = self._hits.get(key)
                if hits is not None:
                    try:
                        hits.remove(reservation.timestamp)
                    except ValueError:
                        continue  # already aged out of the window

    def _window(self, key: str, cutoff: float, *, keep: tuple[str, ...]) -> deque[float]:
        hits = self._hits.get(key)
        if hits is None:
            if len(self._hits) >= self._max_keys:
                self._make_room(cutoff, keep)
            hits = self._hits[key] = deque()
        while hits and hits[0] <= cutoff:
            hits.popleft()
        return hits

    def _make_room(self, cutoff: float, keep: tuple[str, ...]) -> None:
        """Bound memory: drop idle keys, then the least recently active one if still full.

        The keys of the reservation being made are never evicted, or their counts would be lost.
        """
        idle = [
            key
            for key, hits in self._hits.items()
            if key not in keep and (not hits or hits[-1] <= cutoff)
        ]
        for key in idle:
            del self._hits[key]
        if len(self._hits) >= self._max_keys:
            candidates = [key for key in self._hits if key not in keep]
            if candidates:
                del self._hits[min(candidates, key=lambda key: self._hits[key][-1])]
