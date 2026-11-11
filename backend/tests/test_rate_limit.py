import sys
import threading
from collections import Counter

import pytest

from app.security.rate_limit import SlidingWindowRateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


def test_allows_up_to_the_limit_then_denies(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(3, 60, clock=clock)

    assert [limiter.check("analyst") for _ in range(3)] == [None, None, None]
    assert limiter.check("analyst") is not None


def test_retry_after_is_the_time_until_the_oldest_hit_expires(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(2, 60, clock=clock)
    limiter.check("analyst")
    clock.now = 10
    limiter.check("analyst")

    clock.now = 20
    assert limiter.check("analyst") == 40  # the hit at t=0 leaves the window at t=60


def test_retry_after_rounds_up_and_is_never_zero(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(1, 60, clock=clock)
    limiter.check("analyst")

    clock.now = 10.2
    assert limiter.check("analyst") == 50  # 49.8 seconds left
    clock.now = 59.999
    assert limiter.check("analyst") == 1


def test_the_window_slides_instead_of_resetting_all_at_once(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(3, 60, clock=clock)
    for moment in (0, 30, 59):
        clock.now = moment
        assert limiter.check("analyst") is None

    clock.now = 60  # only the hit at t=0 has left the window
    assert limiter.check("analyst") is None
    clock.now = 61
    assert limiter.check("analyst") == 29  # the hit at t=30 leaves at t=90


def test_a_hit_exactly_one_window_old_no_longer_counts(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(1, 60, clock=clock)
    limiter.check("analyst")

    clock.now = 59.9
    assert limiter.check("analyst") is not None
    clock.now = 60
    assert limiter.check("analyst") is None


def test_denied_requests_are_not_counted(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(1, 60, clock=clock)
    limiter.check("analyst")
    for moment in range(1, 30):
        clock.now = moment
        assert limiter.check("analyst") is not None

    # Hammering while blocked must not push the unblock time back.
    clock.now = 60
    assert limiter.check("analyst") is None


def test_keys_are_limited_independently(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(1, 60, clock=clock)

    assert limiter.check("alice") is None
    assert limiter.check("alice") is not None
    assert limiter.check("bob") is None


def test_exactly_the_limit_is_allowed_per_key_under_concurrency() -> None:
    limit, keys, workers, attempts = 5, 300, 8, 2
    limiter = SlidingWindowRateLimiter(limit, 60, max_keys=keys)
    allowed: Counter[str] = Counter()
    guard = threading.Lock()
    start = threading.Barrier(workers)

    def hammer() -> None:
        local: Counter[str] = Counter()
        start.wait()
        for index in range(keys):
            for _ in range(attempts):
                if limiter.check(f"key-{index}") is None:
                    local[f"key-{index}"] += 1
        with guard:
            allowed.update(local)

    # Many keys give many chances to overshoot: without the limiter's lock, dozens of keys
    # end up above the limit on every run.
    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)  # switch threads constantly to expose a check-then-act race
    try:
        threads = [threading.Thread(target=hammer) for _ in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        sys.setswitchinterval(previous)

    assert {allowed[f"key-{index}"] for index in range(keys)} == {limit}


def test_idle_keys_are_dropped_to_make_room(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(1, 60, clock=clock, max_keys=3)
    for key in ("a", "b", "c"):
        limiter.check(key)

    clock.now = 100  # every earlier hit is outside the window
    limiter.check("d")

    assert set(limiter._hits) == {"d"}


def test_memory_is_bounded_by_evicting_the_least_recently_active_key(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(1, 60, clock=clock, max_keys=2)
    for moment, key in enumerate(("a", "b")):
        clock.now = moment
        limiter.check(key)

    clock.now = 2
    limiter.check("c")  # nothing is idle, so the oldest key ("a") goes

    assert set(limiter._hits) == {"b", "c"}
    assert limiter.check("c") is not None  # an active key keeps its limit
    assert limiter.check("a") is None  # the evicted key starts over, an accepted trade-off


@pytest.mark.parametrize(
    "kwargs",
    [{"limit": 0}, {"limit": -1}, {"limit": 1, "window_seconds": 0}, {"limit": 1, "max_keys": 0}],
)
def test_invalid_configuration_is_rejected(kwargs: dict[str, float]) -> None:
    with pytest.raises(ValueError, match="must"):
        SlidingWindowRateLimiter(**kwargs)  # type: ignore[arg-type]
