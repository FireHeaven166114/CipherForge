"""Wrong-password budget: per share and per client network, reserved before the KDF runs."""

import threading

import pytest

from app.files.attempts import (
    AttemptLimitExceeded,
    PasswordAttemptLimiter,
    client_bucket,
)
from tests.files_helpers import Ticker

WINDOW = 900.0


def make_limiter(limit: int = 3, **kwargs: object) -> tuple[PasswordAttemptLimiter, Ticker]:
    ticks = Ticker()
    return PasswordAttemptLimiter(limit, WINDOW, clock=ticks, **kwargs), ticks  # type: ignore[arg-type]


def spend(limiter: PasswordAttemptLimiter, share: str, client: str, times: int) -> None:
    for _ in range(times):
        limiter.reserve(share, client)


def test_attempts_up_to_the_limit_are_allowed_then_the_share_is_locked() -> None:
    limiter, _ = make_limiter(3)

    spend(limiter, "share-1", "198.51.100.1", 3)

    with pytest.raises(AttemptLimitExceeded) as locked:
        limiter.reserve("share-1", "198.51.100.1")
    assert locked.value.retry_after == 900


def test_the_lock_is_shared_by_every_client_of_the_same_share() -> None:
    limiter, _ = make_limiter(3)
    for index in range(3):
        limiter.reserve("share-1", f"198.51.100.{index}")

    with pytest.raises(AttemptLimitExceeded):
        limiter.reserve("share-1", "198.51.100.200")


def test_the_lock_is_shared_by_every_share_of_the_same_client() -> None:
    limiter, _ = make_limiter(3)
    for index in range(3):
        limiter.reserve(f"share-{index}", "198.51.100.1")

    with pytest.raises(AttemptLimitExceeded):
        limiter.reserve("share-other", "198.51.100.1")


def test_other_shares_and_other_clients_are_not_affected() -> None:
    limiter, _ = make_limiter(3)
    spend(limiter, "share-1", "198.51.100.1", 3)

    limiter.reserve("share-2", "198.51.100.2")


def test_a_refused_attempt_is_not_counted() -> None:
    limiter, ticks = make_limiter(2)
    spend(limiter, "share-1", "198.51.100.1", 2)
    for _ in range(10):
        with pytest.raises(AttemptLimitExceeded):
            limiter.reserve("share-1", "198.51.100.1")

    # Ten refusals did not push the end of the lock further out.
    ticks.advance(WINDOW)
    limiter.reserve("share-1", "198.51.100.1")


def test_retry_after_counts_down_to_the_oldest_failure_leaving_the_window() -> None:
    limiter, ticks = make_limiter(2)
    limiter.reserve("share-1", "198.51.100.1")
    ticks.advance(100)
    limiter.reserve("share-1", "198.51.100.1")
    ticks.advance(50)

    with pytest.raises(AttemptLimitExceeded) as locked:
        limiter.reserve("share-1", "198.51.100.1")

    assert locked.value.retry_after == 750
    ticks.advance(750 - 1)
    with pytest.raises(AttemptLimitExceeded) as almost:
        limiter.reserve("share-1", "198.51.100.1")
    assert almost.value.retry_after == 1
    ticks.advance(1)
    limiter.reserve("share-1", "198.51.100.1")


def test_retry_after_is_the_longer_of_the_two_locks() -> None:
    # The share's lock outlasts the client's: share-A is locked by hits at t=100 and t=200,
    # client c1 by hits at t=0 and t=300; asked at t=400 they have 600 s and 500 s left.
    limiter, ticks = make_limiter(2)
    for pause, share, client in [
        (0, "x", "c1"),
        (100, "A", "c2"),
        (100, "A", "c3"),
        (100, "y", "c1"),
    ]:
        ticks.advance(pause)
        limiter.reserve(f"share-{share}", client)
    ticks.advance(100)
    with pytest.raises(AttemptLimitExceeded) as share_longer:
        limiter.reserve("share-A", "c1")
    assert share_longer.value.retry_after == 600

    # And the other way round: the client's lock outlasts the share's (700 s against 500 s).
    limiter, ticks = make_limiter(2)
    for pause, share, client in [
        (0, "A", "c2"),
        (100, "A", "c3"),
        (100, "x", "c1"),
        (100, "y", "c1"),
    ]:
        ticks.advance(pause)
        limiter.reserve(f"share-{share}", client)
    ticks.advance(100)
    with pytest.raises(AttemptLimitExceeded) as client_longer:
        limiter.reserve("share-A", "c1")
    assert client_longer.value.retry_after == 700


def test_a_lock_expires_when_the_window_has_passed() -> None:
    limiter, ticks = make_limiter(3)
    spend(limiter, "share-1", "198.51.100.1", 3)
    ticks.advance(WINDOW - 1)
    with pytest.raises(AttemptLimitExceeded):
        limiter.reserve("share-1", "198.51.100.1")

    ticks.advance(1)

    spend(limiter, "share-1", "198.51.100.1", 3)
    with pytest.raises(AttemptLimitExceeded):
        limiter.reserve("share-1", "198.51.100.1")


def test_a_released_attempt_is_handed_back() -> None:
    limiter, _ = make_limiter(2)
    first = limiter.reserve("share-1", "198.51.100.1")
    limiter.reserve("share-1", "198.51.100.1")

    limiter.release(first)

    limiter.reserve("share-1", "198.51.100.1")
    with pytest.raises(AttemptLimitExceeded):
        limiter.reserve("share-1", "198.51.100.1")


def test_releasing_twice_or_after_the_window_does_not_underflow() -> None:
    limiter, ticks = make_limiter(2)
    reservation = limiter.reserve("share-1", "198.51.100.1")
    limiter.release(reservation)
    limiter.release(reservation)
    other = limiter.reserve("share-1", "198.51.100.1")
    ticks.advance(WINDOW + 1)

    limiter.release(other)

    spend(limiter, "share-1", "198.51.100.1", 2)
    with pytest.raises(AttemptLimitExceeded):
        limiter.reserve("share-1", "198.51.100.1")


def test_releasing_one_reservation_keeps_the_others_counted() -> None:
    limiter, _ = make_limiter(3)
    reservations = [limiter.reserve("share-1", "198.51.100.1") for _ in range(3)]

    limiter.release(reservations[0])

    limiter.reserve("share-1", "198.51.100.1")
    with pytest.raises(AttemptLimitExceeded):
        limiter.reserve("share-1", "198.51.100.1")


def test_parallel_guesses_can_never_exceed_the_budget() -> None:
    limiter = PasswordAttemptLimiter(5, WINDOW)
    barrier = threading.Barrier(50)
    granted: list[int] = []
    refused: list[int] = []

    def guess() -> None:
        barrier.wait()
        try:
            limiter.reserve("share-1", "198.51.100.1")
        except AttemptLimitExceeded:
            refused.append(1)
        else:
            granted.append(1)

    threads = [threading.Thread(target=guess) for _ in range(50)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert (len(granted), len(refused)) == (5, 45)


def test_memory_is_bounded_and_the_active_reservation_survives_eviction() -> None:
    limiter, ticks = make_limiter(2, max_keys=6)
    for index in range(20):
        ticks.advance(1)
        limiter.reserve(f"share-{index}", f"client-{index}")

    assert len(limiter._hits) <= 6

    # The newest keys were kept, so the current attempts still count.
    ticks.advance(1)
    limiter.reserve("share-19", "client-19")
    with pytest.raises(AttemptLimitExceeded):
        limiter.reserve("share-19", "client-19")


def test_idle_keys_are_dropped_before_active_ones() -> None:
    limiter, ticks = make_limiter(2, max_keys=4)
    limiter.reserve("old", "old-client")
    ticks.advance(WINDOW + 1)
    spend(limiter, "busy", "busy-client", 2)

    limiter.reserve("new", "new-client")

    assert "share:busy" in limiter._hits
    assert "client:busy-client" in limiter._hits
    assert "share:old" not in limiter._hits


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"limit": 0}, "limit"),
        ({"limit": -1}, "limit"),
        ({"limit": 1, "window_seconds": 0}, "window"),
        ({"limit": 1, "window_seconds": -5}, "window"),
        ({"limit": 1, "max_keys": 1}, "max_keys"),
    ],
)
def test_nonsensical_configuration_is_refused(kwargs: dict[str, float], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        PasswordAttemptLimiter(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("address", "bucket"),
    [
        ("203.0.113.7", "203.0.113.7"),
        ("2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"),
        ("2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"),
        ("2001:db8:1:3::1", "2001:db8:1:3::/64"),
        ("::ffff:203.0.113.7", "203.0.113.7"),
        ("::1", "::/64"),
        (None, "unknown"),
        ("", "unknown"),
        ("not-an-address", "unknown"),
        ("testclient", "unknown"),
        ("203.0.113.7:8080", "unknown"),
    ],
)
def test_clients_are_bucketed_by_network(address: str | None, bucket: str) -> None:
    assert client_bucket(address) == bucket


def test_every_address_of_one_ipv6_subscriber_shares_a_budget() -> None:
    limiter, _ = make_limiter(2)
    limiter.reserve("share-1", client_bucket("2001:db8:1:2::1"))
    limiter.reserve("share-2", client_bucket("2001:db8:1:2:aaaa::2"))

    with pytest.raises(AttemptLimitExceeded):
        limiter.reserve("share-3", client_bucket("2001:db8:1:2:bbbb::3"))
