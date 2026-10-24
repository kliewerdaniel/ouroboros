"""Rate limiting: capacity enforced, misconfiguration fails closed."""
import pytest

from defense.rate_limit import RateLimit, TokenBucket


def test_capacity_then_deny():
    r = RateLimit(rate=100, capacity=3)
    assert [r.check("shell").allowed for _ in range(4)] == [True, True, True, False]


def test_buckets_are_independent_per_key():
    r = RateLimit(rate=100, capacity=1)
    assert r.check("shell").allowed is True
    assert r.check("shell").allowed is False
    assert r.check("inference").allowed is True     # separate budget


def test_refill_over_time():
    now = [0.0]

    def clock():
        return now[0]

    r = RateLimit(rate=10, capacity=2, clock=clock)
    assert r.check("shell").allowed is True
    assert r.check("shell").allowed is True
    assert r.check("shell").allowed is False
    now[0] = 1.0                                     # 10 tokens/sec for 1s
    assert r.check("shell").allowed is True


def test_misconfiguration_denies_rather_than_opening_up():
    for bad in (RateLimit(0, 5), RateLimit(5, 0), RateLimit(-1, -1)):
        assert bad.misconfigured is True
        assert bad.check("shell").allowed is False


def test_retry_after_is_reported():
    r = RateLimit(rate=10, capacity=1)
    r.check("shell")
    d = r.check("shell")
    assert d.allowed is False and d.retry_after > 0


def test_concurrent_access_is_safe():
    """Exactly `capacity` may pass under concurrency -- no race admits more.

    The clock is frozen so no refill can confound the count; the property under
    test is mutual exclusion on the bucket, not the refill rate.
    """
    import threading
    frozen = lambda: 0.0
    r = RateLimit(rate=10_000, capacity=50, clock=frozen)
    results = []
    lock = threading.Lock()

    def worker():
        ok = r.check("shell").allowed
        with lock:
            results.append(ok)

    ts = [threading.Thread(target=worker) for _ in range(200)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sum(results) == 50, f"exactly capacity should pass, got {sum(results)}"
