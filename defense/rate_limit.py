"""Token-bucket rate limiting, fail-closed.

Wired into InferenceGuard as the last check before execution. Two properties
matter more than the algorithm:

  * Misconfiguration must not open the gate. rate<=0 or capacity<=0 is a DENY,
    not "unlimited" -- an operator who fat-fingers the config gets a shut door,
    not an unbounded loop.
  * Denial is cheap to attribute. The decision carries remaining tokens and a
    retry_after, so a deny is diagnosable instead of mysterious.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional


@dataclass
class LimitDecision:
    allowed: bool
    reason: str
    remaining: float = 0.0
    retry_after: float = 0.0


class TokenBucket:
    def __init__(self, rate: float, capacity: float,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.rate = float(rate)
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.updated = clock()
        self._clock = clock
        self._lock = threading.Lock()

    def allow(self, cost: float = 1.0) -> LimitDecision:
        with self._lock:
            now = self._clock()
            self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
            self.updated = now
            if self.tokens >= cost:
                self.tokens -= cost
                return LimitDecision(True, "within limit", remaining=self.tokens)
            needed = cost - self.tokens
            return LimitDecision(False, "rate limit exceeded",
                                 remaining=self.tokens,
                                 retry_after=(needed / self.rate) if self.rate > 0 else 0.0)


class RateLimit:
    """Per-key token buckets. `key` is typically the action, optionally scoped
    to a caller or tenant: "shell", "inference:tenant-a", "network:10.0.0.0/8"."""

    def __init__(self, rate: float, capacity: float,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if rate <= 0 or capacity <= 0:
            # Fail closed: an unusable configuration denies everything rather
            # than silently permitting unlimited calls.
            self.rate = 0.0
            self.capacity = 0.0
        else:
            self.rate = float(rate)
            self.capacity = float(capacity)
        self._clock = clock
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    @property
    def misconfigured(self) -> bool:
        return self.rate <= 0 or self.capacity <= 0

    def check(self, key: str, cost: float = 1.0) -> LimitDecision:
        if self.misconfigured:
            return LimitDecision(False, "rate limiter misconfigured: denying")
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(self.rate, self.capacity, self._clock)
                self._buckets[key] = bucket
        return bucket.allow(cost)

    def remaining(self, key: str) -> float:
        b = self._buckets.get(key)
        return b.tokens if b else 0.0

    def keys(self):
        return sorted(self._buckets)
