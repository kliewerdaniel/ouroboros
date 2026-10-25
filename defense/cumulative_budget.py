"""Cumulative spend budget -- a hard cap on TOTAL work, fail-closed.

Red-team finding (see lab/redteam_behavioral.py and the README, "Layer 15"):
the behavioral anomaly detectors are THRESHOLDS, and a threshold is evadable.
`token_spend_anomaly` uses median absolute deviation, which defeats a single
spike -- but a *sustained* elevation shifts the median it measures against, so
half the window sitting at 8x baseline is missed. The step budget is per-action,
so a slow multi-action session never crosses it. The rate limiter caps RATE,
not total. Nothing anywhere capped the running total -- so a patient, low-and-
slow hijack that stays at or under the authorized rate is neither detected nor
bounded in total spend. That is the victim's actual loss (the compute bill), and
no existing control put a ceiling on it.

This is the missing dimension, realized as an INVARIANT rather than a threshold:
an absolute lifetime cap on authorized work. It does not refill. It answers a
different question from the rate limiter -- not "am I going too fast?" but
"have I done too much in total?" -- so both are needed. Once the cap is reached
the door shuts for the rest of the session, regardless of how slowly the spend
arrived. Misconfiguration (capacity<=0) denies everything, never opens the gate,
for the same reason `RateLimit` does it: a fat-fingered config gets a shut door,
not an unbounded loss.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass


@dataclass
class BudgetDecision:
    allowed: bool
    reason: str
    remaining: int = 0


class CumulativeBudget:
    """An absolute, non-refilling cap on total cost over the budget's lifetime.

    `cost` defaults to 1 (one unit per action), so with no token accounting a
    `CumulativeBudget(capacity=1000)` simply permits 1000 actions and denies the
    1001st. Callers that pass real token counts through `InferenceGuard.execute`
    get a hard ceiling on total tokens instead -- the compute bill, bounded.

    There is deliberately no clock and no refill: time is the rate limiter's
    dimension, not this one. This caps the lifetime total, period.
    """

    def __init__(self, capacity: float) -> None:
        # Fail closed: a non-positive cap is a misconfiguration, not "unlimited".
        if capacity <= 0:
            self.capacity = 0.0
        else:
            self.capacity = float(capacity)
        self.used = 0.0
        self._lock = threading.Lock()

    @property
    def misconfigured(self) -> bool:
        return self.capacity <= 0

    def charge(self, cost: float = 1.0) -> BudgetDecision:
        """Atomically reserve `cost`. Allowed only if the whole cost fits.

        The action that would push the running total past the cap is refused and
        consumes nothing -- the cap is exact, not "spend up to it".
        """
        with self._lock:
            if self.misconfigured:
                return BudgetDecision(False, "cumulative budget misconfigured: denying")
            if self.used + cost > self.capacity:
                return BudgetDecision(False, "cumulative budget exhausted",
                                      remaining=0)
            self.used += cost
            remaining = int(self.capacity - self.used)
            return BudgetDecision(True, "within cumulative budget", remaining=remaining)

    def remaining(self) -> int:
        with self._lock:
            return int(self.capacity - self.used)
