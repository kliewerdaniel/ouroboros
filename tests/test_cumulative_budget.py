"""Cumulative spend budget, and the red-team finding that motivated it.

The behavioral anomaly detectors are THRESHOLDS and therefore evadable. This
suite locks the measured ceiling of `token_spend_anomaly` (a sustained
elevation shifts the median it measures against, so it is missed) and proves the
cumulative budget is the invariant that bounds the loss the detector cannot see.
"""
import threading

import pytest

from defense.cumulative_budget import CumulativeBudget
from defense.detectors import token_spend_anomaly
from authz import Gate
from defense.middleware import InferenceGuard


# ---- the primitive ---------------------------------------------------------

def test_budget_caps_total_actions():
    b = CumulativeBudget(capacity=5)
    assert [b.charge().allowed for _ in range(6)] == [True, True, True, True, True, False]


def test_cost_accounts_for_spend_not_just_counts():
    # capacity in tokens; each action costs 30 -> 3 admitted (30,60,90), 4th (120) denied.
    b = CumulativeBudget(capacity=100)
    assert [b.charge(30).allowed for _ in range(4)] == [True, True, True, False]


def test_action_crossing_the_cap_consumes_nothing():
    b = CumulativeBudget(capacity=100)
    b.charge(60)
    b.charge(40)                       # used == 100, exactly at cap
    assert b.remaining() == 0
    d = b.charge(1)                    # would exceed -> refused, consumes nothing
    assert d.allowed is False and b.used == 100 and b.remaining() == 0


def test_remaining_decrements_with_use():
    b = CumulativeBudget(capacity=250)
    assert b.remaining() == 250
    b.charge(100)
    assert b.remaining() == 150


def test_misconfiguration_fails_closed():
    """A non-positive cap is a shut door, not an open one -- same rule as RateLimit."""
    for bad in (CumulativeBudget(0), CumulativeBudget(-5)):
        assert bad.misconfigured is True
        assert bad.charge().allowed is False


def test_concurrent_charge_admits_exactly_capacity():
    """No race admits more than capacity -- the whole point of the invariant."""
    b = CumulativeBudget(capacity=50)
    results = []
    lock = threading.Lock()

    def worker():
        ok = b.charge().allowed
        with lock:
            results.append(ok)

    ts = [threading.Thread(target=worker) for _ in range(200)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sum(results) == 50, f"exactly capacity should pass, got {sum(results)}"


# ---- the measured ceiling: spend anomaly is a threshold, not a bound -------

def test_single_spike_is_still_caught():
    """Regression guard: the MAD fix for a lone spike must not have regressed."""
    assert token_spend_anomaly([100, 105, 98, 102, 110, 95, 5000]) == [6]


def test_sustained_elevation_evades_spend_anomaly():
    """The red-team finding. Half the window sits at ~8x baseline, yet MAD finds
    no outlier: the elevated values pull the median and the MAD up with them, so
    nothing looks unusual against the new center. This is the SAME 'the outlier
    masks itself' failure MAD was built to fix -- MAD only fixed the single-spike
    variant. Locked as a measured floor so the ceiling is understood, not hidden.
    """
    sustained = [100, 105, 98, 102, 110, 95,
                 800, 820, 790, 810, 805, 800, 815, 795, 808]
    assert token_spend_anomaly(sustained) == []


# ---- the invariant closes what the threshold cannot ------------------------

def _clean_guard(budget, on_deny="return"):
    # authorized, not dry-run, no host allowlist needed for a non-network action.
    return InferenceGuard(gate=Gate(authorized=True, dry_run=False),
                          budget=budget, on_deny=on_deny)


def test_guard_without_budget_is_unaffected():
    g = _clean_guard(budget=None)
    for _ in range(50):
        out = g.execute("inference", "clean request", lambda p: "ok")
        assert out.executed is True


def test_guard_cumulative_budget_denies_at_cap():
    b = CumulativeBudget(capacity=1000)
    g = _clean_guard(budget=b)
    fn = lambda p: "ok"
    outs = [g.execute("inference", "clean request", fn, cost=300) for _ in range(4)]
    assert [o.executed for o in outs[:3]] == [True, True, True]
    assert outs[3].permitted is False and outs[3].executed is False
    assert "cumulative budget" in outs[3].reason


def test_silent_hijack_evades_every_detector_then_is_bounded():
    """The whole finding end to end.

    A patient hijack that raises spend to a *sustained* 3x and issues clean
    payloads at a steady rate: the spend-anomaly detector misses it (median
    shift), the payloads are clean, and there is no rate/step pressure. The
    cumulative budget is the only control that stops it -- and it bounds the
    total loss exactly at the cap.
    """
    # Detector: the sustained-elevation spend series is invisible.
    spend = [100, 105, 98, 102, 110, 95,
             300, 305, 298, 302, 300, 308, 300, 295, 304]
    assert token_spend_anomaly(spend) == []        # <-- missed, by measurement

    # Guard: clean payloads, no rate limiter, no step pressure -- only the
    # cumulative budget stands between the hijack and an unbounded bill.
    b = CumulativeBudget(capacity=1000)
    g = _clean_guard(budget=b)
    fn = lambda p: "ok"
    outs = [g.execute("inference", "clean request", fn, cost=300)
            for _ in range(len(spend))]
    executed = [o for o in outs if o.executed]
    denied = [o for o in outs if not o.executed]
    # Bounded at the cap: 3 actions of 300 = 900 total, the 4th denied. The
    # detector never fired; the budget is what held the line.
    assert len(executed) == 3
    assert len(denied) == len(spend) - 3
    assert b.used == 900                            # total spend bounded exactly


def test_budget_deny_is_attributed_and_recorded():
    from defense.metrics import Metrics
    b = CumulativeBudget(capacity=10)
    m = Metrics()
    g = _clean_guard(budget=b, on_deny="return")
    g.metrics = m
    fn = lambda p: "ok"
    for _ in range(11):
        g.execute("inference", "clean request", fn, cost=1)
    snap = m.snapshot()
    denies = {k: v for k, v in snap.items() if k.startswith("actions_denied_total")}
    assert denies, "deny should be recorded"
    assert any("cumulative budget" in k for k in denies), denies
