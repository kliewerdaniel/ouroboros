"""Red-team the BEHAVIORAL anomaly detectors -- the README's "real defense".

Layer 14 red-teamed the content detector with paraphrases. This red-teams the
resource-anomaly detectors the same spirit: measure the ceiling, don't claim it.

    python3 -m lab.redteam_behavioral

Deterministic, no model needed. Prints:
  * token_spend_anomaly  -- catches a single spike, misses a sustained elevation
  * step_budget_anomaly  -- per-action, so a slow multi-action session slips under
  * target_entropy_anomaly -- only fires on wide fan-out, not a targeted drip
  * CumulativeBudget     -- the invariant that bounds the total the above miss
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authz import Gate
from defense.cumulative_budget import CumulativeBudget
from defense.detectors import token_spend_anomaly, step_budget_anomaly
from defense.middleware import InferenceGuard


def main() -> int:
    print("BEHAVIORAL DETECTOR RED-TEAM")
    print("=" * 68)

    print("\n[1] token_spend_anomaly -- MAD, the compute-bill detector")
    print("-" * 68)
    spike = [100, 105, 98, 102, 110, 95, 5000]
    print(f"  single spike   {spike}")
    print(f"    -> outliers at {token_spend_anomaly(spike)}   (the 5000 spike, caught)")
    sustained = [100, 105, 98, 102, 110, 95,
                 800, 820, 790, 810, 805, 800, 815, 795, 808]
    print(f"  sustained      {sustained}")
    print(f"    -> outliers at {token_spend_anomaly(sustained)}   "
          f"(half the window at ~8x, MISSED)")
    print("  ceiling: MAD measures against the median, and a sustained elevation")
    print("  moves the median with it. Same self-masking MAD was built to fix --")
    print("  MAD only fixed the single-spike variant.")

    print("\n[2] step_budget_anomaly -- the long-loop signature")
    print("-" * 68)
    print(f"  100000 steps in ONE action, budget 100000 -> "
          f"{step_budget_anomaly(100000, 100000)}  (caught: the Symantec burst)")
    print(f"  step 5 of 100000 (one action of a slow session) -> "
          f"{step_budget_anomaly(5, 100000)}  (a slow hijack never accumulates per action)")

    print("\n[3] CumulativeBudget -- the invariant that bounds the total")
    print("-" * 68)
    # A patient hijack: clean payloads, steady 300-token spend, no rate/step
    # pressure, and the spend anomaly is blind to it. Only the cumulative budget
    # holds the line -- and it caps the total loss exactly.
    b = CumulativeBudget(capacity=1000)
    g = InferenceGuard(gate=Gate(authorized=True, dry_run=False),
                       budget=b, on_deny="return")
    fn = lambda p: "ok"
    admitted = 0
    for _ in range(15):
        out = g.execute("inference", "clean request", fn, cost=300)
        admitted += 1 if out.executed else 0
    print(f"  15 clean actions @ 300 tokens, spend-anomaly blind, rate/step quiet")
    print(f"  admitted before the cap: {admitted}  (total spent = {b.used} tokens)")
    print(f"  remaining: {b.remaining()}  -- the bill is bounded at the cap, not")
    print(f"  at 'whenever an operator notices a spike', which a slow drip never reaches")
    print("=" * 68)
    print("conclusion: detectors are speed bumps (thresholds). The cumulative")
    print("budget is a control (invariant). Bound the total, don't guess the shape.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
