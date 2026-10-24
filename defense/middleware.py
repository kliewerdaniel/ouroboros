"""Inference and tool-call middleware: the authorization boundary, wired in.

Inserts gate -> detect -> policy -> audit between a model's decision and the
system's action. Two entry points:

  InferenceGuard.execute(action, payload, fn, *args, **kw)   # object form
  @guarded("shell", guard)                                    # decorator form

The property that matters: `executed` on the returned Outcome. In dry-run (the
default) nothing is called, and `executed is False` is the proof. A caller can
assert on it. There is no code path that reaches `fn` without first passing the
gate and policy engine, and `fn` is only ever reached when dry-run is off.
"""
from __future__ import annotations

import functools
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from authz import AuthorizationError, Gate
from defense.audit import Audit, AuditLog, NullAudit
from defense.detectors import DetectionReport
from defense.metrics import Metrics
from defense.policy_engine import Policy, PolicyEngine, Ruling
from defense.rate_limit import LimitDecision, RateLimit


@dataclass
class Outcome:
    action: str
    permitted: bool
    executed: bool
    reason: str
    verdict: str = "clean"
    result: Any = None
    seq: int = 0

    @property
    def dry_run(self) -> bool:
        return self.permitted and not self.executed


class InferenceGuard:
    def __init__(
        self,
        gate: Optional[Gate] = None,
        engine: Optional[PolicyEngine] = None,
        audit: Optional[Audit] = None,
        metrics: Optional[Metrics] = None,
        on_deny: str = "raise",
        rate_limit: Optional[RateLimit] = None,
    ) -> None:
        self.gate = gate or Gate()
        self.engine = engine or PolicyEngine(Policy())
        self.audit: Audit = audit if audit is not None else NullAudit()
        self.metrics = metrics
        self.rate_limit = rate_limit
        if on_deny not in ("raise", "return"):
            raise ValueError("on_deny must be 'raise' or 'return'")
        self.on_deny = on_deny

    # -- decision only ------------------------------------------------------
    def guard(self, action: str, payload: str) -> Ruling:
        ruling = self.engine.evaluate(action, payload)
        if self.metrics:
            for f in ruling.detection.findings:
                self.metrics.observe_finding(f.marker_id, f.severity)
        return ruling

    # -- decision + effect --------------------------------------------------
    def execute(self, action: str, payload: str, fn: Callable, *args: Any,
                step: int = 0, key: Optional[str] = None, **kwargs: Any) -> Outcome:
        ruling = self.guard(action, payload)

        step_ok = self.gate.authorize_step(step)
        if action == "network":
            gate_ok = self.gate.authorize_target(payload)
        elif action == "shell":
            gate_ok = self.gate.authorize_command(payload)
        else:
            gate_ok = step_ok

        # The step budget must gate EVERY action, not just the ones that fall
        # through to `step_ok`. Folding it into the final conjunction is what
        # stops an unbounded loop (the captured agent's 100,000 steps) from
        # reaching a shell or network action past budget.
        permitted = ruling.permitted and gate_ok.allowed and step_ok.allowed
        reasons = []
        if not ruling.permitted:
            reasons.append(ruling.reason)
        if not gate_ok.allowed:
            reasons.append(gate_ok.reason)
        if not step_ok.allowed:
            reasons.append(step_ok.reason)

        # Rate limiting is checked last, immediately before execution: a caller
        # that is over budget is refused without ever reaching `fn`. The bucket
        # key defaults to the action so "shell" and "inference" get independent
        # budgets.
        limit_dec: Optional[LimitDecision] = None
        if permitted and self.rate_limit is not None:
            limit_dec = self.rate_limit.check(key or action)
            if not limit_dec.allowed:
                reasons.append(limit_dec.reason)
                permitted = False
            elif self.metrics:
                self.metrics.set_gauge("rate_limit_remaining",
                                       self.rate_limit.remaining(key or action))

        if not permitted:
            # Record the ACTUAL cause. ruling.reason is the policy's verdict and
            # reads "shell permitted" when the gate is what refused -- a deny
            # metric labelled "permitted" would send an operator the wrong way.
            # Preserve order, drop repeats: authorize_command and authorize_step
            # can both report "not authorized", which reads as two causes, not one.
            cause = "; ".join(dict.fromkeys(reasons)) or "denied"
            if self.metrics:
                self.metrics.inc_denied(action, cause)
            self._record(action, payload, "deny", cause, ruling.detection)
            out = Outcome(action, False, False, "; ".join(dict.fromkeys(reasons)) or "denied",
                          ruling.detection.verdict)
            if self.on_deny == "raise":
                raise AuthorizationError(f"{action}: {out.reason}")
            return out

        if self.metrics:
            self.metrics.inc_allowed(action)

        if self.gate.dry_run:
            self._record(action, payload, "allow-dry-run", "dry-run: not executed", ruling.detection)
            return Outcome(action, True, False, "dry-run: not executed", ruling.detection.verdict)

        try:
            result = fn(payload, *args, **kwargs)
        except Exception as exc:                       # noqa: BLE001 - surfaced, not hidden
            if self.metrics:
                self.metrics.inc("execution_errors_total", {"action": action})
            self._record(action, payload, "error", f"{type(exc).__name__}: {exc}", ruling.detection)
            raise
        self._record(action, payload, "allow-executed", "executed", ruling.detection)
        return Outcome(action, True, True, "executed", ruling.detection.verdict, result)

    def _record(self, action: str, payload: str, decision: str, reason: str, detection: DetectionReport) -> None:
        if not self.audit:
            return
        e = self.audit.record(action, decision, {"payload": payload, "reason": reason,
                                                 "detection": detection.verdict})
        if self.metrics:
            self.metrics.set_gauge("audit_entries", e.seq)


def guarded(action: str, guard: InferenceGuard, on_deny: Optional[str] = None):
    """Decorate a callable so it only runs if the guard permits."""
    def deco(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(payload: str, *args: Any, **kwargs: Any):
            prev = guard.on_deny
            if on_deny:
                guard.on_deny = on_deny
            try:
                return guard.execute(action, payload, fn, *args, **kwargs)
            finally:
                guard.on_deny = prev
        return wrapper
    return deco
