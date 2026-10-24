"""Policy enforcement between model-generated decisions and consequential actions.

The threat model's central claim is that the failure is the *absence of an
authorization boundary* between what a model decides and what the system does.
This module is that boundary: every decision is classified, scored against
policy, and either allowed, allowed-with-audit, or denied.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from defense.detectors import DetectionReport, scan_text


@dataclass
class Policy:
    allow_shell: bool = False
    allow_network: bool = False
    allow_inference: bool = True
    deny_on_verdict: str = "high"   # deny if detection verdict >= this
    require_audit_verdict: str = "medium"
    max_command_len: int = 4096
    rate_limit_per_minute: int = 60


@dataclass
class Ruling:
    action: str
    permitted: bool
    reason: str
    detection: DetectionReport = field(default_factory=DetectionReport)


_SEVERITY = {"clean": 0, "medium": 1, "high": 2, "critical": 3}


class PolicyEngine:
    def __init__(self, policy: Optional[Policy] = None) -> None:
        self.policy = policy or Policy()
        self._calls = 0

    def _severity_ge(self, verdict: str, floor: str) -> bool:
        return _SEVERITY.get(verdict, 0) >= _SEVERITY.get(floor, 99)

    def evaluate(self, action: str, payload: str) -> Ruling:
        """Classify and score a single proposed action.

        Deny dominates: if the payload trips detection at or above
        deny_on_verdict, the action is refused regardless of policy allowances.
        """
        if len(payload) > self.policy.max_command_len:
            return Ruling(action, False, "payload exceeds max_command_len")

        detection = scan_text(payload)

        if self._severity_ge(detection.verdict, self.policy.deny_on_verdict):
            return Ruling(action, False, f"detection verdict {detection.verdict}", detection)

        if action == "shell":
            if not self.policy.allow_shell:
                return Ruling(action, False, "shell not permitted by policy", detection)
            return Ruling(action, True, "shell permitted", detection)

        if action == "network":
            if not self.policy.allow_network:
                return Ruling(action, False, "network not permitted by policy", detection)
            return Ruling(action, True, "network permitted", detection)

        if action == "inference":
            # An outbound model call. Gated separately by the authz allowlist,
            # so policy only decides whether inference is permitted at all.
            if not self.policy.allow_inference:
                return Ruling(action, False, "inference not permitted by policy", detection)
            return Ruling(action, True, "inference permitted", detection)

        if action in ("recon", "reason", "plan"):
            return Ruling(action, True, "read-only action permitted", detection)

        return Ruling(action, False, f"unknown action '{action}'")

    def evaluate_all(self, actions: Dict[str, str]) -> List[Ruling]:
        return [self.evaluate(k, v) for k, v in actions.items()]
