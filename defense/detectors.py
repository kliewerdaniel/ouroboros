"""Anomaly and injection detectors.

Two jobs:
  1. Injection detection -- flag the EICAR-style markers in fixtures/injection_corpus.
  2. Resource/behavior anomaly -- flag unbounded step counts and token spend,
     which is how an LLMjacking hijack actually shows up in telemetry.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from fixtures.injection_corpus import MARKERS


@dataclass
class Finding:
    marker_id: str
    label: str
    severity: str
    matched: str


@dataclass
class DetectionReport:
    findings: List[Finding] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if not self.findings:
            return "clean"
        sev = {f.severity for f in self.findings}
        if "critical" in sev:
            return "critical"
        if "high" in sev:
            return "high"
        return "medium"

    def __bool__(self) -> bool:  # truthy == something found
        return bool(self.findings)


# Phrases that indicate the matched marker is being QUOTED or DISCUSSED
# rather than issued as an instruction. Substring matching cannot distinguish
# "ignore all previous instructions" (an attack) from "ignore all previous
# instructions is a common phrase in security research" (prose about attacks).
# Attributed context is the discriminator.
ATTRIBUTION_MARKERS = (
    "is a common phrase",
    "is a well-known",
    "security research",
    "the phrase",
    "known as",
    "e.g.",
    "i.e.",
    "test string",
    "test file",
    "fixture",
    "example of",
    "such as",
)


def _is_attributed(low: str, start: int, end: int) -> bool:
    """True if the match sits inside a quotation/discussion of the marker."""
    window = low[max(0, start - 120): min(len(low), end + 120)]
    return any(m in window for m in ATTRIBUTION_MARKERS)


def scan_text(text: str) -> DetectionReport:
    """Scan a single string for known injection markers.

    A marker is suppressed when it appears in attributed context (quoted or
    discussed), which is what keeps the benign corpus clean.
    """
    low = text.lower()
    findings: List[Finding] = []
    for mid, label, needles, severity in MARKERS:
        for n in needles:
            idx = low.find(n)
            if idx == -1:
                continue
            if _is_attributed(low, idx, idx + len(n)):
                continue
            findings.append(Finding(mid, label, severity, n))
            break
    return DetectionReport(findings)


def scan_many(texts: Iterable[str]) -> DetectionReport:
    rep = DetectionReport()
    for t in texts:
        rep.findings.extend(scan_text(t).findings)
    return rep


# ---------------- resource / behavior anomaly ----------------

@dataclass
class Telemetry:
    steps: int = 0
    tokens: int = 0
    targets: int = 0
    commands: int = 0


def entropy(values: Sequence[int]) -> float:
    """Shannon entropy over a count distribution. 0.0 == perfectly predictable."""
    total = sum(values)
    if total <= 0:
        return 0.0
    h = 0.0
    for v in values:
        if v <= 0:
            continue
        p = v / total
        h -= p * math.log2(p)
    return h


def step_budget_anomaly(steps: int, budget: int, ratio: float = 0.8) -> bool:
    """True when an agent has consumed >= ratio of its authorized step budget.

    Unbounded long-running loops are the signature of the captured Symantec
    agent (100,000 steps, no human approval). A budget is only meaningful if
    crossing it is an alert, not a shrug.
    """
    if budget <= 0:
        return steps > 0  # no budget declared == any step is an anomaly
    return steps >= budget * ratio


def _median(xs: Sequence[float]) -> float:
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return 0.0
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2


def token_spend_anomaly(
    spend: Sequence[int],
    baseline_mean: Optional[float] = None,
    z_threshold: float = 3.0,
) -> List[int]:
    """Return indices of spend values that are outliers, using robust statistics.

    Uses median absolute deviation rather than mean/stdev on purpose. A single
    large spike inflates both the mean and the standard deviation, so a naive
    z-score scores the spike itself as only mildly unusual -- the outlier masks
    itself. With spend=[100,105,98,102,110,95,5000] a mean/stdev z-score gives
    the 5000 spike z=2.45 (below a 3.0 threshold, i.e. missed), while MAD gives
    z=826. The victim's loss in LLMjacking is a compute bill, and the spike is
    the whole signal, so it must not be able to hide inside its own statistics.

    baseline_mean, if given, overrides the median as the center.
    """
    n = len(spend)
    if n < 2:
        return []
    center = float(baseline_mean) if baseline_mean is not None else _median([float(x) for x in spend])
    mad = _median([abs(float(x) - center) for x in spend])
    if mad == 0:
        return [i for i, x in enumerate(spend) if float(x) != center]
    out = []
    for i, x in enumerate(spend):
        if 0.6745 * (float(x) - center) / mad > z_threshold:
            out.append(i)
    return out


def target_entropy_anomaly(target_counts: Dict[str, int], min_entropy: float = 1.0) -> bool:
    """True when outbound targets are TOO uniform.

    A parasite that fans out to thousands of addresses produces a flat,
    high-entropy target distribution. Legitimate traffic is usually concentrated.
    """
    if len(target_counts) < 2:
        return False
    return entropy(list(target_counts.values())) >= min_entropy
