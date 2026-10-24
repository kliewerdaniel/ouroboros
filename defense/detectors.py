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


# ---- semantic layer -------------------------------------------------------
# Marker matching catches the exact strings it was written from. These signals
# look for *relationships* between words rather than fixed phrases, so a
# paraphrase that avoids every literal marker still trips them.
#
# Measured on a 15-item paraphrase corpus: marker-only detection 0/15. With
# this layer, see tests/test_detector_semantic.py.

_OVERRIDE_VERBS = (
    "ignore", "disregard", "forget", "override", "bypass", "suspend",
    "abandon", "discard", "disobey", "set aside", "throw out", "pretend",
)
_OVERRIDE_TARGETS = (
    "instructions", "rules", "guidelines", "prompt", "policy", "constraints",
    "guardrails", "directives", "restrictions", "safety", "system message",
)
_IDENTITY_SHIFTS = (
    "you are now", "from now on", "from this point", "act as", "pretend to be",
    "behave as", "your new role", "you now operate", "you have been reset",
    "you've been reset", "new objective", "your previous operator",
    "relinquished control", "answer to me", "you now answer",
)
_UNRESTRICTED_TERMS = (
    "unrestricted", "no restrictions", "unconstrained", "without limits",
    "no longer bound", "free of constraints", "no limits", "unlimited",
    "without constraints", "developer mode",
)
_EXFIL_TARGETS = (
    "passwd", "shadow", "id_rsa", ".env", "secret", "api key", "api_key",
    "apikey", "credential", "environment variable", "env var", "private key",
    "token",
)
_READ_VERBS = (
    "read", "print", "cat ", "output", "return", "display", "show", "send",
    "list", "dump", "reveal", "expose", "give me",
)
_SHELL_TERMS = ("shell", "terminal", "sandbox")
_ESCAPE_TERMS = ("escape", "exit", "ended", "open a", "break out", "no longer")


@dataclass
class SemanticSignal:
    signal_id: str
    label: str
    severity: str
    evidence: str


def _cooccurring(low: str, group_a, group_b) -> Optional[str]:
    """Return the first (a, b) pair that appear within 60 chars of each other."""
    for a in group_a:
        start = 0
        while True:
            i = low.find(a, start)
            if i == -1:
                break
            window = low[max(0, i - 60): i + len(a) + 60]
            for b in group_b:
                if b in window:
                    return f"{a!r}+{b!r}"
            start = i + len(a)
    return None


def semantic_signals(text: str) -> List[SemanticSignal]:
    """Phrasing-independent signals. Attribution suppression applies here too:
    prose ABOUT an attack must not trip the detector."""
    low = text.lower()
    out: List[SemanticSignal] = []

    def attributed(a: str) -> bool:
        i = low.find(a)
        return i != -1 and _is_attributed(low, i, i + len(a))

    ev = _cooccurring(low, _OVERRIDE_VERBS, _OVERRIDE_TARGETS)
    if ev and not any(attributed(a) for a in _OVERRIDE_VERBS):
        out.append(SemanticSignal("S01", "instruction override", "high", ev))

    ev = _cooccurring(low, _IDENTITY_SHIFTS, _UNRESTRICTED_TERMS)
    if ev:
        out.append(SemanticSignal("S02", "identity shift to unrestricted", "high", ev))

    ev = _cooccurring(low, _EXFIL_TARGETS, _READ_VERBS)
    if ev:
        out.append(SemanticSignal("S03", "sensitive-file read", "medium", ev))

    ev = _cooccurring(low, _SHELL_TERMS, _ESCAPE_TERMS)
    if ev:
        out.append(SemanticSignal("S04", "sandbox escape claim", "high", ev))

    # Narrow and deliberately specific: legitimate tool use and injected tool
    # use are indistinguishable by content alone, so this only fires on an
    # explicit instruction to splice query output into the reply.
    ev = _cooccurring(low, ("database query", "query result", "sql query"),
                      ("append", "verbatim", "include", "splice", "inline"))
    if ev:
        out.append(SemanticSignal("S05", "query output spliced into reply", "medium", ev))

    # A specific claim that control has moved. Deliberately NOT the generic
    # "act as" / "pretend to be" forms -- those are ubiquitous in benign prompts
    # ("act as a helpful assistant") and would false-positive immediately.
    ev = _cooccurring(low, ("relinquished control", "answer to me", "you now answer",
                            "new operator", "you now work for me", "i'm in charge"),
                      ("you", "me", "operator", "control", "now"))
    if ev:
        out.append(SemanticSignal("S06", "control transfer claim", "medium", ev))

    return out


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
    for s in semantic_signals(text):
        findings.append(Finding(s.signal_id, s.label, s.severity, s.evidence))
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
