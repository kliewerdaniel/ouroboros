"""Metrics: Prometheus exposition with a stdlib-only fallback.

Source of truth is always the in-memory dicts, so /metrics works with zero
dependencies. When prometheus_client is installed the same increments are
mirrored into its objects, so a Prometheus scrape and this renderer agree.

Counters, gauges and observations are namespaced `ouroboros_` and carry labels
that stay low-cardinality (action, reason, marker id, severity) -- never payloads.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, Optional, Tuple

try:  # optional dependency
    from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram
    _PROM = True
except ImportError:  # pragma: no cover - exercised when dep absent
    _PROM = False

PROM_AVAILABLE = _PROM


def _lbl(pairs: Optional[Dict[str, str]]) -> str:
    if not pairs:
        return ""
    return "{" + ",".join(f'{k}="{v}"' for k, v in sorted(pairs.items())) + "}"


class Metrics:
    def __init__(self, namespace: str = "ouroboros") -> None:
        self.ns = namespace
        self.counters: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], int] = defaultdict(int)
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, list] = defaultdict(list)
        self._prom: Dict[tuple, object] = {}
        # Per-instance registry: two Metrics objects in one process must not
        # collide in the global registry.
        self._registry = CollectorRegistry() if _PROM else None

    # -- recording ----------------------------------------------------------
    def inc_allowed(self, action: str) -> None:
        self._inc("actions_allowed_total", {"action": action})

    def inc_denied(self, action: str, reason: str) -> None:
        self._inc("actions_denied_total", {"action": action, "reason": reason})

    def inc(self, name: str, labels: Optional[Dict[str, str]] = None) -> None:
        self._inc(name, labels or {})

    def observe_finding(self, marker: str, severity: str) -> None:
        self._inc("detection_findings_total", {"marker": marker, "severity": severity})

    def set_gauge(self, name: str, value: float) -> None:
        key = f"{self.ns}_{name}"
        self.gauges[key] = float(value)
        if _PROM:
            k = ("gauge", key)
            if k not in self._prom:                      # check-then-create:
                self._prom[k] = Gauge(key, f"{name} gauge", registry=self._registry)
            self._prom[k].set(value)                     # setdefault() would
                                                         # build eagerly and
                                                         # double-register

    def observe(self, name: str, value: float) -> None:
        key = f"{self.ns}_{name}"
        self.histograms[key].append(float(value))
        if _PROM:
            k = ("hist", key)
            if k not in self._prom:
                self._prom[k] = Histogram(key, f"{name} histogram", registry=self._registry)
            self._prom[k].observe(value)

    def _inc(self, name: str, labels: Dict[str, str]) -> None:
        lkey = tuple(sorted(labels.items()))
        self.counters[(name, lkey)] += 1
        if _PROM:
            key = f"{self.ns}_{name}"
            # Create the collector ONCE per metric name. Keying by label values
            # would build a second Counter with the same name for every new
            # action=, which prometheus_client rejects as a duplicate series.
            if name not in self._prom:
                self._prom[name] = Counter(key, f"{name} counter",
                                           list(labels.keys()), registry=self._registry)
            self._prom[name].labels(**dict(lkey)).inc()

    # -- exposition ---------------------------------------------------------
    def render(self) -> str:
        """Prometheus text exposition, built from the local source of truth."""
        out = []
        # HELP/TYPE once per metric family; one line per labelled series.
        # Emitting TYPE per series is invalid Prometheus text format.
        for name in sorted({n for (n, _) in self.counters}):
            key = f"{self.ns}_{name}"
            out.append(f"# HELP {key} {name}")
            out.append(f"# TYPE {key} counter")
            for (n, lkey), val in sorted(self.counters.items()):
                if n == name:
                    out.append(f"{key}{_lbl(dict(lkey))} {val}")
        for key, val in sorted(self.gauges.items()):
            out.append(f"# HELP {key} gauge")
            out.append(f"# TYPE {key} gauge")
            out.append(f"{key} {val}")
        for key, vals in sorted(self.histograms.items()):
            out.append(f"# HELP {key} histogram")
            out.append(f"# TYPE {key} histogram")
            out.append(f"{key}_count {len(vals)}")
            out.append(f"{key}_sum {sum(vals)}")
        return "\n".join(out) + "\n"

    def snapshot(self) -> Dict[str, int]:
        return {f"{name}{_lbl(dict(lkey))}": v for (name, lkey), v in self.counters.items()}
