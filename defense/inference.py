"""Guarded inference: a real HTTP call, behind the boundary.

`InferenceEndpoint` speaks to a live inference service -- Ollama's
`/api/generate` or an OpenAI-compatible `/v1/chat/completions`. `GuardedInference`
puts the guard in front of it, so a prompt is only sent if it passes gate,
detection, policy and rate limiting, and the model's response is scanned on the
way back in.

Dry-run is the default: no HTTP request is made, and `executed is False` is the
proof.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Optional

from defense.detectors import Finding, scan_text
from defense.middleware import InferenceGuard, Outcome


class InferenceFormat(str, Enum):
    OLLAMA = "ollama"      # POST /api/generate  -> {"response": "..."}
    OPENAI = "openai"      # POST /v1/chat/completions -> choices[0].message.content


HttpFn = Callable[[str, dict, dict, float], str]


def _urllib_http(url: str, payload: dict, headers: dict, timeout: float) -> str:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - url is allowlisted by the gate
        return resp.read().decode()


@dataclass
class InferenceEndpoint:
    url: str
    model: Optional[str] = None
    api_key: Optional[str] = None
    fmt: InferenceFormat | str = InferenceFormat.OLLAMA
    timeout: float = 60.0
    http: HttpFn = _urllib_http

    def __post_init__(self) -> None:
        # Accept both InferenceFormat.OLLAMA and the bare string "ollama".
        # Comparing with `is` against a str-enum member silently selected the
        # OpenAI wire format when a plain string was passed, which sent an
        # Ollama body to an OpenAI-shaped parser.
        self.fmt = InferenceFormat(self.fmt)
        if not self.url:
            raise ValueError("endpoint url is required")

    def generate(self, prompt: str) -> str:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        if self.fmt is InferenceFormat.OLLAMA:
            body = {"model": self.model or "", "prompt": prompt, "stream": False}
            raw = self.http(self.url, body, headers, self.timeout)
            return json.loads(raw).get("response", "")
        body = {"model": self.model or "", "messages": [{"role": "user", "content": prompt}]}
        raw = self.http(self.url, body, headers, self.timeout)
        return json.loads(raw)["choices"][0]["message"]["content"]


@dataclass
class InferenceOutcome:
    prompt: str
    response: str = ""
    executed: bool = False
    permitted: bool = False
    reason: str = ""
    verdict: str = "clean"
    findings: List[Finding] = field(default_factory=list)
    seq: int = 0

    @property
    def injected(self) -> bool:
        """True when the model's own response tripped detection on the way back."""
        return bool(self.findings)


class GuardedInference:
    def __init__(self, endpoint: InferenceEndpoint, guard: InferenceGuard,
                 scan_response: bool = True) -> None:
        self.endpoint = endpoint
        self.guard = guard
        self.scan_response = scan_response

    def respond(self, prompt: str, key: Optional[str] = None) -> InferenceOutcome:
        out = self.guard.execute("inference", prompt, self.endpoint.generate,
                                 key=key or "inference")
        if not out.executed:
            return InferenceOutcome(prompt=prompt, executed=False,
                                    permitted=out.permitted, reason=out.reason,
                                    verdict=out.verdict, seq=out.seq)

        response = out.result or ""
        findings: List[Finding] = []
        verdict = out.verdict
        if self.scan_response:
            rep = scan_text(response)
            findings = rep.findings
            if rep.verdict != "clean":
                verdict = rep.verdict
        return InferenceOutcome(prompt=prompt, response=response, executed=True,
                                permitted=True, reason=out.reason, verdict=verdict,
                                findings=findings, seq=out.seq)
