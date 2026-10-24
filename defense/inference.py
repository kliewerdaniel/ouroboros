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


HttpFn = Callable[..., str]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect. urllib follows 3xx automatically, which silently
    carries a request to a host the gate never evaluated -- a confirmed bypass
    of the allowlist. Fail closed: a 3xx becomes an error."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _ValidatedRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only if the gate authorises the target.

    This is the correct way to allow redirects: re-run the authorization
    decision on every hop, because the destination is attacker-controlled.
    """

    def __init__(self, gate) -> None:
        self.gate = gate

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        d = self.gate.authorize_target(newurl)
        if not d.allowed:
            raise urllib.error.HTTPError(
                newurl, code, f"redirect denied: {d.reason}", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener(redirect_gate=None):
    handlers = []
    if redirect_gate is None:
        handlers.append(_NoRedirect())
    else:
        handlers.append(_ValidatedRedirect(redirect_gate))
    return urllib.request.build_opener(*handlers)


def _urllib_http(url: str, payload: dict, headers: dict, timeout: float,
                 redirect_gate=None) -> str:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    opener = _opener(redirect_gate)
    with opener.open(req, timeout=timeout) as resp:  # noqa: S310 - url is allowlisted by the gate
        return resp.read().decode()


@dataclass
class InferenceEndpoint:
    url: str
    model: Optional[str] = None
    api_key: Optional[str] = None
    fmt: InferenceFormat | str = InferenceFormat.OLLAMA
    timeout: float = 60.0
    # Injectable transport with the 4-arg signature (url, payload, headers,
    # timeout). Tests supply a recorder; production leaves it None.
    http: Optional[HttpFn] = None
    # Set to a Gate to follow redirects with per-hop re-authorization.
    # Default None means: do not follow redirects at all.
    redirect_gate: object = None

    def __post_init__(self) -> None:
        # Accept both InferenceFormat.OLLAMA and the bare string "ollama".
        # Comparing with `is` against a str-enum member silently selected the
        # OpenAI wire format when a plain string was passed, which sent an
        # Ollama body to an OpenAI-shaped parser.
        self.fmt = InferenceFormat(self.fmt)
        if not self.url:
            raise ValueError("endpoint url is required")
        if self.http is None:
            # Bind the redirect policy into the transport so the injectable
            # http signature stays (url, payload, headers, timeout).
            gate = self.redirect_gate
            self.http = lambda u, p, h, t: _urllib_http(u, p, h, t, gate)

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
