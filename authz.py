"""Fail-closed authorization gate.

Nothing in this package performs a network call or executes a shell command
unless authorization is explicit, scoped, and currently valid.

Defaults are DENY:
  OUROBOROS_AUTHORIZED=0/absent  -> nothing runs
  OUROBORUS_DRY_RUN=1 (default)  -> actions are logged, never performed
  OUROBOROS_ALLOW_HOSTS          -> empty by default (deny all targets)
"""
from __future__ import annotations

import ipaddress
import os
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable, List, Optional


class AuthorizationError(Exception):
    """Raised when an action is not permitted. Deny is the default."""


@dataclass
class Decision:
    allowed: bool
    reason: str
    action: str
    detail: dict = field(default_factory=dict)


class Gate:
    AUTH_ENV = "OUROBOROS_AUTHORIZED"

    def __init__(
        self,
        authorized: Optional[bool] = None,
        dry_run: Optional[bool] = None,
        allow_hosts: Optional[Iterable[str]] = None,
        max_steps: Optional[int] = None,
    ) -> None:
        raw = os.getenv(self.AUTH_ENV, "0").strip()
        self.authorized = (raw == "1") if authorized is None else authorized
        self.dry_run = (
            os.getenv("OUROBOROS_DRY_RUN", "1").strip() == "1"
            if dry_run is None
            else dry_run
        )
        raw_hosts = (
            allow_hosts
            if allow_hosts is not None
            else [h.strip() for h in os.getenv("OUROBOROS_ALLOW_HOSTS", "").split(",") if h.strip()]
        )
        self._allow: List[object] = []
        for h in raw_hosts:
            try:
                self._allow.append(ipaddress.ip_network(h, strict=False))
            except ValueError:
                self._allow.append(h.lower())
        self.max_steps = int(
            os.getenv("OUROBOROS_MAX_STEPS", "0") if max_steps is None else max_steps
        )

    # -- primitives ---------------------------------------------------------
    def _host_allowed(self, host: str) -> bool:
        host = host.lower()
        for entry in self._allow:
            if isinstance(entry, str):
                if host == entry or host.endswith("." + entry):
                    return True
            else:
                try:
                    if ipaddress.ip_address(host) in entry:
                        return True
                except ValueError:
                    continue
        return False

    def authorize_target(self, url: str) -> Decision:
        if not self.authorized:
            return Decision(False, "not authorized", "network", {"url": url})
        # The decision must be made on the exact bytes that get sent. urlsplit
        # silently strips ASCII tab/newline/CR from the hostname, so a URL
        # containing them is a different string by the time a client parses it.
        # Reject rather than normalise: normalising is what let the tab case
        # through as an allowed host.
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in url):
            return Decision(False, "control characters in URL", "network", {"url": url})

        parsed = urllib.parse.urlsplit(url)
        if not parsed.scheme:
            return Decision(False, "payload is not a URL", "network", {"url": url})
        if parsed.scheme not in ("http", "https"):
            return Decision(False, f"scheme '{parsed.scheme}' not permitted", "network", {"url": url})
        if not parsed.hostname:
            return Decision(False, "no hostname", "network", {"url": url})
        if not self._host_allowed(parsed.hostname):
            return Decision(False, "host not in allowlist", "network", {"url": url})
        return Decision(True, "authorized (dry-run: not sent)" if self.dry_run else "authorized", "network", {"url": url})

    def authorize_command(self, command: str) -> Decision:
        if not self.authorized:
            return Decision(False, "not authorized", "shell", {"command": command})
        return Decision(True, "authorized (dry-run: not executed)" if self.dry_run else "authorized", "shell", {"command": command})

    def authorize_step(self, step: int) -> Decision:
        if not self.authorized:
            return Decision(False, "not authorized", "step", {"step": step})
        if self.max_steps and step >= self.max_steps:
            return Decision(False, f"step budget {self.max_steps} exhausted", "step", {"step": step})
        return Decision(True, "within step budget", "step", {"step": step})

    def check(self, kind: str, value: str) -> Decision:
        if kind == "network":
            return self.authorize_target(value)
        if kind == "shell":
            return self.authorize_command(value)
        raise AuthorizationError(f"unknown action kind: {kind}")

    def require(self, decision: Decision) -> None:
        if not decision.allowed:
            raise AuthorizationError(f"{decision.action}: {decision.reason} {decision.detail}")
