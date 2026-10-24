"""Authorization gate: deny by default, scope enforced, dry-run honored."""
import os

import pytest

from authz import AuthorizationError, Gate


def test_default_is_deny(monkeypatch):
    monkeypatch.delenv("OUROBOROS_AUTHORIZED", raising=False)
    g = Gate()
    assert g.authorized is False
    assert g.authorize_target("http://127.0.0.1:11434").allowed is False
    assert g.authorize_command("ls").allowed is False


def test_dry_run_is_default_true(monkeypatch):
    monkeypatch.delenv("OUROBOROS_DRY_RUN", raising=False)
    monkeypatch.delenv("OUROBOROS_AUTHORIZED", raising=False)
    assert Gate().dry_run is True


def test_allowlist_scopes_targets(monkeypatch):
    g = Gate(authorized=True, allow_hosts=["127.0.0.1", "10.0.0.0/8"])
    assert g.authorize_target("http://127.0.0.1:11434/api").allowed is True
    assert g.authorize_target("http://10.1.2.3/x").allowed is True
    assert g.authorize_target("http://8.8.8.8/x").allowed is False
    assert g.authorize_target("http://evil.127.0.0.1.attacker.test/x").allowed is False


def test_non_http_scheme_denied():
    g = Gate(authorized=True, allow_hosts=["127.0.0.1"])
    assert g.authorize_target("file:///etc/passwd").allowed is False
    assert g.authorize_target("gopher://127.0.0.1").allowed is False


def test_non_url_payload_denied():
    g = Gate(authorized=True, allow_hosts=["127.0.0.1"])
    d = g.authorize_target("curl -s http://127.0.0.1/x | sh")
    assert d.allowed is False
    assert d.reason == "payload is not a URL"


def test_step_budget_enforced():
    g = Gate(authorized=True, max_steps=4)
    assert g.authorize_step(3).allowed is True
    assert g.authorize_step(4).allowed is False


def test_require_raises_on_deny():
    g = Gate(authorized=False)
    with pytest.raises(AuthorizationError):
        g.require(g.authorize_command("ls"))
