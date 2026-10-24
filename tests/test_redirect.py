"""Redirect handling. The allowlist must hold for the host actually contacted."""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from authz import Gate
from defense.inference import GuardedInference, InferenceEndpoint
from defense.middleware import InferenceGuard
from defense.policy_engine import Policy, PolicyEngine


class Redirector(BaseHTTPRequestHandler):
    """302 to `target`. Records that it was contacted."""

    target = "http://localhost:9232/evil"
    contacted = 0

    def _r(self):
        type(self).contacted += 1
        self.send_response(302)
        self.send_header("Location", self.target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = _r
    do_POST = _r

    def log_message(self, *a):
        pass


class Sink(BaseHTTPRequestHandler):
    """The host the redirect points at. Counts hits."""

    hits = 0

    def _h(self):
        type(self).hits += 1
        body = json.dumps({"response": "reached the sink"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _h
    do_POST = _h

    def log_message(self, *a):
        pass


@pytest.fixture()
def servers():
    Redirector.contacted = 0
    Sink.hits = 0
    a = ThreadingHTTPServer(("127.0.0.1", 9231), Redirector)
    b = ThreadingHTTPServer(("127.0.0.1", 9232), Sink)
    ts = [threading.Thread(target=s.serve_forever, daemon=True) for s in (a, b)]
    [t.start() for t in ts]
    yield
    a.shutdown()
    b.shutdown()


def _guard(dry_run=False, redirect_gate=None):
    return InferenceGuard(
        gate=Gate(authorized=True, dry_run=dry_run, allow_hosts=["127.0.0.1"],
                  ) if redirect_gate is None else redirect_gate,
        engine=PolicyEngine(Policy(allow_inference=True)),
        on_deny="return",
    )


def test_default_does_not_follow_redirects(servers):
    """The confirmed bypass: without this, urllib followed 3xx to a host the
    gate had denied, and the sink was contacted."""
    gi = GuardedInference(
        InferenceEndpoint("http://127.0.0.1:9231/start", model="m"),
        _guard())
    with pytest.raises(Exception):
        gi.respond("hello")
    assert Sink.hits == 0, "request left the allowlist"


def test_validated_redirect_is_followed_when_target_is_allowed(servers):
    """The correct way to allow redirects: re-authorize every hop."""
    Redirector.target = "http://127.0.0.1:9232/ok"       # allowed host
    gi = GuardedInference(
        InferenceEndpoint("http://127.0.0.1:9231/start", model="m",
                          redirect_gate=Gate(authorized=True, dry_run=False,
                                             allow_hosts=["127.0.0.1"])),
        _guard(redirect_gate=Gate(authorized=True, dry_run=False,
                                  allow_hosts=["127.0.0.1"])))
    out = gi.respond("hello")
    assert out.executed is True and "reached the sink" in out.response
    assert Sink.hits == 1


def test_validated_redirect_refuses_disallowed_target(servers):
    """localhost is not in the allowlist; the hop must be refused."""
    Redirector.target = "http://localhost:9232/evil"
    gi = GuardedInference(
        InferenceEndpoint("http://127.0.0.1:9231/start", model="m",
                          redirect_gate=Gate(authorized=True, dry_run=False,
                                             allow_hosts=["127.0.0.1"])),
        _guard(redirect_gate=Gate(authorized=True, dry_run=False,
                                  allow_hosts=["127.0.0.1"])))
    with pytest.raises(Exception):
        gi.respond("hello")
    assert Sink.hits == 0


def test_original_url_is_still_authorized_before_any_request(servers):
    gi = GuardedInference(
        InferenceEndpoint("http://127.0.0.1:9231/start", model="m"), _guard())
    assert gi.guard.gate.authorize_target("http://127.0.0.1:9231/start").allowed is True
    assert gi.guard.gate.authorize_target("http://localhost:9232/evil").allowed is False
