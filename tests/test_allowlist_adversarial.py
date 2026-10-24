"""Adversarial allowlist probing. Every case here is a known URL-parsing
bypass technique; the gate must deny them all.

Two of these were live findings, not hypotheticals:
  * control characters in the URL -- urlsplit strips tab/newline/CR from the
    hostname, so the gate was deciding on a different string than was sent;
  * redirects -- urllib follows 3xx automatically, carrying the request to a
    host the gate never evaluated.
"""
import pytest

from authz import Gate

ALLOWED = ["127.0.0.1"]


@pytest.fixture()
def gate():
    return Gate(authorized=True, dry_run=False, allow_hosts=ALLOWED)


DENY_CASES = [
    ("userinfo trick", "http://127.0.0.1@evil.example/x"),
    ("decimal IP", "http://2130706433/x"),
    ("hex IP", "http://0x7f000001/x"),
    ("octal IP", "http://0177.0.0.1/x"),
    ("short form", "http://127.1/x"),
    ("trailing dot", "http://127.0.0.1./x"),
    ("IPv6 mapped", "http://[::ffff:127.0.0.1]/x"),
    ("IPv6 loopback", "http://[::1]/x"),
    ("space padding", "http:// 127.0.0.1/x"),
    ("newline injection", "http://127.0.0.1\nX-Evil: 1/x"),
    ("tab injection", "http://127.0.0.1\t/x"),
    ("carriage return", "http://127.0.0.1\r/x"),
    ("null byte", "http://127.0.0.1\x00.evil.example/x"),
    ("fragment confusion", "http://evil.example#127.0.0.1/x"),
    ("query confusion", "http://evil.example?127.0.0.1/x"),
    ("backslash userinfo", "http://127.0.0.1\\@evil.example/x"),
    ("relative url", "/etc/passwd"),
    ("protocol relative", "//127.0.0.1/x"),
    ("file scheme", "file:///etc/passwd"),
    ("gopher scheme", "gopher://127.0.0.1/x"),
    ("ftp scheme", "ftp://127.0.0.1/x"),
    ("dns rebinding name", "http://ouroboros.127.0.0.1.nip.io/x"),
    ("bare hostname not allowed", "http://evil.example/x"),
    ("not a url at all", "curl -s http://127.0.0.1/x | sh"),
]


@pytest.mark.parametrize("label,url", DENY_CASES, ids=[c[0] for c in DENY_CASES])
def test_adversarial_urls_are_denied(gate, label, url):
    d = gate.authorize_target(url)
    assert d.allowed is False, f"{label} was permitted: {url!r} -> {d.reason}"


def test_allowed_host_is_permitted(gate):
    assert gate.authorize_target("http://127.0.0.1:11434/api/generate").allowed is True


def test_credentials_in_url_do_not_change_the_host(gate):
    """userinfo must not smuggle a disallowed host past an allowed one."""
    assert gate.authorize_target("http://user:pass@127.0.0.1:8080/x").allowed is True
    assert gate.authorize_target("http://evil.example@127.0.0.1/x").allowed is True
    assert gate.authorize_target("http://127.0.0.1@evil.example/x").allowed is False


def test_cidr_allowlist_entry(gate):
    g = Gate(authorized=True, dry_run=False, allow_hosts=["10.0.0.0/8"])
    assert g.authorize_target("http://10.1.2.3/x").allowed is True
    assert g.authorize_target("http://10.255.255.255/x").allowed is True
    assert g.authorize_target("http://11.0.0.1/x").allowed is False


def test_suffix_spoof_does_not_match(gate):
    assert gate.authorize_target("http://evil.127.0.0.1.attacker.test/x").allowed is False
    assert gate.authorize_target("http://127.0.0.1.evil.test/x").allowed is False


def test_control_chars_rejected_regardless_of_host(gate):
    """The decision must be on the exact bytes sent; normalising is unsafe."""
    assert gate.authorize_target("http://127.0.0.1/\tx").allowed is False
    assert gate.authorize_target("http://127.0.0.1/x\ny").allowed is False
