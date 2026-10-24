"""Audit chain: append-only, hash-chained, tamper-evident."""
import json
import os

from defense.audit import AuditLog


def _log(tmp_path, n=5):
    p = tmp_path / "audit.jsonl"
    log = AuditLog(str(p))
    for i in range(n):
        log.record("shell", "deny", {"i": i})
    return str(p), log


def test_chain_verifies(tmp_path):
    _, log = _log(tmp_path)
    v = log.verify()
    assert v.ok and v.entries == 5 and v.reason == "ok"


def test_appending_preserves_chain(tmp_path):
    p, log = _log(tmp_path, 3)
    AuditLog(p).record("shell", "allow", {"i": 99})
    assert AuditLog(p).verify().ok


def test_edited_entry_breaks_chain(tmp_path):
    p, _ = _log(tmp_path, 4)
    lines = open(p).read().splitlines()
    rec = json.loads(lines[1])
    rec["decision"] = "allow"          # attacker rewrites a deny into an allow
    lines[1] = json.dumps(rec)
    open(p, "w").write("\n".join(lines) + "\n")
    v = AuditLog(p).verify()
    assert v.ok is False and v.entries == 2


def test_deleted_entry_breaks_chain(tmp_path):
    p, _ = _log(tmp_path, 4)
    lines = open(p).read().splitlines()
    del lines[2]
    open(p, "w").write("\n".join(lines) + "\n")
    assert AuditLog(p).verify().ok is False
