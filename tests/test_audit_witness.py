"""Audit hardening: witness anchoring detects truncation; signatures detect
re-derivation without the key."""
import hashlib
import json

import pytest

from defense.audit import AuditLog, FileWitness, InMemoryWitness, SignedAuditLog

GENESIS = "0" * 64


def _rederive(lines):
    """Attacker move: recompute a valid hash chain over a subset of entries."""
    prev = GENESIS
    for rec in lines:
        body = {"seq": rec["seq"], "ts": rec["ts"], "kind": rec["kind"],
                "decision": rec["decision"], "detail": rec["detail"], "prev_hash": prev}
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
        rec["prev_hash"] = prev
        rec["entry_hash"] = hashlib.sha256(payload.encode()).hexdigest()
        prev = rec["entry_hash"]
    return lines


def test_plain_verify_accepts_a_truncated_redehashed_chain(tmp_path):
    """The gap the witness exists to close: local verification cannot tell."""
    p = tmp_path / "a.jsonl"
    log = AuditLog(str(p))
    for i in range(5):
        log.record("shell", "deny", {"i": i})
    w = InMemoryWitness()
    w.anchor(log.head)

    lines = [json.loads(l) for l in open(p)]
    _rederive(lines[:3])
    open(p, "w").write("\n".join(json.dumps(r) for r in lines[:3]) + "\n")

    t = AuditLog(str(p))
    assert t.verify().ok is True, "truncated chain must look internally consistent"
    assert len(t._entries) == 3


def test_witness_detects_truncation(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(str(p))
    for i in range(5):
        log.record("shell", "deny", {"i": i})
    w = InMemoryWitness()
    w.anchor(log.head)

    lines = [json.loads(l) for l in open(p)]
    _rederive(lines[:3])
    open(p, "w").write("\n".join(json.dumps(r) for r in lines[:3]) + "\n")

    v = AuditLog(str(p)).verify_with_witness(w)
    assert v.ok is False
    assert "truncated or replaced" in v.reason


def test_witness_accepts_anchored_chain(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(str(p))
    for i in range(3):
        log.record("shell", "deny", {"i": i})
    w = InMemoryWitness()
    w.anchor(log.head)
    assert AuditLog(str(p)).verify_with_witness(w).ok is True


def test_no_anchor_published_is_not_a_failure(tmp_path):
    log = AuditLog(str(tmp_path / "a.jsonl"))
    log.record("shell", "deny", {})
    v = log.verify_with_witness(InMemoryWitness())
    assert v.ok is True and v.reason == "no anchor published"


def test_witness_unavailable_is_reported(tmp_path):
    class Broken:
        def latest(self):
            raise RuntimeError("sink down")

    log = AuditLog(str(tmp_path / "a.jsonl"))
    log.record("shell", "deny", {})
    v = log.verify_with_witness(Broken())
    assert v.ok is False and "witness unavailable" in v.reason


def test_file_witness_roundtrip(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(str(p))
    log.record("shell", "deny", {"i": 1})
    w = FileWitness(str(tmp_path / "heads.txt"))
    w.anchor(log.head)
    log.record("shell", "deny", {"i": 2})
    w.anchor(log.head)
    assert w.latest() == log.head
    assert AuditLog(str(p)).verify_with_witness(w).ok is True


def test_signature_rejects_rederived_chain_without_the_key(tmp_path):
    """The case hashing cannot catch: hashes re-derived, signing key absent.

    An attacker who edits an early entry and rebuilds the hash chain defeats the
    hash layer entirely. Only the signature still fails -- and only because they
    cannot re-sign. (Truncating the tail does NOT do this: the retained prefix's
    hashes are unchanged, so its signatures still match.)
    """
    p = tmp_path / "s.jsonl"
    log = SignedAuditLog(str(p), key="secret")
    for i in range(4):
        log.record("shell", "deny", {"i": i})
    assert log.verify().ok is True

    lines = [json.loads(l) for l in open(p)]
    lines[0]["decision"] = "allow"          # the edit: a deny becomes an allow
    _rederive(lines)                         # attacker rebuilds the hash chain
    open(p, "w").write("\n".join(json.dumps(r) for r in lines) + "\n")

    assert AuditLog(str(p)).verify().ok is True, "hash layer is defeated by re-derivation"
    v = SignedAuditLog(str(p), key="secret").verify()
    assert v.ok is False, "signature layer must still catch it"
    assert v.reason == "signature mismatch"


def test_hash_layer_alone_is_defeated_by_rederivation(tmp_path):
    """Makes the signature's value concrete: the plain chain passes."""
    p = tmp_path / "a.jsonl"
    log = AuditLog(str(p))
    for i in range(3):
        log.record("shell", "deny", {"i": i})

    lines = [json.loads(l) for l in open(p)]
    lines[0]["decision"] = "allow"
    _rederive(lines)
    open(p, "w").write("\n".join(json.dumps(r) for r in lines) + "\n")

    assert AuditLog(str(p)).verify().ok is True


def test_signature_rejects_wrong_key(tmp_path):
    p = tmp_path / "s.jsonl"
    SignedAuditLog(str(p), key="right").record("shell", "deny", {"i": 1})
    v = SignedAuditLog(str(p), key="wrong").verify()
    assert v.ok is False


def test_signature_rejects_unsigned_entries(tmp_path):
    p = tmp_path / "s.jsonl"
    log = SignedAuditLog(str(p), key="k")
    log.record("shell", "deny", {"i": 1})
    lines = [json.loads(l) for l in open(p)]
    lines[0]["sig"] = ""
    open(p, "w").write("\n".join(json.dumps(r) for r in lines) + "\n")
    v = SignedAuditLog(str(p), key="k").verify()
    assert v.ok is False and v.reason == "entry unsigned"


def test_signed_log_survives_reopen(tmp_path):
    p = str(tmp_path / "s.jsonl")
    SignedAuditLog(p, key="k").record("shell", "deny", {"i": 1})
    SignedAuditLog(p, key="k").record("shell", "allow", {"i": 2})
    v = SignedAuditLog(p, key="k").verify()
    assert v.ok is True and v.entries == 2 and v.reason == "signed"
