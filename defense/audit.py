"""Tamper-evident audit log.

Every entry chains the previous entry's SHA-256, so any deletion, insertion,
or edit of a past entry breaks verification. This is the "independent logs"
layer the threat model requires: the agent can write to it, but cannot rewrite
history without detection.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Protocol
from dataclasses import dataclass, field
from typing import List, Optional

GENESIS = "0" * 64


@dataclass
class Entry:
    seq: int
    ts: float
    kind: str
    decision: str
    detail: dict
    prev_hash: str
    entry_hash: str = ""
    sig: str = ""

    def payload(self) -> str:
        body = {
            "seq": self.seq,
            "ts": self.ts,
            "kind": self.kind,
            "decision": self.decision,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":"))


class NullAudit:
    """Discards records. Lets InferenceGuard default to a usable audit sink
    instead of an Optional that callers must null-check."""

    def record(self, kind: str, decision: str, detail: dict) -> Entry:
        return Entry(0, 0.0, kind, decision, detail, GENESIS, GENESIS)

    def verify(self) -> "Verification":
        return Verification(True, 0, "null audit")


class AuditLog:
    def __init__(self, path: str) -> None:
        self.path = path
        self._entries: List[Entry] = []
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        with open(self.path, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                self._entries.append(
                    Entry(
                        seq=rec["seq"],
                        ts=rec["ts"],
                        kind=rec["kind"],
                        decision=rec["decision"],
                        detail=rec["detail"],
                        prev_hash=rec["prev_hash"],
                        entry_hash=rec["entry_hash"],
                        sig=rec.get("sig", ""),
                    )
                )

    @property
    def head(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS

    def record(self, kind: str, decision: str, detail: dict) -> Entry:
        e = Entry(
            seq=len(self._entries) + 1,
            ts=time.time(),
            kind=kind,
            decision=decision,
            detail=detail,
            prev_hash=self.head,
        )
        e.entry_hash = hashlib.sha256(e.payload().encode()).hexdigest()
        with open(self.path, "a") as fh:
            fh.write(json.dumps(e.__dict__, sort_keys=True) + "\n")
        self._entries.append(e)
        return e

    def verify(self) -> "Verification":
        prev = GENESIS
        for e in self._entries:
            if e.prev_hash != prev:
                return Verification(False, e.seq, "prev_hash mismatch")
            if hashlib.sha256(e.payload().encode()).hexdigest() != e.entry_hash:
                return Verification(False, e.seq, "entry_hash mismatch")
            prev = e.entry_hash
        return Verification(True, len(self._entries), "ok")

    def hashes(self) -> set:
        return {e.entry_hash for e in self._entries}

    def contains_hash(self, h: str) -> bool:
        """True if `h` is reachable in this chain.

        This is what makes truncation detectable: an anchored head that is no
        longer present means entries were removed and the chain re-derived.
        """
        return h in self.hashes()

    def verify_with_witness(self, witness: "Witness") -> "Verification":
        """Verify locally, then against an externally anchored head.

        Hash chaining alone proves the chain is internally consistent -- which a
        truncated-and-rederived chain also is. The witness closes that gap: the
        head was published to a sink the node cannot rewrite, so a shorter
        replacement chain fails here.
        """
        v = self.verify()
        if not v.ok:
            return v
        try:
            anchored = witness.latest()
        except Exception as exc:                      # noqa: BLE001 - reported, not hidden
            return Verification(False, v.entries, f"witness unavailable: {exc}")
        if not anchored:
            return Verification(True, v.entries, "no anchor published")
        if not self.contains_hash(anchored):
            return Verification(False, v.entries,
                                f"anchored head {anchored[:12]} not in chain -- "
                                f"log truncated or replaced")
        return Verification(True, v.entries, "anchored")


@dataclass
class SignedAuditLog(AuditLog):
    """AuditLog whose entries carry an HMAC the verifier recomputes.

    Covers a different threat than the witness: an attacker who can tamper with
    the file in transit or from a neighbouring process, but does NOT hold the
    signing key. If the key lives on the node, this does not stop a compromised
    node -- use the witness for that. Pair the two for both.
    """

    def __init__(self, path: str, key) -> None:
        super().__init__(path)
        self._key = key if isinstance(key, bytes) else key.encode()

    def _sign(self, e: Entry) -> str:
        return hmac.new(self._key, e.payload().encode(), hashlib.sha256).hexdigest()

    def record(self, kind: str, decision: str, detail: dict) -> Entry:
        e = Entry(seq=len(self._entries) + 1, ts=time.time(), kind=kind,
                  decision=decision, detail=detail, prev_hash=self.head)
        e.entry_hash = hashlib.sha256(e.payload().encode()).hexdigest()
        e.sig = self._sign(e)
        with open(self.path, "a") as fh:
            fh.write(json.dumps(e.__dict__, sort_keys=True) + "\n")
        self._entries.append(e)
        return e

    def verify(self) -> "Verification":
        v = super().verify()
        if not v.ok:
            return v
        for e in self._entries:
            if not e.sig:
                return Verification(False, e.seq, "entry unsigned")
            if not hmac.compare_digest(e.sig, self._sign(e)):
                return Verification(False, e.seq, "signature mismatch")
        return Verification(True, len(self._entries), "signed")


@dataclass
class Verification:
    ok: bool
    entries: int
    reason: str


class Witness(Protocol):
    """An append-only sink the node cannot rewrite. `latest` returns the most
    recently anchored head hash, or "" if nothing has been published."""

    def anchor(self, head: str) -> None: ...

    def latest(self) -> str: ...


class InMemoryWitness:
    """Test and single-process use."""

    def __init__(self) -> None:
        self._heads: List[str] = []

    def anchor(self, head: str) -> None:
        self._heads.append(head)

    def latest(self) -> str:
        return self._heads[-1] if self._heads else ""

    @property
    def anchored(self) -> List[str]:
        return list(self._heads)


class FileWitness:
    """Append-only file, one head per line. Same-host, so it defends against
    accidental loss and casual tampering, not against an attacker who owns the
    box -- for that, anchor to a remote sink."""

    def __init__(self, path: str) -> None:
        self.path = path

    def anchor(self, head: str) -> None:
        with open(self.path, "a") as fh:
            fh.write(head + "\n")

    def latest(self) -> str:
        if not os.path.exists(self.path):
            return ""
        with open(self.path) as fh:
            lines = [l.strip() for l in fh if l.strip()]
        return lines[-1] if lines else ""


class CallbackWitness:
    """Anchor by calling out -- ship the head to WORM object storage, a separate
    logging service, or a ledger. This is the deployment that actually defeats
    a compromised node."""

    def __init__(self, fn, latest_fn) -> None:
        self._fn = fn
        self._latest_fn = latest_fn
        self.anchored: List[str] = []

    def anchor(self, head: str) -> None:
        self.anchored.append(head)
        self._fn(head)

    def latest(self) -> str:
        return self._latest_fn()


class Audit(Protocol):
    """Anything that can record and verify. Lets InferenceGuard accept a real
    AuditLog or a NullAudit without Optional null-checks at call sites."""

    def record(self, kind: str, decision: str, detail: dict) -> Entry: ...

    def verify(self) -> Verification: ...
