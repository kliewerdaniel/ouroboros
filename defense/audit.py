"""Tamper-evident audit log.

Every entry chains the previous entry's SHA-256, so any deletion, insertion,
or edit of a past entry breaks verification. This is the "independent logs"
layer the threat model requires: the agent can write to it, but cannot rewrite
history without detection.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
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


@dataclass
class Verification:
    ok: bool
    entries: int
    reason: str
