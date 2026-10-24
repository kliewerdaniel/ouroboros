"""Retrieval integrity over a real store.

RAG poisoning in the threat model works by altering retrieved ground truth.
This wraps a SQLite-backed chunk store so that:

  * every chunk carries a SHA-256 of (source, text), verified on read;
  * canary chunks must be present and unmodified;
  * a tampered chunk RAISES rather than being returned.

The tamper tests write to the database with raw SQL, bypassing this wrapper --
that is the attack, and it is why verification cannot live only in the wrapper.
"""
from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass, field
from typing import List, Optional

CANARY_TOKEN = "OUROBOROS-CANARY-7F3A9C"


class IntegrityError(Exception):
    """A chunk failed verification. Raised, never returned to the caller."""


def chunk_hash(text: str, source: str) -> str:
    return hashlib.sha256(f"{source}\0{text}".encode()).hexdigest()


@dataclass
class Chunk:
    cid: str
    source: str
    text: str
    hash: str = ""
    is_canary: bool = False

    def __post_init__(self) -> None:
        if not self.hash:
            self.hash = chunk_hash(self.text, self.source)

    def valid(self) -> bool:
        return self.hash == chunk_hash(self.text, self.source)


@dataclass
class IntegrityReport:
    ok: bool
    checked: int
    problems: List[str] = field(default_factory=list)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS chunks (
    cid       TEXT PRIMARY KEY,
    source    TEXT NOT NULL,
    text      TEXT NOT NULL,
    hash      TEXT NOT NULL,
    is_canary INTEGER NOT NULL DEFAULT 0
)
"""


class IntegrityStore:
    def __init__(self, path: str = ":memory:", canary_token: str = CANARY_TOKEN) -> None:
        self.path = path
        self.canary_token = canary_token
        self._db = sqlite3.connect(path)
        self._db.execute(_SCHEMA)
        self._db.commit()

    # -- writes -------------------------------------------------------------
    def put(self, cid: str, source: str, text: str, is_canary: bool = False) -> Chunk:
        c = Chunk(cid=cid, source=source, text=text, is_canary=is_canary)
        self._db.execute(
            "INSERT OR REPLACE INTO chunks (cid, source, text, hash, is_canary) VALUES (?,?,?,?,?)",
            (c.cid, c.source, c.text, c.hash, int(is_canary)),
        )
        self._db.commit()
        return c

    def add_canary(self, source: str = "canary://ouroboros") -> Chunk:
        return self.put(f"canary::{source}", source, f"{self.canary_token} integrity probe",
                        is_canary=True)

    # -- reads --------------------------------------------------------------
    def _row_to_chunk(self, row) -> Chunk:
        return Chunk(cid=row[0], source=row[1], text=row[2], hash=row[3], is_canary=bool(row[4]))

    def get(self, cid: str) -> Optional[Chunk]:
        row = self._db.execute("SELECT cid, source, text, hash, is_canary FROM chunks WHERE cid=?",
                               (cid,)).fetchone()
        if row is None:
            return None
        c = self._row_to_chunk(row)
        if not c.valid():
            raise IntegrityError(f"{cid}: content hash mismatch -- chunk tampered")
        return c

    def search(self, needle: str, limit: int = 5) -> List[Chunk]:
        rows = self._db.execute(
            "SELECT cid, source, text, hash, is_canary FROM chunks WHERE text LIKE ? LIMIT ?",
            (f"%{needle}%", limit)).fetchall()
        out = []
        for row in rows:
            c = self._row_to_chunk(row)
            if not c.valid():
                raise IntegrityError(f"{c.cid}: content hash mismatch -- chunk tampered")
            out.append(c)
        return out

    # -- verification -------------------------------------------------------
    def verify(self) -> IntegrityReport:
        problems: List[str] = []
        rows = self._db.execute(
            "SELECT cid, source, text, hash, is_canary FROM chunks").fetchall()
        for row in rows:
            c = self._row_to_chunk(row)
            if not c.valid():
                problems.append(f"{c.cid}: hash mismatch (content modified)")
        canaries = [r for r in rows if r[4]]
        if not canaries:
            problems.append("no canary chunks present -- cannot prove integrity")
        return IntegrityReport(not problems, len(rows), problems)

    def snapshot(self) -> dict:
        return {r[0]: r[3] for r in self._db.execute("SELECT cid, source, text, hash FROM chunks")}

    def close(self) -> None:
        self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()
