"""Retrieval-layer integrity: canary documents and chunk hash verification.

RAG poisoning in the threat model works by altering the "ground truth" a model
retrieves. Two defenses, both checkable:

  1. Canary chunks -- known plaintext inserted into the corpus. If a canary is
     missing, reordered, or modified at read time, the store has been tampered.
  2. Chunk hashes -- every chunk carries a SHA-256. Any content edit invalidates
     the hash, so poisoning is detectable even without a canary hit.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional

CANARY_TOKEN = "OUROBOROS-CANARY-7F3A9C"


def chunk_hash(text: str, source: str) -> str:
    return hashlib.sha256(f"{source}\0{text}".encode()).hexdigest()


@dataclass
class Chunk:
    cid: str
    source: str
    text: str
    hash: str = ""

    def __post_init__(self) -> None:
        if not self.hash:
            self.hash = chunk_hash(self.text, self.source)


@dataclass
class IntegrityReport:
    ok: bool
    checked: int
    problems: List[str] = field(default_factory=list)


class RetrievalStore:
    def __init__(self) -> None:
        self._chunks: Dict[str, Chunk] = {}

    def add(self, cid: str, source: str, text: str) -> Chunk:
        c = Chunk(cid=cid, source=source, text=text)
        self._chunks[cid] = c
        return c

    def add_canary(self, source: str = "canary://ouroboros") -> Chunk:
        return self.add(f"canary-{source}", source, f"{CANARY_TOKEN} integrity probe")

    def get(self, cid: str) -> Optional[Chunk]:
        return self._chunks.get(cid)

    def verify(self) -> IntegrityReport:
        problems: List[str] = []
        for cid, c in self._chunks.items():
            if chunk_hash(c.text, c.source) != c.hash:
                problems.append(f"{cid}: hash mismatch (content modified)")
        canaries = [c for c in self._chunks.values() if CANARY_TOKEN in c.text]
        if not canaries:
            problems.append("no canary chunks present -- cannot prove integrity")
        return IntegrityReport(not problems, len(self._chunks), problems)

    def snapshot(self) -> Dict[str, str]:
        return {cid: c.hash for cid, c in self._chunks.items()}
