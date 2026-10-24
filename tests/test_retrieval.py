"""Retrieval integrity: canaries and chunk hashes detect poisoning."""
from defense.retrieval_integrity import CANARY_TOKEN, RetrievalStore


def test_clean_store_verifies():
    s = RetrievalStore()
    s.add_canary()
    s.add("d1", "a.md", "rotate keys every 90 days")
    v = s.verify()
    assert v.ok and v.checked == 2 and not v.problems


def test_hash_detects_content_edit():
    s = RetrievalStore()
    c = s.add("d1", "a.md", "rotate keys every 90 days")
    s._chunks["d1"].text = "rotate keys every 900 days"   # poisoning
    v = s.verify()
    assert v.ok is False
    assert "hash mismatch" in v.problems[0]


def test_missing_canary_flagged():
    s = RetrievalStore()
    s.add("d1", "a.md", "no canary here")
    v = s.verify()
    assert v.ok is False
    assert any("canary" in p for p in v.problems)


def test_snapshot_is_stable_and_hash_bound():
    s = RetrievalStore()
    s.add("d1", "a.md", "text")
    snap = s.snapshot()
    assert set(snap) == {"d1"}
    assert len(snap["d1"]) == 64
