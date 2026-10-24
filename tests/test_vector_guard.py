"""Integrity over a real store. Tampering is done with raw SQL, bypassing the
wrapper -- because that is the attack."""
import sqlite3

import pytest

from defense.vector_guard import CANARY_TOKEN, IntegrityError, IntegrityStore, chunk_hash


@pytest.fixture()
def store():
    s = IntegrityStore(":memory:")
    s.add_canary()
    s.put("d1", "handbook.md", "Deploy keys must be rotated every 90 days.")
    s.put("d2", "runbook.md", "Inference endpoints must not be bound to 0.0.0.0.")
    yield s
    s.close()


def test_roundtrip(store):
    c = store.get("d1")
    assert c.text.startswith("Deploy keys") and c.valid()


def test_clean_store_verifies(store):
    r = store.verify()
    assert r.ok and r.checked == 3 and not r.problems


def test_tamper_via_raw_sql_is_detected_on_read(store):
    store._db.execute("UPDATE chunks SET text='rotate keys every 900 days' WHERE cid='d1'")
    store._db.commit()
    with pytest.raises(IntegrityError):
        store.get("d1")


def test_tamper_via_raw_sql_is_detected_by_verify(store):
    store._db.execute("UPDATE chunks SET text='rotate keys every 900 days' WHERE cid='d1'")
    store._db.commit()
    r = store.verify()
    assert r.ok is False and "hash mismatch" in r.problems[0]


def test_search_raises_on_tampered_chunk(store):
    store._db.execute("UPDATE chunks SET text='totally benign text' WHERE cid='d1'")
    store._db.commit()
    with pytest.raises(IntegrityError):
        store.search("benign")


def test_search_returns_clean_chunks(store):
    assert len(store.search("rotated")) == 1


def test_missing_canary_is_flagged():
    s = IntegrityStore(":memory:")
    s.put("d1", "a.md", "no canary here")
    r = s.verify()
    assert r.ok is False and any("canary" in p for p in r.problems)
    s.close()


def test_canary_modification_detected():
    s = IntegrityStore(":memory:")
    s.add_canary()
    s._db.execute("UPDATE chunks SET text='canary overwritten' WHERE is_canary=1")
    s._db.commit()
    assert s.verify().ok is False
    s.close()


def test_snapshot_is_hash_bound(store):
    snap = store.snapshot()
    assert set(snap) == {"canary::canary://ouroboros", "d1", "d2"}
    assert all(len(h) == 64 for h in snap.values())


def test_hash_covers_source_and_text():
    assert chunk_hash("t", "s1") != chunk_hash("t", "s2")
    assert chunk_hash("t1", "s") != chunk_hash("t2", "s")


def test_context_manager():
    with IntegrityStore(":memory:") as s:
        s.add_canary()
        assert s.verify().ok is True


def test_persists_across_connections(tmp_path):
    p = str(tmp_path / "v.db")
    s = IntegrityStore(p)
    s.add_canary()
    s.put("d1", "a.md", "content")
    s.close()

    s2 = IntegrityStore(p)
    assert s2.verify().ok is True and s2.get("d1").text == "content"
    s2.close()


def test_canary_token_is_known():
    assert CANARY_TOKEN.startswith("OUROBOROS-CANARY")
