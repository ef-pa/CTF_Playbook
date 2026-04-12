"""Tests for the database layer."""

import json
import sqlite3
from pathlib import Path

import pytest

from ctf_playbook.db import (
    init_db, db_session, get_connection,
    upsert_event, upsert_challenge, insert_writeup,
    get_unfetched, get_unclassified,
    mark_fetched, mark_fetch_failed,
    mark_classified, mark_class_failed,
    infer_category, backfill_categories,
    find_duplicates, deduplicate,
    search_writeups, get_stats,
)


@pytest.fixture
def db(tmp_path):
    """Create a fresh in-memory-like test database."""
    db_path = tmp_path / "test.db"
    init_db(db_path)
    conn = get_connection(db_path)
    yield conn
    conn.close()


def _seed(conn):
    """Insert a minimal event -> challenge -> writeup chain. Returns IDs."""
    eid = upsert_event(conn, ctftime_id=1, name="TestCTF", year=2024, url="https://example.com")
    cid = upsert_challenge(conn, eid, "baby-pwn", category=None)
    wid = insert_writeup(conn, cid, "github", "https://example.com/writeup1", team="team1")
    return eid, cid, wid


# ── Schema & init ────────────────────────────────────────────────────────

class TestInit:
    def test_tables_created(self, db):
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        assert {"events", "challenges", "writeups"} <= tables

    def test_idempotent(self, tmp_path):
        db_path = tmp_path / "test.db"
        init_db(db_path)
        init_db(db_path)  # should not raise


# ── Insert helpers ───────────────────────────────────────────────────────

class TestInserts:
    def test_upsert_event_returns_id(self, db):
        eid = upsert_event(db, ctftime_id=42, name="CTF1", year=2024, url="https://a.com")
        assert isinstance(eid, int)

    def test_upsert_event_updates_on_conflict(self, db):
        eid1 = upsert_event(db, ctftime_id=42, name="Old", year=2023, url="https://a.com")
        eid2 = upsert_event(db, ctftime_id=42, name="New", year=2024, url="https://b.com")
        assert eid1 == eid2
        row = db.execute("SELECT name, year FROM events WHERE id=?", (eid1,)).fetchone()
        assert row["name"] == "New"
        assert row["year"] == 2024

    def test_upsert_challenge_returns_id(self, db):
        eid = upsert_event(db, ctftime_id=1, name="E", year=2024, url="")
        cid = upsert_challenge(db, eid, "challenge1", "pwn")
        assert isinstance(cid, int)

    def test_upsert_challenge_ignores_duplicate(self, db):
        eid = upsert_event(db, ctftime_id=1, name="E", year=2024, url="")
        cid1 = upsert_challenge(db, eid, "challenge1", "pwn")
        cid2 = upsert_challenge(db, eid, "challenge1", "web")
        assert cid1 == cid2

    def test_insert_writeup_returns_id(self, db):
        eid, cid, wid = _seed(db)
        assert isinstance(wid, int)

    def test_insert_writeup_rejects_duplicate_url(self, db):
        eid, cid, wid = _seed(db)
        dup = insert_writeup(db, cid, "ctftime", "https://example.com/writeup1")
        assert dup is None


# ── Query helpers ────────────────────────────────────────────────────────

class TestQueries:
    def test_get_unfetched(self, db):
        _seed(db)
        rows = get_unfetched(db, limit=10)
        assert len(rows) == 1
        assert rows[0]["challenge_name"] == "baby-pwn"

    def test_get_unfetched_excludes_fetched(self, db):
        _, _, wid = _seed(db)
        mark_fetched(db, wid, "/tmp/raw.md", content_hash="abc")
        rows = get_unfetched(db, limit=10)
        assert len(rows) == 0

    def test_get_unclassified_requires_fetched(self, db):
        _seed(db)
        # Still pending fetch, shouldn't appear
        rows = get_unclassified(db, limit=10)
        assert len(rows) == 0

    def test_get_unclassified_after_fetch(self, db):
        _, _, wid = _seed(db)
        mark_fetched(db, wid, "/tmp/raw.md")
        rows = get_unclassified(db, limit=10)
        assert len(rows) == 1

    def test_get_unclassified_category_filter(self, db):
        eid = upsert_event(db, ctftime_id=1, name="E", year=2024, url="")
        cid1 = upsert_challenge(db, eid, "c1", "pwn")
        cid2 = upsert_challenge(db, eid, "c2", "web")
        wid1 = insert_writeup(db, cid1, "github", "https://a.com")
        wid2 = insert_writeup(db, cid2, "github", "https://b.com")
        mark_fetched(db, wid1, "/tmp/1.md")
        mark_fetched(db, wid2, "/tmp/2.md")

        assert len(get_unclassified(db, limit=10, category="pwn")) == 1
        assert len(get_unclassified(db, limit=10, category="web")) == 1
        assert len(get_unclassified(db, limit=10, category="crypto")) == 0


# ── Status transitions ──────────────────────────────────────────────────

class TestStatusTransitions:
    def test_mark_fetched(self, db):
        _, _, wid = _seed(db)
        mark_fetched(db, wid, "/tmp/raw.md", content_hash="deadbeef")
        row = db.execute("SELECT fetch_status, raw_path, content_hash FROM writeups WHERE id=?",
                         (wid,)).fetchone()
        assert row["fetch_status"] == "fetched"
        assert row["raw_path"] == "/tmp/raw.md"
        assert row["content_hash"] == "deadbeef"

    def test_mark_fetch_failed(self, db):
        _, _, wid = _seed(db)
        mark_fetch_failed(db, wid)
        row = db.execute("SELECT fetch_status FROM writeups WHERE id=?", (wid,)).fetchone()
        assert row["fetch_status"] == "failed"

    def test_mark_classified(self, db):
        _, _, wid = _seed(db)
        mark_fetched(db, wid, "/tmp/raw.md")
        mark_classified(db, wid,
                        techniques=["buffer-overflow", "rop-chains"],
                        tools_used=["gdb", "pwntools"],
                        solve_steps=["find vuln", "exploit"],
                        recognition=["gets() call"],
                        difficulty="medium",
                        notes="A pwn challenge")

        row = db.execute("SELECT * FROM writeups WHERE id=?", (wid,)).fetchone()
        assert row["class_status"] == "classified"
        assert json.loads(row["techniques"]) == ["buffer-overflow", "rop-chains"]
        assert json.loads(row["tools_used"]) == ["gdb", "pwntools"]
        assert row["difficulty"] == "medium"

    def test_mark_classified_backfills_category(self, db):
        """Classifying a writeup should set the challenge category if missing."""
        eid = upsert_event(db, ctftime_id=1, name="E", year=2024, url="")
        cid = upsert_challenge(db, eid, "test-challenge")  # no category
        wid = insert_writeup(db, cid, "github", "https://a.com")
        mark_fetched(db, wid, "/tmp/raw.md")
        mark_classified(db, wid,
                        techniques=["buffer-overflow"],
                        tools_used=[], solve_steps=[], recognition=[],
                        difficulty="easy")

        row = db.execute("SELECT category FROM challenges WHERE id=?", (cid,)).fetchone()
        assert row["category"] == "binary-exploitation"

    def test_mark_classified_does_not_overwrite_existing_category(self, db):
        eid = upsert_event(db, ctftime_id=1, name="E", year=2024, url="")
        cid = upsert_challenge(db, eid, "test-challenge", category="pwn")
        wid = insert_writeup(db, cid, "github", "https://a.com")
        mark_fetched(db, wid, "/tmp/raw.md")
        mark_classified(db, wid,
                        techniques=["sql-injection"],
                        tools_used=[], solve_steps=[], recognition=[],
                        difficulty="easy")

        row = db.execute("SELECT category FROM challenges WHERE id=?", (cid,)).fetchone()
        assert row["category"] == "pwn"  # unchanged

    def test_mark_class_failed(self, db):
        _, _, wid = _seed(db)
        mark_class_failed(db, wid)
        row = db.execute("SELECT class_status FROM writeups WHERE id=?", (wid,)).fetchone()
        assert row["class_status"] == "failed"


# ── Category inference ───────────────────────────────────────────────────

class TestInferCategory:
    def test_single_technique(self):
        assert infer_category(["buffer-overflow"]) == "binary-exploitation"
        assert infer_category(["sql-injection"]) == "web"
        assert infer_category(["rsa-attacks"]) == "cryptography"
        assert infer_category(["static-analysis"]) == "reverse-engineering"
        assert infer_category(["file-carving"]) == "forensics"
        assert infer_category(["osint"]) == "misc"

    def test_majority_vote(self):
        # 2 binary vs 1 web -> binary-exploitation
        result = infer_category(["buffer-overflow", "rop-chains", "sql-injection"])
        assert result == "binary-exploitation"

    def test_unknown_techniques_ignored(self):
        assert infer_category(["some-custom-technique"]) is None

    def test_empty_list(self):
        assert infer_category([]) is None

    def test_mixed_known_unknown(self):
        result = infer_category(["buffer-overflow", "custom-thing"])
        assert result == "binary-exploitation"


# ── Backfill categories ─────────────────────────────────────────────────

class TestBackfillCategories:
    def test_backfills_missing_categories(self, db):
        eid = upsert_event(db, ctftime_id=1, name="E", year=2024, url="")
        cid = upsert_challenge(db, eid, "c1")  # no category
        wid = insert_writeup(db, cid, "github", "https://a.com")
        mark_fetched(db, wid, "/tmp/raw.md")
        mark_classified(db, wid,
                        techniques=["rsa-attacks"],
                        tools_used=[], solve_steps=[], recognition=[],
                        difficulty="easy")
        # Reset category to simulate pre-backfill state
        db.execute("UPDATE challenges SET category = NULL WHERE id=?", (cid,))

        updated = backfill_categories(db)
        assert updated == 1
        row = db.execute("SELECT category FROM challenges WHERE id=?", (cid,)).fetchone()
        assert row["category"] == "cryptography"

    def test_skips_already_categorized(self, db):
        eid = upsert_event(db, ctftime_id=1, name="E", year=2024, url="")
        cid = upsert_challenge(db, eid, "c1", category="web")
        wid = insert_writeup(db, cid, "github", "https://a.com")
        mark_fetched(db, wid, "/tmp/raw.md")
        mark_classified(db, wid,
                        techniques=["buffer-overflow"],
                        tools_used=[], solve_steps=[], recognition=[],
                        difficulty="easy")

        updated = backfill_categories(db)
        assert updated == 0


# ── Deduplication ────────────────────────────────────────────────────────

class TestDedup:
    def _make_dupes(self, db):
        eid = upsert_event(db, ctftime_id=1, name="E", year=2024, url="")
        cid = upsert_challenge(db, eid, "c1")
        wid1 = insert_writeup(db, cid, "github", "https://a.com")
        wid2 = insert_writeup(db, cid, "ctftime", "https://b.com")
        wid3 = insert_writeup(db, cid, "github", "https://c.com")
        mark_fetched(db, wid1, "/tmp/1.md", content_hash="samehash")
        mark_fetched(db, wid2, "/tmp/2.md", content_hash="samehash")
        mark_fetched(db, wid3, "/tmp/3.md", content_hash="samehash")
        return wid1, wid2, wid3

    def test_find_duplicates(self, db):
        self._make_dupes(db)
        dupes = find_duplicates(db)
        assert len(dupes) == 1
        assert dupes[0]["cnt"] == 3

    def test_deduplicate_marks_extras(self, db):
        self._make_dupes(db)
        removed = deduplicate(db)
        assert removed == 2

        statuses = db.execute(
            "SELECT id, fetch_status FROM writeups ORDER BY id"
        ).fetchall()
        # ctftime source should be kept (preferred), others marked duplicate
        kept = [r for r in statuses if r["fetch_status"] == "fetched"]
        duped = [r for r in statuses if r["fetch_status"] == "duplicate"]
        assert len(kept) == 1
        assert len(duped) == 2

    def test_deduplicate_prefers_ctftime(self, db):
        """ctftime source should be preferred over github."""
        wid1, wid2, wid3 = self._make_dupes(db)
        deduplicate(db)

        # wid2 is ctftime, should be kept
        row = db.execute("SELECT fetch_status FROM writeups WHERE id=?", (wid2,)).fetchone()
        assert row["fetch_status"] == "fetched"

    def test_no_duplicates(self, db):
        _seed(db)
        assert find_duplicates(db) == []
        assert deduplicate(db) == 0


# ── Search ───────────────────────────────────────────────────────────────

class TestSearch:
    def _classified_writeup(self, db, url="https://a.com", techniques=None,
                            tools=None, difficulty="medium", notes="",
                            challenge_name="test-chall", category=None):
        eid = upsert_event(db, ctftime_id=abs(hash(url)) % 10_000_000,
                           name="TestCTF", year=2024, url="")
        cid = upsert_challenge(db, eid, challenge_name, category)
        wid = insert_writeup(db, cid, "github", url)
        mark_fetched(db, wid, "/tmp/raw.md")
        mark_classified(db, wid,
                        techniques=techniques or ["buffer-overflow"],
                        tools_used=tools or ["gdb"],
                        solve_steps=["step1"],
                        recognition=["signal1"],
                        difficulty=difficulty,
                        notes=notes)
        return wid

    def test_search_by_keyword(self, db):
        self._classified_writeup(db, notes="heap spray attack")
        results = search_writeups(db, query="heap")
        assert len(results) == 1

    def test_search_by_technique(self, db):
        self._classified_writeup(db, techniques=["rsa-attacks"])
        results = search_writeups(db, technique="rsa-attacks")
        assert len(results) == 1
        results = search_writeups(db, technique="sql-injection")
        assert len(results) == 0

    def test_search_by_tool(self, db):
        self._classified_writeup(db, tools=["pwntools", "gdb"])
        results = search_writeups(db, tool="pwntools")
        assert len(results) == 1

    def test_search_by_difficulty(self, db):
        self._classified_writeup(db, difficulty="insane")
        results = search_writeups(db, difficulty="insane")
        assert len(results) == 1
        results = search_writeups(db, difficulty="easy")
        assert len(results) == 0

    def test_search_by_challenge_name(self, db):
        self._classified_writeup(db, challenge_name="heap-overflow-101")
        results = search_writeups(db, query="heap-overflow")
        assert len(results) == 1

    def test_search_no_results(self, db):
        self._classified_writeup(db)
        results = search_writeups(db, query="nonexistent-thing-xyz")
        assert len(results) == 0

    def test_search_only_classified(self, db):
        """Pending/failed writeups should not appear in search."""
        eid, cid, wid = _seed(db)
        mark_fetched(db, wid, "/tmp/raw.md")
        # Not classified yet
        results = search_writeups(db, query="baby-pwn")
        assert len(results) == 0


# ── Stats ────────────────────────────────────────────────────────────────

class TestStats:
    def test_empty_db(self, db):
        s = get_stats(db)
        assert s["events"] == 0
        assert s["writeups_total"] == 0
        assert s["writeups_duplicate"] == 0

    def test_after_seed(self, db):
        _seed(db)
        s = get_stats(db)
        assert s["events"] == 1
        assert s["challenges"] == 1
        assert s["writeups_total"] == 1
        assert s["writeups_pending_fetch"] == 1

    def test_status_tracking(self, db):
        _, _, wid = _seed(db)
        mark_fetched(db, wid, "/tmp/raw.md")
        s = get_stats(db)
        assert s["writeups_fetched"] == 1
        assert s["writeups_pending_class"] == 1
