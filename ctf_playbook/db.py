"""SQLite database for the writeup index.

Stores metadata about every discovered writeup and its classification status.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ctf_playbook.config import DB_PATH


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def db_session(db_path: Path = DB_PATH):
    conn = get_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Path = DB_PATH):
    """Create tables if they don't exist."""
    with db_session(db_path) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY,
                ctftime_id  INTEGER UNIQUE,
                name        TEXT NOT NULL,
                year        INTEGER,
                url         TEXT,
                scraped_at  TEXT
            );

            CREATE TABLE IF NOT EXISTS challenges (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id    INTEGER REFERENCES events(id),
                name        TEXT NOT NULL,
                category    TEXT,           -- original CTF category (pwn, web, etc.)
                points      INTEGER,
                UNIQUE(event_id, name)
            );

            CREATE TABLE IF NOT EXISTS writeups (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_id    INTEGER REFERENCES challenges(id),
                source          TEXT NOT NULL,       -- 'ctftime', 'github', 'blog'
                url             TEXT NOT NULL UNIQUE,
                author          TEXT,
                team            TEXT,
                -- Processing status
                fetch_status    TEXT DEFAULT 'pending',  -- pending / fetched / failed
                raw_path        TEXT,                     -- path to saved content
                fetched_at      TEXT,
                -- Classification status
                class_status    TEXT DEFAULT 'pending',  -- pending / classified / failed
                classified_at   TEXT,
                -- Extracted metadata (JSON)
                techniques      TEXT,   -- JSON list of technique slugs
                tools_used      TEXT,   -- JSON list of tool names
                solve_steps     TEXT,   -- JSON list of step descriptions
                recognition     TEXT,   -- JSON list of recognition signals
                difficulty      TEXT,   -- easy / medium / hard / insane
                notes           TEXT,
                created_at      TEXT DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_writeups_fetch ON writeups(fetch_status);
            CREATE INDEX IF NOT EXISTS idx_writeups_class ON writeups(class_status);
            CREATE INDEX IF NOT EXISTS idx_writeups_source ON writeups(source);
            CREATE INDEX IF NOT EXISTS idx_challenges_category ON challenges(category);
        """)


# ── Insert helpers ─────────────────────────────────────────────────────────

def upsert_event(conn: sqlite3.Connection, ctftime_id: int, name: str,
                 year: int, url: str) -> int:
    """Insert or update an event; return the internal event id."""
    conn.execute("""
        INSERT INTO events (ctftime_id, name, year, url, scraped_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ctftime_id) DO UPDATE SET
            name=excluded.name, year=excluded.year, url=excluded.url,
            scraped_at=excluded.scraped_at
    """, (ctftime_id, name, year, url, datetime.now(timezone.utc).isoformat()))
    row = conn.execute("SELECT id FROM events WHERE ctftime_id=?", (ctftime_id,)).fetchone()
    return row["id"]


def upsert_challenge(conn: sqlite3.Connection, event_id: int, name: str,
                     category: str = None, points: int = None) -> int:
    """Insert or ignore a challenge; return its id."""
    conn.execute("""
        INSERT OR IGNORE INTO challenges (event_id, name, category, points)
        VALUES (?, ?, ?, ?)
    """, (event_id, name, category, points))
    row = conn.execute(
        "SELECT id FROM challenges WHERE event_id=? AND name=?",
        (event_id, name)
    ).fetchone()
    return row["id"]


def insert_writeup(conn: sqlite3.Connection, challenge_id: int, source: str,
                   url: str, author: str = None, team: str = None) -> Optional[int]:
    """Insert a writeup if the URL doesn't already exist. Returns id or None."""
    try:
        cur = conn.execute("""
            INSERT INTO writeups (challenge_id, source, url, author, team)
            VALUES (?, ?, ?, ?, ?)
        """, (challenge_id, source, url, author, team))
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None  # duplicate URL


# ── Query helpers ──────────────────────────────────────────────────────────

def get_unfetched(conn: sqlite3.Connection, limit: int = 100) -> list[sqlite3.Row]:
    return conn.execute("""
        SELECT w.id, w.url, w.source, c.name as challenge_name, c.category,
               e.name as event_name, e.year
        FROM writeups w
        JOIN challenges c ON w.challenge_id = c.id
        JOIN events e ON c.event_id = e.id
        WHERE w.fetch_status = 'pending'
        ORDER BY e.year DESC
        LIMIT ?
    """, (limit,)).fetchall()


def get_unclassified(conn: sqlite3.Connection, limit: int = 100,
                     category: str = None) -> list[sqlite3.Row]:
    query = """
        SELECT w.id, w.raw_path, w.url, c.name as challenge_name, c.category,
               e.name as event_name, e.year
        FROM writeups w
        JOIN challenges c ON w.challenge_id = c.id
        JOIN events e ON c.event_id = e.id
        WHERE w.fetch_status = 'fetched' AND w.class_status = 'pending'
    """
    params = []
    if category:
        query += " AND LOWER(c.category) = LOWER(?)"
        params.append(category)
    query += " ORDER BY e.year DESC LIMIT ?"
    params.append(limit)
    return conn.execute(query, params).fetchall()


def mark_fetched(conn: sqlite3.Connection, writeup_id: int, raw_path: str):
    conn.execute("""
        UPDATE writeups SET fetch_status='fetched', raw_path=?, fetched_at=?
        WHERE id=?
    """, (raw_path, datetime.now(timezone.utc).isoformat(), writeup_id))


def mark_fetch_failed(conn: sqlite3.Connection, writeup_id: int):
    conn.execute("UPDATE writeups SET fetch_status='failed' WHERE id=?", (writeup_id,))


def mark_classified(conn: sqlite3.Connection, writeup_id: int, techniques: list,
                    tools_used: list, solve_steps: list, recognition: list,
                    difficulty: str, notes: str = ""):
    conn.execute("""
        UPDATE writeups SET
            class_status='classified', classified_at=?,
            techniques=?, tools_used=?, solve_steps=?, recognition=?,
            difficulty=?, notes=?
        WHERE id=?
    """, (
        datetime.now(timezone.utc).isoformat(),
        json.dumps(techniques), json.dumps(tools_used),
        json.dumps(solve_steps), json.dumps(recognition),
        difficulty, notes, writeup_id
    ))


def mark_class_failed(conn: sqlite3.Connection, writeup_id: int):
    conn.execute("UPDATE writeups SET class_status='failed' WHERE id=?", (writeup_id,))


def get_stats(conn: sqlite3.Connection) -> dict:
    """Return a summary of database contents."""
    stats = {}
    for label, query in [
        ("events", "SELECT COUNT(*) FROM events"),
        ("challenges", "SELECT COUNT(*) FROM challenges"),
        ("writeups_total", "SELECT COUNT(*) FROM writeups"),
        ("writeups_fetched", "SELECT COUNT(*) FROM writeups WHERE fetch_status='fetched'"),
        ("writeups_classified", "SELECT COUNT(*) FROM writeups WHERE class_status='classified'"),
        ("writeups_pending_fetch", "SELECT COUNT(*) FROM writeups WHERE fetch_status='pending'"),
        ("writeups_pending_class",
         "SELECT COUNT(*) FROM writeups WHERE fetch_status='fetched' AND class_status='pending'"),
    ]:
        stats[label] = conn.execute(query).fetchone()[0]
    return stats


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at {DB_PATH}")
