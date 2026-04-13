"""Data layer for the GUI — loads playbook.json and wraps DB queries."""

import json
from pathlib import Path

from ctf_playbook.config import DB_PATH
from ctf_playbook.db import get_connection, search_writeups, get_stats
from ctf_playbook.services.builder import PLAYBOOK_JSON_PATH

_playbook: dict | None = None


def load_playbook(path: Path | None = None) -> dict:
    """Load playbook.json into memory. Caches on first call."""
    global _playbook
    p = path or PLAYBOOK_JSON_PATH
    if not p.exists():
        return {}
    with open(p, encoding="utf-8") as f:
        _playbook = json.load(f)
    return _playbook


def get_playbook() -> dict:
    """Return the cached playbook dict, loading if needed."""
    if _playbook is None:
        load_playbook()
    return _playbook or {}


def get_technique(slug: str) -> dict | None:
    """Look up a single technique by slug."""
    pb = get_playbook()
    return pb.get("techniques", {}).get(slug)


def get_techniques_by_category() -> dict[str, list[dict]]:
    """Group techniques by category for the sidebar tree.

    Returns {category: [{slug, difficulty, example_count, sub_techniques}, ...]}.
    """
    pb = get_playbook()
    grouped: dict[str, list[dict]] = {}
    for slug, tech in pb.get("techniques", {}).items():
        cat = tech.get("category", "misc")
        entry = {
            "slug": slug,
            "difficulty": tech.get("difficulty", ""),
            "example_count": tech.get("example_count", 0),
            "sub_techniques": list(tech.get("sub_techniques", {}).keys()),
        }
        grouped.setdefault(cat, []).append(entry)
    # Sort categories and techniques within each
    for cat in grouped:
        grouped[cat].sort(key=lambda t: t["slug"])
    return dict(sorted(grouped.items()))


def search_db(query: str | None = None, technique: str | None = None,
              tool: str | None = None, difficulty: str | None = None,
              limit: int = 20) -> list[dict]:
    """Search writeups via the SQLite database."""
    conn = get_connection(DB_PATH)
    try:
        rows = search_writeups(conn, query=query, technique=technique,
                               tool=tool, difficulty=difficulty, limit=limit)
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_db_stats() -> dict:
    """Get live database statistics."""
    conn = get_connection(DB_PATH)
    try:
        return get_stats(conn)
    finally:
        conn.close()
