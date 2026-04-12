"""Tests for GitHub scraper path parsing and filtering logic.

Since the path parsing is inside index_repo_writeups, we test it by
feeding a mock repo tree and checking what gets inserted into the DB.
"""

from unittest.mock import patch

import pytest

from ctf_playbook.db import init_db, get_connection
from ctf_playbook.scrapers.github import index_repo_writeups


MOCK_REPO = {
    "full_name": "user/ctf-writeups",
    "url": "https://github.com/user/ctf-writeups",
    "stars": 10,
    "default_branch": "main",
    "description": "test",
}


def _tree(*paths):
    """Build a mock GitHub tree API response."""
    return {
        "tree": [{"type": "blob", "path": p} for p in paths]
    }


@pytest.fixture
def db(tmp_path):
    db_path = tmp_path / "test.db"
    init_db(db_path)
    conn = get_connection(db_path)
    yield conn
    conn.close()


def _index(db, *paths):
    """Run index_repo_writeups with mocked API returning the given paths."""
    with patch("ctf_playbook.scrapers.github._gh_get", return_value=_tree(*paths)):
        return index_repo_writeups(MOCK_REPO, db)


def _get_challenges(db):
    """Get all challenge rows."""
    return db.execute(
        "SELECT c.name, c.category FROM challenges c ORDER BY c.name"
    ).fetchall()


def _get_writeups(db):
    """Get all writeup rows."""
    return db.execute("SELECT url FROM writeups").fetchall()


# ── README filtering ─────────────────────────────────────────────────────

class TestReadmeFiltering:
    def test_skips_top_level_readme(self, db):
        count = _index(db, "README.md")
        assert count == 0

    def test_skips_depth2_readme(self, db):
        count = _index(db, "event-name/README.md")
        assert count == 0

    def test_keeps_depth3_readme(self, db):
        count = _index(db, "event-name/challenge/README.md")
        assert count == 1

    def test_skips_license_and_contributing(self, db):
        count = _index(db, "LICENSE.md", ".github/PULL_REQUEST_TEMPLATE.md",
                       "CONTRIBUTING.md")
        assert count == 0


# ── Path parsing ─────────────────────────────────────────────────────────

class TestPathParsing:
    def test_event_challenge_file(self, db):
        """event/challenge/README.md -> event + challenge."""
        _index(db, "my-ctf/baby-pwn/README.md")
        challs = _get_challenges(db)
        assert len(challs) == 1
        assert challs[0]["name"] == "baby pwn"

    def test_year_event_challenge(self, db):
        """2024/event/challenge/README.md -> strips year, gets event + challenge."""
        _index(db, "2024/my-ctf/baby-pwn/README.md")
        challs = _get_challenges(db)
        assert challs[0]["name"] == "baby pwn"

    def test_event_category_challenge(self, db):
        """event/pwn/challenge/README.md -> detects category."""
        _index(db, "my-ctf/pwn/baby-overflow/README.md")
        challs = _get_challenges(db)
        assert challs[0]["name"] == "baby overflow"
        assert challs[0]["category"] == "pwn"

    def test_year_event_category_challenge(self, db):
        """2024/event/crypto/challenge/README.md -> year + category."""
        _index(db, "2024/my-ctf/crypto/rsa-baby/README.md")
        challs = _get_challenges(db)
        assert challs[0]["name"] == "rsa baby"
        assert challs[0]["category"] == "crypto"

    def test_single_file(self, db):
        """challenge-name.md at root."""
        _index(db, "baby-pwn.md")
        challs = _get_challenges(db)
        assert challs[0]["name"] == "baby pwn"

    def test_event_and_file(self, db):
        """event/writeup.md -> event + challenge from filename."""
        _index(db, "my-ctf/baby-pwn.md")
        challs = _get_challenges(db)
        assert challs[0]["name"] == "baby pwn"


# ── Category aliases ─────────────────────────────────────────────────────

class TestCategoryAliases:
    @pytest.mark.parametrize("folder,expected", [
        ("pwn", "pwn"),
        ("pwnable", "pwn"),
        ("exploitation", "pwn"),
        ("web", "web"),
        ("web-exploitation", "web"),
        ("crypto", "crypto"),
        ("cryptography", "crypto"),
        ("rev", "reverse-engineering"),
        ("reversing", "reverse-engineering"),
        ("forensics", "forensics"),
        ("stego", "forensics"),
        ("misc", "misc"),
        ("osint", "misc"),
        ("blockchain", "misc"),
    ])
    def test_category_detected(self, db, folder, expected):
        _index(db, f"my-ctf/{folder}/challenge1/README.md")
        challs = _get_challenges(db)
        assert challs[0]["category"] == expected

    def test_unknown_folder_not_treated_as_category(self, db):
        """A folder name that isn't a category alias should be treated as challenge name."""
        _index(db, "my-ctf/some-challenge/writeup.md")
        challs = _get_challenges(db)
        assert challs[0]["category"] is None
        assert challs[0]["name"] == "some challenge"


# ── Year extraction ──────────────────────────────────────────────────────

class TestYearExtraction:
    def test_year_from_path_prefix(self, db):
        _index(db, "2023/my-ctf/challenge/README.md")
        event = db.execute("SELECT year FROM events").fetchone()
        assert event["year"] == 2023

    def test_year_from_event_name(self, db):
        """Year embedded in event name like 'my-ctf-2024'."""
        _index(db, "my-ctf-2024/challenge/README.md")
        event = db.execute("SELECT year FROM events").fetchone()
        assert event["year"] == 2024

    def test_no_year(self, db):
        _index(db, "my-ctf/challenge/README.md")
        event = db.execute("SELECT year FROM events").fetchone()
        assert event["year"] == 0


# ── URL construction ─────────────────────────────────────────────────────

class TestUrlConstruction:
    def test_raw_url_format(self, db):
        _index(db, "event/challenge/README.md")
        writeups = _get_writeups(db)
        expected = "https://raw.githubusercontent.com/user/ctf-writeups/main/event/challenge/README.md"
        assert writeups[0]["url"] == expected
