"""Tests for fetcher utility functions."""

import hashlib

from ctf_playbook.fetcher import _url_to_filename


class TestUrlToFilename:
    def test_with_challenge_name(self):
        result = _url_to_filename("https://example.com/writeup", "baby-pwn")
        assert result.startswith("baby-pwn_")
        assert result.endswith(".md")

    def test_without_challenge_name(self):
        result = _url_to_filename("https://example.com/writeup")
        # Should be just the hash + .md
        expected_hash = hashlib.sha256(b"https://example.com/writeup").hexdigest()[:12]
        assert result == f"{expected_hash}.md"

    def test_deterministic(self):
        r1 = _url_to_filename("https://example.com/writeup", "test")
        r2 = _url_to_filename("https://example.com/writeup", "test")
        assert r1 == r2

    def test_different_urls_different_filenames(self):
        r1 = _url_to_filename("https://a.com/1", "test")
        r2 = _url_to_filename("https://a.com/2", "test")
        assert r1 != r2

    def test_special_chars_cleaned(self):
        result = _url_to_filename("https://a.com", "My Challenge! (2024)")
        # Special chars should be replaced with underscores
        assert "!" not in result
        assert "(" not in result
        assert " " not in result

    def test_long_name_truncated(self):
        long_name = "a" * 200
        result = _url_to_filename("https://a.com", long_name)
        # Name portion should be truncated to 50 chars
        name_part = result.rsplit("_", 1)[0]
        assert len(name_part) <= 50

    def test_empty_challenge_name(self):
        result = _url_to_filename("https://a.com", "")
        expected_hash = hashlib.sha256(b"https://a.com").hexdigest()[:12]
        assert result == f"{expected_hash}.md"
