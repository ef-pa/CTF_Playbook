"""Tests for the shared CTF title parser."""

from ctf_playbook.scrapers._title_parser import parse_ctf_title, is_writeup_title


class TestIsWriteupTitle:
    def test_writeup_keyword(self):
        assert is_writeup_title("[Writeup] picoCTF 2024 - buffer overflow")
        assert is_writeup_title("My CTF walkthrough")
        assert is_writeup_title("ASIS CTF solution")

    def test_not_a_writeup(self):
        assert not is_writeup_title("Best restaurants in New York")
        assert not is_writeup_title("Python programming tutorial")

    def test_case_insensitive(self):
        assert is_writeup_title("WRITEUP for a hard challenge")
        assert is_writeup_title("ctf Challenge Solved")


class TestParseCTFTitle:
    def test_tagged_title(self):
        result = parse_ctf_title("[Writeup] picoCTF 2024 - Crypto - RSA Challenge")
        assert "picoCTF" in result["event_name"]
        assert result["year"] == 2024
        assert result["category"] == "crypto"
        assert result["challenge_name"] == "RSA Challenge"

    def test_simple_event_challenge(self):
        result = parse_ctf_title("ASIS CTF 2023 - baby_rop writeup")
        assert result["event_name"] == "ASIS CTF 2023"
        assert result["challenge_name"] is not None
        assert result["year"] == 2023

    def test_no_separators(self):
        result = parse_ctf_title("Simple CTF challenge writeup")
        assert result["challenge_name"] is not None

    def test_year_extraction(self):
        result = parse_ctf_title("Some event 2025 challenge")
        assert result["year"] == 2025

    def test_no_year(self):
        result = parse_ctf_title("Some CTF writeup")
        assert result["year"] is None

    def test_pipe_separator(self):
        result = parse_ctf_title("HackTheBox | baby_overflow")
        assert result["event_name"] == "HackTheBox"
        assert result["challenge_name"] == "baby_overflow"

    def test_dash_separator(self):
        result = parse_ctf_title("DiceCTF 2024 - Web - magic_login")
        assert "DiceCTF" in result["event_name"]
        assert result["category"] == "web"
        assert result["challenge_name"] == "magic_login"

    def test_empty_title(self):
        result = parse_ctf_title("")
        assert result["challenge_name"] is not None or result["challenge_name"] == ""

    def test_only_year(self):
        result = parse_ctf_title("2024")
        # Year gets stripped from parts, should handle gracefully
        assert result["year"] == 2024

    def test_strip_writeup_noise(self):
        result = parse_ctf_title("[Writeup] EventCTF - challenge_name solution")
        assert "writeup" not in (result["challenge_name"] or "").lower()
