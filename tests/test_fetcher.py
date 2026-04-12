"""Tests for fetcher utility functions."""

import hashlib

from ctf_playbook.services.fetcher import _url_to_filename, is_useful_writeup


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


class TestIsUsefulWriteup:
    def test_rejects_short_content(self):
        assert not is_useful_writeup("just a link https://example.com")
        assert not is_useful_writeup("x" * 50)
        assert not is_useful_writeup("")

    def test_accepts_real_writeup(self):
        content = (
            "# Baby PWN - CTF 2024\n\n"
            "This challenge gives us a binary with a buffer overflow vulnerability.\n"
            "First, we check the protections with checksec and find no PIE, no canary.\n"
            "We use gdb to find the offset to the return address is 72 bytes.\n"
            "Then we build a ROP chain to call system('/bin/sh').\n\n"
            "```python\nfrom pwn import *\np = remote('host', 1337)\n"
            "payload = b'A' * 72 + p64(pop_rdi) + p64(binsh) + p64(system)\n"
            "p.sendline(payload)\np.interactive()\n```\n"
        )
        assert is_useful_writeup(content)

    def test_rejects_link_index(self):
        """The ctf-wiki style link-only index pages."""
        content = (
            "- 题目名称 BelluminarBank\n"
            "    - 题目链接 https://github.com/beched/ctf/tree/master/2018/wctf\n"
            "    - WP 链接 https://github.com/beched/ctf/tree/master/2018/wctf\n"
            "- 题目名称 AnotherChall\n"
            "    - 题目链接 https://github.com/example/repo\n"
            "    - WP 链接 https://github.com/example/repo\n"
            "- 题目名称 ThirdChall\n"
            "    - 题目链接 https://github.com/example/third\n"
            "    - WP 链接 https://github.com/example/third\n"
        )
        assert not is_useful_writeup(content)

    def test_rejects_single_url(self):
        content = "https://ropsten.etherscan.io/address/0x7caa18D765e5B4c3BF0831137923841FE3e7258a#code"
        assert not is_useful_writeup(content)

    def test_accepts_writeup_with_some_links(self):
        """Real writeups often have a few links mixed with prose."""
        content = (
            "# Challenge Writeup\n\n"
            "Source: https://example.com/challenge\n\n"
            "We start by analyzing the binary. The main function reads input\n"
            "with gets() into a stack buffer of 64 bytes. Since there's no\n"
            "canary and PIE is disabled, we can overflow the return address.\n\n"
            "We use ROPgadget to find useful gadgets and build our chain.\n"
            "The final exploit sends 72 bytes of padding followed by the\n"
            "ROP chain to pop a shell. Flag: CTF{buffer_overflow_101}\n"
        )
        assert is_useful_writeup(content)

    def test_rejects_table_of_contents(self):
        content = (
            "# Real World CTF 6th\n\n"
            "Team: player1, player2\n\n"
            "### Table of contents\n"
            "* [Challenge 1 (crypto)](challenge1)\n"
            "* [Challenge 2 (pwn)](challenge2)\n"
            "* [Challenge 3 (web)](challenge3)\n"
        )
        assert not is_useful_writeup(content)
