"""Tests for the blog RSS feed parser."""

from ctf_playbook.scrapers.blogs import _parse_feed


RSS_SAMPLE = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>CTF Blog</title>
    <item>
      <title>picoCTF 2024 - Crypto - RSA writeup</title>
      <link>https://blog.example.com/pico-rsa</link>
      <pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate>
      <category>ctf</category>
      <category>writeup</category>
    </item>
    <item>
      <title>My vacation photos</title>
      <link>https://blog.example.com/vacation</link>
      <pubDate>Tue, 02 Jan 2024 00:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>"""

ATOM_SAMPLE = b"""<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>CTF Blog</title>
  <entry>
    <title>HackTheBox - binary_rain walkthrough</title>
    <link rel="alternate" href="https://blog.example.com/htb-rain"/>
    <category term="ctf"/>
  </entry>
</feed>"""


class TestParseFeed:
    def test_rss(self):
        entries = _parse_feed(RSS_SAMPLE)
        assert len(entries) == 2
        assert entries[0]["title"] == "picoCTF 2024 - Crypto - RSA writeup"
        assert entries[0]["url"] == "https://blog.example.com/pico-rsa"
        assert "ctf" in entries[0]["categories"]

    def test_atom(self):
        entries = _parse_feed(ATOM_SAMPLE)
        assert len(entries) == 1
        assert entries[0]["title"] == "HackTheBox - binary_rain walkthrough"
        assert entries[0]["url"] == "https://blog.example.com/htb-rain"

    def test_invalid_xml(self):
        entries = _parse_feed(b"not xml at all")
        assert entries == []

    def test_empty_feed(self):
        xml = b"""<?xml version="1.0"?><rss version="2.0"><channel></channel></rss>"""
        entries = _parse_feed(xml)
        assert entries == []
