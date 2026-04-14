"""Discover CTF writeups from curated blog RSS/Atom feeds.

Maintains a list of known CTF team and player blogs. Parses their
RSS/Atom feeds to index writeup posts.
"""

from typing import Iterator

from lxml import etree

from ctf_playbook.config import BLOG_DELAY
from ctf_playbook.scrapers._base import BaseScraper, WriteupItem, make_synthetic_id
from ctf_playbook.scrapers._title_parser import parse_ctf_title, is_writeup_title

# Curated list of CTF blog feeds — expandable
CURATED_FEEDS = [
    {"url": "https://ctftime.org/writeups/rss/", "name": "CTFtime Writeups"},
    {"url": "https://blog.bi0s.in/feed/", "name": "bi0s"},
    {"url": "https://nandynarwhals.org/feed/", "name": "NandyNarwhals"},
    {"url": "https://0xdf.gitlab.io/feed.xml", "name": "0xdf"},
    {"url": "https://blog.cryptohack.org/feed", "name": "CryptoHack"},
    {"url": "https://ctf.zeyu2001.com/rss.xml", "name": "zeyu2001"},
    {"url": "https://blog.maple3142.net/atom.xml", "name": "maple3142"},
    {"url": "https://www.sigflag.at/feed.xml", "name": "SigFlag"},
    {"url": "https://blog.bawolff.net/feeds/posts/default", "name": "bawolff"},
]


def _parse_feed(xml_bytes: bytes) -> list[dict]:
    """Parse an RSS 2.0 or Atom feed into a list of entries."""
    entries = []
    try:
        root = etree.fromstring(xml_bytes)
    except etree.XMLSyntaxError:
        return []

    ns = {"atom": "http://www.w3.org/2005/Atom"}

    # Try RSS 2.0 first: <rss><channel><item>
    items = root.findall(".//item")
    if items:
        for item in items:
            title = item.findtext("title", "").strip()
            link = item.findtext("link", "").strip()
            pub_date = item.findtext("pubDate", "")
            categories = [c.text for c in item.findall("category") if c.text]
            if title and link:
                entries.append({
                    "title": title,
                    "url": link,
                    "published": pub_date,
                    "categories": categories,
                })
        return entries

    # Try Atom: <feed><entry>
    atom_entries = root.findall("atom:entry", ns)
    if not atom_entries:
        atom_entries = root.findall("entry")
    for entry in atom_entries:
        title = (entry.findtext("atom:title", "", ns)
                 or entry.findtext("title", "")).strip()
        link_el = entry.find("atom:link[@rel='alternate']", ns)
        if link_el is None:
            link_el = entry.find("atom:link", ns)
        if link_el is None:
            link_el = entry.find("link[@rel='alternate']")
        if link_el is None:
            link_el = entry.find("link")
        link = link_el.get("href", "") if link_el is not None else ""
        categories = [
            c.get("term", "")
            for c in entry.findall("atom:category", ns) + entry.findall("category")
            if c.get("term")
        ]
        if title and link:
            entries.append({
                "title": title,
                "url": link,
                "published": "",
                "categories": categories,
            })

    return entries


class BlogScraper(BaseScraper):
    display_name = "Blog RSS Scraper"
    source_tag = "blog"
    delay = BLOG_DELAY
    default_headers = {
        "User-Agent": "CTF-Playbook-Builder/1.0 (RSS reader; research)",
    }

    def scrape(self, conn, max_feeds: int | None = None,
               **kwargs) -> Iterator[WriteupItem]:
        feeds = CURATED_FEEDS[:max_feeds] if max_feeds else CURATED_FEEDS
        for i, feed in enumerate(feeds, 1):
            self.console.print(
                f"  Fetching feed [cyan]{feed['name']}[/] ({i}/{len(feeds)})..."
            )
            resp = self.fetch(feed["url"])
            if not resp:
                continue

            entries = _parse_feed(resp.content)
            for entry in entries:
                title = entry["title"]

                cat_hint = any(
                    kw in c.lower()
                    for c in entry["categories"]
                    for kw in ("ctf", "writeup", "security", "hacking", "challenge")
                )
                if not is_writeup_title(title) and not cat_hint:
                    continue

                parsed = parse_ctf_title(title)
                yield WriteupItem(
                    event_name=parsed["event_name"] or feed["name"],
                    challenge_name=parsed["challenge_name"] or title,
                    writeup_url=entry["url"],
                    source="blog",
                    ctftime_id=make_synthetic_id("blog",
                                                 parsed["event_name"] or feed["name"]),
                    year=parsed["year"] or 0,
                    category=parsed["category"],
                    event_url=feed["url"],
                    team=feed["name"],
                )


def run(**kwargs):
    BlogScraper().run(**kwargs)
