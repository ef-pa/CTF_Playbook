"""Discover CTF writeups from curated blog RSS/Atom feeds.

Maintains a list of known CTF team and player blogs. Parses their
RSS/Atom feeds to index writeup posts.
"""

import time
from typing import Optional

import requests
from lxml import etree
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ctf_playbook.config import BLOG_DELAY
from ctf_playbook.db import db_session, upsert_event, upsert_challenge, insert_writeup
from ctf_playbook.scrapers._title_parser import parse_ctf_title, is_writeup_title

console = Console()

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "CTF-Playbook-Builder/1.0 (RSS reader; research)",
})

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


def _fetch_feed(url: str) -> Optional[bytes]:
    """Download a feed with rate limiting."""
    time.sleep(BLOG_DELAY)
    try:
        resp = SESSION.get(url, timeout=15)
        if resp.status_code == 200:
            return resp.content
        console.print(f"  [yellow]HTTP {resp.status_code}[/] for {url}")
    except requests.RequestException as e:
        console.print(f"  [yellow]Feed error ({url}):[/] {e}")
    return None


def _parse_feed(xml_bytes: bytes) -> list[dict]:
    """Parse an RSS 2.0 or Atom feed into a list of entries."""
    entries = []
    try:
        root = etree.fromstring(xml_bytes)
    except etree.XMLSyntaxError:
        return []

    # Namespace map for Atom
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
        # Some feeds don't use namespaces
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


def index_feed(feed_config: dict, conn) -> int:
    """Fetch and parse one feed, indexing writeup entries."""
    xml = _fetch_feed(feed_config["url"])
    if not xml:
        return 0

    entries = _parse_feed(xml)
    count = 0

    for entry in entries:
        title = entry["title"]

        # Filter: must look like a writeup
        cat_hint = any(
            kw in c.lower()
            for c in entry["categories"]
            for kw in ("ctf", "writeup", "security", "hacking", "challenge")
        )
        if not is_writeup_title(title) and not cat_hint:
            continue

        parsed = parse_ctf_title(title)
        event_name = parsed["event_name"] or feed_config["name"]
        challenge_name = parsed["challenge_name"] or title
        year = parsed["year"] or 0
        category = parsed["category"]

        ctftime_id = abs(hash(f"blog:{event_name}")) % 10_000_000

        event_id = upsert_event(conn, ctftime_id, event_name, year,
                                url=feed_config["url"])
        challenge_id = upsert_challenge(conn, event_id, challenge_name, category)
        if insert_writeup(conn, challenge_id, "blog", entry["url"],
                          team=feed_config["name"]):
            count += 1

    return count


def run(max_feeds: int | None = None):
    """Main entry point: discover and index blog RSS writeups."""
    console.rule("[bold blue]Blog RSS Scraper")

    feeds = CURATED_FEEDS[:max_feeds] if max_feeds else CURATED_FEEDS

    with db_session() as conn:
        total = 0
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      console=console) as progress:
            for feed in feeds:
                task = progress.add_task(f"Fetching {feed['name']}...", total=None)
                n = index_feed(feed, conn)
                progress.update(task,
                                description=f"{feed['name']}: {n} writeups indexed")
                total += n

        console.print(f"\nTotal: [green]{total}[/] writeups from {len(feeds)} feeds")
