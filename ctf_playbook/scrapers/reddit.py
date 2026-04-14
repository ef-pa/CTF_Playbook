"""Discover CTF writeups from Reddit.

Uses Reddit's public JSON API (append .json to any URL) to search for
writeup posts across CTF-related subreddits. No authentication required.
"""

import time
from typing import Optional

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ctf_playbook.config import REDDIT_DELAY, REDDIT_SUBREDDITS, REDDIT_MIN_SCORE
from ctf_playbook.db import db_session, upsert_event, upsert_challenge, insert_writeup
from ctf_playbook.scrapers._title_parser import parse_ctf_title, is_writeup_title

console = Console()

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "CTF-Playbook-Builder/1.0 (research; respectful scraping)",
})


def _reddit_get(url: str, params: dict | None = None) -> Optional[dict]:
    """Fetch a Reddit JSON endpoint with rate limiting."""
    time.sleep(REDDIT_DELAY)
    try:
        resp = SESSION.get(url, params=params, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 429:
            console.print("[red]Reddit rate limited[/] — backing off 60s")
            time.sleep(60)
            return None
        console.print(f"  [yellow]HTTP {resp.status_code}[/] for {url}")
    except requests.RequestException as e:
        console.print(f"  [red]Error[/]: {e}")
    return None


def _extract_writeup_url(post: dict) -> str:
    """Get the best writeup URL from a Reddit post.

    If the post links externally, use that URL.
    If it's a self-post, use the Reddit permalink.
    """
    if post.get("is_self", False):
        return f"https://reddit.com{post.get('permalink', '')}"
    return post.get("url", f"https://reddit.com{post.get('permalink', '')}")


def search_subreddit(subreddit: str, max_posts: int, conn) -> int:
    """Search a subreddit for writeup posts and index them."""
    count = 0
    after = None

    while count < max_posts:
        params = {
            "limit": 100,
            "sort": "new",
            "t": "all",
        }
        if after:
            params["after"] = after

        data = _reddit_get(
            f"https://www.reddit.com/r/{subreddit}/search.json",
            params={**params, "q": "writeup OR write-up OR walkthrough", "restrict_sr": "1"},
        )
        if not data or "data" not in data:
            break

        listing = data["data"]
        children = listing.get("children", [])
        if not children:
            break

        for child in children:
            post = child.get("data", {})
            title = post.get("title", "")
            score = post.get("score", 0)

            # Filter: must be writeup-related and meet score threshold
            if score < REDDIT_MIN_SCORE:
                continue
            if not is_writeup_title(title):
                continue

            # Parse title for structured metadata
            parsed = parse_ctf_title(title)
            event_name = parsed["event_name"] or f"r/{subreddit}"
            challenge_name = parsed["challenge_name"] or title
            year = parsed["year"] or 0
            category = parsed["category"]

            writeup_url = _extract_writeup_url(post)

            # Synthetic event ID (same pattern as GitHub scraper)
            ctftime_id = abs(hash(f"reddit:{event_name}")) % 10_000_000

            event_id = upsert_event(conn, ctftime_id, event_name, year,
                                    url=f"https://reddit.com/r/{subreddit}")
            challenge_id = upsert_challenge(conn, event_id, challenge_name, category)
            if insert_writeup(conn, challenge_id, "reddit", writeup_url,
                              team=post.get("author", "")):
                count += 1

            if count >= max_posts:
                break

        after = listing.get("after")
        if not after:
            break

    return count


def run(max_posts: int = 500):
    """Main entry point: discover and index Reddit CTF writeups."""
    console.rule("[bold blue]Reddit Scraper")

    with db_session() as conn:
        total = 0
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      console=console) as progress:
            for sub in REDDIT_SUBREDDITS:
                task = progress.add_task(f"Searching r/{sub}...", total=None)
                n = search_subreddit(sub, max_posts=max_posts, conn=conn)
                progress.update(task, description=f"r/{sub}: {n} writeups indexed")
                total += n

        console.print(f"\nTotal: [green]{total}[/] writeups from Reddit")
