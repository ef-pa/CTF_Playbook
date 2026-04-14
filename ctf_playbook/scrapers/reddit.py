"""Discover CTF writeups from Reddit.

Uses Reddit's public JSON API (append .json to any URL) to search for
writeup posts across CTF-related subreddits. No authentication required.
"""

import time
from typing import Iterator

import requests

from ctf_playbook.config import REDDIT_DELAY, REDDIT_SUBREDDITS, REDDIT_MIN_SCORE
from ctf_playbook.scrapers._base import BaseScraper, WriteupItem, make_synthetic_id
from ctf_playbook.scrapers._title_parser import parse_ctf_title, is_writeup_title


def _extract_writeup_url(post: dict) -> str:
    """Get the best writeup URL from a Reddit post."""
    if post.get("is_self", False):
        return f"https://reddit.com{post.get('permalink', '')}"
    return post.get("url", f"https://reddit.com{post.get('permalink', '')}")


class RedditScraper(BaseScraper):
    display_name = "Reddit Scraper"
    source_tag = "reddit"
    delay = REDDIT_DELAY
    default_headers = {
        "User-Agent": "CTF-Playbook-Builder/1.0 (research; respectful scraping)",
    }

    def on_error_status(self, resp: requests.Response, url: str):
        if resp.status_code == 429:
            self.console.print("[red]Reddit rate limited[/] — backing off 60s")
            time.sleep(60)
        else:
            super().on_error_status(resp, url)

    def _search_subreddit(self, subreddit: str,
                          max_posts: int) -> Iterator[WriteupItem]:
        """Search one subreddit for writeup posts."""
        count = 0
        after = None

        while count < max_posts:
            params = {
                "q": "writeup OR write-up OR walkthrough",
                "restrict_sr": "1",
                "limit": 100,
                "sort": "new",
                "t": "all",
            }
            if after:
                params["after"] = after

            resp = self.fetch(
                f"https://www.reddit.com/r/{subreddit}/search.json",
                params=params,
            )
            if not resp:
                break

            data = resp.json()
            if "data" not in data:
                break

            listing = data["data"]
            children = listing.get("children", [])
            if not children:
                break

            for child in children:
                post = child.get("data", {})
                title = post.get("title", "")
                score = post.get("score", 0)

                if score < REDDIT_MIN_SCORE:
                    continue
                if not is_writeup_title(title):
                    continue

                parsed = parse_ctf_title(title)
                event_name = parsed["event_name"] or f"r/{subreddit}"

                yield WriteupItem(
                    event_name=event_name,
                    challenge_name=parsed["challenge_name"] or title,
                    writeup_url=_extract_writeup_url(post),
                    source="reddit",
                    ctftime_id=make_synthetic_id("reddit", event_name),
                    year=parsed["year"] or 0,
                    category=parsed["category"],
                    event_url=f"https://reddit.com/r/{subreddit}",
                    team=post.get("author", ""),
                )

                count += 1
                if count >= max_posts:
                    break

            after = listing.get("after")
            if not after:
                break

    def scrape(self, conn, max_posts: int = 500,
               **kwargs) -> Iterator[WriteupItem]:
        for sub in REDDIT_SUBREDDITS:
            self.console.print(f"  Searching [cyan]r/{sub}[/]...")
            yield from self._search_subreddit(sub, max_posts)


def run(**kwargs):
    RedditScraper().run(**kwargs)
