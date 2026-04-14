"""Discover CTF writeup repositories on GitHub.

Uses the GitHub Search API to find repos, then indexes individual writeup
files (markdown) within those repos as writeup entries.
"""

import re
from typing import Iterator

import requests
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ctf_playbook.config import (
    GITHUB_TOKEN, GITHUB_API, GITHUB_DELAY,
    GITHUB_SEARCH_QUERIES, GITHUB_MIN_STARS,
)
from ctf_playbook.db import get_stats
from ctf_playbook.scrapers._base import BaseScraper, WriteupItem, make_synthetic_id

# Category aliases — maps common folder names to normalized categories
CATEGORY_ALIASES = {
    "pwn": "pwn", "pwnable": "pwn", "exploitation": "pwn", "binary": "pwn",
    "binary-exploitation": "pwn", "bof": "pwn",
    "web": "web", "web-exploitation": "web", "web-security": "web",
    "crypto": "crypto", "cryptography": "crypto",
    "rev": "reverse-engineering", "reverse": "reverse-engineering",
    "reversing": "reverse-engineering", "re": "reverse-engineering",
    "reverse-engineering": "reverse-engineering",
    "forensics": "forensics", "forensic": "forensics", "dfir": "forensics",
    "misc": "misc", "miscellaneous": "misc",
    "stego": "forensics", "steganography": "forensics",
    "osint": "misc", "blockchain": "misc", "ppc": "misc",
    "hardware": "misc", "iot": "misc",
}

# ── Curated high-value repos ──────────────────────────────────────────────

CURATED_REPOS = [
    {"full_name": "p4-team/ctf", "url": "https://github.com/p4-team/ctf",
     "stars": 0, "default_branch": "master", "description": "p4 team writeups"},
    {"full_name": "TFNS/writeups", "url": "https://github.com/TFNS/writeups",
     "stars": 0, "default_branch": "master", "description": "TFNS writeups"},
]

# Repos that look like writeup collections but are actually indexes,
# challenge archives, or documentation — not actual solve writeups.
EXCLUDED_REPOS = {
    "ctf-wiki/ctf-wiki",
    "ctf-wiki/ctf-challenges",
}


class GitHubScraper(BaseScraper):
    display_name = "GitHub Scraper"
    source_tag = "github"
    delay = GITHUB_DELAY
    default_headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    def __init__(self):
        if GITHUB_TOKEN:
            self.auth_header = ("Authorization", f"Bearer {GITHUB_TOKEN}")
        super().__init__()

    def on_error_status(self, resp: requests.Response, url: str):
        if resp.status_code == 403:
            reset = resp.headers.get("X-RateLimit-Reset")
            self.console.print(f"  [red]Rate limited.[/] Reset at: {reset}")
        else:
            super().on_error_status(resp, url)

    def _get_json(self, url: str, params: dict | None = None) -> dict | None:
        """Fetch a GitHub API endpoint and return parsed JSON."""
        resp = self.fetch(url, params)
        return resp.json() if resp else None

    def _search_repos(self, max_repos: int = 200) -> list[dict]:
        """Search GitHub for CTF writeup repositories."""
        repos = {}

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      console=self.console) as progress:
            task = progress.add_task("Searching GitHub repos...", total=None)

            for query in GITHUB_SEARCH_QUERIES:
                page = 1
                while len(repos) < max_repos and page <= 10:
                    data = self._get_json(f"{GITHUB_API}/search/repositories", params={
                        "q": f"{query} in:name,description,readme",
                        "sort": "stars",
                        "order": "desc",
                        "per_page": 30,
                        "page": page,
                    })
                    if not data or "items" not in data:
                        break

                    for repo in data["items"]:
                        if (repo["stargazers_count"] >= GITHUB_MIN_STARS
                                and repo["full_name"] not in EXCLUDED_REPOS):
                            repos[repo["full_name"]] = {
                                "full_name": repo["full_name"],
                                "url": repo["html_url"],
                                "description": repo.get("description", ""),
                                "stars": repo["stargazers_count"],
                                "default_branch": repo.get("default_branch", "main"),
                            }

                    progress.update(task,
                                    description=f"Searching... ({len(repos)} repos found)")

                    if len(data["items"]) < 30:
                        break
                    page += 1

        repo_list = sorted(repos.values(), key=lambda r: r["stars"], reverse=True)
        self.console.print(f"Found [green]{len(repo_list)}[/] repos with {GITHUB_MIN_STARS}+ stars")
        return repo_list[:max_repos]

    def _index_repo(self, repo: dict, conn) -> int:
        """Walk a repo's tree and index markdown files as writeups."""
        count = 0

        data = self._get_json(
            f"{GITHUB_API}/repos/{repo['full_name']}/git/trees/{repo['default_branch']}",
            params={"recursive": "1"}
        )
        if not data or "tree" not in data:
            return 0

        md_files = [
            item for item in data["tree"]
            if item["type"] == "blob"
            and item["path"].lower().endswith((".md", ".markdown"))
            and not item["path"].lower().startswith(("license", ".github", "contributing"))
        ]

        for item in md_files:
            wi = self._parse_writeup_path(item["path"], repo)
            if wi is None:
                continue
            if self._store_item(conn, wi):
                count += 1

        return count

    def _parse_writeup_path(self, path: str, repo: dict) -> WriteupItem | None:
        """Parse a markdown file path into a WriteupItem, or None to skip."""
        parts = path.split("/")
        filename = parts[-1].lower()
        is_readme = filename in ("readme.md", "readme.markdown")

        # Skip READMEs that aren't actual challenge writeups
        if is_readme:
            if len(parts) <= 2:
                return None
            check = parts[:-1]
            if check and re.match(r"^20\d{2}$", check[0]):
                check = check[1:]
            if len(check) >= 2 and check[-1].lower() in CATEGORY_ALIASES:
                return None

        # Infer event and challenge names from path
        event_name = repo["full_name"]
        challenge_name = "unknown"
        category = None

        remaining = parts[:-1]
        year_from_path = 0
        if remaining and re.match(r"^20\d{2}$", remaining[0]):
            year_from_path = int(remaining[0])
            remaining = remaining[1:]

        if len(remaining) >= 3:
            event_name = remaining[0].replace("-", " ").replace("_", " ")
            if remaining[1].lower() in CATEGORY_ALIASES:
                category = CATEGORY_ALIASES[remaining[1].lower()]
                challenge_name = remaining[2].replace("-", " ").replace("_", " ")
            else:
                challenge_name = remaining[1].replace("-", " ").replace("_", " ")
        elif len(remaining) == 2:
            event_name = remaining[0].replace("-", " ").replace("_", " ")
            if remaining[1].lower() in CATEGORY_ALIASES:
                category = CATEGORY_ALIASES[remaining[1].lower()]
                challenge_name = filename.replace(".md", "").replace(".markdown", "")
                challenge_name = challenge_name.replace("-", " ").replace("_", " ")
            else:
                challenge_name = remaining[1].replace("-", " ").replace("_", " ")
        elif len(remaining) == 1:
            event_name = remaining[0].replace("-", " ").replace("_", " ")
            challenge_name = filename.replace(".md", "").replace(".markdown", "")
            challenge_name = challenge_name.replace("-", " ").replace("_", " ")
        elif len(remaining) == 0:
            challenge_name = filename.replace(".md", "").replace(".markdown", "")
            challenge_name = challenge_name.replace("-", " ").replace("_", " ")

        raw_url = (f"https://raw.githubusercontent.com/{repo['full_name']}/"
                   f"{repo['default_branch']}/{path}")

        year = year_from_path
        if not year:
            year_match = re.search(r"20\d{2}", path)
            if year_match:
                year = int(year_match.group())

        return WriteupItem(
            event_name=event_name,
            challenge_name=challenge_name,
            writeup_url=raw_url,
            source="github",
            ctftime_id=make_synthetic_id(repo["full_name"], event_name),
            year=year or 0,
            category=category,
            event_url=repo["url"],
            team=repo["full_name"].split("/")[0],
        )

    def scrape(self, conn, **kwargs) -> Iterator[WriteupItem]:
        """Not used directly — phases call _index_repo."""
        yield from ()

    def _run_phases(self, conn, max_repos: int = 50, **kwargs) -> int:
        total = 0

        # Phase 1: Curated repos
        self.console.print("\n[bold]Phase 1:[/] Indexing curated repos...")
        for repo in CURATED_REPOS:
            n = self._index_repo(repo, conn)
            self.console.print(f"  {repo['full_name']}: [green]{n}[/] writeups")
            total += n

        # Phase 2: Search-discovered repos
        self.console.print("\n[bold]Phase 2:[/] Searching for more repos...")
        repos = self._search_repos(max_repos)

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), console=self.console) as progress:
            task = progress.add_task("Indexing repos...", total=len(repos))
            for repo in repos:
                n = self._index_repo(repo, conn)
                total += n
                progress.update(task, advance=1,
                                description=f"Indexing... ({total} writeups found)")

        stats = get_stats(conn)
        self.console.print(f"Database totals: {stats}")
        return total


# ── Backward-compatible module-level functions ────────────────────────────

def index_repo_writeups(repo: dict, conn) -> int:
    """Wrapper for tests and external callers."""
    return GitHubScraper()._index_repo(repo, conn)


def run(**kwargs):
    GitHubScraper().run(**kwargs)
