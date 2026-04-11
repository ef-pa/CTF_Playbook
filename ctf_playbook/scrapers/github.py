"""Discover CTF writeup repositories on GitHub.

Uses the GitHub Search API to find repos, then indexes individual writeup
files (markdown) within those repos as writeup entries.
"""

import re
import time
from typing import Optional

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ctf_playbook.config import (
    GITHUB_TOKEN, GITHUB_API, GITHUB_DELAY,
    GITHUB_SEARCH_QUERIES, GITHUB_MIN_STARS,
)
from ctf_playbook.db import (
    db_session, upsert_event, upsert_challenge, insert_writeup, get_stats
)

console = Console()

SESSION = requests.Session()
SESSION.headers.update({
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
})
if GITHUB_TOKEN:
    SESSION.headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"


def _gh_get(url: str, params: dict = None) -> Optional[dict]:
    """Make a GitHub API request with rate-limit awareness."""
    time.sleep(GITHUB_DELAY)
    try:
        resp = SESSION.get(url, params=params, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 403:
            # Rate limited — check reset time
            reset = resp.headers.get("X-RateLimit-Reset")
            console.print(f"  [red]Rate limited.[/] Reset at: {reset}")
            return None
        console.print(f"  [yellow]HTTP {resp.status_code}[/] for {url}")
    except requests.RequestException as e:
        console.print(f"  [red]Error[/]: {e}")
    return None


def search_repos(max_repos: int = 200) -> list[dict]:
    """Search GitHub for CTF writeup repositories."""
    repos = {}  # full_name -> repo data (dedup)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  console=console) as progress:
        task = progress.add_task("Searching GitHub repos...", total=None)

        for query in GITHUB_SEARCH_QUERIES:
            page = 1
            while len(repos) < max_repos and page <= 10:
                data = _gh_get(f"{GITHUB_API}/search/repositories", params={
                    "q": f"{query} in:name,description,readme",
                    "sort": "stars",
                    "order": "desc",
                    "per_page": 30,
                    "page": page,
                })
                if not data or "items" not in data:
                    break

                for repo in data["items"]:
                    if repo["stargazers_count"] >= GITHUB_MIN_STARS:
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
    console.print(f"Found [green]{len(repo_list)}[/] repos with {GITHUB_MIN_STARS}+ stars")
    return repo_list[:max_repos]


def index_repo_writeups(repo: dict, conn) -> int:
    """Walk a repo's directory tree and index markdown files as writeups.

    Looks for patterns like:
      - event-name/challenge-name/writeup.md
      - event-name/challenge-name/README.md
      - YYYY/event-name/challenge-name/...
    """
    count = 0

    # Get the repo tree (recursive)
    data = _gh_get(
        f"{GITHUB_API}/repos/{repo['full_name']}/git/trees/{repo['default_branch']}",
        params={"recursive": "1"}
    )
    if not data or "tree" not in data:
        return 0

    # Filter to markdown files that look like writeups
    md_files = [
        item for item in data["tree"]
        if item["type"] == "blob"
        and item["path"].lower().endswith((".md", ".markdown"))
        and not item["path"].lower().startswith(("license", ".github", "contributing"))
    ]

    # Try to extract event/challenge structure from paths
    # Common patterns:
    #   2024/event-name/challenge-name/README.md
    #   event-name/category/challenge-name/writeup.md
    #   challenge-name.md
    for item in md_files:
        path = item["path"]
        parts = path.split("/")

        # Skip top-level README (it's usually repo description)
        if len(parts) == 1 and parts[0].lower() in ("readme.md", "readme.markdown"):
            continue

        # Try to infer event and challenge names from path
        event_name = repo["full_name"]  # fallback
        challenge_name = "unknown"
        category = None

        if len(parts) >= 3:
            # Could be year/event/challenge/file or event/category/challenge/file
            if re.match(r"^20\d{2}$", parts[0]):
                event_name = parts[1].replace("-", " ").replace("_", " ")
                challenge_name = parts[2].replace("-", " ").replace("_", " ")
            else:
                event_name = parts[0].replace("-", " ").replace("_", " ")
                # Check if second part is a category
                if parts[1].lower() in ("pwn", "web", "crypto", "rev", "reversing",
                                         "forensics", "misc", "stego", "osint", "re",
                                         "binary", "ppc", "blockchain"):
                    category = parts[1].lower()
                    challenge_name = parts[2].replace("-", " ").replace("_", " ")
                else:
                    challenge_name = parts[1].replace("-", " ").replace("_", " ")
        elif len(parts) == 2:
            event_name = parts[0].replace("-", " ").replace("_", " ")
            challenge_name = parts[1].replace(".md", "").replace("-", " ").replace("_", " ")

        # Build the raw file URL on GitHub
        raw_url = (f"https://raw.githubusercontent.com/{repo['full_name']}/"
                   f"{repo['default_branch']}/{path}")

        # Extract year if present
        year = 0
        year_match = re.search(r"20\d{2}", path)
        if year_match:
            year = int(year_match.group())

        # Store in DB
        db_event_id = upsert_event(
            conn,
            ctftime_id=abs(hash(f"{repo['full_name']}:{event_name}")) % 10_000_000,
            name=event_name,
            year=year,
            url=repo["url"],
        )
        db_challenge_id = upsert_challenge(conn, db_event_id, challenge_name, category)
        if insert_writeup(conn, db_challenge_id, "github", raw_url,
                          team=repo["full_name"].split("/")[0]):
            count += 1

    return count


# ── Curated high-value repos ──────────────────────────────────────────────

CURATED_REPOS = [
    # These are well-known, high-quality writeup collections
    {"full_name": "ctf-wiki/ctf-wiki", "url": "https://github.com/ctf-wiki/ctf-wiki",
     "stars": 0, "default_branch": "master", "description": "CTF Wiki"},
    {"full_name": "p4-team/ctf", "url": "https://github.com/p4-team/ctf",
     "stars": 0, "default_branch": "master", "description": "p4 team writeups"},
    {"full_name": "TFNS/writeups", "url": "https://github.com/TFNS/writeups",
     "stars": 0, "default_branch": "master", "description": "TFNS writeups"},
]


def run(max_repos: int = 50):
    """Main entry point: discover and index GitHub CTF writeups."""
    console.rule("[bold blue]GitHub Scraper")

    with db_session() as conn:
        # Phase 1: Curated repos
        console.print("\n[bold]Phase 1:[/] Indexing curated repos...")
        for repo in CURATED_REPOS:
            n = index_repo_writeups(repo, conn)
            console.print(f"  {repo['full_name']}: [green]{n}[/] writeups")

        # Phase 2: Search-discovered repos
        console.print("\n[bold]Phase 2:[/] Searching for more repos...")
        repos = search_repos(max_repos)

        total = 0
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      console=console) as progress:
            task = progress.add_task("Indexing repos...", total=len(repos))

            for repo in repos:
                n = index_repo_writeups(repo, conn)
                total += n
                progress.update(task, advance=1,
                                description=f"Indexing... ({total} writeups found)")

        console.print(f"\n[green]Done![/] {total} new writeups indexed from GitHub")
        stats = get_stats(conn)
        console.print(f"Database totals: {stats}")


if __name__ == "__main__":
    from ctf_playbook.db import init_db
    init_db()
    run(max_repos=30)
