"""Fetch and extract writeup content from discovered URLs.

Downloads writeup content, extracts readable text (stripping HTML chrome),
and saves as plain text/markdown files in the raw-writeups directory.
"""

import hashlib
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
import trafilatura
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ctf_playbook.config import FETCH_DELAY, FETCH_TIMEOUT, FETCH_MAX_SIZE, RAW_WRITEUPS_DIR
from ctf_playbook.db import db_session, get_unfetched, mark_fetched, mark_fetch_failed

console = Console()

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "CTF-Playbook-Builder/1.0 (research)",
    "Accept": "text/html,text/markdown,text/plain,application/json",
})

# Track per-domain timing to be respectful
_domain_last_request: dict[str, float] = {}


def _domain_delay(url: str):
    """Enforce per-domain rate limiting."""
    domain = urlparse(url).netloc
    last = _domain_last_request.get(domain, 0)
    elapsed = time.time() - last
    if elapsed < FETCH_DELAY:
        time.sleep(FETCH_DELAY - elapsed)
    _domain_last_request[domain] = time.time()


def _url_to_filename(url: str, challenge_name: str = "") -> str:
    """Generate a deterministic filename from a URL."""
    url_hash = hashlib.sha256(url.encode()).hexdigest()[:12]
    # Clean challenge name for use in filename
    clean_name = re.sub(r"[^a-zA-Z0-9_-]", "_", challenge_name)[:50] if challenge_name else ""
    if clean_name:
        return f"{clean_name}_{url_hash}.md"
    return f"{url_hash}.md"


def fetch_github_raw(url: str) -> str | None:
    """Fetch raw content from a GitHub raw URL or regular GitHub URL."""
    # Convert github.com URLs to raw.githubusercontent.com
    if "github.com" in url and "raw.githubusercontent.com" not in url:
        # Convert blob URLs: github.com/user/repo/blob/branch/path
        # to raw: raw.githubusercontent.com/user/repo/branch/path
        raw_url = url.replace("github.com", "raw.githubusercontent.com")
        raw_url = raw_url.replace("/blob/", "/")
    else:
        raw_url = url

    try:
        _domain_delay(raw_url)
        resp = SESSION.get(raw_url, timeout=FETCH_TIMEOUT)
        if resp.status_code == 200 and len(resp.content) < FETCH_MAX_SIZE:
            return resp.text
    except requests.RequestException:
        pass
    return None


def fetch_webpage(url: str) -> str | None:
    """Fetch a webpage and extract its main content as text."""
    try:
        _domain_delay(url)
        resp = SESSION.get(url, timeout=FETCH_TIMEOUT)
        if resp.status_code != 200 or len(resp.content) > FETCH_MAX_SIZE:
            return None

        content_type = resp.headers.get("content-type", "")

        # If it's already markdown or plain text, return as-is
        if "text/markdown" in content_type or "text/plain" in content_type:
            return resp.text

        # For HTML, extract the main content
        if "text/html" in content_type or "<html" in resp.text[:500].lower():
            extracted = trafilatura.extract(
                resp.text,
                include_comments=False,
                include_tables=True,
                output_format="txt",
            )
            if extracted and len(extracted) > 100:  # skip near-empty extractions
                return extracted

            # Fallback: trafilatura failed, try a simple extraction
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "lxml")
            # Remove script/style tags
            for tag in soup(["script", "style", "nav", "header", "footer"]):
                tag.decompose()
            text = soup.get_text(separator="\n", strip=True)
            if len(text) > 200:
                return text

        # For JSON (some APIs return writeups as JSON)
        if "application/json" in content_type:
            import json
            try:
                data = resp.json()
                # Try common fields
                for field in ("content", "body", "text", "description"):
                    if field in data and isinstance(data[field], str):
                        return data[field]
            except json.JSONDecodeError:
                pass

        return resp.text if len(resp.text) > 100 else None

    except requests.RequestException:
        return None


def is_useful_writeup(content: str) -> bool:
    """Check if fetched content is an actual writeup, not an index or link dump.

    Rejects:
    - Content under 200 chars (too short to be a real writeup)
    - Content that's mostly URLs with little prose
    """
    text = content.strip()
    if len(text) < 200:
        return False

    # Count lines vs lines that are just URLs or bullet-pointed links
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        return False

    link_line = re.compile(
        r"^\s*[-*]?\s*("
        r"https?://\S+"              # bare URL
        r"|.*https?://\S+\s*$"       # line ending with a URL
        r"|题目|WP\s"                 # Chinese index labels
        r"|\[.*\]\(.*\)\s*$"         # markdown link-only line
        r"|\*\s*\[.*\]\(.*\)"        # bullet + markdown link
        r")",
        re.IGNORECASE,
    )
    link_lines = sum(1 for l in lines if link_line.match(l))

    # If more than 60% of non-empty lines are just links, it's an index
    if len(lines) > 0 and link_lines / len(lines) > 0.6:
        return False

    return True


def fetch_writeup(url: str) -> str | None:
    """Fetch a writeup from any URL, dispatching to the right method."""
    domain = urlparse(url).netloc.lower()

    if "github" in domain or "raw.githubusercontent.com" in domain:
        content = fetch_github_raw(url)
        if content:
            return content

    if "ctftime.org" in domain:
        # CTFtime writeup pages contain the writeup inline sometimes
        content = fetch_webpage(url)
        if content:
            return content

    # Generic webpage fetch
    return fetch_webpage(url)


def run(limit: int = 500):
    """Main entry point: fetch unfetched writeups and save them."""
    console.rule("[bold blue]Writeup Fetcher")

    RAW_WRITEUPS_DIR.mkdir(parents=True, exist_ok=True)

    with db_session() as conn:
        unfetched = get_unfetched(conn, limit=limit)
        console.print(f"Found [yellow]{len(unfetched)}[/] unfetched writeups")

        if not unfetched:
            console.print("[green]Nothing to fetch!")
            return

        success = 0
        failed = 0

        with Progress(SpinnerColumn(),
                      TextColumn("[progress.description]{task.description}"),
                      BarColumn(), console=console) as progress:
            task = progress.add_task("Fetching...", total=len(unfetched))

            for row in unfetched:
                writeup_id = row["id"]
                url = row["url"]
                challenge_name = row["challenge_name"] or ""

                content = fetch_writeup(url)

                # Retry once on failure
                if not content or not is_useful_writeup(content):
                    time.sleep(FETCH_DELAY)
                    content = fetch_writeup(url)

                if content and is_useful_writeup(content):
                    # Save to file
                    filename = _url_to_filename(url, challenge_name)
                    filepath = RAW_WRITEUPS_DIR / filename

                    # Add metadata header
                    header = (
                        f"---\n"
                        f"source_url: {url}\n"
                        f"event: {row['event_name']}\n"
                        f"challenge: {challenge_name}\n"
                        f"category: {row['category'] or 'unknown'}\n"
                        f"year: {row['year']}\n"
                        f"---\n\n"
                    )
                    full_content = header + content
                    filepath.write_text(full_content, encoding="utf-8")

                    # Hash the raw content (not header) for dedup
                    content_hash = hashlib.sha256(content.strip().encode()).hexdigest()

                    mark_fetched(conn, writeup_id, str(filepath), content_hash)
                    success += 1
                else:
                    mark_fetch_failed(conn, writeup_id)
                    failed += 1

                progress.update(
                    task, advance=1,
                    description=f"Fetching... ({success} ok, {failed} failed)"
                )

        console.print(f"\n[green]Done![/] Fetched {success}, failed {failed}")


if __name__ == "__main__":
    run(limit=100)
