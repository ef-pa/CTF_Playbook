"""Fetch and extract writeup content from discovered URLs.

Downloads writeup content, extracts readable text (stripping HTML chrome),
and saves as plain text/markdown files in the raw-writeups directory.
"""

import hashlib
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import requests
import trafilatura
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ctf_playbook.config import FETCH_DELAY, FETCH_TIMEOUT, FETCH_MAX_SIZE, RAW_WRITEUPS_DIR
from ctf_playbook.db import db_session, get_unfetched, mark_fetched, mark_fetch_failed, mark_fetch_retry

console = Console()

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "CTF-Playbook-Builder/1.0 (research)",
    "Accept": "text/html,text/markdown,text/plain,application/json",
})

# Track per-domain timing to be respectful (thread-safe)
_domain_lock = threading.Lock()
_domain_last_request: dict[str, float] = {}


def _domain_delay(url: str):
    """Enforce per-domain rate limiting (thread-safe)."""
    domain = urlparse(url).netloc
    with _domain_lock:
        last = _domain_last_request.get(domain, 0)
        now = time.time()
        wait = max(0, FETCH_DELAY - (now - last))
        # Reserve our time slot so the next thread for this domain waits further
        _domain_last_request[domain] = max(now, last + FETCH_DELAY)
    if wait > 0:
        time.sleep(wait)


def _url_to_filename(url: str, challenge_name: str = "") -> str:
    """Generate a deterministic filename from a URL."""
    url_hash = hashlib.sha256(url.encode()).hexdigest()[:12]
    # Clean challenge name for use in filename
    clean_name = re.sub(r"[^a-zA-Z0-9_-]", "_", challenge_name)[:50] if challenge_name else ""
    if clean_name:
        return f"{clean_name}_{url_hash}.md"
    return f"{url_hash}.md"


def fetch_github_raw(url: str) -> tuple[str | None, str | None]:
    """Fetch raw content from a GitHub raw URL or regular GitHub URL.

    Returns (content, failure_reason).
    """
    # Convert github.com URLs to raw.githubusercontent.com
    if "github.com" in url and "raw.githubusercontent.com" not in url:
        raw_url = url.replace("github.com", "raw.githubusercontent.com")
        raw_url = raw_url.replace("/blob/", "/")
    else:
        raw_url = url

    try:
        _domain_delay(raw_url)
        resp = SESSION.get(raw_url, timeout=FETCH_TIMEOUT)
        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code}"
        if len(resp.content) >= FETCH_MAX_SIZE:
            return None, f"too large ({len(resp.content)} bytes)"
        return resp.text, None
    except requests.Timeout:
        return None, "timeout"
    except requests.ConnectionError:
        return None, "connection error"
    except requests.RequestException as e:
        return None, str(e)


def fetch_webpage(url: str) -> tuple[str | None, str | None]:
    """Fetch a webpage and extract its main content as text.

    Returns (content, failure_reason).
    """
    try:
        _domain_delay(url)
        resp = SESSION.get(url, timeout=FETCH_TIMEOUT)
        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code}"
        if len(resp.content) > FETCH_MAX_SIZE:
            return None, f"too large ({len(resp.content)} bytes)"

        content_type = resp.headers.get("content-type", "")

        # If it's already markdown or plain text, return as-is
        if "text/markdown" in content_type or "text/plain" in content_type:
            return resp.text, None

        # For HTML, extract the main content
        if "text/html" in content_type or "<html" in resp.text[:500].lower():
            extracted = trafilatura.extract(
                resp.text,
                include_comments=False,
                include_tables=True,
                output_format="txt",
            )
            if extracted and len(extracted) > 100:
                return extracted, None

            # Fallback: trafilatura failed, try a simple extraction
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "lxml")
            for tag in soup(["script", "style", "nav", "header", "footer"]):
                tag.decompose()
            text = soup.get_text(separator="\n", strip=True)
            if len(text) > 200:
                return text, None

            return None, "extraction failed (no readable content)"

        # For JSON (some APIs return writeups as JSON)
        if "application/json" in content_type:
            import json
            try:
                data = resp.json()
                for field in ("content", "body", "text", "description"):
                    if field in data and isinstance(data[field], str):
                        return data[field], None
            except json.JSONDecodeError:
                pass
            return None, "JSON without recognized content field"

        if len(resp.text) > 100:
            return resp.text, None
        return None, "response too short"

    except requests.Timeout:
        return None, "timeout"
    except requests.ConnectionError:
        return None, "connection error"
    except requests.RequestException as e:
        return None, str(e)


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


def fetch_writeup(url: str) -> tuple[str | None, str | None]:
    """Fetch a writeup from any URL, dispatching to the right method.

    Returns (content, failure_reason).
    """
    domain = urlparse(url).netloc.lower()

    if "github" in domain or "raw.githubusercontent.com" in domain:
        content, reason = fetch_github_raw(url)
        if content:
            return content, None
        # Fall through to generic fetch on GitHub failure

    if "ctftime.org" in domain:
        content, reason = fetch_webpage(url)
        if content:
            return content, None
        return None, reason

    # Generic webpage fetch
    return fetch_webpage(url)


_PERMANENT_FAILURES = {
    "HTTP 404", "HTTP 403", "HTTP 410", "HTTP 451",
    "extraction failed (no readable content)",
    "JSON without recognized content field",
    "response too short",
    "not a writeup (link dump or too short)",
}


def _is_permanent(reason: str) -> bool:
    """Check if a failure reason is permanent (no point retrying)."""
    if reason in _PERMANENT_FAILURES:
        return True
    return reason.startswith("too large")


def _fetch_one(url: str) -> tuple[str | None, str | None]:
    """Fetch and validate a single writeup. Returns (content, reason)."""
    content, reason = fetch_writeup(url)

    if content and not is_useful_writeup(content):
        content, reason = None, "not a writeup (link dump or too short)"

    # Retry once on transient failures
    if not content and not _is_permanent(reason):
        time.sleep(FETCH_DELAY)
        content, reason = fetch_writeup(url)
        if content and not is_useful_writeup(content):
            content, reason = None, "not a writeup (link dump or too short)"

    return content, reason


def run(limit: int = 500, workers: int = 1):
    """Main entry point: fetch unfetched writeups and save them."""
    console.rule("[bold blue]Writeup Fetcher")

    RAW_WRITEUPS_DIR.mkdir(parents=True, exist_ok=True)

    with db_session() as conn:
        unfetched = get_unfetched(conn, limit=limit)
        console.print(f"Found [yellow]{len(unfetched)}[/] unfetched writeups")
        if workers > 1:
            console.print(f"Using [cyan]{workers}[/] concurrent workers")

        if not unfetched:
            console.print("[green]Nothing to fetch!")
            return

        success = 0
        failed = 0
        fail_reasons: dict[str, int] = {}

        def _handle_result(row, content, reason):
            nonlocal success, failed
            url = row["url"]
            challenge_name = row["challenge_name"] or ""

            if content:
                filename = _url_to_filename(url, challenge_name)
                filepath = RAW_WRITEUPS_DIR / filename

                header = (
                    f"---\n"
                    f"source_url: {url}\n"
                    f"event: {row['event_name']}\n"
                    f"challenge: {challenge_name}\n"
                    f"category: {row['category'] or 'unknown'}\n"
                    f"year: {row['year']}\n"
                    f"---\n\n"
                )
                filepath.write_text(header + content, encoding="utf-8")

                content_hash = hashlib.sha256(content.strip().encode()).hexdigest()
                mark_fetched(conn, row["id"], str(filepath), content_hash)
                conn.commit()
                success += 1
            else:
                r = reason or "unknown"
                if _is_permanent(r):
                    mark_fetch_failed(conn, row["id"])
                else:
                    mark_fetch_retry(conn, row["id"])
                conn.commit()
                failed += 1
                fail_reasons[r] = fail_reasons.get(r, 0) + 1

        with Progress(SpinnerColumn(),
                      TextColumn("[progress.description]{task.description}"),
                      BarColumn(), console=console) as progress:
            task = progress.add_task("Fetching...", total=len(unfetched))

            if workers <= 1:
                for row in unfetched:
                    content, reason = _fetch_one(row["url"])
                    _handle_result(row, content, reason)
                    progress.update(
                        task, advance=1,
                        description=f"Fetching... ({success} ok, {failed} failed)",
                    )
            else:
                executor = ThreadPoolExecutor(max_workers=workers)
                interrupted = False
                try:
                    future_map = {}
                    for row in unfetched:
                        f = executor.submit(_fetch_one, row["url"])
                        future_map[f] = row

                    for future in as_completed(future_map):
                        row = future_map[future]
                        content, reason = future.result()
                        _handle_result(row, content, reason)
                        progress.update(
                            task, advance=1,
                            description=f"Fetching... ({success} ok, {failed} failed)",
                        )
                except KeyboardInterrupt:
                    interrupted = True
                    console.print("\n[yellow]Interrupted[/]")
                finally:
                    executor.shutdown(wait=False, cancel_futures=True)
                    if interrupted:
                        conn.commit()
                        console.print(
                            f"[green]Saved progress:[/] {success} fetched"
                        )
                        os._exit(130)

        console.print(f"\n[green]Done![/] Fetched {success}, failed {failed}")
        if fail_reasons:
            console.print("\n[yellow]Failure breakdown:[/]")
            for reason, count in sorted(fail_reasons.items(), key=lambda x: -x[1]):
                console.print(f"  {reason}: {count}")


if __name__ == "__main__":
    run(limit=100)
