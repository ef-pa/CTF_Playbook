"""Scrape CTFtime for events, challenges, and writeup links.

Iterates through CTFtime events in reverse chronological order, extracts
challenge lists and writeup URLs, and stores everything in the index DB.
"""

import re
import time
from typing import Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ctf_playbook.config import CTFTIME_BASE, CTFTIME_DELAY, CTFTIME_USER_AGENT
from ctf_playbook.db import (
    db_session, upsert_event, upsert_challenge, insert_writeup, get_stats
)

console = Console()

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": CTFTIME_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml",
})


def _get(url: str) -> Optional[BeautifulSoup]:
    """Fetch a URL and return parsed soup, or None on failure."""
    try:
        time.sleep(CTFTIME_DELAY)
        resp = SESSION.get(url, timeout=15)
        if resp.status_code == 200:
            return BeautifulSoup(resp.text, "lxml")
        console.print(f"  [yellow]HTTP {resp.status_code}[/] for {url}")
    except requests.RequestException as e:
        console.print(f"  [red]Error[/] fetching {url}: {e}")
    return None


def get_recent_event_ids(max_events: int = 200) -> list[int]:
    """Get event IDs from CTFtime's event listing pages (most recent first).

    CTFtime lists past events at /event/list/past with pagination.
    Each page shows ~50 events.
    """
    event_ids = []
    page = 1

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), console=console) as progress:
        task = progress.add_task("Discovering events...", total=max_events)

        while len(event_ids) < max_events:
            url = f"{CTFTIME_BASE}/event/list/past?page={page}"
            soup = _get(url)
            if not soup:
                break

            # Event links look like /event/1234
            links = soup.find_all("a", href=re.compile(r"^/event/\d+$"))
            if not links:
                break

            for link in links:
                eid = int(link["href"].split("/")[-1])
                if eid not in event_ids:
                    event_ids.append(eid)
                    progress.update(task, completed=len(event_ids))
                    if len(event_ids) >= max_events:
                        break

            page += 1

    console.print(f"Found [green]{len(event_ids)}[/] event IDs")
    return event_ids


def scrape_event(event_id: int, conn) -> dict:
    """Scrape a single event: metadata, challenges, and writeup links.

    Returns a summary dict with counts.
    """
    result = {"challenges": 0, "writeups": 0}

    # ── Event page ─────────────────────────────────────────────────────
    event_url = f"{CTFTIME_BASE}/event/{event_id}"
    soup = _get(event_url)
    if not soup:
        return result

    # Extract event name and year
    title_tag = soup.find("h2")
    if not title_tag:
        return result
    event_name = title_tag.get_text(strip=True)

    # Try to get year from the event date info
    year = None
    date_div = soup.find("p", class_="date")
    if date_div:
        year_match = re.search(r"20\d{2}", date_div.get_text())
        if year_match:
            year = int(year_match.group())

    db_event_id = upsert_event(conn, event_id, event_name, year or 0, event_url)

    # ── Tasks/writeups page ────────────────────────────────────────────
    tasks_url = f"{CTFTIME_BASE}/event/{event_id}/tasks/"
    soup = _get(tasks_url)
    if not soup:
        return result

    # Task rows typically contain the challenge name, category, and writeup links
    task_rows = soup.find_all("tr")
    for row in task_rows:
        cells = row.find_all("td")
        if len(cells) < 2:
            continue

        # First cell usually has the challenge name as a link
        name_link = cells[0].find("a")
        if not name_link:
            continue
        challenge_name = name_link.get_text(strip=True)

        # Category might be in a separate cell or tag
        category = None
        for cell in cells:
            cat_span = cell.find("span", class_="tag")
            if cat_span:
                category = cat_span.get_text(strip=True).lower()
                break

        # If no tag-based category, try the second cell
        if not category and len(cells) >= 2:
            cat_text = cells[1].get_text(strip=True).lower()
            if cat_text in ("pwn", "web", "crypto", "rev", "reversing", "forensics",
                            "misc", "stego", "osint", "blockchain", "hardware", "ppc"):
                category = cat_text

        db_challenge_id = upsert_challenge(conn, db_event_id, challenge_name, category)
        result["challenges"] += 1

        # Find writeup links (external links from writeup cells)
        writeup_links = row.find_all("a", href=re.compile(r"^/writeup/\d+"))
        for wlink in writeup_links:
            writeup_id = wlink["href"].split("/")[-1]
            writeup_page_url = f"{CTFTIME_BASE}/writeup/{writeup_id}"

            # Get the actual writeup page to find the external URL
            wu_soup = _get(writeup_page_url)
            if not wu_soup:
                continue

            # Look for the external link (the actual writeup)
            ext_link = wu_soup.find("a", class_="btn", href=re.compile(r"^https?://"))
            if not ext_link:
                # Fallback: find any external link in the content area
                content_div = wu_soup.find("div", class_="well") or wu_soup.find("div", id="content")
                if content_div:
                    ext_link = content_div.find("a", href=re.compile(r"^https?://"))

            url = ext_link["href"] if ext_link else writeup_page_url

            # Extract author/team info
            author = None
            team = None
            team_link = wu_soup.find("a", href=re.compile(r"/team/\d+"))
            if team_link:
                team = team_link.get_text(strip=True)

            inserted = insert_writeup(conn, db_challenge_id, "ctftime", url, author, team)
            if inserted:
                result["writeups"] += 1

    return result


def scrape_writeup_list_pages(max_pages: int = 50, conn=None) -> int:
    """Alternative approach: scrape CTFtime's writeup listing pages directly.

    /writeups/ lists recent writeups across all events. This is faster than
    going event-by-event and catches writeups that might not be linked from
    event pages.
    """
    total = 0

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as progress:
        task = progress.add_task("Scraping writeup listing pages...", total=max_pages)

        for page in range(1, max_pages + 1):
            url = f"{CTFTIME_BASE}/writeups?page={page}&hidden=0"
            soup = _get(url)
            if not soup:
                break

            writeup_divs = soup.find_all("div", class_="writeup-card") or \
                           soup.find_all("div", class_="span10")
            if not writeup_divs:
                # Try finding writeup links directly
                writeup_links = soup.find_all("a", href=re.compile(r"^/writeup/\d+"))
                if not writeup_links:
                    break

                for link in writeup_links:
                    # Parse the surrounding context for metadata
                    parent = link.find_parent("tr") or link.find_parent("div")
                    if not parent:
                        continue

                    challenge_name = link.get_text(strip=True)
                    if not challenge_name:
                        continue

                    # Find event info
                    event_link = parent.find("a", href=re.compile(r"/event/\d+"))
                    event_name = "Unknown Event"
                    event_ctftime_id = 0
                    if event_link:
                        event_name = event_link.get_text(strip=True)
                        eid_match = re.search(r"/event/(\d+)", event_link["href"])
                        if eid_match:
                            event_ctftime_id = int(eid_match.group(1))

                    # Find category
                    category = None
                    tags = parent.find_all("span", class_="tag")
                    for tag in tags:
                        category = tag.get_text(strip=True).lower()
                        break

                    # Build the writeup URL
                    wu_id = re.search(r"/writeup/(\d+)", link["href"])
                    if not wu_id:
                        continue
                    writeup_url = f"{CTFTIME_BASE}/writeup/{wu_id.group(1)}"

                    # Store in DB
                    db_event_id = upsert_event(
                        conn, event_ctftime_id or hash(event_name) % 100000,
                        event_name, 0, ""
                    )
                    db_challenge_id = upsert_challenge(conn, db_event_id, challenge_name, category)
                    if insert_writeup(conn, db_challenge_id, "ctftime", writeup_url):
                        total += 1

            progress.update(task, completed=page)

    console.print(f"Found [green]{total}[/] writeups from listing pages")
    return total


def run(max_events: int = 200):
    """Main entry point: discover and index CTFtime writeups."""
    console.rule("[bold blue]CTFtime Scraper")

    with db_session() as conn:
        # Approach 1: Scrape writeup listing pages (faster, broader)
        console.print("\n[bold]Phase 1:[/] Scraping writeup listing pages...")
        scrape_writeup_list_pages(max_pages=max_events // 4, conn=conn)

        # Approach 2: Scrape individual events (more structured)
        console.print("\n[bold]Phase 2:[/] Scraping individual events...")
        event_ids = get_recent_event_ids(max_events)

        total_challenges = 0
        total_writeups = 0

        with Progress(SpinnerColumn(),
                      TextColumn("[progress.description]{task.description}"),
                      BarColumn(), console=console) as progress:
            task = progress.add_task("Scraping events...", total=len(event_ids))

            for eid in event_ids:
                result = scrape_event(eid, conn)
                total_challenges += result["challenges"]
                total_writeups += result["writeups"]
                progress.update(task, advance=1,
                                description=f"Events... ({total_writeups} writeups found)")

        console.print(f"\n[green]Done![/] {total_challenges} challenges, "
                      f"{total_writeups} new writeups indexed")
        stats = get_stats(conn)
        console.print(f"Database totals: {stats}")


if __name__ == "__main__":
    from ctf_playbook.db import init_db
    init_db()
    run(max_events=100)
