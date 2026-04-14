"""Scrape CTFtime for events, challenges, and writeup links.

Iterates through CTFtime events in reverse chronological order, extracts
challenge lists and writeup URLs, and stores everything in the index DB.
"""

import re
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ctf_playbook.config import CTFTIME_BASE, CTFTIME_DELAY, CTFTIME_USER_AGENT
from ctf_playbook.db import get_stats
from ctf_playbook.scrapers._base import BaseScraper, WriteupItem


class CTFtimeScraper(BaseScraper):
    display_name = "CTFtime Scraper"
    source_tag = "ctftime"
    delay = CTFTIME_DELAY
    default_headers = {
        "User-Agent": CTFTIME_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
    }

    def _get_soup(self, url: str) -> BeautifulSoup | None:
        """Fetch a URL and return parsed BeautifulSoup, or None on failure."""
        resp = self.fetch(url)
        if resp:
            return BeautifulSoup(resp.text, "lxml")
        return None

    def _get_recent_event_ids(self, max_events: int = 200) -> list[int]:
        """Get event IDs from CTFtime's event listing pages (most recent first)."""
        event_ids = []
        page = 1

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), console=self.console) as progress:
            task = progress.add_task("Discovering events...", total=max_events)

            while len(event_ids) < max_events:
                url = f"{CTFTIME_BASE}/event/list/past?page={page}"
                soup = self._get_soup(url)
                if not soup:
                    break

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

        self.console.print(f"Found [green]{len(event_ids)}[/] event IDs")
        return event_ids

    def _scrape_event(self, event_id: int, conn) -> dict:
        """Scrape a single event: metadata, challenges, and writeup links."""
        result = {"challenges": 0, "writeups": 0}

        event_url = f"{CTFTIME_BASE}/event/{event_id}"
        soup = self._get_soup(event_url)
        if not soup:
            return result

        title_tag = soup.find("h2")
        if not title_tag:
            return result
        event_name = title_tag.get_text(strip=True)

        year = None
        date_div = soup.find("p", class_="date")
        if date_div:
            year_match = re.search(r"20\d{2}", date_div.get_text())
            if year_match:
                year = int(year_match.group())

        # Store via _store_item isn't suitable here — we need the DB IDs
        # for the challenge/writeup chain, so use db functions directly.
        from ctf_playbook.db import upsert_event, upsert_challenge, insert_writeup

        db_event_id = upsert_event(conn, event_id, event_name, year or 0, event_url)

        tasks_url = f"{CTFTIME_BASE}/event/{event_id}/tasks/"
        soup = self._get_soup(tasks_url)
        if not soup:
            return result

        task_rows = soup.find_all("tr")
        for row in task_rows:
            cells = row.find_all("td")
            if len(cells) < 2:
                continue

            name_link = cells[0].find("a")
            if not name_link:
                continue
            challenge_name = name_link.get_text(strip=True)

            category = None
            for cell in cells:
                cat_span = cell.find("span", class_="tag")
                if cat_span:
                    category = cat_span.get_text(strip=True).lower()
                    break

            if not category and len(cells) >= 2:
                cat_text = cells[1].get_text(strip=True).lower()
                if cat_text in ("pwn", "web", "crypto", "rev", "reversing",
                                "forensics", "misc", "stego", "osint",
                                "blockchain", "hardware", "ppc"):
                    category = cat_text

            db_challenge_id = upsert_challenge(conn, db_event_id, challenge_name, category)
            result["challenges"] += 1

            writeup_links = row.find_all("a", href=re.compile(r"^/writeup/\d+"))
            for wlink in writeup_links:
                writeup_id = wlink["href"].split("/")[-1]
                writeup_page_url = f"{CTFTIME_BASE}/writeup/{writeup_id}"

                wu_soup = self._get_soup(writeup_page_url)
                if not wu_soup:
                    continue

                ext_link = wu_soup.find("a", class_="btn", href=re.compile(r"^https?://"))
                if not ext_link:
                    content_div = (wu_soup.find("div", class_="well")
                                   or wu_soup.find("div", id="content"))
                    if content_div:
                        ext_link = content_div.find("a", href=re.compile(r"^https?://"))

                url = ext_link["href"] if ext_link else writeup_page_url

                team = None
                team_link = wu_soup.find("a", href=re.compile(r"/team/\d+"))
                if team_link:
                    team = team_link.get_text(strip=True)

                if insert_writeup(conn, db_challenge_id, "ctftime", url, None, team):
                    result["writeups"] += 1

        return result

    def _scrape_writeup_list_pages(self, conn, max_pages: int = 50) -> int:
        """Scrape CTFtime's writeup listing pages directly.

        /writeups/ lists recent writeups across all events. Faster than
        going event-by-event and catches writeups not linked from event pages.
        """
        from ctf_playbook.db import upsert_event, upsert_challenge, insert_writeup

        total = 0

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      console=self.console) as progress:
            task = progress.add_task("Scraping writeup listing pages...", total=max_pages)

            for page in range(1, max_pages + 1):
                url = f"{CTFTIME_BASE}/writeups?page={page}&hidden=0"
                soup = self._get_soup(url)
                if not soup:
                    break

                writeup_divs = (soup.find_all("div", class_="writeup-card")
                                or soup.find_all("div", class_="span10"))
                if not writeup_divs:
                    writeup_links = soup.find_all("a", href=re.compile(r"^/writeup/\d+"))
                    if not writeup_links:
                        break

                    for link in writeup_links:
                        parent = link.find_parent("tr") or link.find_parent("div")
                        if not parent:
                            continue

                        challenge_name = link.get_text(strip=True)
                        if not challenge_name:
                            continue

                        event_link = parent.find("a", href=re.compile(r"/event/\d+"))
                        event_name = "Unknown Event"
                        event_ctftime_id = 0
                        if event_link:
                            event_name = event_link.get_text(strip=True)
                            eid_match = re.search(r"/event/(\d+)", event_link["href"])
                            if eid_match:
                                event_ctftime_id = int(eid_match.group(1))

                        category = None
                        tags = parent.find_all("span", class_="tag")
                        for tag in tags:
                            category = tag.get_text(strip=True).lower()
                            break

                        wu_id = re.search(r"/writeup/(\d+)", link["href"])
                        if not wu_id:
                            continue
                        writeup_url = f"{CTFTIME_BASE}/writeup/{wu_id.group(1)}"

                        db_event_id = upsert_event(
                            conn, event_ctftime_id or hash(event_name) % 100000,
                            event_name, 0, ""
                        )
                        db_challenge_id = upsert_challenge(
                            conn, db_event_id, challenge_name, category
                        )
                        if insert_writeup(conn, db_challenge_id, "ctftime", writeup_url):
                            total += 1

                progress.update(task, completed=page)

        self.console.print(f"Found [green]{total}[/] writeups from listing pages")
        return total

    def scrape(self, conn, **kwargs):
        """Not used directly — phases call specific methods."""
        yield from ()

    def _run_phases(self, conn, max_events: int = 200, **kwargs) -> int:
        total_writeups = 0

        # Phase 1: Scrape writeup listing pages (faster, broader)
        self.console.print("\n[bold]Phase 1:[/] Scraping writeup listing pages...")
        total_writeups += self._scrape_writeup_list_pages(
            conn, max_pages=max_events // 4
        )

        # Phase 2: Scrape individual events (more structured)
        self.console.print("\n[bold]Phase 2:[/] Scraping individual events...")
        event_ids = self._get_recent_event_ids(max_events)

        total_challenges = 0

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), console=self.console) as progress:
            task = progress.add_task("Scraping events...", total=len(event_ids))

            for eid in event_ids:
                result = self._scrape_event(eid, conn)
                total_challenges += result["challenges"]
                total_writeups += result["writeups"]
                progress.update(task, advance=1,
                                description=f"Events... ({total_writeups} writeups found)")

        stats = get_stats(conn)
        self.console.print(f"Database totals: {stats}")
        return total_writeups


def run(max_events: int = 200):
    CTFtimeScraper().run(max_events=max_events)
