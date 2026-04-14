"""Base scraper class and shared types for all CTF writeup scrapers.

Provides session management, rate-limited fetching, DB upsert pipeline,
and progress display. Subclasses implement scrape() to yield WriteupItems.
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterator

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ctf_playbook.db import (
    db_session, upsert_event, upsert_challenge, insert_writeup,
)


@dataclass
class WriteupItem:
    """Standardized output from any scraper's parsing logic."""
    event_name: str
    challenge_name: str
    writeup_url: str
    source: str
    ctftime_id: int | None = None
    year: int = 0
    category: str | None = None
    event_url: str = ""
    author: str | None = None
    team: str | None = None


def make_synthetic_id(prefix: str, name: str) -> int:
    """Generate a deterministic synthetic ctftime_id."""
    return abs(hash(f"{prefix}:{name}")) % 10_000_000


class BaseScraper(ABC):
    """Template for CTF writeup scrapers.

    Subclasses must set class attributes:
        display_name: str  — shown in console header
        source_tag: str    — DB source column value
        delay: float       — seconds between requests
        default_headers: dict — session headers

    Subclasses implement:
        scrape(conn, **kwargs) -> Iterator[WriteupItem]

    Optionally override:
        on_error_status(resp, url) — custom rate-limit handling
        _run_phases(conn, **kwargs) — multi-phase scrapers
    """

    display_name: str = "Scraper"
    source_tag: str = "unknown"
    delay: float = 1.0
    timeout: int = 15
    default_headers: dict = {}
    auth_header: tuple[str, str] | None = None

    def __init__(self):
        self.session = self._build_session()
        self.console = Console()

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update(self.default_headers)
        if self.auth_header:
            s.headers[self.auth_header[0]] = self.auth_header[1]
        return s

    def fetch(self, url: str, params: dict | None = None) -> requests.Response | None:
        """Rate-limited GET. Returns Response on 200, None on failure."""
        time.sleep(self.delay)
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout)
            if resp.status_code == 200:
                return resp
            self.on_error_status(resp, url)
        except requests.RequestException as e:
            self.console.print(f"  [red]Error[/]: {e}")
        return None

    def on_error_status(self, resp: requests.Response, url: str):
        """Hook for subclass-specific error handling (403, 429, etc.)."""
        self.console.print(f"  [yellow]HTTP {resp.status_code}[/] for {url}")

    def _store_item(self, conn, item: WriteupItem) -> bool:
        """Run the DB upsert pipeline for one item. Returns True if inserted."""
        ctftime_id = item.ctftime_id
        if ctftime_id is None:
            ctftime_id = make_synthetic_id(item.source, item.event_name)

        event_id = upsert_event(conn, ctftime_id, item.event_name,
                                item.year, item.event_url)
        challenge_id = upsert_challenge(conn, event_id, item.challenge_name,
                                        item.category)
        return insert_writeup(conn, challenge_id, item.source, item.writeup_url,
                              item.author, item.team) is not None

    @abstractmethod
    def scrape(self, conn, **kwargs) -> Iterator[WriteupItem]:
        """Yield WriteupItems. Called inside db_session + Progress context."""
        ...

    def _run_phases(self, conn, **kwargs) -> int:
        """Default single-phase implementation. Override for multi-phase scrapers."""
        total = 0
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      console=self.console) as progress:
            task = progress.add_task(f"Running {self.display_name}...", total=None)
            for item in self.scrape(conn, **kwargs):
                if self._store_item(conn, item):
                    total += 1
                progress.update(task,
                                description=f"{self.display_name}: {total} writeups")
        return total

    def run(self, **kwargs):
        """Standard entry point: console header, db session, progress, totals."""
        self.console.rule(f"[bold blue]{self.display_name}")
        with db_session() as conn:
            total = self._run_phases(conn, **kwargs)
            self.console.print(f"\n[green]Done![/] {total} new writeups indexed")
