#!/usr/bin/env python3
"""CTF Playbook Builder — CLI orchestrator.

Usage:
    python pipeline.py all                          # Run full pipeline
    python pipeline.py scrape [--max-events N]      # Discover writeups
    python pipeline.py scrape --source github       # GitHub only
    python pipeline.py scrape --source ctftime      # CTFtime only
    python pipeline.py fetch [--limit N]            # Download content
    python pipeline.py classify [--limit N]         # LLM classification
    python pipeline.py classify --category pwn      # Classify specific category
    python pipeline.py build                        # Generate playbook
    python pipeline.py stats                        # Show database stats
"""

import sys

import click
from rich.console import Console
from rich.table import Table

from ctf_playbook.db import init_db, db_session, get_stats

console = Console()


@click.group()
def cli():
    """CTF Playbook Builder - scrape, index, and classify CTF writeups."""
    init_db()


@cli.command()
@click.option("--max-events", default=200, help="Max events to scrape from CTFtime")
@click.option("--max-repos", default=50, help="Max repos to scan from GitHub")
@click.option("--source", type=click.Choice(["all", "ctftime", "github"]), default="all",
              help="Which source to scrape")
def scrape(max_events, max_repos, source):
    """Stage 1: Discover writeups from CTFtime and GitHub."""
    if source in ("all", "ctftime"):
        from ctf_playbook.scrapers.ctftime import run as run_ctftime
        run_ctftime(max_events=max_events)

    if source in ("all", "github"):
        from ctf_playbook.scrapers.github import run as run_github
        run_github(max_repos=max_repos)


@cli.command()
@click.option("--limit", default=500, help="Max writeups to fetch")
def fetch(limit):
    """Stage 2: Download writeup content from discovered URLs."""
    from ctf_playbook.fetcher import run as run_fetcher
    run_fetcher(limit=limit)


@cli.command()
@click.option("--limit", default=100, help="Max writeups to classify")
@click.option("--category", default=None, help="Only classify this CTF category")
def classify(limit, category):
    """Stage 3: Classify writeups using LLM analysis."""
    from ctf_playbook.classifier import run as run_classifier
    run_classifier(limit=limit, category=category)


@cli.command()
def build():
    """Stage 4: Generate the playbook folder structure."""
    from ctf_playbook.taxonomy import run as run_taxonomy
    run_taxonomy()


@cli.command()
def stats():
    """Show database statistics."""
    with db_session() as conn:
        s = get_stats(conn)

        table = Table(title="Playbook Database Stats")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="green", justify="right")

        table.add_row("Events", str(s["events"]))
        table.add_row("Challenges", str(s["challenges"]))
        table.add_row("Writeups (total)", str(s["writeups_total"]))
        table.add_row("Writeups (fetched)", str(s["writeups_fetched"]))
        table.add_row("Writeups (classified)", str(s["writeups_classified"]))
        table.add_row("Pending fetch", str(s["writeups_pending_fetch"]))
        table.add_row("Pending classification", str(s["writeups_pending_class"]))

        console.print(table)

        # Category breakdown
        cats = conn.execute("""
            SELECT COALESCE(c.category, 'unknown') as cat, COUNT(*) as cnt
            FROM writeups w
            JOIN challenges c ON w.challenge_id = c.id
            GROUP BY cat ORDER BY cnt DESC LIMIT 15
        """).fetchall()

        if cats:
            cat_table = Table(title="Writeups by Category")
            cat_table.add_column("Category", style="cyan")
            cat_table.add_column("Count", style="green", justify="right")
            for row in cats:
                cat_table.add_row(row["cat"], str(row["cnt"]))
            console.print(cat_table)

        # Technique breakdown (if any classified)
        if s["writeups_classified"] > 0:
            import json
            from collections import Counter
            tech_counter = Counter()
            rows = conn.execute(
                "SELECT techniques FROM writeups WHERE class_status='classified'"
            ).fetchall()
            for row in rows:
                techs = json.loads(row["techniques"]) if row["techniques"] else []
                tech_counter.update(techs)

            if tech_counter:
                tech_table = Table(title="Top Techniques (classified writeups)")
                tech_table.add_column("Technique", style="cyan")
                tech_table.add_column("Count", style="green", justify="right")
                for tech, count in tech_counter.most_common(20):
                    tech_table.add_row(tech, str(count))
                console.print(tech_table)


@cli.command(name="all")
@click.option("--max-events", default=200, help="Max events for CTFtime")
@click.option("--max-repos", default=50, help="Max repos for GitHub")
@click.option("--fetch-limit", default=500, help="Max writeups to fetch")
@click.option("--classify-limit", default=100, help="Max writeups to classify")
def run_all(max_events, max_repos, fetch_limit, classify_limit):
    """Run the full pipeline: scrape -> fetch -> classify -> build."""
    console.rule("[bold magenta]CTF Playbook Builder — Full Pipeline")

    console.print("\n[bold]Stage 1/4:[/] Scraping...")
    from ctf_playbook.scrapers.ctftime import run as run_ctftime
    from ctf_playbook.scrapers.github import run as run_github
    run_ctftime(max_events=max_events)
    run_github(max_repos=max_repos)

    console.print("\n[bold]Stage 2/4:[/] Fetching content...")
    from ctf_playbook.fetcher import run as run_fetcher
    run_fetcher(limit=fetch_limit)

    console.print("\n[bold]Stage 3/4:[/] Classifying...")
    from ctf_playbook.classifier import run as run_classifier
    run_classifier(limit=classify_limit)

    console.print("\n[bold]Stage 4/4:[/] Building playbook...")
    from ctf_playbook.taxonomy import run as run_taxonomy
    run_taxonomy()

    console.rule("[bold green]Pipeline complete!")


if __name__ == "__main__":
    cli()
