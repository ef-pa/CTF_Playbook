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

import json
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
    from ctf_playbook.services.fetcher import run as run_fetcher
    run_fetcher(limit=limit)


@cli.command()
@click.option("--limit", default=100, help="Max writeups to classify")
@click.option("--category", default=None, help="Only classify this CTF category")
def classify(limit, category):
    """Stage 3: Classify writeups using LLM analysis."""
    from ctf_playbook.scrapers.github import EXCLUDED_REPOS
    from ctf_playbook.db import (
        backfill_content_hashes, clean_junk_writeups, deduplicate,
    )
    from ctf_playbook.services.classifier import run as run_classifier

    console.print("[dim]Running pre-classification cleanup...[/]")
    with db_session() as conn:
        backfill_content_hashes(conn)
        cleaned = clean_junk_writeups(conn, excluded_repos=EXCLUDED_REPOS)
        removed = deduplicate(conn)
        if cleaned or removed:
            console.print(
                f"  Cleaned {cleaned} junk, removed {removed} duplicates"
            )

    run_classifier(limit=limit, category=category)


@cli.command()
def build():
    """Stage 4: Generate the playbook (JSON data + markdown files)."""
    from ctf_playbook.services.builder import run as run_builder
    run_builder()


@cli.command()
@click.option("--port", default=8080, help="Port to serve on")
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--no-browser", is_flag=True, help="Don't auto-open browser")
def serve(port, host, no_browser):
    """Launch the interactive playbook browser."""
    import uvicorn
    from ctf_playbook.gui.app import create_app

    url = f"http://{host}:{port}"
    console.print(f"Starting playbook browser at [cyan]{url}[/]")

    if not no_browser:
        import webbrowser
        webbrowser.open(url)

    uvicorn.run(create_app(), host=host, port=port, log_level="warning")


@cli.command()
@click.option("--output", "-o", default=None, help="Output path for JSON file")
def export(output):
    """Export playbook data as JSON (without generating markdown)."""
    from pathlib import Path
    from ctf_playbook.services.builder import (
        build_playbook_data, export_playbook_json,
    )

    playbook = build_playbook_data()
    if playbook:
        path = Path(output) if output else None
        export_playbook_json(playbook, path)


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
        table.add_row("Duplicates", str(s["writeups_duplicate"]))

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

            # Sub-technique stats from the join table
            sub_count = conn.execute(
                "SELECT COUNT(DISTINCT sub_technique) FROM writeup_techniques "
                "WHERE sub_technique IS NOT NULL"
            ).fetchone()[0]
            if sub_count:
                console.print(f"\nDistinct sub-techniques observed: [cyan]{sub_count}[/]")

                sub_rows = conn.execute("""
                    SELECT technique, sub_technique, COUNT(*) as cnt
                    FROM writeup_techniques
                    WHERE sub_technique IS NOT NULL
                    GROUP BY technique, sub_technique
                    ORDER BY cnt DESC LIMIT 15
                """).fetchall()
                if sub_rows:
                    sub_table = Table(title="Top Sub-Techniques")
                    sub_table.add_column("Technique", style="cyan")
                    sub_table.add_column("Sub-Technique", style="yellow")
                    sub_table.add_column("Count", style="green", justify="right")
                    for row in sub_rows:
                        sub_table.add_row(row["technique"], row["sub_technique"], str(row["cnt"]))
                    console.print(sub_table)

            # Promotion candidates
            promo_rows = conn.execute("""
                SELECT slug, parent_technique, occurrence_count
                FROM taxonomy_nodes
                WHERE promoted = 0 AND occurrence_count >= 3
                ORDER BY occurrence_count DESC LIMIT 10
            """).fetchall()
            if promo_rows:
                promo_table = Table(title="Promotion Candidates (3+ occurrences)")
                promo_table.add_column("Parent Technique", style="cyan")
                promo_table.add_column("Sub-Technique", style="yellow")
                promo_table.add_column("Occurrences", style="green", justify="right")
                for row in promo_rows:
                    promo_table.add_row(
                        row["parent_technique"], row["slug"],
                        str(row["occurrence_count"]),
                    )
                console.print(promo_table)


@cli.command(name="fix-categories")
def fix_categories():
    """Backfill challenge categories from classified technique data."""
    from ctf_playbook.db import backfill_categories
    from ctf_playbook.taxonomy import TECHNIQUE_TO_CATEGORY

    with db_session() as conn:
        updated = backfill_categories(conn, TECHNIQUE_TO_CATEGORY)
        if updated:
            console.print(f"[green]Updated {updated} challenge categories from technique data[/]")
        else:
            console.print("[green]All classified challenges already have categories[/]")


@cli.command()
def clean():
    """Re-check fetched writeups and remove junk (link indexes, too-short content, excluded repos)."""
    from ctf_playbook.scrapers.github import EXCLUDED_REPOS
    from ctf_playbook.db import clean_junk_writeups

    with db_session() as conn:
        cleaned = clean_junk_writeups(conn, excluded_repos=EXCLUDED_REPOS)
        if cleaned:
            console.print(f"[green]Cleaned {cleaned} total junk writeups[/]")
        else:
            console.print("[green]No junk found![/]")


@cli.command()
@click.argument("query", required=False)
@click.option("--technique", "-t", default=None, help="Filter by technique slug")
@click.option("--tool", default=None, help="Filter by tool name")
@click.option("--difficulty", "-d", type=click.Choice(["easy", "medium", "hard", "insane"]),
              default=None, help="Filter by difficulty")
@click.option("--limit", default=20, help="Max results to show")
def search(query, technique, tool, difficulty, limit):
    """Search classified writeups by keyword, technique, or tool."""
    from ctf_playbook.db import search_writeups

    if not any([query, technique, tool, difficulty]):
        console.print("[yellow]Provide a search query or filter (--technique, --tool, --difficulty)[/]")
        return

    with db_session() as conn:
        results = search_writeups(conn, query=query, technique=technique,
                                  tool=tool, difficulty=difficulty, limit=limit)

        if not results:
            console.print("[yellow]No matching writeups found.[/]")
            return

        console.print(f"Found [green]{len(results)}[/] matching writeups:\n")

        for row in results:
            techs = json.loads(row["techniques"]) if row["techniques"] else []
            tools = json.loads(row["tools_used"]) if row["tools_used"] else []
            steps = json.loads(row["solve_steps"]) if row["solve_steps"] else []
            signals = json.loads(row["recognition"]) if row["recognition"] else []

            console.print(f"[bold cyan]{row['challenge_name']}[/] ({row['event_name']} {row['year']})")
            console.print(f"  Difficulty: [yellow]{row['difficulty'] or '?'}[/]  |  Category: {row['category'] or '?'}")
            console.print(f"  Techniques: {', '.join(techs)}")
            if tools:
                console.print(f"  Tools: {', '.join(tools)}")
            if signals:
                console.print(f"  Recognition: {'; '.join(signals)}")
            if steps:
                console.print(f"  Solve steps:")
                for i, step in enumerate(steps, 1):
                    console.print(f"    {i}. {step}")
            if row["notes"]:
                console.print(f"  Summary: [dim]{row['notes']}[/]")
            console.print(f"  URL: {row['url']}")
            console.print()


@cli.command()
def dedup():
    """Find and remove duplicate writeups (by content hash)."""
    from ctf_playbook.db import (
        backfill_content_hashes, find_duplicates, deduplicate,
    )

    with db_session() as conn:
        backfilled = backfill_content_hashes(conn)
        if backfilled:
            console.print(f"Backfilled content hashes for [cyan]{backfilled}[/] writeups")

        dupes = find_duplicates(conn)
        if not dupes:
            console.print("[green]No duplicates found![/]")
            return

        total_dupes = sum(row["cnt"] - 1 for row in dupes)
        console.print(f"Found [yellow]{len(dupes)}[/] duplicate groups ({total_dupes} redundant writeups)")

        for row in dupes:
            console.print(f"  Hash {row['content_hash'][:12]}... -> {row['cnt']} copies (ids: {row['ids']})")

        removed = deduplicate(conn)
        console.print(f"\n[green]Marked {removed} writeups as duplicate[/]")


@cli.command(name="soft-reset")
@click.confirmation_option(prompt="This will reset all classifications to pending. Continue?")
def soft_reset():
    """Reset classified writeups to pending for re-classification."""
    from ctf_playbook.db import soft_reset_classifications

    with db_session() as conn:
        count = soft_reset_classifications(conn)
        if count:
            console.print(f"[green]Reset {count} writeups to pending for re-classification[/]")
        else:
            console.print("[green]No classified writeups to reset[/]")


@cli.command()
@click.option("--threshold", default=3, help="Minimum occurrences to propose promotion")
def promote(threshold):
    """Review discovered sub-techniques for promotion to the taxonomy."""
    from ctf_playbook.db import get_promotion_candidates, promote_sub_technique

    with db_session() as conn:
        candidates = get_promotion_candidates(conn, threshold=threshold)
        if not candidates:
            console.print("[green]No sub-techniques ready for promotion[/]")
            return

        console.print(f"Found [yellow]{len(candidates)}[/] promotion candidates:\n")

        for row in candidates:
            console.print(
                f"  [cyan]{row['parent_technique']}/{row['slug']}[/] "
                f"({row['occurrence_count']} occurrences, category: {row['category']})"
            )
            if click.confirm(f"  Promote {row['slug']}?"):
                promote_sub_technique(conn, row["slug"], row["parent_technique"])
                console.print(f"    [green]Promoted![/]")
            else:
                console.print(f"    [dim]Skipped[/]")


@cli.command(name="all")
@click.option("--max-events", default=200, help="Max events for CTFtime")
@click.option("--max-repos", default=50, help="Max repos for GitHub")
@click.option("--fetch-limit", default=500, help="Max writeups to fetch")
@click.option("--classify-limit", default=100, help="Max writeups to classify")
def run_all(max_events, max_repos, fetch_limit, classify_limit):
    """Run the full pipeline: scrape -> fetch -> clean -> classify -> build."""
    console.rule("[bold magenta]CTF Playbook Builder — Full Pipeline")

    console.print("\n[bold]Stage 1/5:[/] Scraping...")
    from ctf_playbook.scrapers.ctftime import run as run_ctftime
    from ctf_playbook.scrapers.github import run as run_github
    from ctf_playbook.scrapers.github import EXCLUDED_REPOS
    run_ctftime(max_events=max_events)
    run_github(max_repos=max_repos)

    console.print("\n[bold]Stage 2/5:[/] Fetching content...")
    from ctf_playbook.services.fetcher import run as run_fetcher
    run_fetcher(limit=fetch_limit)

    console.print("\n[bold]Stage 3/5:[/] Cleaning & deduplicating...")
    from ctf_playbook.db import (
        backfill_content_hashes, clean_junk_writeups, deduplicate,
    )
    with db_session() as conn:
        backfill_content_hashes(conn)
        cleaned = clean_junk_writeups(conn, excluded_repos=EXCLUDED_REPOS)
        removed = deduplicate(conn)
        if cleaned or removed:
            console.print(
                f"  Cleaned {cleaned} junk, removed {removed} duplicates"
            )

    console.print("\n[bold]Stage 4/5:[/] Classifying...")
    from ctf_playbook.services.classifier import run as run_classifier
    run_classifier(limit=classify_limit)

    console.print("\n[bold]Stage 5/5:[/] Building playbook...")
    from ctf_playbook.services.builder import run as run_builder
    run_builder()

    console.rule("[bold green]Pipeline complete!")


if __name__ == "__main__":
    cli()
