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


@cli.command(name="export")
@click.option("--output", "-o", default=None, help="Output path for JSON file")
def export_cmd(output):
    """Export playbook data as JSON (without generating markdown)."""
    from pathlib import Path
    from ctf_playbook.services.builder import (
        build_playbook_data, export_playbook_json,
    )

    playbook = build_playbook_data()
    if playbook:
        path = Path(output) if output else None
        export_playbook_json(playbook, path)


@cli.command(name="import")
@click.argument("input_path", type=click.Path(exists=True))
def import_cmd(input_path):
    """Import a playbook.json file for the GUI to serve."""
    import json
    import shutil
    from pathlib import Path
    from ctf_playbook.services.builder import PLAYBOOK_JSON_PATH

    src = Path(input_path)
    # Validate it's actual playbook JSON
    try:
        with open(src, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        console.print(f"[red]Invalid JSON:[/] {e}")
        return

    if "techniques" not in data:
        console.print("[red]Not a valid playbook file[/] (missing 'techniques' key)")
        return

    stats = data.get("stats", {})
    console.print(f"Importing: {stats.get('total_techniques', '?')} techniques, "
                  f"{stats.get('total_writeups', '?')} writeups")

    PLAYBOOK_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, PLAYBOOK_JSON_PATH)
    console.print(f"Imported to [green]{PLAYBOOK_JSON_PATH}[/]")


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


@cli.command()
@click.option("--limit", "-n", default=5, help="Number of writeups to compare")
@click.option("--category", "-c", default=None, help="Filter by category")
def compare(limit, category):
    """Compare Gemini classification against existing Claude results."""
    from pathlib import Path
    from ctf_playbook.config import GEMINI_API_KEY
    from ctf_playbook.services.gemini_classifier import classify_writeup_gemini

    if not GEMINI_API_KEY:
        console.print("[red]Set GEMINI_API_KEY in your .env to use comparison[/]")
        return

    with db_session() as conn:
        # Get already-classified writeups with real techniques
        query = """
            SELECT w.id, w.raw_path, w.techniques, w.tools_used, w.difficulty,
                   w.notes, c.name as challenge_name, c.category
            FROM writeups w
            JOIN challenges c ON w.challenge_id = c.id
            WHERE w.class_status = 'classified'
              AND w.raw_path IS NOT NULL
              AND w.techniques != '[]'
        """
        params = []
        if category:
            query += " AND c.category = ?"
            params.append(category)
        query += " ORDER BY RANDOM() LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()

        if not rows:
            console.print("[yellow]No classified writeups found to compare[/]")
            return

        # Avoid Windows cp1252 encoding crashes on special characters
        import io, os
        if os.name == "nt":
            console.file = io.TextIOWrapper(
                console.file.buffer, encoding="utf-8", errors="replace",
            )

        console.rule("[bold blue]Claude vs Gemini Comparison")
        console.print(f"Comparing {len(rows)} writeups\n")

        # Track agreement scores
        tech_matches = 0
        diff_matches = 0
        tool_overlaps = []
        total = 0

        for row in rows:
            raw_path = row["raw_path"]
            if not raw_path or not Path(raw_path).exists():
                console.print(f"  [dim]Skipping {row['challenge_name']} (missing file)[/]")
                continue

            content = Path(raw_path).read_text(encoding="utf-8", errors="replace")
            if len(content.strip()) < 50:
                continue

            # Claude's existing results
            claude_techs = json.loads(row["techniques"])
            claude_tools = set(json.loads(row["tools_used"]))
            claude_diff = row["difficulty"]

            # Gemini's fresh classification
            console.print(f"[bold cyan]{row['challenge_name']}[/] ({row['category'] or '?'})")
            result = classify_writeup_gemini(
                content, row["challenge_name"], row["category"] or "",
            )

            if not result:
                console.print("  [red]Gemini failed to classify[/]\n")
                continue

            gemini_techs = result.technique_slugs
            gemini_tools = set(result.tools_used)
            gemini_diff = result.difficulty

            total += 1

            # Compare techniques
            claude_set = set(claude_techs)
            gemini_set = set(gemini_techs)
            tech_overlap = claude_set & gemini_set
            if tech_overlap:
                tech_matches += 1

            # Compare difficulty
            diff_match = claude_diff == gemini_diff
            if diff_match:
                diff_matches += 1

            # Compare tools
            if claude_tools or gemini_tools:
                overlap = len(claude_tools & gemini_tools)
                union = len(claude_tools | gemini_tools)
                tool_overlaps.append(overlap / union if union else 0)

            # Display comparison
            tech_indicator = "[green]MATCH[/]" if tech_overlap else "[red]DIFF[/]"
            diff_indicator = "[green]MATCH[/]" if diff_match else "[red]DIFF[/]"

            table = Table(show_header=True, box=None, padding=(0, 2))
            table.add_column("", style="dim", width=12)
            table.add_column("Claude", style="cyan")
            table.add_column("Gemini", style="yellow")
            table.add_column("", width=7)

            table.add_row(
                "Techniques",
                ", ".join(claude_techs),
                ", ".join(gemini_techs),
                tech_indicator,
            )
            table.add_row(
                "Difficulty",
                claude_diff or "?",
                gemini_diff or "?",
                diff_indicator,
            )
            table.add_row(
                "Tools",
                ", ".join(sorted(claude_tools)[:6]),
                ", ".join(sorted(gemini_tools)[:6]),
                "",
            )
            table.add_row(
                "Summary",
                (row["notes"] or "")[:80],
                (result.summary or "")[:80],
                "",
            )
            console.print(table)
            console.print()

        # Summary stats
        if total:
            console.rule("[bold]Agreement Summary")
            console.print(f"  Technique overlap: [cyan]{tech_matches}/{total}[/] ({tech_matches/total:.0%})")
            console.print(f"  Difficulty match:  [cyan]{diff_matches}/{total}[/] ({diff_matches/total:.0%})")
            if tool_overlaps:
                avg_tool = sum(tool_overlaps) / len(tool_overlaps)
                console.print(f"  Avg tool overlap:  [cyan]{avg_tool:.0%}[/] (Jaccard similarity)")
        else:
            console.print("[yellow]No writeups were successfully compared[/]")


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
