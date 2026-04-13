"""Orchestrate writeup classification: DB queries, concurrency, progress UI."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ctf_playbook.config import GEMINI_API_KEY
from ctf_playbook.taxonomy import TECHNIQUE_TO_CATEGORY, get_category, all_sub_slugs
from ctf_playbook.models import ClassificationResult
from ctf_playbook.db import (
    db_session, get_unclassified, mark_classified, mark_class_failed,
    infer_category, backfill_challenge_category, record_sub_technique,
)
from ctf_playbook.services.classifier import classify_writeup, TransientAPIError

console = Console()


def _prepare_row(row) -> tuple[int, str, str, str, str | None]:
    """Read and validate a writeup row for classification.

    Returns (writeup_id, content, challenge_name, category, skip_reason).
    skip_reason is None when the row is ready for classification.
    """
    writeup_id = row["id"]
    raw_path = row["raw_path"]
    challenge_name = row["challenge_name"] or ""
    cat = row["category"] or ""

    if not raw_path or not Path(raw_path).exists():
        return writeup_id, "", challenge_name, cat, "missing"

    try:
        content = Path(raw_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return writeup_id, "", challenge_name, cat, "unreadable"

    if len(content.strip()) < 50:
        return writeup_id, "", challenge_name, cat, "too_short"

    return writeup_id, content, challenge_name, cat, None


def _classify_worker(content: str, challenge_name: str,
                     category: str) -> ClassificationResult | None | TransientAPIError:
    """Worker function for concurrent classification.

    Returns the result, None for permanent failure, or a TransientAPIError.
    """
    try:
        return classify_writeup(content, challenge_name, category)
    except TransientAPIError as e:
        return e


def run(limit: int = 100, category: str = None, workers: int = 1):
    """Main entry point: classify unclassified writeups."""
    console.rule("[bold blue]Writeup Classifier")

    if not GEMINI_API_KEY:
        console.print("[red]Set GEMINI_API_KEY to use the classifier[/]")
        return

    with db_session() as conn:
        unclassified = get_unclassified(conn, limit=limit, category=category)
        console.print(f"Found [yellow]{len(unclassified)}[/] unclassified writeups")
        if workers > 1:
            console.print(f"Using [cyan]{workers}[/] concurrent workers")

        if not unclassified:
            console.print("[green]Nothing to classify!")
            return

        success = 0
        failed = 0
        skipped = 0
        consecutive_transient = 0
        max_consecutive_transient = 5 * max(workers, 1)  # scale with concurrency
        stop = False

        # Pre-filter: read files, skip bad rows before hitting the API
        ready = []  # (writeup_id, content, challenge_name, category)
        with Progress(SpinnerColumn(),
                      TextColumn("[progress.description]{task.description}"),
                      BarColumn(), console=console) as progress:
            task = progress.add_task("Classifying...", total=len(unclassified))

            for row in unclassified:
                wid, content, cname, cat, skip_reason = _prepare_row(row)
                if skip_reason == "missing":
                    conn.execute(
                        "UPDATE writeups SET fetch_status='pending', "
                        "raw_path=NULL WHERE id=?", (wid,),
                    )
                    skipped += 1
                    progress.update(task, advance=1)
                elif skip_reason:
                    mark_class_failed(conn, wid)
                    failed += 1
                    progress.update(task, advance=1)
                else:
                    ready.append((wid, content, cname, cat))

            # Classify — concurrent or sequential
            def _handle_result(wid, cname, outcome):
                nonlocal success, failed, skipped, consecutive_transient, stop

                if isinstance(outcome, TransientAPIError):
                    consecutive_transient += 1
                    skipped += 1
                    console.print(f"  [yellow]API error:[/] {outcome}")
                    if consecutive_transient >= max_consecutive_transient:
                        console.print(
                            f"\n[red]Stopping:[/] {consecutive_transient} "
                            f"API failures. Remaining writeups left as pending."
                        )
                        stop = True
                    return

                consecutive_transient = 0
                result = outcome

                if result:
                    mark_classified(
                        conn, wid,
                        techniques=result.techniques,
                        tools_used=result.tools_used,
                        solve_steps=result.solve_steps,
                        recognition=result.recognition_signals,
                        difficulty=result.difficulty,
                        notes=result.summary,
                    )

                    known_subs = all_sub_slugs()
                    for tm in result.techniques:
                        if tm.sub_technique and tm.sub_technique not in known_subs:
                            cat_for_tech = get_category(tm.technique)
                            if cat_for_tech:
                                record_sub_technique(
                                    conn, tm.sub_technique,
                                    tm.technique, cat_for_tech,
                                )

                    inferred = infer_category(
                        result.technique_slugs, TECHNIQUE_TO_CATEGORY,
                    )
                    if inferred:
                        backfill_challenge_category(conn, wid, inferred)

                    success += 1
                    techs = ", ".join(
                        f"{t.technique}/{t.sub_technique}"
                        if t.sub_technique else t.technique
                        for t in result.techniques[:3]
                    )
                    console.print(f"  [dim]{cname}[/] -> [cyan]{techs}[/]")
                else:
                    mark_class_failed(conn, wid)
                    failed += 1

                progress.update(
                    task, advance=1,
                    description=f"Classifying... ({success} ok, {failed} failed)"
                )

            if workers <= 1:
                # Sequential mode
                for wid, content, cname, cat in ready:
                    if stop:
                        break
                    outcome = _classify_worker(content, cname, cat)
                    _handle_result(wid, cname, outcome)
            else:
                # Concurrent mode
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    future_map = {}
                    for wid, content, cname, cat in ready:
                        f = executor.submit(_classify_worker, content, cname, cat)
                        future_map[f] = (wid, cname)

                    for future in as_completed(future_map):
                        if stop:
                            for f in future_map:
                                f.cancel()
                            break
                        wid, cname = future_map[future]
                        outcome = future.result()
                        _handle_result(wid, cname, outcome)

        parts = [f"Classified {success}"]
        if failed:
            parts.append(f"failed {failed}")
        if skipped:
            parts.append(f"skipped {skipped} (will retry)")
        console.print(f"\n[green]Done![/] {', '.join(parts)}")


if __name__ == "__main__":
    run(limit=50)
