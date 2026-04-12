"""Classify writeups using an LLM to extract techniques, tools, and solve patterns.

Reads fetched writeup content, sends it to Claude for structured analysis,
and stores the extracted metadata back in the database.
"""

import json
from pathlib import Path

from anthropic import Anthropic, APIConnectionError, APITimeoutError, RateLimitError
from anthropic import AuthenticationError, InternalServerError
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn


# Transient errors — the writeup itself is fine, the API is temporarily unavailable.
# These should NOT mark the writeup as failed.
_TRANSIENT_ERRORS = (APIConnectionError, APITimeoutError, RateLimitError,
                     AuthenticationError, InternalServerError)


class TransientAPIError(Exception):
    """Raised when the API fails for a reason unrelated to the writeup content."""
    pass

from ctf_playbook.config import ANTHROPIC_API_KEY, CLASSIFIER_MODEL, CLASSIFIER_MAX_TOKENS
from ctf_playbook.taxonomy import TAXONOMY, TECHNIQUE_TO_CATEGORY, get_category, all_sub_slugs
from ctf_playbook.models import ClassificationResult, TechniqueMatch
from ctf_playbook.db import (
    db_session, get_unclassified, mark_classified, mark_class_failed,
    infer_category, backfill_challenge_category, record_sub_technique,
)

console = Console()

_client: Anthropic | None = None


def _get_client() -> Anthropic | None:
    """Lazily create the Anthropic client."""
    global _client
    if _client is None and ANTHROPIC_API_KEY:
        _client = Anthropic(api_key=ANTHROPIC_API_KEY)
    return _client


def build_taxonomy_reference() -> str:
    """Build a text reference of all known techniques for the prompt."""
    lines = []
    for category, info in TAXONOMY.items():
        lines.append(f"\n## {category} — {info['description']}")
        for tech, tech_info in info["techniques"].items():
            desc = tech_info.get("description", "")
            lines.append(f"  - {tech}: {desc}" if desc else f"  - {tech}")
            for sub in tech_info.get("sub_techniques", []):
                lines.append(f"      - {tech}/{sub}")
    return "\n".join(lines)


def build_classification_prompt() -> str:
    """Build the full system prompt for the classifier."""
    return f"""You are a CTF (Capture The Flag) challenge analyst. Given a writeup of a solved CTF challenge, extract structured information about the solving technique.

## Known Taxonomy
{build_taxonomy_reference()}

## Your Task
Analyze the writeup and return a JSON object with these fields:

- **techniques**: List of technique objects. Each object has:
  - "technique": The technique slug from the taxonomy above (e.g., "rsa-attacks", "buffer-overflow")
  - "sub_technique": (optional) A more specific sub-technique slug if applicable. Use an existing sub-technique from the taxonomy when it fits, or create a new descriptive slug (lowercase, hyphenated).
  Example: [{{"technique": "rsa-attacks", "sub_technique": "wiener"}}, {{"technique": "buffer-overflow"}}]
  Usually 1-3 technique objects. If the technique doesn't fit any listed, create a new descriptive slug for the "technique" field.
- **tools_used**: List of specific tools, libraries, or scripts mentioned (e.g., "gdb", "pwntools", "z3", "burpsuite", "ghidra", "wireshark", "john", "hashcat", "sqlmap").
- **recognition_signals**: List of 1-3 short phrases describing how you'd recognize this type of challenge from its description or initial examination (e.g., "binary with no PIE and gets() call", "RSA with small public exponent").
- **solve_steps**: List of 3-7 short descriptions of the key solving steps in order (e.g., "identify buffer overflow in input handler", "calculate offset to return address", "build ROP chain to call system('/bin/sh')").
- **difficulty**: One of "easy", "medium", "hard", "insane" — based on the complexity of the technique and steps involved.
- **summary**: A 1-2 sentence summary of what the challenge was and how it was solved.

Respond with ONLY the JSON object. No markdown fences, no preamble."""


def classify_writeup(content: str, challenge_name: str = "",
                     category: str = "") -> ClassificationResult | None:
    """Send a writeup to the LLM for classification."""
    client = _get_client()
    if not client:
        console.print("[red]No ANTHROPIC_API_KEY set — cannot classify[/]")
        return None

    # Truncate very long writeups to avoid token limits
    max_content_chars = 12_000
    if len(content) > max_content_chars:
        # Keep beginning and end (most important parts)
        half = max_content_chars // 2
        content = content[:half] + "\n\n[... truncated ...]\n\n" + content[-half:]

    user_message = f"""Challenge: {challenge_name}
Original CTF Category: {category or 'unknown'}

--- WRITEUP CONTENT ---
{content}
--- END WRITEUP ---

Analyze this writeup and extract the technique information as JSON."""

    try:
        prompt = build_classification_prompt()
        response = client.messages.create(
            model=CLASSIFIER_MODEL,
            max_tokens=CLASSIFIER_MAX_TOKENS,
            system=prompt,
            messages=[{"role": "user", "content": user_message}],
        )

        text = response.content[0].text.strip()

        # Clean up potential markdown fences
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.strip()

        data = json.loads(text)

        # Parse techniques into TechniqueMatch objects
        # Handles both new format (list of dicts) and old format (list of strings)
        raw_techniques = data.get("techniques", [])
        technique_matches = [TechniqueMatch.from_dict(t) for t in raw_techniques]

        return ClassificationResult(
            techniques=technique_matches,
            tools_used=data.get("tools_used", []),
            solve_steps=data.get("solve_steps", []),
            recognition_signals=data.get("recognition_signals", []),
            difficulty=data.get("difficulty", "medium"),
            summary=data.get("summary", ""),
        )

    except json.JSONDecodeError as e:
        console.print(f"  [yellow]JSON parse error:[/] {e}")
        return None  # permanent — the LLM returned unparseable output
    except _TRANSIENT_ERRORS as e:
        raise TransientAPIError(str(e)) from e
    except Exception as e:
        console.print(f"  [red]Unexpected error:[/] {e}")
        return None  # permanent — unknown issue with this specific writeup


def run(limit: int = 100, category: str = None):
    """Main entry point: classify unclassified writeups."""
    console.rule("[bold blue]Writeup Classifier")

    if not ANTHROPIC_API_KEY:
        console.print("[red]Set ANTHROPIC_API_KEY to use the classifier[/]")
        return

    with db_session() as conn:
        unclassified = get_unclassified(conn, limit=limit, category=category)
        console.print(f"Found [yellow]{len(unclassified)}[/] unclassified writeups")

        if not unclassified:
            console.print("[green]Nothing to classify!")
            return

        success = 0
        failed = 0
        skipped = 0
        consecutive_transient = 0
        max_consecutive_transient = 3

        with Progress(SpinnerColumn(),
                      TextColumn("[progress.description]{task.description}"),
                      BarColumn(), console=console) as progress:
            task = progress.add_task("Classifying...", total=len(unclassified))

            for row in unclassified:
                writeup_id = row["id"]
                raw_path = row["raw_path"]
                challenge_name = row["challenge_name"] or ""
                cat = row["category"] or ""

                # Read the raw content
                if not raw_path or not Path(raw_path).exists():
                    mark_class_failed(conn, writeup_id)
                    failed += 1
                    progress.update(task, advance=1)
                    continue

                content = Path(raw_path).read_text(encoding="utf-8", errors="replace")
                if len(content.strip()) < 50:
                    mark_class_failed(conn, writeup_id)
                    failed += 1
                    progress.update(task, advance=1)
                    continue

                try:
                    result = classify_writeup(content, challenge_name, cat)
                except TransientAPIError as e:
                    # API is down, rate limited, or out of credits.
                    # Leave the writeup as 'pending' so it gets retried next run.
                    consecutive_transient += 1
                    skipped += 1
                    console.print(f"  [yellow]API unavailable:[/] {e}")

                    if consecutive_transient >= max_consecutive_transient:
                        console.print(
                            f"\n[red]Stopping:[/] {consecutive_transient} consecutive "
                            f"API failures — likely out of credits or rate limited. "
                            f"Remaining writeups left as pending for next run."
                        )
                        break

                    progress.update(task, advance=1)
                    continue

                # Reset transient counter on any non-transient outcome
                consecutive_transient = 0

                if result:
                    mark_classified(
                        conn, writeup_id,
                        techniques=result.techniques,
                        tools_used=result.tools_used,
                        solve_steps=result.solve_steps,
                        recognition=result.recognition_signals,
                        difficulty=result.difficulty,
                        notes=result.summary,
                    )

                    # Record discovered sub-techniques in taxonomy_nodes
                    known_subs = all_sub_slugs()
                    for tm in result.techniques:
                        if tm.sub_technique and tm.sub_technique not in known_subs:
                            cat_for_tech = get_category(tm.technique)
                            if cat_for_tech:
                                record_sub_technique(
                                    conn, tm.sub_technique,
                                    tm.technique, cat_for_tech,
                                )

                    # Backfill challenge category from inferred techniques
                    inferred = infer_category(
                        result.technique_slugs, TECHNIQUE_TO_CATEGORY,
                    )
                    if inferred:
                        backfill_challenge_category(conn, writeup_id, inferred)

                    success += 1

                    # Log the classification
                    techs = ", ".join(
                        f"{t.technique}/{t.sub_technique}"
                        if t.sub_technique else t.technique
                        for t in result.techniques[:3]
                    )
                    console.print(
                        f"  [dim]{challenge_name}[/] -> [cyan]{techs}[/]"
                    )
                else:
                    # Permanent failure (bad content, unparseable LLM output)
                    mark_class_failed(conn, writeup_id)
                    failed += 1

                progress.update(
                    task, advance=1,
                    description=f"Classifying... ({success} ok, {failed} failed)"
                )

        parts = [f"Classified {success}"]
        if failed:
            parts.append(f"failed {failed}")
        if skipped:
            parts.append(f"skipped {skipped} (will retry)")
        console.print(f"\n[green]Done![/] {', '.join(parts)}")


if __name__ == "__main__":
    run(limit=50)
