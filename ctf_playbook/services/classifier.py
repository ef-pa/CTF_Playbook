"""Classify writeups using an LLM to extract techniques, tools, and solve patterns.

Reads fetched writeup content, sends it to Claude for structured analysis,
and stores the extracted metadata back in the database.
"""

import json
from pathlib import Path

from anthropic import Anthropic
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ctf_playbook.config import ANTHROPIC_API_KEY, CLASSIFIER_MODEL, CLASSIFIER_MAX_TOKENS
from ctf_playbook.taxonomy import TAXONOMY, TECHNIQUE_TO_CATEGORY
from ctf_playbook.models import ClassificationResult
from ctf_playbook.db import (
    db_session, get_unclassified, mark_classified, mark_class_failed,
    infer_category, backfill_challenge_category,
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
        for tech in info["techniques"]:
            lines.append(f"  - {tech}")
    return "\n".join(lines)


def build_classification_prompt() -> str:
    """Build the full system prompt for the classifier."""
    return f"""You are a CTF (Capture The Flag) challenge analyst. Given a writeup of a solved CTF challenge, extract structured information about the solving technique.

## Known Taxonomy
{build_taxonomy_reference()}

## Your Task
Analyze the writeup and return a JSON object with these fields:

- **techniques**: List of technique slugs from the taxonomy above that were used. Use the exact slug names. If the technique doesn't fit any listed, create a new descriptive slug (lowercase, hyphenated). Usually 1-3 techniques.
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
        return ClassificationResult(
            techniques=data.get("techniques", []),
            tools_used=data.get("tools_used", []),
            solve_steps=data.get("solve_steps", []),
            recognition_signals=data.get("recognition_signals", []),
            difficulty=data.get("difficulty", "medium"),
            summary=data.get("summary", ""),
        )

    except json.JSONDecodeError as e:
        console.print(f"  [yellow]JSON parse error:[/] {e}")
        return None
    except Exception as e:
        console.print(f"  [red]API error:[/] {e}")
        return None


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

                result = classify_writeup(content, challenge_name, cat)

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

                    # Backfill challenge category from inferred techniques
                    inferred = infer_category(result.techniques, TECHNIQUE_TO_CATEGORY)
                    if inferred:
                        backfill_challenge_category(conn, writeup_id, inferred)

                    success += 1

                    # Log the classification
                    techs = ", ".join(result.techniques[:3])
                    console.print(
                        f"  [dim]{challenge_name}[/] -> [cyan]{techs}[/]"
                    )
                else:
                    mark_class_failed(conn, writeup_id)
                    failed += 1

                progress.update(
                    task, advance=1,
                    description=f"Classifying... ({success} ok, {failed} failed)"
                )

        console.print(f"\n[green]Done![/] Classified {success}, failed {failed}")


if __name__ == "__main__":
    run(limit=50)
