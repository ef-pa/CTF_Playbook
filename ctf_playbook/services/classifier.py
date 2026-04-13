"""Classify writeups using an LLM to extract techniques, tools, and solve patterns.

Reads fetched writeup content, sends it to Gemini for structured analysis,
and stores the extracted metadata back in the database.
"""

import json
import time
from pathlib import Path

import google.generativeai as genai
from google.api_core.exceptions import (
    ResourceExhausted, TooManyRequests, ServiceUnavailable,
    InternalServerError, DeadlineExceeded, RetryError,
)
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

# Transient errors — the writeup itself is fine, the API is temporarily unavailable.
# These should NOT mark the writeup as failed.
_TRANSIENT_ERRORS = (ResourceExhausted, TooManyRequests, ServiceUnavailable,
                     InternalServerError, DeadlineExceeded, RetryError)

from ctf_playbook.config import GEMINI_API_KEY, GEMINI_MODEL, GEMINI_RPM
from ctf_playbook.taxonomy import TAXONOMY, TECHNIQUE_TO_CATEGORY, get_category, all_sub_slugs
from ctf_playbook.models import ClassificationResult, TechniqueMatch
from ctf_playbook.db import (
    db_session, get_unclassified, mark_classified, mark_class_failed,
    infer_category, backfill_challenge_category, record_sub_technique,
)

console = Console()

_configured = False
_last_request = 0.0  # timestamp of last API call


def _ensure_configured():
    """Lazily configure the Gemini client."""
    global _configured
    if not _configured and GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
        _configured = True


def _rate_limit():
    """Sleep if needed to stay within Gemini free tier RPM."""
    global _last_request
    min_interval = 60.0 / GEMINI_RPM  # 4s at 15 RPM
    elapsed = time.time() - _last_request
    if elapsed < min_interval:
        time.sleep(min_interval - elapsed)
    _last_request = time.time()


class TransientAPIError(Exception):
    """Raised when the API fails for a reason unrelated to the writeup content."""

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


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

- **techniques**: List of technique objects (usually 1-3). Each object has:
  - "technique": The technique slug from the taxonomy above (e.g., "rsa-attacks", "buffer-overflow"). If nothing fits, create a new descriptive slug (lowercase, hyphenated).
  - "sub_technique": (optional) A more specific sub-technique slug if applicable. Use an existing sub-technique from the taxonomy when it fits, or create a new descriptive slug.
  - "recognition_signals": 1-3 short phrases for how to recognize THIS technique family from a challenge description (e.g., "RSA with unusual parameters", "binary with gets() and no canary"). These should be general to the technique, not specific to the sub-technique.
  - "solve_steps": 3-7 key solving steps at the technique level, in order.
  - "sub_recognition_signals": (only when sub_technique is set) 1-2 phrases for what distinguishes THIS SPECIFIC variant from the parent technique. Focus on the differentiating signal, not general technique signals. (e.g., for wiener specifically: "public exponent e is extremely large relative to N")
  - "sub_solve_steps": (only when sub_technique is set) Solving steps specific to this variant that differ from the general technique flow.

  Example: [{{"technique": "rsa-attacks", "sub_technique": "wiener", "recognition_signals": ["RSA with unusual parameters", "public key available for analysis"], "solve_steps": ["extract public key components", "identify vulnerability in parameters", "apply attack to recover private key"], "sub_recognition_signals": ["public exponent e is extremely large relative to N"], "sub_solve_steps": ["compute continued fraction expansion of e/N", "test convergents for valid private key"]}}]

- **tools_used**: List of specific tools, libraries, or scripts mentioned (e.g., "gdb", "pwntools", "z3", "burpsuite", "ghidra", "wireshark", "john", "hashcat", "sqlmap").
- **difficulty**: One of "easy", "medium", "hard", "insane" — based on the complexity of the technique and steps involved.
- **summary**: A 1-2 sentence summary of what the challenge was and how it was solved.

Respond with ONLY the JSON object. No markdown fences, no preamble.

## IMPORTANT RULES

1. **Technique specificity**: NEVER use a category name (like "web", "cryptography", "binary-exploitation", "reverse-engineering", "forensics", "misc") as a technique slug. Always use the most specific technique from the taxonomy above. For example, use "buffer-overflow" not "binary-exploitation", use "rsa-attacks" not "cryptography", use "command-injection" not "web". If multiple techniques apply, list each specific one.

2. **Tools must be actual software tools**: Only list real, named tools, libraries, or frameworks (e.g., "gdb", "pwntools", "pycryptodome", "ghidra", "burpsuite", "wireshark", "z3", "sage"). Do NOT list programming languages ("python", "javascript") or generic descriptions ("assembly patching", "manual analysis") as tools. A tool is something you install or import.

3. **Avoid catch-all technique slugs**: These are NOT valid technique slugs — they are too vague:
   - "deobfuscation" → use the actual technique (e.g., "static-analysis", "vm-cracking", "dynamic-analysis")
   - "shellcode" → use the exploitation technique that enables it (e.g., "buffer-overflow", "format-string")
   - "side-channel-attacks" → only use for TRUE hardware/timing side channels. Padding oracles are "padding-oracle", brute-force key recovery is the relevant crypto technique, and black-box input testing is "constraint-solving" or "dynamic-analysis"
   - "steganography" → only if data is hidden in media using steganographic encoding. Extracting embedded files from containers is "file-carving". Reconstructing damaged data is not steganography.
   Pick the technique that describes the core vulnerability or method, not auxiliary steps.

4. **Prefer existing taxonomy slugs**: Always check the taxonomy list above first. Only create a new slug if nothing in the taxonomy fits. When in doubt between a taxonomy slug and a novel one, use the taxonomy slug.

5. **NEVER return a bare category name as a technique**: The following are CATEGORY names, NOT technique slugs: "cryptography", "web", "binary-exploitation", "reverse-engineering", "forensics", "misc". Returning these is ALWAYS wrong. Even for simple challenges, pick the most relevant technique: a basic RSA challenge is "rsa-attacks", a simple XOR cipher is "classical-ciphers", a basic SQL injection is "sql-injection". If truly nothing in the taxonomy fits, create a descriptive slug like "digital-signature-forgery" or "hash-length-extension"."""


def classify_writeup(content: str, challenge_name: str = "",
                     category: str = "") -> ClassificationResult | None:
    """Send a writeup to the LLM for classification."""
    _ensure_configured()
    if not GEMINI_API_KEY:
        console.print("[red]No GEMINI_API_KEY set — cannot classify[/]")
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

Analyze this writeup and extract the technique information as JSON. Remember: use SPECIFIC technique slugs from the taxonomy, never category names. Only list actual software tools, not programming languages."""

    try:
        _rate_limit()
        prompt = build_classification_prompt()
        model = genai.GenerativeModel(
            model_name=GEMINI_MODEL,
            system_instruction=prompt,
        )
        response = model.generate_content(user_message)
        text = response.text.strip()

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

        # Build flat recognition/steps from per-technique data, with
        # top-level fields as fallback for backward compat
        result = ClassificationResult(
            techniques=technique_matches,
            tools_used=data.get("tools_used", []),
            solve_steps=data.get("solve_steps", []),
            recognition_signals=data.get("recognition_signals", []),
            difficulty=data.get("difficulty", "medium"),
            summary=data.get("summary", ""),
        )

        # If the LLM put signals in per-technique objects but omitted
        # top-level fields, populate them from the aggregation helpers
        if not result.recognition_signals:
            result.recognition_signals = result.flat_recognition
        if not result.solve_steps:
            result.solve_steps = result.flat_solve_steps

        return result

    except json.JSONDecodeError as e:
        console.print(f"  [yellow]JSON parse error:[/] {e}")
        return None  # permanent — the LLM returned unparseable output
    except _TRANSIENT_ERRORS as e:
        # Rate limit, quota, or server error — writeup is fine, API is not
        retry_after = None
        if isinstance(e, (ResourceExhausted, TooManyRequests)):
            retry_after = 60.0  # wait a full minute on rate limit
        raise TransientAPIError(str(e), retry_after=retry_after) from e
    except Exception as e:
        console.print(f"  [red]Unexpected error:[/] {e}")
        return None  # permanent — unknown issue with this specific writeup


def run(limit: int = 100, category: str = None):
    """Main entry point: classify unclassified writeups."""
    console.rule("[bold blue]Writeup Classifier")

    if not GEMINI_API_KEY:
        console.print("[red]Set GEMINI_API_KEY to use the classifier[/]")
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
                    # Missing file is a fetch problem, not a classification
                    # failure. Reset to re-fetch instead of marking as failed.
                    conn.execute(
                        "UPDATE writeups SET fetch_status='pending', "
                        "raw_path=NULL WHERE id=?",
                        (writeup_id,),
                    )
                    skipped += 1
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
                    # Rate limit: wait and retry the same writeup
                    if e.retry_after:
                        wait = min(e.retry_after, 120)  # cap at 2 minutes
                        console.print(
                            f"  [yellow]Rate limited:[/] waiting {wait:.0f}s..."
                        )
                        time.sleep(wait)
                        try:
                            result = classify_writeup(content, challenge_name, cat)
                        except TransientAPIError:
                            # Still failing after wait — count as transient
                            consecutive_transient += 1
                            skipped += 1
                            if consecutive_transient >= max_consecutive_transient:
                                console.print(
                                    f"\n[red]Stopping:[/] {consecutive_transient} "
                                    f"consecutive API failures. "
                                    f"Remaining writeups left as pending."
                                )
                                break
                            progress.update(task, advance=1)
                            continue
                    else:
                        # Non-rate-limit transient error (connection, etc.)
                        consecutive_transient += 1
                        skipped += 1
                        console.print(f"  [yellow]API unavailable:[/] {e}")

                        if consecutive_transient >= max_consecutive_transient:
                            console.print(
                                f"\n[red]Stopping:[/] {consecutive_transient} "
                                f"consecutive API failures. "
                                f"Remaining writeups left as pending."
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
