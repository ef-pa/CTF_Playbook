"""Gemini-based classifier for comparison testing against Claude.

Uses the exact same prompt and parsing logic as the Claude classifier,
just with a different LLM backend.
"""

import json

import google.generativeai as genai
from rich.console import Console

from ctf_playbook.config import GEMINI_API_KEY, GEMINI_MODEL
from ctf_playbook.models import ClassificationResult, TechniqueMatch
from ctf_playbook.services.classifier import build_classification_prompt

console = Console()

_configured = False


def _ensure_configured():
    global _configured
    if not _configured and GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
        _configured = True


def classify_writeup_gemini(content: str, challenge_name: str = "",
                            category: str = "") -> ClassificationResult | None:
    """Classify a writeup using Gemini, same interface as Claude classifier."""
    _ensure_configured()
    if not GEMINI_API_KEY:
        console.print("[red]No GEMINI_API_KEY set[/]")
        return None

    # Truncate same as Claude
    max_content_chars = 12_000
    if len(content) > max_content_chars:
        half = max_content_chars // 2
        content = content[:half] + "\n\n[... truncated ...]\n\n" + content[-half:]

    system_prompt = build_classification_prompt() + """

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

    user_message = f"""Challenge: {challenge_name}
Original CTF Category: {category or 'unknown'}

--- WRITEUP CONTENT ---
{content}
--- END WRITEUP ---

Analyze this writeup and extract the technique information as JSON. Remember: use SPECIFIC technique slugs from the taxonomy, never category names. Only list actual software tools, not programming languages."""

    try:
        model = genai.GenerativeModel(
            model_name=GEMINI_MODEL,
            system_instruction=system_prompt,
        )
        response = model.generate_content(user_message)
        text = response.text.strip()

        # Clean up markdown fences
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.strip()

        data = json.loads(text)

        raw_techniques = data.get("techniques", [])
        technique_matches = [TechniqueMatch.from_dict(t) for t in raw_techniques]

        result = ClassificationResult(
            techniques=technique_matches,
            tools_used=data.get("tools_used", []),
            solve_steps=data.get("solve_steps", []),
            recognition_signals=data.get("recognition_signals", []),
            difficulty=data.get("difficulty", "medium"),
            summary=data.get("summary", ""),
        )

        if not result.recognition_signals:
            result.recognition_signals = result.flat_recognition
        if not result.solve_steps:
            result.solve_steps = result.flat_solve_steps

        return result

    except json.JSONDecodeError as e:
        console.print(f"  [yellow]Gemini JSON parse error:[/] {e}")
        return None
    except Exception as e:
        console.print(f"  [red]Gemini error:[/] {e}")
        return None
