"""Classify writeups using an LLM to extract techniques, tools, and solve patterns.

Pure classification logic: prompt building, Gemini API calls, response parsing,
and output sanitization. No DB access, no orchestration — see runner.py for that.
"""

import itertools
import json
import threading
import time
from dataclasses import dataclass, field

from google import genai
from google.genai import types, errors
from rich.console import Console

from ctf_playbook.config import GEMINI_API_KEYS, GEMINI_MODEL, GEMINI_RPM
from ctf_playbook.taxonomy import TAXONOMY
from ctf_playbook.models import ClassificationResult, TechniqueMatch

console = Console()


# ── Client pool with per-key rate limiting ─────────────────────────────────


@dataclass
class _KeySlot:
    """One API key's client and rate-limit state."""
    client: genai.Client
    lock: threading.Lock = field(default_factory=threading.Lock)
    last_request: float = 0.0


_slots: list[_KeySlot] = []
_slot_cycle: itertools.cycle | None = None
_pool_lock = threading.Lock()


def _init_pool():
    """Build the client pool from configured API keys (called once)."""
    global _slots, _slot_cycle
    for key in GEMINI_API_KEYS:
        _slots.append(_KeySlot(client=genai.Client(api_key=key)))
    if _slots:
        _slot_cycle = itertools.cycle(_slots)


def _next_slot() -> _KeySlot | None:
    """Thread-safe round-robin selection of the next key slot.

    Lazily initializes the pool on first call.
    """
    global _slot_cycle
    with _pool_lock:
        if _slot_cycle is None and GEMINI_API_KEYS:
            _init_pool()
        if _slot_cycle is None:
            return None
        return next(_slot_cycle)


def _rate_limited_client() -> genai.Client | None:
    """Get the next client, sleeping if needed for its per-key rate limit."""
    slot = _next_slot()
    if slot is None:
        return None
    min_interval = 60.0 / GEMINI_RPM
    with slot.lock:
        elapsed = time.time() - slot.last_request
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        slot.last_request = time.time()
    return slot.client


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
  - "solve_steps": 3-7 key solving steps at the technique level, in order. Write GENERIC steps that apply to ANY challenge using this technique, not steps specific to this particular challenge. Use short, reusable phrases like "identify vulnerable input", "craft malicious payload", "extract flag from output" — never mention challenge-specific details like specific variable names, endpoints, or values.
  - "sub_recognition_signals": (only when sub_technique is set) 1-2 phrases for what distinguishes THIS SPECIFIC variant from the parent technique. Focus on the differentiating signal, not general technique signals. (e.g., for wiener specifically: "public exponent e is extremely large relative to N")
  - "sub_solve_steps": (only when sub_technique is set) Solving steps specific to this variant that differ from the general technique flow. Same rule: write GENERIC steps, not challenge-specific ones.

  Example: [{{"technique": "rsa-attacks", "sub_technique": "wiener", "recognition_signals": ["RSA with unusual parameters", "public key available for analysis"], "solve_steps": ["extract public key components", "identify vulnerability in parameters", "apply mathematical attack to recover private key"], "sub_recognition_signals": ["public exponent e is extremely large relative to N"], "sub_solve_steps": ["compute continued fraction expansion of e/N", "test convergents for valid private key", "decrypt ciphertext with recovered key"]}}]

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
    client = _rate_limited_client()
    if not client:
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
        prompt = build_classification_prompt()
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            config=types.GenerateContentConfig(system_instruction=prompt),
            contents=user_message,
        )
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

        # Sanitize LLM output quirks
        _CATEGORIES = {"binary-exploitation", "web", "cryptography",
                       "reverse-engineering", "forensics", "misc"}
        for tm in technique_matches:
            # Sub-technique must be a simple slug, never a path
            # e.g. "heap-exploitation/tcache-poisoning" -> "tcache-poisoning"
            if tm.sub_technique and "/" in tm.sub_technique:
                tm.sub_technique = tm.sub_technique.rsplit("/", 1)[-1]

            # Promote sub-technique when LLM used a category name as technique
            # e.g. technique="cryptography", sub="chosen-plaintext-attack"
            if tm.technique in _CATEGORIES and tm.sub_technique:
                tm.technique = tm.sub_technique
                tm.sub_technique = None

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
    except errors.ClientError as e:
        # 4xx — includes 429 rate limit
        retry_after = 60.0 if e.code == 429 else None
        raise TransientAPIError(str(e), retry_after=retry_after) from e
    except errors.ServerError as e:
        # 5xx — server-side transient error
        raise TransientAPIError(str(e)) from e
    except Exception as e:
        console.print(f"  [red]Unexpected error:[/] {e}")
        return None  # permanent — unknown issue with this specific writeup
