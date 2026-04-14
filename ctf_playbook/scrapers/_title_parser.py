"""Shared title parser for extracting CTF event/challenge metadata from text.

Used by the Reddit and blog scrapers to parse writeup titles into structured
data that maps to the events/challenges/writeups schema.
"""

import re

# Pattern: [Writeup] EventCTF 2024 - Category - ChallengeName
# Pattern: EventName CTF Year - ChallengeName writeup
# Pattern: ChallengeName (EventName CTF Year)
# Pattern: Event CTF 2024 | challenge-name

_YEAR_RE = re.compile(r"\b(20[12]\d)\b")

# Separators between event / category / challenge in titles
_SEPARATORS = re.compile(r"\s*[\-|:–—]\s*")

# Words that signal the title contains a writeup (used for filtering)
WRITEUP_KEYWORDS = frozenset({
    "writeup", "write-up", "write up", "walkthrough", "solution",
    "solved", "solving", "ctf", "challenge", "flag",
})

# Tag-like prefixes to strip
_TAG_RE = re.compile(r"^\s*\[[\w\s\-]+\]\s*")

# Category hints
_CATEGORY_HINTS = {
    "pwn", "web", "crypto", "cryptography", "rev", "reverse",
    "reversing", "forensics", "misc", "stego", "osint", "blockchain",
    "binary", "exploitation", "re", "hardware",
}


def is_writeup_title(title: str) -> bool:
    """Check if a title looks like a CTF writeup."""
    lower = title.lower()
    return any(kw in lower for kw in WRITEUP_KEYWORDS)


def parse_ctf_title(title: str) -> dict:
    """Parse a writeup title into structured metadata.

    Returns {event_name, challenge_name, year, category}.
    All fields are best-effort — may be None if not extractable.
    """
    result = {
        "event_name": None,
        "challenge_name": None,
        "year": None,
        "category": None,
    }

    # Strip leading tags like [Writeup], [CTF], etc.
    clean = _TAG_RE.sub("", title).strip()

    # Extract year
    year_match = _YEAR_RE.search(clean)
    if year_match:
        result["year"] = int(year_match.group(1))

    # Remove "writeup", "write-up", "solution", etc. noise words
    cleaned = re.sub(
        r"\b(writeup|write[\-\s]?up|walkthrough|solution|solved)\b",
        "", clean, flags=re.IGNORECASE,
    ).strip()

    # Try splitting on separators
    parts = [p.strip() for p in _SEPARATORS.split(cleaned) if p.strip()]

    # Remove year-only parts
    parts = [p for p in parts if not re.fullmatch(r"20[12]\d", p)]

    if not parts:
        result["challenge_name"] = clean
        return result

    if len(parts) == 1:
        # Can't distinguish event from challenge — use as challenge name
        result["challenge_name"] = parts[0]
        return result

    # First part is usually the event name
    result["event_name"] = parts[0]

    # Check if any middle part is a category hint
    if len(parts) >= 3:
        if parts[1].lower() in _CATEGORY_HINTS:
            result["category"] = parts[1].lower()
            result["challenge_name"] = parts[2]
        else:
            result["challenge_name"] = parts[1]
    else:
        result["challenge_name"] = parts[1]

    # Handle parenthetical event names: "ChallengeName (EventCTF 2024)"
    paren_match = re.search(r"\(([^)]+)\)\s*$", title)
    if paren_match and not result["event_name"]:
        result["event_name"] = paren_match.group(1).strip()

    return result
