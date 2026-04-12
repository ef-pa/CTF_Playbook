"""CTF technique taxonomy — the canonical list of categories and techniques.

This module is the single source of truth for technique classification.
It drives folder generation, classifier prompts, and category inference.
"""

# ── Taxonomy ───────────────────────────────────────────────────────────────
# Top-level technique categories and their sub-techniques.

TAXONOMY = {
    "binary-exploitation": {
        "description": "Exploiting compiled binaries",
        "techniques": [
            "buffer-overflow",
            "format-string",
            "heap-exploitation",
            "rop-chains",
            "race-condition",
            "integer-overflow",
            "use-after-free",
            "double-free",
            "shellcode",
            "kernel-exploitation",
            "sigreturn-oriented-programming",
            "got-overwrite",
            "stack-canary-bypass",
            "privilege-escalation",
        ],
    },
    "web": {
        "description": "Web application vulnerabilities",
        "techniques": [
            "sql-injection",
            "xss",
            "ssrf",
            "deserialization",
            "path-traversal",
            "command-injection",
            "authentication-bypass",
            "jwt-attacks",
            "xxe",
            "prototype-pollution",
            "race-condition-web",
            "template-injection",
            "file-upload",
            "request-smuggling",
            "file-inclusion",
            "header-injection",
        ],
    },
    "cryptography": {
        "description": "Breaking or misusing cryptographic primitives",
        "techniques": [
            "rsa-attacks",
            "block-cipher-attacks",
            "hash-collisions",
            "padding-oracle",
            "stream-cipher-reuse",
            "elliptic-curve-attacks",
            "diffie-hellman-attacks",
            "lattice-based",
            "classical-ciphers",
            "prng-prediction",
            "homomorphic-misuse",
            "differential-cryptanalysis",
            "chosen-plaintext-attack",
            "known-plaintext-attack",
            "cbc-bit-flipping",
            "side-channel-attacks",
            "timing-attack",
        ],
    },
    "reverse-engineering": {
        "description": "Analyzing compiled or obfuscated code",
        "techniques": [
            "static-analysis",
            "dynamic-analysis",
            "deobfuscation",
            "anti-debugging-bypass",
            "vm-cracking",
            "firmware-analysis",
            "android-reversing",
            "dotnet-java-reversing",
            "constraint-solving",
            "patching",
        ],
    },
    "forensics": {
        "description": "Recovering or analyzing digital evidence",
        "techniques": [
            "file-carving",
            "memory-forensics",
            "disk-forensics",
            "network-capture-analysis",
            "log-analysis",
            "steganography",
            "metadata-extraction",
            "registry-analysis",
            "timeline-reconstruction",
        ],
    },
    "misc": {
        "description": "Challenges that cross categories or don't fit neatly",
        "techniques": [
            "osint",
            "jail-escape",
            "programming-challenge",
            "blockchain",
            "hardware",
            "ai-ml-exploitation",
            "game-hacking",
            "signal-processing",
            "ppc",
        ],
    },
}


# ── Lookup helpers ─────────────────────────────────────────────────────────

# Reverse lookup: technique slug -> top-level category
TECHNIQUE_TO_CATEGORY: dict[str, str] = {}
for _cat, _info in TAXONOMY.items():
    for _tech in _info["techniques"]:
        TECHNIQUE_TO_CATEGORY[_tech] = _cat


def get_category(slug: str) -> str | None:
    """Return the top-level category for a technique slug, or None."""
    return TECHNIQUE_TO_CATEGORY.get(slug)


def get_techniques(category: str) -> list[str]:
    """Return the list of technique slugs for a category."""
    info = TAXONOMY.get(category)
    return list(info["techniques"]) if info else []


def all_slugs() -> set[str]:
    """Return the set of all known technique slugs."""
    return set(TECHNIQUE_TO_CATEGORY.keys())


def categories() -> list[str]:
    """Return the list of all category names."""
    return list(TAXONOMY.keys())
