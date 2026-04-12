"""Centralized configuration for the CTF Playbook Builder."""

import os
from pathlib import Path

from dotenv import load_dotenv

# ── Paths ──────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")
DB_PATH = PROJECT_ROOT / "playbook.db"
RAW_WRITEUPS_DIR = PROJECT_ROOT / "playbook" / "raw-writeups"
PLAYBOOK_DIR = PROJECT_ROOT / "playbook"

# ── Scraping ───────────────────────────────────────────────────────────────
CTFTIME_BASE = "https://ctftime.org"
CTFTIME_DELAY = 1.5  # seconds between requests
CTFTIME_USER_AGENT = "CTF-Playbook-Builder/1.0 (research; respectful scraping)"

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_API = "https://api.github.com"
GITHUB_DELAY = 0.5  # seconds between API calls
GITHUB_SEARCH_QUERIES = [
    "ctf writeup",
    "ctf-writeups",
    "ctf solutions",
    "capture the flag writeup",
]
GITHUB_MIN_STARS = 5  # filter out very low-quality repos

# ── Fetching ───────────────────────────────────────────────────────────────
FETCH_DELAY = 1.0  # seconds between requests to the same domain
FETCH_TIMEOUT = 15  # seconds
FETCH_MAX_SIZE = 5_000_000  # 5 MB max per page

# ── Classification ─────────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
CLASSIFIER_MODEL = "claude-sonnet-4-20250514"
CLASSIFIER_MAX_TOKENS = 2048

# ── Taxonomy ───────────────────────────────────────────────────────────────
# Top-level technique categories and their sub-techniques.
# This drives both classification prompts and folder generation.
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
