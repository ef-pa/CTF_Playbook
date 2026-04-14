"""Centralized configuration for the CTF Playbook Builder.

Settings only — paths, API keys, scraping params.
For the technique taxonomy, see taxonomy.py.
"""

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
FETCH_DELAY = 0.5  # seconds between requests to the same domain
FETCH_TIMEOUT = 10  # seconds
FETCH_MAX_SIZE = 5_000_000  # 5 MB max per page

# ── Reddit ─────────────────────────────────────────────────────────────
REDDIT_DELAY = 2.0  # seconds between requests
REDDIT_SUBREDDITS = ["securityCTF", "netsec", "CTF"]
REDDIT_MIN_SCORE = 2  # filter low-quality posts

# ── Blog RSS ───────────────────────────────────────────────────────────
BLOG_DELAY = 1.0  # seconds between feed fetches

# ── Classification (Gemini) ────────────────────────────────────────────────
# Supports multiple comma-separated keys for parallel throughput:
#   GEMINI_API_KEY=key1,key2,key3  →  3 × 15 RPM = 45 RPM
_raw_keys = os.getenv("GEMINI_API_KEY", "")
GEMINI_API_KEYS: list[str] = [k.strip() for k in _raw_keys.split(",") if k.strip()]
GEMINI_MODEL = "gemini-3.1-flash-lite-preview"
GEMINI_RPM = 15  # free tier: 15 requests per minute per key
