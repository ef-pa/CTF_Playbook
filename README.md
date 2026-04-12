# CTF Playbook Builder

A pipeline that scrapes thousands of CTF (Capture The Flag) writeups from CTFtime and GitHub,
downloads the content, classifies them using an LLM to extract solving techniques/tools/patterns,
and organizes everything into a technique-based playbook designed to help solve new challenges.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐     ┌──────────────┐
│  1. Scrape  │───▶│  2. Fetch     │───▶│  3. Classify  │───▶│  4. Build    │
│  (discover) │     │  (content)   │     │  (taxonomy)   │     │ (playbook)   │
└─────────────┘     └──────────────┘     └───────────────┘     └──────────────┘
```

### Stages

1. **Scrape** (`ctf_playbook/scrapers/`) — Crawl CTFtime events + tasks + writeup links; discover GitHub repos. Stores metadata in SQLite.
2. **Fetch** (`ctf_playbook/services/fetcher.py`) — Download writeup content (HTML->text via trafilatura, raw markdown). Filters out junk (link indexes, too-short content). Saves to `playbook/raw-writeups/`.
3. **Classify** (`ctf_playbook/services/classifier.py`) — Send fetched writeups to the Claude API for structured analysis. Extracts: techniques, tools, recognition signals, solve steps, difficulty. Stores results as JSON in the DB.
4. **Build** (`ctf_playbook/services/builder.py`) — Generate the playbook folder structure from classified data. Creates `_pattern.md` files per technique aggregating recognition signals, common tools, and solve flows.

## Key Design Decisions

- **Organized by technique within categories.** A heap exploit and a format string bug are both "pwn" but have totally different solve paths. The playbook groups by what-you-actually-do, with optional sub-techniques for finer granularity (e.g., XSS splits into reflected, stored, DOM).
- **SQLite as the central index.** Every writeup has a `fetch_status` and `class_status` so you can resume any stage. Content-hash deduplication detects the same writeup found via different sources.
- **Taxonomy is defined in `ctf_playbook/taxonomy.py`** as a dict. The classifier maps writeups into this taxonomy but can also discover new technique slugs not in the original list.
- **Layered architecture.** Configuration, taxonomy data, data access (db), and service logic (classify, build, fetch) are separated so a GUI or API can reuse the same services without importing CLI code.

## Project Structure

```
CTF_Playbook/
├── pyproject.toml
├── README.md
├── ctf_playbook/                     # Source code
│   ├── __init__.py
│   ├── __main__.py
│   ├── config.py                     # Settings: paths, API keys, rate limits
│   ├── taxonomy.py                   # Technique taxonomy (categories, techniques, sub-techniques)
│   ├── models.py                     # Dataclasses (TechniqueMatch, ClassificationResult, etc.)
│   ├── db.py                         # SQLite schema, CRUD, sub-technique tracking
│   ├── cli.py                        # Click CLI orchestrator
│   ├── scrapers/
│   │   ├── __init__.py
│   │   ├── ctftime.py                # CTFtime event/task/writeup scraper
│   │   └── github.py                 # GitHub repo discovery + tree walking
│   └── services/
│       ├── __init__.py
│       ├── fetcher.py                # URL fetcher with per-domain rate limiting
│       ├── classifier.py             # LLM classification with hierarchical technique output
│       └── builder.py                # Playbook + sub-technique file generation
├── tests/                            # pytest suite
│   ├── test_config.py                # Taxonomy structure + sub-technique tests
│   ├── test_db.py                    # CRUD, sub-technique tracking, soft reset tests
│   ├── test_fetcher.py
│   └── test_github_parser.py
└── playbook/                         # Output (generated at runtime, gitignored)
    ├── techniques/                   # category/technique/_pattern.md + sub-technique .md files
    ├── recon-patterns/
    ├── toolchains/
    └── raw-writeups/
```

## Setup

```bash
uv sync
```

Set environment variables:
```bash
export GITHUB_TOKEN="ghp_..."        # GitHub personal access token (optional, raises rate limit)
export ANTHROPIC_API_KEY="sk-..."    # Required for the classify stage
```

## Usage

```bash
# Run the full pipeline
uv run ctf-playbook all

# Or run individual stages
uv run ctf-playbook scrape          # Discover writeups from CTFtime + GitHub
uv run ctf-playbook fetch           # Download writeup content
uv run ctf-playbook classify        # Extract techniques via LLM
uv run ctf-playbook build           # Generate the playbook folder structure

# Stage options
uv run ctf-playbook scrape --max-events 100     # Limit CTFtime events
uv run ctf-playbook scrape --source github      # Only scrape GitHub
uv run ctf-playbook fetch --limit 500           # Fetch up to 500 writeups
uv run ctf-playbook classify --limit 100        # Classify up to 100 writeups
uv run ctf-playbook classify --category pwn     # Only classify pwn challenges

# Utilities
uv run ctf-playbook stats           # Database statistics (includes sub-technique breakdown)
uv run ctf-playbook search "heap"   # Search classified writeups by keyword
uv run ctf-playbook search -t buffer-overflow   # Filter by technique
uv run ctf-playbook search --tool gdb           # Filter by tool
uv run ctf-playbook dedup           # Remove duplicate writeups (by content hash)
uv run ctf-playbook clean           # Purge junk content from fetched writeups
uv run ctf-playbook fix-categories  # Backfill challenge categories from technique data

# Sub-technique management
uv run ctf-playbook promote         # Review and promote discovered sub-techniques
uv run ctf-playbook promote --threshold 5   # Require 5+ occurrences
uv run ctf-playbook soft-reset      # Reset classifications for re-classification
```

## Testing

```bash
uv run pytest
```

## Rate Limiting

- **CTFtime**: 1.5s delay between requests (be respectful)
- **GitHub API**: 5,000 req/hr with token, 60/hr without
- **Blog fetching**: 1s delay per domain, randomized

## Taxonomy Design

The playbook is organized by **technique** (what you do to solve it), grouped under top-level
categories. This means a "pwn" challenge using heap exploitation and a "pwn" challenge using
format strings live in different technique branches, because the solve paths are different.

### Hierarchy

The taxonomy has up to 3 levels: **category / technique / sub-technique**.

```
playbook/techniques/
  cryptography/
    rsa-attacks/
      _pattern.md              # Technique overview + sub-technique table
      coppersmith.md           # Sub-technique pattern file
      wiener.md
      hastad.md
    padding-oracle/
      _pattern.md              # No sub-techniques — just the overview
  web/
    xss/
      _pattern.md
      reflected-xss.md
      stored-xss.md
      dom-xss.md
```

- `_pattern.md` — technique overview with recognition signals, tools, solve flow, and examples
- `{sub-technique}.md` — same structure, scoped to a specific sub-technique
- Not all techniques have sub-techniques — most are just `_pattern.md`

### Sub-Technique Discovery

Sub-techniques come from two sources:
1. **Seeded** — predefined in the taxonomy (e.g., RSA attack variants, XSS types)
2. **Discovered** — the classifier identifies new sub-techniques during classification

Discovered sub-techniques are tracked in the database with occurrence counts. Once a
sub-technique appears in 3+ writeups, it becomes a **promotion candidate**. Use
`ctf-playbook promote` to review and approve candidates.

Recon-pattern files provide the reverse lookup: from what you observe in a challenge
to which technique to try first.
