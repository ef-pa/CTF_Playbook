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
2. **Fetch** (`ctf_playbook/fetcher.py`) — Download writeup content (HTML→text via trafilatura, raw markdown). Filters out junk (link indexes, too-short content). Saves to `playbook/raw-writeups/`.
3. **Classify** (`ctf_playbook/classifier.py`) — Send fetched writeups to the Claude API for structured analysis. Extracts: techniques, tools, recognition signals, solve steps, difficulty. Stores results as JSON in the DB.
4. **Build** (`ctf_playbook/taxonomy.py`) — Generate the playbook folder structure from classified data. Creates `_pattern.md` files per technique aggregating recognition signals, common tools, and solve flows.

## Key Design Decisions

- **Organized by technique, not CTF category.** A heap exploit and a format string bug are both "pwn" but have totally different solve paths. The playbook groups by what-you-actually-do.
- **SQLite as the central index.** Every writeup has a `fetch_status` and `class_status` so you can resume any stage. Content-hash deduplication detects the same writeup found via different sources.
- **Taxonomy is defined in `ctf_playbook/config.py`** as a dict. The classifier maps writeups into this taxonomy but can also discover new technique slugs not in the original list.

## Project Structure

```
CTF_Playbook/
├── pyproject.toml
├── README.md
├── ctf_playbook/                   # Source code
│   ├── __init__.py
│   ├── __main__.py
│   ├── config.py                   # Settings, paths, API keys, rate limits, full taxonomy
│   ├── db.py                       # SQLite schema, init, query/insert helpers
│   ├── scrapers/
│   │   ├── __init__.py
│   │   ├── ctftime.py              # CTFtime event/task/writeup scraper
│   │   └── github.py               # GitHub repo discovery + tree walking
│   ├── fetcher.py                  # URL fetcher with per-domain rate limiting
│   ├── classifier.py               # Anthropic API integration, classification prompt
│   ├── taxonomy.py                 # Playbook folder/pattern/recon-pattern generator
│   └── pipeline.py                 # Click CLI orchestrator
├── tests/                          # pytest suite
│   ├── test_config.py
│   ├── test_db.py
│   ├── test_fetcher.py
│   └── test_github_parser.py
└── playbook/                       # Output (generated at runtime, gitignored)
    ├── techniques/
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
uv run ctf-playbook stats           # Database statistics
uv run ctf-playbook search "heap"   # Search classified writeups by keyword
uv run ctf-playbook search -t buffer-overflow   # Filter by technique
uv run ctf-playbook search --tool gdb           # Filter by tool
uv run ctf-playbook dedup           # Remove duplicate writeups (by content hash)
uv run ctf-playbook clean           # Purge junk content from fetched writeups
uv run ctf-playbook fix-categories  # Backfill challenge categories from technique data
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

The playbook is organized by **technique** (what you do to solve it), not by CTF category.
This means a "pwn" challenge using heap exploitation and a "pwn" challenge using format
strings live in different technique branches, because the solve paths are different.

Each technique folder contains:
- `_pattern.md` — generalized recognition signals + solve flow
- Individual writeup notes linking to raw sources
- Tags for CTF category, difficulty, tools used, event

Recon-pattern files provide the reverse lookup: from what you observe in a challenge
to which technique to try first.
