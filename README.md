# CTF Playbook Builder

A pipeline for scraping, indexing, and classifying thousands of CTF writeups into a
technique-based taxonomy designed to help you solve new challenges.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐     ┌──────────────┐
│  1. Scrape   │────▶│  2. Index     │────▶│  3. Fetch      │────▶│ 4. Classify  │
│  (discover)  │     │  (database)   │     │  (content)     │     │ (taxonomy)   │
└─────────────┘     └──────────────┘     └───────────────┘     └──────────────┘
```

### Stages

1. **Scrape** — Crawl CTFtime events + tasks + writeup links; discover GitHub repos
2. **Index** — Store structured metadata in SQLite (event, challenge, category, URL, status)
3. **Fetch** — Download actual writeup content (markdown, HTML→text) into raw files
4. **Classify** — Use an LLM to extract techniques, tools, solve steps; file into taxonomy

## Project Structure

```
CTF_Walkthrough/
├── pyproject.toml
├── README.md
├── CLAUDE.md
├── ctf_playbook/               # Source code
│   ├── __init__.py
│   ├── __main__.py
│   ├── config.py               # Centralized settings
│   ├── db.py                   # SQLite schema + helpers
│   ├── scrapers/
│   │   ├── __init__.py
│   │   ├── ctftime.py          # CTFtime event/task/writeup scraper
│   │   └── github.py           # GitHub repo discovery + indexing
│   ├── fetcher.py              # Download and extract writeup content
│   ├── classifier.py           # LLM-based technique extraction
│   ├── taxonomy.py             # Playbook folder builder
│   └── pipeline.py             # Orchestrator CLI
└── playbook/                   # Output (generated at runtime)
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
export ANTHROPIC_API_KEY="sk-..."    # For the classifier stage (required for stage 3)
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

# Options
uv run ctf-playbook scrape --max-events 100     # Limit CTFtime events to scrape
uv run ctf-playbook scrape --source github      # Only scrape GitHub
uv run ctf-playbook fetch --limit 500           # Fetch up to 500 unfetched writeups
uv run ctf-playbook classify --limit 100        # Classify up to 100 unclassified writeups
uv run ctf-playbook classify --category pwn     # Only classify pwn challenges

# Check database stats
uv run ctf-playbook stats
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
