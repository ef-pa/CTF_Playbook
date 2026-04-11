# CTF Playbook Builder

## What This Project Is
A pipeline that scrapes thousands of CTF (Capture The Flag) writeups from CTFtime and GitHub, downloads the content, classifies them using an LLM to extract solving techniques/tools/patterns, and organizes everything into a technique-based playbook designed to help solve new CTF challenges.

## Architecture
4-stage pipeline, each stage runnable independently via CLI:

1. **Scrape** (`ctf_playbook/scrapers/ctftime.py`, `ctf_playbook/scrapers/github.py`) — Discovers writeup URLs from CTFtime event pages and GitHub repos. Stores metadata in SQLite.
2. **Fetch** (`ctf_playbook/fetcher.py`) — Downloads actual writeup content from discovered URLs. Uses trafilatura for HTML→text extraction. Saves as markdown in `playbook/raw-writeups/`.
3. **Classify** (`ctf_playbook/classifier.py`) — Sends fetched writeups to Claude API for structured analysis. Extracts: techniques used, tools, recognition signals, solve steps, difficulty. Stores results as JSON in the DB.
4. **Build** (`ctf_playbook/taxonomy.py`) — Generates the playbook folder structure from classified data. Creates `_pattern.md` files per technique that aggregate recognition signals, common tools, and solve flows across all writeups using that technique.

## Key Design Decisions
- **Organized by technique, not CTF category.** A heap exploit and a format string bug are both "pwn" but have totally different solve paths. The playbook groups by what-you-actually-do.
- **SQLite as the central index.** Every writeup has a fetch_status and class_status so you can resume any stage. Schema is in `ctf_playbook/db.py`.
- **Taxonomy is defined in `ctf_playbook/config.py`** as a dict. The classifier maps writeups into this taxonomy but can also discover new technique slugs not in the original list.

## File Map
- `ctf_playbook/config.py` — All settings, paths, API keys, rate limits, and the full taxonomy definition
- `ctf_playbook/db.py` — SQLite schema, init, and all query/insert helpers
- `ctf_playbook/scrapers/ctftime.py` — CTFtime HTML scraper (events, tasks, writeup links)
- `ctf_playbook/scrapers/github.py` — GitHub API scraper (repo search, tree walking for markdown files)
- `ctf_playbook/fetcher.py` — URL fetcher with per-domain rate limiting, trafilatura extraction
- `ctf_playbook/classifier.py` — Anthropic API integration, classification prompt, JSON parsing
- `ctf_playbook/taxonomy.py` — Playbook folder generator, pattern file aggregator, master index builder
- `ctf_playbook/pipeline.py` — Click CLI that orchestrates all stages

## Current State
This is a freshly generated codebase that hasn't been run yet. The core logic is there but expect:
- CTFtime HTML parsing may need adjustment (their DOM structure can vary)
- GitHub path inference for event/challenge names is heuristic and will have edge cases
- The classifier prompt will need tuning after seeing real output
- No tests yet
- No resume/checkpoint logic beyond the DB status fields

## Environment
- Python 3.14+
- Managed with uv (`uv sync` to install, `uv run ctf-playbook` to run)
- Key deps: requests, httpx, beautifulsoup4, lxml, trafilatura, anthropic, rich, click
- Env vars: `GITHUB_TOKEN` (optional, raises rate limit), `ANTHROPIC_API_KEY` (needed for classify stage)

## Running
```bash
uv run ctf-playbook scrape --max-events 50   # start small
uv run ctf-playbook fetch --limit 100
uv run ctf-playbook classify --limit 50      # needs ANTHROPIC_API_KEY
uv run ctf-playbook build
uv run ctf-playbook stats
uv run ctf-playbook all                       # full pipeline
```

## Priority TODO
1. Run the scraper against a small batch and fix HTML parsing issues
2. Test the fetcher on a mix of GitHub raw URLs, blog posts, and CTFtime pages
3. Run the classifier on ~20 writeups and evaluate/tune the prompt
4. Add deduplication (same writeup found via CTFtime and GitHub)
5. Add a `search` CLI command to query the classified DB ("what techniques for a challenge that looks like X")
6. Add `--resume` logic and better error recovery
7. Tests for the DB layer and parsers
