"""Build the playbook folder structure from classified writeup data.

Generates:
  - Technique folders with _pattern.md files (aggregated recognition signals + solve flows)
  - Individual writeup reference files linking back to sources
  - A master index for searching
"""

import json
from collections import defaultdict
from pathlib import Path

from rich.console import Console

from ctf_playbook.taxonomy import TAXONOMY, get_sub_techniques
from ctf_playbook.config import PLAYBOOK_DIR
from ctf_playbook.db import db_session

console = Console()

TECHNIQUES_DIR = PLAYBOOK_DIR / "techniques"
RECON_DIR = PLAYBOOK_DIR / "recon-patterns"
TOOLCHAINS_DIR = PLAYBOOK_DIR / "toolchains"
INDEX_PATH = PLAYBOOK_DIR / "INDEX.md"


def _slug_to_title(slug: str) -> str:
    return slug.replace("-", " ").title()


def _find_parent_category(technique_slug: str) -> str | None:
    """Find which top-level category a technique belongs to."""
    for category, info in TAXONOMY.items():
        if technique_slug in info["techniques"]:
            return category
    return None


def build_folder_structure():
    """Create the empty taxonomy folders."""
    for category, info in TAXONOMY.items():
        for technique in info["techniques"]:
            (TECHNIQUES_DIR / category / technique).mkdir(parents=True, exist_ok=True)

    RECON_DIR.mkdir(parents=True, exist_ok=True)
    TOOLCHAINS_DIR.mkdir(parents=True, exist_ok=True)
    (PLAYBOOK_DIR / "raw-writeups").mkdir(parents=True, exist_ok=True)


def _render_pattern_content(slug: str, data: dict) -> str:
    """Render the markdown content for a technique or sub-technique pattern file."""
    # Sort recognition signals by frequency
    top_signals = sorted(data["recognition"].items(), key=lambda x: -x[1])[:10]
    # Sort tools by frequency
    top_tools = sorted(data["tools"].items(), key=lambda x: -x[1])[:15]
    # Most common difficulty
    top_diff = max(data["difficulties"].items(), key=lambda x: x[1])[0] \
        if data["difficulties"] else "medium"

    # Build a generalized solve flow from the most common step patterns
    # (simplified: just show a representative example)
    representative_steps = data["steps"][0] if data["steps"] else []

    lines = [
        f"# {_slug_to_title(slug)}",
        "",
        f"**Typical Difficulty:** {top_diff}",
        f"**Examples in collection:** {len(data['examples'])}",
        "",
        "## Recognition Signals",
        "",
        "How to identify when this technique applies:",
        "",
    ]
    for signal, count in top_signals:
        lines.append(f"- {signal} (seen {count}x)")

    lines += [
        "",
        "## Common Tools",
        "",
    ]
    for tool, count in top_tools:
        lines.append(f"- **{tool}** (used {count}x)")

    lines += [
        "",
        "## Generalized Solve Flow",
        "",
    ]
    for i, step in enumerate(representative_steps, 1):
        lines.append(f"{i}. {step}")

    lines += [
        "",
        "## Example Writeups",
        "",
    ]
    # Show up to 10 examples, newest first
    sorted_examples = sorted(data["examples"], key=lambda x: x["year"] or 0, reverse=True)
    for ex in sorted_examples[:10]:
        year_str = f" ({ex['year']})" if ex['year'] else ""
        lines.append(f"- **{ex['challenge']}** — {ex['event']}{year_str} "
                     f"[{ex['difficulty']}]")
        if ex["summary"]:
            lines.append(f"  {ex['summary']}")
        lines.append(f"  [{ex['url']}]({ex['url']})")
        lines.append("")

    return "\n".join(lines)


def _empty_data_bucket() -> dict:
    """Create an empty data aggregation bucket."""
    return {
        "recognition": defaultdict(int),
        "tools": defaultdict(int),
        "steps": [],
        "difficulties": defaultdict(int),
        "examples": [],
    }


def build_pattern_files():
    """Aggregate classified writeups into _pattern.md files per technique.

    Each pattern file contains:
      - How to recognize this type of challenge
      - Common tools
      - Generalized solve steps
      - Links to example writeups

    When sub-techniques exist, generates additional .md files per sub-technique
    inside the technique folder.
    """
    console.print("Building pattern files from classified data...")

    with db_session() as conn:
        rows = conn.execute("""
            SELECT w.id, w.url, w.techniques, w.tools_used, w.solve_steps,
                   w.recognition, w.difficulty, w.notes,
                   c.name as challenge_name, c.category, e.name as event_name, e.year
            FROM writeups w
            JOIN challenges c ON w.challenge_id = c.id
            JOIN events e ON c.event_id = e.id
            WHERE w.class_status = 'classified'
        """).fetchall()

        # Query sub-technique mappings from the join table
        sub_rows = conn.execute("""
            SELECT writeup_id, technique, sub_technique
            FROM writeup_techniques
            WHERE sub_technique IS NOT NULL
        """).fetchall()

    if not rows:
        console.print("[yellow]No classified writeups found. Run the classifier first.[/]")
        return

    # Build writeup_id -> list of (technique, sub_technique) from join table
    writeup_subs: dict[int, list[tuple[str, str]]] = defaultdict(list)
    for sr in sub_rows:
        writeup_subs[sr["writeup_id"]].append((sr["technique"], sr["sub_technique"]))

    # Group by technique (top-level aggregation, same as before)
    technique_data = defaultdict(_empty_data_bucket)
    # Group by (technique, sub_technique) for sub-technique files
    sub_technique_data: dict[str, dict[str, dict]] = defaultdict(
        lambda: defaultdict(_empty_data_bucket)
    )

    for row in rows:
        techniques = json.loads(row["techniques"]) if row["techniques"] else []
        tools = json.loads(row["tools_used"]) if row["tools_used"] else []
        steps = json.loads(row["solve_steps"]) if row["solve_steps"] else []
        recognition = json.loads(row["recognition"]) if row["recognition"] else []

        example = {
            "challenge": row["challenge_name"],
            "event": row["event_name"],
            "year": row["year"],
            "url": row["url"],
            "summary": row["notes"] or "",
            "difficulty": row["difficulty"] or "medium",
        }

        for tech in techniques:
            td = technique_data[tech]
            for sig in recognition:
                td["recognition"][sig] += 1
            for tool in tools:
                td["tools"][tool] += 1
            td["steps"].append(steps)
            td["difficulties"][row["difficulty"] or "medium"] += 1
            td["examples"].append(example)

        # Aggregate sub-technique data from the join table
        for parent_tech, sub_tech in writeup_subs.get(row["id"], []):
            std = sub_technique_data[parent_tech][sub_tech]
            for sig in recognition:
                std["recognition"][sig] += 1
            for tool in tools:
                std["tools"][tool] += 1
            std["steps"].append(steps)
            std["difficulties"][row["difficulty"] or "medium"] += 1
            std["examples"].append(example)

    # Generate _pattern.md for each technique
    for tech_slug, data in technique_data.items():
        parent = _find_parent_category(tech_slug)
        if parent:
            tech_dir = TECHNIQUES_DIR / parent / tech_slug
        else:
            tech_dir = TECHNIQUES_DIR / "misc" / tech_slug

        tech_dir.mkdir(parents=True, exist_ok=True)

        # Render the main _pattern.md
        content = _render_pattern_content(tech_slug, data)

        # If this technique has sub-technique data, add a sub-techniques section
        subs_for_tech = sub_technique_data.get(tech_slug, {})
        if subs_for_tech:
            sub_lines = [
                "",
                "## Sub-Techniques",
                "",
                "| Sub-Technique | Writeups | Typical Difficulty |",
                "|---|---|---|",
            ]
            for sub_slug, sub_data in sorted(subs_for_tech.items()):
                sub_count = len(sub_data["examples"])
                sub_diff = max(sub_data["difficulties"].items(), key=lambda x: x[1])[0] \
                    if sub_data["difficulties"] else "medium"
                sub_lines.append(
                    f"| [{_slug_to_title(sub_slug)}]({sub_slug}.md) "
                    f"| {sub_count} | {sub_diff} |"
                )
            sub_lines.append("")
            content += "\n" + "\n".join(sub_lines)

        (tech_dir / "_pattern.md").write_text(content, encoding="utf-8")

        # Generate sub-technique .md files
        for sub_slug, sub_data in subs_for_tech.items():
            sub_content = _render_pattern_content(sub_slug, sub_data)
            (tech_dir / f"{sub_slug}.md").write_text(sub_content, encoding="utf-8")

    sub_file_count = sum(len(subs) for subs in sub_technique_data.values())
    console.print(
        f"Built pattern files for [green]{len(technique_data)}[/] techniques"
        + (f" ({sub_file_count} sub-technique files)" if sub_file_count else "")
    )
    return technique_data


def build_tool_cheatsheets(technique_data: dict = None):
    """Generate tool cheatsheets from the most commonly used tools."""
    if not technique_data:
        console.print("[yellow]No technique data — skipping tool cheatsheets[/]")
        return

    # Aggregate all tools across techniques
    all_tools = defaultdict(lambda: {"count": 0, "techniques": set()})
    for tech, data in technique_data.items():
        for tool, count in data["tools"].items():
            all_tools[tool]["count"] += count
            all_tools[tool]["techniques"].add(tech)

    top_tools = sorted(all_tools.items(), key=lambda x: -x[1]["count"])[:30]

    lines = [
        "# Tool Reference",
        "",
        "Tools most frequently used across classified writeups.",
        "",
    ]
    for tool, info in top_tools:
        techs = ", ".join(sorted(info["techniques"])[:5])
        lines.append(f"## {tool}")
        lines.append(f"Used {info['count']} times across techniques: {techs}")
        lines.append("")

    (TOOLCHAINS_DIR / "tool-reference.md").write_text("\n".join(lines), encoding="utf-8")
    console.print(f"Built tool reference with [green]{len(top_tools)}[/] tools")


def build_recon_patterns(technique_data: dict = None):
    """Generate recon-pattern files that map observable signals to techniques.

    The idea: when you first look at a CTF challenge, you see symptoms
    (e.g. "binary with gets() and no canary", "RSA with small e").
    These files let you go from what-you-see to what-technique-to-try.

    Generates one file per top-level category, each listing recognition
    signals grouped by technique, plus a master "quick-reference.md".
    """
    if not technique_data:
        console.print("[yellow]No technique data — skipping recon patterns[/]")
        return

    # Collect signals grouped by category -> technique -> signals
    cat_signals: dict[str, dict[str, list[tuple[str, int]]]] = defaultdict(dict)
    # Also build a flat signal -> techniques lookup for the quick reference
    signal_to_techs: dict[str, list[str]] = defaultdict(list)

    for tech_slug, data in technique_data.items():
        if not data["recognition"]:
            continue

        parent = _find_parent_category(tech_slug) or "misc"
        top_signals = sorted(data["recognition"].items(), key=lambda x: -x[1])[:5]
        cat_signals[parent][tech_slug] = top_signals

        for signal, count in top_signals:
            signal_to_techs[signal].append(tech_slug)

    # Write per-category recon files
    for category, techs in sorted(cat_signals.items()):
        lines = [
            f"# Recon Patterns: {_slug_to_title(category)}",
            "",
            "What to look for when you suspect a challenge falls in this category.",
            "",
        ]

        for tech_slug in sorted(techs):
            signals = techs[tech_slug]
            lines.append(f"## {_slug_to_title(tech_slug)}")
            lines.append("")
            for signal, count in signals:
                lines.append(f"- {signal}")
            lines.append("")

        path = RECON_DIR / f"{category}.md"
        path.write_text("\n".join(lines), encoding="utf-8")

    # Write the quick-reference: signal -> technique lookup
    lines = [
        "# Recon Quick Reference",
        "",
        "Reverse lookup: from what you observe to which technique to try.",
        "",
        "| Signal | Likely Technique(s) |",
        "|--------|-------------------|",
    ]

    # Sort by number of techniques (more specific signals first)
    for signal, techs in sorted(signal_to_techs.items(), key=lambda x: len(x[1])):
        tech_list = ", ".join(techs[:3])
        # Escape pipe chars in signal text for markdown table
        safe_signal = signal.replace("|", "\\|")
        lines.append(f"| {safe_signal} | {tech_list} |")

    lines.append("")
    (RECON_DIR / "quick-reference.md").write_text("\n".join(lines), encoding="utf-8")

    console.print(f"Built recon patterns for [green]{len(cat_signals)}[/] categories "
                  f"({sum(len(t) for t in cat_signals.values())} techniques)")


def build_master_index():
    """Generate a master INDEX.md with links to all technique patterns."""
    lines = [
        "# CTF Playbook Index",
        "",
        "## Techniques",
        "",
    ]

    for category, info in TAXONOMY.items():
        lines.append(f"### {_slug_to_title(category)}")
        lines.append(f"_{info['description']}_")
        lines.append("")

        for tech in info["techniques"]:
            pattern_file = TECHNIQUES_DIR / category / tech / "_pattern.md"
            if pattern_file.exists():
                lines.append(f"- [{_slug_to_title(tech)}]"
                             f"(techniques/{category}/{tech}/_pattern.md)")
            else:
                lines.append(f"- {_slug_to_title(tech)} _(no writeups yet)_")

            # List sub-technique files if they exist
            tech_dir = TECHNIQUES_DIR / category / tech
            if tech_dir.is_dir():
                for sub_file in sorted(tech_dir.glob("*.md")):
                    if sub_file.name.startswith("_"):
                        continue  # skip _pattern.md
                    sub_slug = sub_file.stem
                    lines.append(
                        f"  - [{_slug_to_title(sub_slug)}]"
                        f"(techniques/{category}/{tech}/{sub_file.name})"
                    )
        lines.append("")

    # Check for techniques not in the taxonomy (discovered by classifier)
    known_techs = set()
    for info in TAXONOMY.values():
        known_techs.update(info["techniques"])

    discovered = []
    for cat_dir in TECHNIQUES_DIR.iterdir():
        if cat_dir.is_dir():
            for tech_dir in cat_dir.iterdir():
                if tech_dir.is_dir() and tech_dir.name not in known_techs:
                    pattern = tech_dir / "_pattern.md"
                    if pattern.exists():
                        discovered.append((cat_dir.name, tech_dir.name))

    if discovered:
        lines.append("### Discovered Techniques")
        lines.append("_Techniques found by the classifier that weren't in the original taxonomy_")
        lines.append("")
        for cat, tech in sorted(discovered):
            lines.append(f"- [{_slug_to_title(tech)}]"
                         f"(techniques/{cat}/{tech}/_pattern.md)")
        lines.append("")

    # Recon patterns section
    recon_files = sorted(RECON_DIR.glob("*.md"))
    if recon_files:
        lines.append("## Recon Patterns")
        lines.append("_From what you observe to which technique to try_")
        lines.append("")
        for f in recon_files:
            lines.append(f"- [{_slug_to_title(f.stem)}](recon-patterns/{f.name})")
        lines.append("")

    INDEX_PATH.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"Built master index at [green]{INDEX_PATH}[/]")


def run():
    """Main entry point: build the complete playbook structure."""
    console.rule("[bold blue]Playbook Builder")

    build_folder_structure()
    console.print("[green]Folder structure created[/]")

    technique_data = build_pattern_files()
    build_recon_patterns(technique_data)
    build_tool_cheatsheets(technique_data)
    build_master_index()

    console.print("\n[bold green]Playbook built successfully![/]")
    console.print(f"Browse it at: {PLAYBOOK_DIR}")


if __name__ == "__main__":
    run()
