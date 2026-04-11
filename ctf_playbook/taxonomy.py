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

from ctf_playbook.config import TAXONOMY, PLAYBOOK_DIR
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


def build_pattern_files():
    """Aggregate classified writeups into _pattern.md files per technique.

    Each pattern file contains:
      - How to recognize this type of challenge
      - Common tools
      - Generalized solve steps
      - Links to example writeups
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

    if not rows:
        console.print("[yellow]No classified writeups found. Run the classifier first.[/]")
        return

    # Group by technique
    technique_data = defaultdict(lambda: {
        "recognition": defaultdict(int),  # signal -> count
        "tools": defaultdict(int),        # tool -> count
        "steps": [],                      # list of step-lists
        "difficulties": defaultdict(int),
        "examples": [],                   # list of example dicts
    })

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

    # Generate _pattern.md for each technique
    for tech_slug, data in technique_data.items():
        # Find the right directory
        parent = _find_parent_category(tech_slug)
        if parent:
            tech_dir = TECHNIQUES_DIR / parent / tech_slug
        else:
            # Unknown technique — put in misc
            tech_dir = TECHNIQUES_DIR / "misc" / tech_slug

        tech_dir.mkdir(parents=True, exist_ok=True)
        pattern_path = tech_dir / "_pattern.md"

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
            f"# {_slug_to_title(tech_slug)}",
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

        pattern_path.write_text("\n".join(lines), encoding="utf-8")

    console.print(f"Built pattern files for [green]{len(technique_data)}[/] techniques")
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

    INDEX_PATH.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"Built master index at [green]{INDEX_PATH}[/]")


def run():
    """Main entry point: build the complete playbook structure."""
    console.rule("[bold blue]Playbook Builder")

    build_folder_structure()
    console.print("[green]Folder structure created[/]")

    technique_data = build_pattern_files()
    build_tool_cheatsheets(technique_data)
    build_master_index()

    console.print("\n[bold green]Playbook built successfully![/]")
    console.print(f"Browse it at: {PLAYBOOK_DIR}")


if __name__ == "__main__":
    run()
