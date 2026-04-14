"""Build the playbook from classified writeup data.

Three-phase pipeline:
  1. Data assembly — query DB, aggregate into a structured dict
  2. JSON export  — write playbook.json (the single source of truth)
  3. Markdown render — generate browsable .md files from the data
"""

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from difflib import SequenceMatcher
from itertools import combinations
from pathlib import Path

from rich.console import Console

from ctf_playbook.taxonomy import TAXONOMY, get_sub_techniques, infer_category_from_slug
from ctf_playbook.config import PLAYBOOK_DIR
from ctf_playbook.db import db_session

console = Console()

TECHNIQUES_DIR = PLAYBOOK_DIR / "techniques"
RECON_DIR = PLAYBOOK_DIR / "recon-patterns"
TOOLCHAINS_DIR = PLAYBOOK_DIR / "toolchains"
INDEX_PATH = PLAYBOOK_DIR / "INDEX.md"
PLAYBOOK_JSON_PATH = PLAYBOOK_DIR / "playbook.json"


def _slug_to_title(slug: str) -> str:
    return slug.replace("-", " ").title()


def _find_parent_category(technique_slug: str) -> str | None:
    """Find which top-level category a technique belongs to.

    Direct taxonomy lookup first, then keyword-based inference as fallback.
    """
    for category, info in TAXONOMY.items():
        if technique_slug in info["techniques"]:
            return category
    return infer_category_from_slug(technique_slug)


def build_folder_structure():
    """Create the empty taxonomy folders."""
    for category, info in TAXONOMY.items():
        for technique in info["techniques"]:
            (TECHNIQUES_DIR / category / technique).mkdir(parents=True, exist_ok=True)

    RECON_DIR.mkdir(parents=True, exist_ok=True)
    TOOLCHAINS_DIR.mkdir(parents=True, exist_ok=True)
    (PLAYBOOK_DIR / "raw-writeups").mkdir(parents=True, exist_ok=True)


def _merge_solve_steps(step_lists: list[list[str]], max_steps: int = 7) -> list[str]:
    """Merge multiple solve step lists into a generalized flow.

    Uses frequency and positional analysis: steps that appear across multiple
    writeups are preferred, ordered by their average position. Falls back to
    the longest individual step list when there isn't enough consensus.
    """
    if not step_lists:
        return []
    if len(step_lists) == 1:
        return step_lists[0][:max_steps]

    # Track each normalized step's frequency and average position
    step_info: dict[str, dict] = {}  # normalized -> {original, count, total_pos}
    for steps in step_lists:
        for pos, step in enumerate(steps):
            key = step.strip().lower()
            if key not in step_info:
                step_info[key] = {"original": step, "count": 0, "total_pos": 0}
            step_info[key]["count"] += 1
            step_info[key]["total_pos"] += pos

    # Steps appearing in 2+ writeups = consensus
    consensus = [s for s in step_info.values() if s["count"] >= 2]
    if len(consensus) >= 3:
        # Sort by average position for natural ordering
        consensus.sort(key=lambda s: s["total_pos"] / s["count"])
        return [s["original"] for s in consensus[:max_steps]]

    # Not enough consensus — use the longest individual step list
    longest = max(step_lists, key=len)
    return longest[:max_steps]


def _normalize_signal(signal: str) -> str:
    """Normalize a signal string for dedup comparison."""
    s = signal.strip().lower()
    s = s.rstrip(".,;:!?")
    s = re.sub(r"\s+", " ", s)
    return s


def _merge_signals(raw_signals: dict[str, int],
                   similarity_threshold: float = 0.85) -> dict[str, int]:
    """Merge near-duplicate recognition signals.

    Three-pass approach:
    1. Exact match after normalization (case, whitespace, punctuation)
    2. Substring absorption (shorter signal subsumes longer)
    3. Fuzzy similarity via SequenceMatcher
    """
    # Pass 1: Group by normalized form
    groups: dict[str, dict] = {}  # normalized_key -> {canonical, count}
    for signal, count in raw_signals.items():
        key = _normalize_signal(signal)
        if not key:
            continue
        if key in groups:
            groups[key]["count"] += count
            # Prefer shorter signal as canonical (more general)
            if len(signal) < len(groups[key]["canonical"]):
                groups[key]["canonical"] = signal
        else:
            groups[key] = {"canonical": signal, "count": count}

    # Pass 2: Substring absorption — shorter subsumes longer
    keys = sorted(groups.keys(), key=len)
    absorbed: set[str] = set()
    for i, shorter in enumerate(keys):
        if shorter in absorbed:
            continue
        for longer in keys[i + 1:]:
            if longer in absorbed:
                continue
            if shorter in longer:
                groups[shorter]["count"] += groups[longer]["count"]
                absorbed.add(longer)
    for key in absorbed:
        del groups[key]

    # Pass 3: Fuzzy similarity merge
    remaining = list(groups.keys())
    merged_into: dict[str, str] = {}  # key -> target_key
    for i in range(len(remaining)):
        if remaining[i] in merged_into:
            continue
        for j in range(i + 1, len(remaining)):
            if remaining[j] in merged_into:
                continue
            ratio = SequenceMatcher(None, remaining[i], remaining[j]).ratio()
            if ratio >= similarity_threshold:
                merged_into[remaining[j]] = remaining[i]

    for src, dst in merged_into.items():
        while dst in merged_into:
            dst = merged_into[dst]
        groups[dst]["count"] += groups[src]["count"]
        if len(groups[src]["canonical"]) < len(groups[dst]["canonical"]):
            groups[dst]["canonical"] = groups[src]["canonical"]
        del groups[src]

    return {info["canonical"]: info["count"] for info in groups.values()}


def _merge_tools(raw_tools: dict[str, int]) -> dict[str, int]:
    """Merge tool name variants by case-insensitive normalization."""
    groups: dict[str, dict] = {}  # lowered -> {canonical, count}
    for tool, count in raw_tools.items():
        key = tool.strip().lower()
        if key in groups:
            groups[key]["count"] += count
            # Keep the form with higher count as canonical
            if count > groups[key]["best_count"]:
                groups[key]["canonical"] = tool
                groups[key]["best_count"] = count
        else:
            groups[key] = {"canonical": tool, "count": count, "best_count": count}
    return {info["canonical"]: info["count"] for info in groups.values()}


# ── Data Assembly ────────────────────────────────────────────────────────


def _empty_data_bucket() -> dict:
    """Create an empty data aggregation bucket."""
    return {
        "recognition": defaultdict(int),
        "tools": defaultdict(int),
        "steps": [],
        "difficulties": defaultdict(int),
        "examples": [],
    }


def _assemble_technique_data(conn) -> tuple[dict, dict]:
    """Query DB and aggregate writeups into per-technique data buckets.

    Returns (technique_data, sub_technique_data) where:
    - technique_data: {slug: data_bucket}
    - sub_technique_data: {parent_slug: {sub_slug: data_bucket}}
    """
    rows = conn.execute("""
        SELECT w.id, w.url, w.techniques, w.tools_used, w.solve_steps,
               w.recognition, w.difficulty, w.notes,
               c.name as challenge_name, c.category, e.name as event_name, e.year
        FROM writeups w
        JOIN challenges c ON w.challenge_id = c.id
        JOIN events e ON c.event_id = e.id
        WHERE w.class_status = 'classified'
    """).fetchall()

    # Query per-technique data from the join table
    wt_rows = conn.execute("""
        SELECT writeup_id, technique, sub_technique,
               recognition_signals, sub_recognition_signals,
               solve_steps, sub_solve_steps
        FROM writeup_techniques
    """).fetchall()

    # Build lookup: writeup_id -> {technique -> row data}
    wt_lookup: dict[int, dict[str, dict]] = defaultdict(dict)
    writeup_subs: dict[int, list[tuple[str, str]]] = defaultdict(list)
    for wr in wt_rows:
        wt_lookup[wr["writeup_id"]][wr["technique"]] = {
            "recognition_signals": json.loads(wr["recognition_signals"])
                if wr["recognition_signals"] else None,
            "sub_recognition_signals": json.loads(wr["sub_recognition_signals"])
                if wr["sub_recognition_signals"] else None,
            "solve_steps": json.loads(wr["solve_steps"])
                if wr["solve_steps"] else None,
            "sub_solve_steps": json.loads(wr["sub_solve_steps"])
                if wr["sub_solve_steps"] else None,
        }
        if wr["sub_technique"]:
            writeup_subs[wr["writeup_id"]].append(
                (wr["technique"], wr["sub_technique"])
            )

    # Aggregate by technique
    technique_data = defaultdict(_empty_data_bucket)
    sub_technique_data: dict[str, dict[str, dict]] = defaultdict(
        lambda: defaultdict(_empty_data_bucket)
    )

    for row in rows:
        techniques = json.loads(row["techniques"]) if row["techniques"] else []
        tools = json.loads(row["tools_used"]) if row["tools_used"] else []
        flat_steps = json.loads(row["solve_steps"]) if row["solve_steps"] else []
        flat_recognition = json.loads(row["recognition"]) if row["recognition"] else []

        example = {
            "challenge": row["challenge_name"],
            "event": row["event_name"],
            "year": row["year"],
            "url": row["url"],
            "summary": row["notes"] or "",
            "difficulty": row["difficulty"] or "medium",
        }

        wt_for_writeup = wt_lookup.get(row["id"], {})

        for tech in techniques:
            td = technique_data[tech]

            wt_data = wt_for_writeup.get(tech, {})
            tech_signals = wt_data.get("recognition_signals") or flat_recognition
            tech_steps = wt_data.get("solve_steps") or flat_steps

            for sig in tech_signals:
                td["recognition"][sig] += 1
            for tool in tools:
                td["tools"][tool] += 1
            td["steps"].append(tech_steps)
            td["difficulties"][row["difficulty"] or "medium"] += 1
            td["examples"].append(example)

        # Sub-technique aggregation
        for parent_tech, sub_tech in writeup_subs.get(row["id"], []):
            std = sub_technique_data[parent_tech][sub_tech]

            wt_data = wt_for_writeup.get(parent_tech, {})
            sub_signals = wt_data.get("sub_recognition_signals") or flat_recognition
            sub_steps = wt_data.get("sub_solve_steps") or flat_steps

            for sig in sub_signals:
                std["recognition"][sig] += 1
            for tool in tools:
                std["tools"][tool] += 1
            std["steps"].append(sub_steps)
            std["difficulties"][row["difficulty"] or "medium"] += 1
            std["examples"].append(example)

    return technique_data, sub_technique_data


def _assemble_cross_references(conn, min_count: int = 2) -> dict[str, list[dict]]:
    """Mine co-occurring technique pairs from writeups.

    Returns {technique: [{"technique": related_slug, "count": N}, ...]}
    sorted by count descending.
    """
    rows = conn.execute("""
        SELECT techniques FROM writeups
        WHERE class_status = 'classified' AND techniques IS NOT NULL
    """).fetchall()

    pair_counts: Counter = Counter()
    for row in rows:
        techs = json.loads(row["techniques"])
        if len(techs) < 2:
            continue
        for a, b in combinations(sorted(set(techs)), 2):
            pair_counts[(a, b)] += 1

    # Build per-technique lists
    xrefs: dict[str, list[dict]] = defaultdict(list)
    for (a, b), count in pair_counts.items():
        if count >= min_count:
            xrefs[a].append({"technique": b, "count": count})
            xrefs[b].append({"technique": a, "count": count})

    # Sort each list by count descending, cap at 5
    for slug in xrefs:
        xrefs[slug] = sorted(xrefs[slug], key=lambda x: -x["count"])[:5]

    return dict(xrefs)


def _serialize_technique(slug: str, data: dict,
                         sub_data: dict | None = None) -> dict:
    """Convert an internal data bucket to a JSON-serializable dict."""
    merged_recognition = _merge_signals(dict(data["recognition"]))
    top_signals = sorted(merged_recognition.items(), key=lambda x: -x[1])[:10]
    merged_tools = _merge_tools(dict(data["tools"]))
    top_tools = sorted(merged_tools.items(), key=lambda x: -x[1])[:15]
    top_diff = (max(data["difficulties"].items(), key=lambda x: x[1])[0]
                if data["difficulties"] else "medium")
    merged_steps = _merge_solve_steps(data["steps"])

    result = {
        "difficulty": top_diff,
        "example_count": len(data["examples"]),
        "recognition_signals": [
            {"signal": s, "count": c} for s, c in top_signals
        ],
        "tools": [{"tool": t, "count": c} for t, c in top_tools],
        "solve_steps": merged_steps,
        "examples": sorted(
            data["examples"], key=lambda x: x["year"] or 0, reverse=True
        ),
    }

    if sub_data:
        result["sub_techniques"] = {
            sub_slug: _serialize_technique(sub_slug, sd)
            for sub_slug, sd in sorted(sub_data.items())
        }

    return result


def _assemble_recon_patterns(techniques: dict) -> dict:
    """Build recon pattern data grouped by category."""
    categories: dict[str, dict] = {}
    for slug, tech in techniques.items():
        if not tech["recognition_signals"]:
            continue
        cat = tech["category"]
        if cat not in categories:
            categories[cat] = {
                "description": TAXONOMY.get(cat, {}).get("description", ""),
                "techniques": {},
            }
        signals = [s["signal"] for s in tech["recognition_signals"][:5]]
        categories[cat]["techniques"][slug] = signals
    return categories


def _assemble_tool_reference(techniques: dict) -> list[dict]:
    """Build tool reference aggregated across all techniques."""
    all_tools: dict[str, dict] = defaultdict(
        lambda: {"count": 0, "techniques": set()}
    )
    for slug, tech in techniques.items():
        for item in tech["tools"]:
            all_tools[item["tool"]]["count"] += item["count"]
            all_tools[item["tool"]]["techniques"].add(slug)

    result = []
    for tool, info in sorted(all_tools.items(), key=lambda x: -x[1]["count"])[:30]:
        result.append({
            "tool": tool,
            "count": info["count"],
            "techniques": sorted(info["techniques"])[:5],
        })
    return result


def build_playbook_data() -> dict | None:
    """Assemble the complete playbook as a structured dict.

    This is the single source of truth. Both JSON export and markdown
    rendering work from this data model.
    """
    console.print("Assembling playbook data...")

    with db_session() as conn:
        technique_data, sub_technique_data = _assemble_technique_data(conn)
        cross_refs = _assemble_cross_references(conn)

    if not technique_data:
        console.print("[yellow]No classified writeups found. Run the classifier first.[/]")
        return None

    # Serialize every technique into a clean, JSON-safe dict
    techniques: dict[str, dict] = {}
    for slug, data in technique_data.items():
        cat = _find_parent_category(slug) or "misc"
        tech = _serialize_technique(slug, data, sub_technique_data.get(slug))
        tech["category"] = cat
        tech["cross_references"] = cross_refs.get(slug, [])
        techniques[slug] = tech

    recon = _assemble_recon_patterns(techniques)
    tools = _assemble_tool_reference(techniques)

    total_subs = sum(
        len(t.get("sub_techniques", {})) for t in techniques.values()
    )

    playbook = {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "total_techniques": len(techniques),
            "total_writeups": len({
                ex["url"]
                for t in techniques.values()
                for ex in t.get("examples", [])
            }),
            "total_sub_techniques": total_subs,
        },
        "techniques": techniques,
        "recon_patterns": recon,
        "tool_reference": tools,
    }

    console.print(
        f"Assembled [green]{len(techniques)}[/] techniques"
        + (f" ({total_subs} sub-technique variants)" if total_subs else "")
    )
    return playbook


# ── JSON Export ──────────────────────────────────────────────────────────


def export_playbook_json(playbook: dict, path: Path | None = None):
    """Write the playbook data model to a JSON file."""
    path = path or PLAYBOOK_JSON_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(playbook, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    console.print(f"Exported playbook JSON to [green]{path}[/]")


# ── Markdown Rendering ──────────────────────────────────────────────────


def _render_pattern_content(slug: str, tech: dict) -> str:
    """Render the markdown content for a technique or sub-technique."""
    lines = [
        f"# {_slug_to_title(slug)}",
        "",
        f"**Typical Difficulty:** {tech['difficulty']}",
        f"**Examples in collection:** {tech['example_count']}",
        "",
        "## Recognition Signals",
        "",
        "How to identify when this technique applies:",
        "",
    ]
    for item in tech["recognition_signals"]:
        lines.append(f"- {item['signal']} (seen {item['count']}x)")

    lines += ["", "## Common Tools", ""]
    for item in tech["tools"]:
        lines.append(f"- **{item['tool']}** (used {item['count']}x)")

    # Only show solve flow for techniques without sub-techniques
    if tech["solve_steps"] and not tech.get("sub_techniques"):
        lines += ["", "## Generalized Solve Flow", ""]
        for i, step in enumerate(tech["solve_steps"], 1):
            lines.append(f"{i}. {step}")

    # Cross-references (if any)
    xrefs = tech.get("cross_references", [])
    if xrefs:
        lines += ["", "## See Also", ""]
        lines.append("Techniques that frequently co-occur with this one:")
        lines.append("")
        for xref in xrefs:
            slug = xref["technique"]
            cat = _find_parent_category(slug)
            if cat:
                link = f"../{slug}/_pattern.md"
            else:
                link = f"../../misc/{slug}/_pattern.md"
            lines.append(
                f"- [{_slug_to_title(slug)}]({link}) "
                f"(seen together {xref['count']}x)"
            )

    lines += ["", "## Example Writeups", ""]
    # Cap at 10 examples in the markdown view
    for ex in tech["examples"][:10]:
        year_str = f" ({ex['year']})" if ex["year"] else ""
        lines.append(
            f"- **{ex['challenge']}** — {ex['event']}{year_str} "
            f"[{ex['difficulty']}]"
        )
        if ex["summary"]:
            lines.append(f"  {ex['summary']}")
        lines.append(f"  [{ex['url']}]({ex['url']})")
        lines.append("")

    return "\n".join(lines)


def _render_technique_files(techniques: dict):
    """Write _pattern.md and sub-technique .md files for every technique."""
    sub_file_count = 0
    for slug, tech in techniques.items():
        cat = tech["category"]
        tech_dir = TECHNIQUES_DIR / cat / slug
        tech_dir.mkdir(parents=True, exist_ok=True)

        content = _render_pattern_content(slug, tech)

        # Append sub-technique table if any exist
        subs = tech.get("sub_techniques", {})
        if subs:
            sub_lines = [
                "",
                "## Sub-Techniques",
                "",
            ]
            if len(subs) >= 2:
                sub_lines.append(
                    "See the [decision tree](_recon.md) to identify "
                    "which variant applies."
                )
                sub_lines.append("")
            sub_lines += [
                "| Sub-Technique | Writeups | Typical Difficulty |",
                "|---|---|---|",
            ]
            for sub_slug, sub_data in subs.items():
                sub_lines.append(
                    f"| [{_slug_to_title(sub_slug)}]({sub_slug}.md) "
                    f"| {sub_data['example_count']} | {sub_data['difficulty']} |"
                )
            sub_lines.append("")
            content += "\n" + "\n".join(sub_lines)

        (tech_dir / "_pattern.md").write_text(content, encoding="utf-8")

        # Individual sub-technique files
        for sub_slug, sub_data in subs.items():
            sub_content = _render_pattern_content(sub_slug, sub_data)
            (tech_dir / f"{sub_slug}.md").write_text(sub_content, encoding="utf-8")
            sub_file_count += 1

    console.print(
        f"Built pattern files for [green]{len(techniques)}[/] techniques"
        + (f" ({sub_file_count} sub-technique files)" if sub_file_count else "")
    )


def _render_recon_patterns(recon_patterns: dict):
    """Write per-category recon files and the quick-reference lookup table."""
    signal_to_techs: dict[str, list[str]] = defaultdict(list)

    for cat, cat_data in sorted(recon_patterns.items()):
        lines = [
            f"# Recon Patterns: {_slug_to_title(cat)}",
            "",
            "What to look for when you suspect a challenge falls in this category.",
            "",
        ]
        for tech_slug in sorted(cat_data["techniques"]):
            signals = cat_data["techniques"][tech_slug]
            lines.append(f"## {_slug_to_title(tech_slug)}")
            lines.append("")
            for signal in signals:
                lines.append(f"- {signal}")
                signal_to_techs[signal].append(tech_slug)
            lines.append("")

        (RECON_DIR / f"{cat}.md").write_text("\n".join(lines), encoding="utf-8")

    # Quick reference: signal -> technique lookup
    lines = [
        "# Recon Quick Reference",
        "",
        "Reverse lookup: from what you observe to which technique to try.",
        "",
        "| Signal | Likely Technique(s) |",
        "|--------|-------------------|",
    ]
    for signal, techs in sorted(signal_to_techs.items(), key=lambda x: len(x[1])):
        tech_list = ", ".join(techs[:3])
        safe_signal = signal.replace("|", "\\|")
        lines.append(f"| {safe_signal} | {tech_list} |")
    lines.append("")

    (RECON_DIR / "quick-reference.md").write_text("\n".join(lines), encoding="utf-8")
    console.print(
        f"Built recon patterns for [green]{len(recon_patterns)}[/] categories"
    )


def _render_tool_reference(tool_reference: list[dict]):
    """Write the tool reference markdown file."""
    lines = [
        "# Tool Reference",
        "",
        "Tools most frequently used across classified writeups.",
        "",
    ]
    for item in tool_reference:
        techs = ", ".join(item["techniques"])
        lines.append(f"## {item['tool']}")
        lines.append(f"Used {item['count']} times across techniques: {techs}")
        lines.append("")

    (TOOLCHAINS_DIR / "tool-reference.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )
    console.print(f"Built tool reference with [green]{len(tool_reference)}[/] tools")


def _render_master_index(techniques: dict):
    """Generate the master INDEX.md with links to all technique patterns."""
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
                lines.append(
                    f"- [{_slug_to_title(tech)}]"
                    f"(techniques/{category}/{tech}/_pattern.md)"
                )
            else:
                lines.append(f"- {_slug_to_title(tech)} _(no writeups yet)_")

            # Link to recon decision tree if it exists
            recon_file = TECHNIQUES_DIR / category / tech / "_recon.md"
            if recon_file.exists():
                lines.append(
                    f"  - [Decision Tree]"
                    f"(techniques/{category}/{tech}/_recon.md)"
                )

            # List sub-technique files
            tech_dir = TECHNIQUES_DIR / category / tech
            if tech_dir.is_dir():
                for sub_file in sorted(tech_dir.glob("*.md")):
                    if sub_file.name.startswith("_"):
                        continue
                    sub_slug = sub_file.stem
                    lines.append(
                        f"  - [{_slug_to_title(sub_slug)}]"
                        f"(techniques/{category}/{tech}/{sub_file.name})"
                    )
        lines.append("")

    # Discovered techniques not in the taxonomy
    known_techs = set()
    for info in TAXONOMY.values():
        known_techs.update(info["techniques"])

    discovered = []
    for cat_dir in TECHNIQUES_DIR.iterdir():
        if cat_dir.is_dir():
            for tech_dir in cat_dir.iterdir():
                if tech_dir.is_dir() and tech_dir.name not in known_techs:
                    if (tech_dir / "_pattern.md").exists():
                        discovered.append((cat_dir.name, tech_dir.name))

    if discovered:
        lines.append("### Discovered Techniques")
        lines.append(
            "_Techniques found by the classifier that weren't in the original taxonomy_"
        )
        lines.append("")
        for cat, tech in sorted(discovered):
            lines.append(
                f"- [{_slug_to_title(tech)}](techniques/{cat}/{tech}/_pattern.md)"
            )
        lines.append("")

    # Link to recon pattern files
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


def _render_recon_trees(techniques: dict):
    """Write _recon.md decision trees for techniques with 2+ sub-techniques.

    Each file maps sub-technique recognition signals to the specific variant,
    helping a player narrow down which sub-technique applies.
    """
    count = 0
    for slug, tech in techniques.items():
        subs = tech.get("sub_techniques", {})
        if len(subs) < 2:
            continue

        cat = tech["category"]
        tech_dir = TECHNIQUES_DIR / cat / slug
        tech_dir.mkdir(parents=True, exist_ok=True)

        lines = [
            f"# {_slug_to_title(slug)} — Decision Tree",
            "",
            "When you've identified this technique family, use these signals "
            "to narrow down the specific variant:",
            "",
        ]

        # Sort sub-techniques: most examples first for prominence
        sorted_subs = sorted(
            subs.items(), key=lambda x: -x[1]["example_count"]
        )

        for sub_slug, sub_data in sorted_subs:
            n = sub_data["example_count"]
            signals = sub_data.get("recognition_signals", [])

            lines.append(f"## {_slug_to_title(sub_slug)}")
            lines.append(f"*{n} writeup{'s' if n != 1 else ''}*")
            lines.append("")

            if signals:
                lines.append("**Look for:**")
                lines.append("")
                for item in signals[:5]:
                    lines.append(f"- {item['signal']}")
            else:
                lines.append("*(no distinguishing signals yet)*")

            lines.append("")
            lines.append(f"→ [{_slug_to_title(sub_slug)}]({sub_slug}.md)")
            lines.append("")

        (tech_dir / "_recon.md").write_text("\n".join(lines), encoding="utf-8")
        count += 1

    if count:
        console.print(
            f"Built recon decision trees for [green]{count}[/] techniques"
        )


def render_markdown(playbook: dict):
    """Generate all markdown files from the playbook data model."""
    _render_technique_files(playbook["techniques"])
    _render_recon_trees(playbook["techniques"])
    _render_recon_patterns(playbook["recon_patterns"])
    _render_tool_reference(playbook["tool_reference"])
    _render_master_index(playbook["techniques"])


# ── Entry Points ────────────────────────────────────────────────────────


def run():
    """Main entry point: build the complete playbook."""
    console.rule("[bold blue]Playbook Builder")

    build_folder_structure()
    console.print("[green]Folder structure created[/]")

    playbook = build_playbook_data()
    if not playbook:
        return

    export_playbook_json(playbook)
    render_markdown(playbook)

    console.print("\n[bold green]Playbook built successfully![/]")
    console.print(f"Browse it at: {PLAYBOOK_DIR}")


if __name__ == "__main__":
    run()
