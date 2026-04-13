"""HTML page routes for the playbook browser."""

import json
from collections import Counter

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ctf_playbook.gui.app import TEMPLATES, _slug_to_title
from ctf_playbook.gui.data import (
    get_playbook, get_technique, get_techniques_by_category, search_db,
)

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Dashboard page with stats and category overview."""
    pb = get_playbook()
    if not pb:
        return TEMPLATES.TemplateResponse(
            request, "error.html",
            {"message": "No playbook data found. Run `ctf-playbook build` first."},
        )

    techniques = pb.get("techniques", {})
    stats = pb.get("stats", {})

    # Category breakdown
    cat_counts: Counter = Counter()
    diff_counts: Counter = Counter()
    for tech in techniques.values():
        cat_counts[tech.get("category", "misc")] += 1
        diff_counts[tech.get("difficulty", "unknown")] += 1

    tree = get_techniques_by_category()

    generated_at = pb.get("generated_at", "")

    return TEMPLATES.TemplateResponse(request, "index.html", {
        "stats": stats,
        "cat_counts": cat_counts.most_common(),
        "diff_counts": diff_counts.most_common(),
        "tree": tree,
        "generated_at": generated_at,
        "page_title": "Dashboard",
    })


@router.get("/technique/{slug}", response_class=HTMLResponse)
async def technique_detail(request: Request, slug: str):
    """Technique detail page."""
    tech = get_technique(slug)
    if not tech:
        return TEMPLATES.TemplateResponse(
            request, "error.html",
            {"message": f"Technique '{slug}' not found."},
            status_code=404,
        )

    tree = get_techniques_by_category()

    return TEMPLATES.TemplateResponse(request, "technique.html", {
        "slug": slug,
        "tech": tech,
        "tree": tree,
        "page_title": _slug_to_title(slug),
    })


@router.get("/category/{category}", response_class=HTMLResponse)
async def category_overview(request: Request, category: str):
    """Category overview — lists all techniques in a category."""
    pb = get_playbook()
    techniques = pb.get("techniques", {})
    tree = get_techniques_by_category()

    cat_techniques = []
    for slug, tech in techniques.items():
        if tech.get("category") == category:
            cat_techniques.append({"slug": slug, **tech})
    cat_techniques.sort(key=lambda t: t.get("example_count", 0), reverse=True)

    if not cat_techniques:
        return TEMPLATES.TemplateResponse(
            request, "error.html",
            {"message": f"Category '{category}' not found or has no techniques."},
            status_code=404,
        )

    return TEMPLATES.TemplateResponse(request, "category.html", {
        "category": category,
        "techniques": cat_techniques,
        "tree": tree,
        "page_title": _slug_to_title(category),
    })


@router.get("/search", response_class=HTMLResponse)
async def search_page(request: Request, q: str = "", technique: str = "",
                      tool: str = "", difficulty: str = ""):
    """Search page with form and results."""
    tree = get_techniques_by_category()
    results = []
    searched = any([q, technique, tool, difficulty])

    if searched:
        results = search_db(
            query=q or None,
            technique=technique or None,
            tool=tool or None,
            difficulty=difficulty or None,
            limit=50,
        )
        # Parse JSON fields for display
        for r in results:
            for field in ("techniques", "tools_used", "solve_steps", "recognition"):
                val = r.get(field)
                if isinstance(val, str):
                    try:
                        r[field] = json.loads(val)
                    except (json.JSONDecodeError, TypeError):
                        r[field] = []

    # Get all technique slugs for the dropdown
    pb = get_playbook()
    all_techniques = sorted(pb.get("techniques", {}).keys())

    return TEMPLATES.TemplateResponse(request, "search.html", {
        "q": q,
        "technique_filter": technique,
        "tool_filter": tool,
        "difficulty_filter": difficulty,
        "results": results,
        "searched": searched,
        "all_techniques": all_techniques,
        "tree": tree,
        "page_title": "Search",
    })


@router.get("/recon", response_class=HTMLResponse)
async def recon_patterns(request: Request):
    """Recon patterns page — per-category recognition signals for triage."""
    pb = get_playbook()
    recon = pb.get("recon_patterns", {})
    tree = get_techniques_by_category()

    return TEMPLATES.TemplateResponse(request, "recon.html", {
        "recon_patterns": recon,
        "tree": tree,
        "page_title": "Recon Patterns",
    })


@router.get("/tools", response_class=HTMLResponse)
async def tools_page(request: Request):
    """Tool reference page."""
    pb = get_playbook()
    tool_ref = pb.get("tool_reference", [])
    tree = get_techniques_by_category()

    return TEMPLATES.TemplateResponse(request, "tools.html", {
        "tool_reference": tool_ref,
        "tree": tree,
        "page_title": "Tool Reference",
    })
