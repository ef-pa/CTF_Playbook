"""JSON API routes for client-side interactivity."""

from fastapi import APIRouter

from ctf_playbook.gui.data import (
    get_playbook, get_technique, search_db, get_db_stats,
)

router = APIRouter()


@router.get("/stats")
async def api_stats():
    """Return playbook + live DB stats."""
    pb = get_playbook()
    return {
        "playbook": pb.get("stats", {}),
        "db": get_db_stats(),
    }


@router.get("/techniques")
async def api_techniques():
    """Return lightweight technique index."""
    pb = get_playbook()
    index = {}
    for slug, tech in pb.get("techniques", {}).items():
        index[slug] = {
            "category": tech.get("category"),
            "difficulty": tech.get("difficulty"),
            "example_count": tech.get("example_count", 0),
            "sub_technique_count": len(tech.get("sub_techniques", {})),
        }
    return index


@router.get("/technique/{slug}")
async def api_technique(slug: str):
    """Return full data for a single technique."""
    tech = get_technique(slug)
    if not tech:
        return {"error": f"Technique '{slug}' not found"}
    return tech


@router.get("/search")
async def api_search(q: str = "", technique: str = "",
                     tool: str = "", difficulty: str = "", limit: int = 20):
    """Search writeups via the database."""
    results = search_db(
        query=q or None,
        technique=technique or None,
        tool=tool or None,
        difficulty=difficulty or None,
        limit=min(limit, 100),
    )
    return {"results": results, "count": len(results)}
