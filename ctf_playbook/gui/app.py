"""FastAPI application factory for the playbook browser."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ctf_playbook.gui.data import load_playbook

_GUI_DIR = Path(__file__).parent
TEMPLATES = Jinja2Templates(directory=str(_GUI_DIR / "templates"))


def _slug_to_title(slug: str) -> str:
    return slug.replace("-", " ").title()


def create_app() -> FastAPI:
    """Build and configure the FastAPI app."""
    app = FastAPI(title="CTF Playbook Browser", docs_url=None, redoc_url=None)

    # Mount static files
    app.mount("/static", StaticFiles(directory=str(_GUI_DIR / "static")), name="static")

    # Load playbook data at startup
    @app.on_event("startup")
    def startup():
        load_playbook()

    # Make helpers available in all templates
    TEMPLATES.env.globals["slug_to_title"] = _slug_to_title

    # Register route modules
    from ctf_playbook.gui.routes.pages import router as pages_router
    from ctf_playbook.gui.routes.api import router as api_router
    app.include_router(pages_router)
    app.include_router(api_router, prefix="/api")

    return app
