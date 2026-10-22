"""FastAPI application entrypoint."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.config import get_settings
from app.routers import (
    accounts,
    analysis,
    auth,
    breach,
    graph,
    health,
    knowledge,
    oauth,
    password_check,
    phishing,
    planner,
    permissions,
    propagation,
    relationships,
)

settings = get_settings()

app = FastAPI(
    title="CRIX API",
    version=__version__,
    description=(
        "CRIX correlates security signals into a contextual risk score, "
        "attributes it transparently, and prioritizes what to fix first."
    ),
)

# Restrictive CORS — explicit origins, never a wildcard with credentials (§14).
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
)

for router in (
    health.router,
    auth.router,
    accounts.router,
    breach.router,
    password_check.router,
    phishing.router,
    permissions.router,
    analysis.router,
    graph.router,
    planner.router,
    knowledge.router,
    oauth.router,
    relationships.router,
    propagation.router,
):
    app.include_router(router)


@app.on_event("startup")
def _startup() -> None:
    settings.assert_production_safe()
    if not settings.is_production:
        # Local dev convenience: create tables if they don't exist and ensure the
        # curated reference data (providers, dependency edges, knowledge graph) is
        # seeded — otherwise those features would silently run on empty tables.
        from app.db import SessionLocal, init_db

        try:
            init_db()
            from app.data.loader import seed_all

            session = SessionLocal()
            try:
                seed_all(session)
            finally:
                session.close()
        except Exception as exc:  # pragma: no cover - dev convenience only
            print(f"[crix] startup init skipped: {exc}")