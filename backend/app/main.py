"""FastAPI application entrypoint."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.config import get_settings
from app.routers import (
    accounts,
    access,
    analysis,
    assets,
    auth,
    breach,
    domains,
    graph,
    health,
    knowledge,
    oauth,
    org,
    password_check,
    phishing,
    planner,
    permissions,
    propagation,
    relationships,
    remediation,
    repo_scan,
)

settings = get_settings()

# In production the schema explorer is an attack-surface detail leak; disable it.
_prod = settings.is_production

app = FastAPI(
    title="CRIX API",
    version=__version__,
    description=(
        "CRIX correlates security signals into a contextual risk score, "
        "attributes it transparently, and prioritizes what to fix first."
    ),
    docs_url=None if _prod else "/docs",
    redoc_url=None if _prod else "/redoc",
    openapi_url=None if _prod else "/openapi.json",
)

# Restrictive CORS — explicit origins, never a wildcard with credentials (§14).
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
)


@app.middleware("http")
async def _security_headers(request, call_next):
    """Baseline browser hardening headers on every response.

    This is an API serving a same-front-end SPA, so a restrictive CSP applies:
    nothing should frame the API, and script execution from API origins should
    be impossible from the network path alone.
    """
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if _prod:
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; form-action 'none'",
        )
        # HSTS is only meaningful (and only respected) over HTTPS in production.
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


for router in (
    health.router,
    auth.router,
    org.router,
    assets.router,
    domains.router,
    accounts.router,
    breach.router,
    password_check.router,
    phishing.router,
    permissions.router,
    repo_scan.router,
    access.router,
    analysis.router,
    graph.router,
    planner.router,
    knowledge.router,
    oauth.router,
    relationships.router,
    propagation.router,
    remediation.router,
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

    if settings.is_production:
        # Honest ops note (§14): the in-house rate limiter and the OAuth
        # pending-state table are process-local. A single uvicorn worker is
        # the supported deployment; multiple workers would split both.
        print(
            "[crix] NOTE: rate limiting and OAuth state are per-process. "
            "Run a single worker (uvicorn default) or back these with shared storage."
        )