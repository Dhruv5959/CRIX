"""Health & capability probe.

Exposes which modules are currently available (e.g. HIBP key configured) so the
frontend can honestly render UNAVAILABLE vs. CHECKED_SAFE (§4, §12).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app import __version__
from app.config import Settings, get_settings
from app.db import get_engine
from app.schemas import HealthResponse
from app.signals.breach import provider_label, resolve_email_provider

router = APIRouter(tags=["health"])


@router.get("/api/health", response_model=HealthResponse)
def health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    provider = resolve_email_provider(settings)
    return HealthResponse(
        status="ok",
        version=__version__,
        env=settings.env,
        hibp_configured=bool(settings.hibp_api_key),
        breach_email_provider=provider,
        breach_email_provider_label=provider_label(provider),
    )


@router.get("/api/ready")
def readiness() -> dict[str, str]:
    """Prove database connectivity without exposing connection details."""
    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable.",
        ) from exc
    return {"status": "ready"}
