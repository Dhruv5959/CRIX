"""Health & capability probe.

Exposes which modules are currently available (e.g. HIBP key configured) so the
frontend can honestly render UNAVAILABLE vs. CHECKED_SAFE (§4, §12).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app import __version__
from app.config import Settings, get_settings
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