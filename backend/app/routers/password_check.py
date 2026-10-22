"""Password hygiene + k-anonymity range proxy (§3.B, §0.4).

CRITICAL: plaintext passwords never reach this server. The browser hashes the
password to SHA-1, keeps the first 5 hex chars locally for the grouping, and
requests ONLY those 5 chars from ``/range/{prefix}``. The full hash and the
plaintext stay on the client. Reuse comparison is likewise done client-side;
only a boolean per credential label is submitted.
"""
from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.config import Settings, get_settings
from app.data.loader import providers_data
from app.db import get_db
from app.deps import get_current_user
from app.engine import normalizer
from app.models import ProviderMetadata, User
from app.rate_limit import client_ip, enforce, password_check_limiter
from app.routers.accounts import _get_owned_account
from app.schemas import PasswordHygieneRequest
from app.signals.hibp import HIBPClient, HIBPUnavailable
from app.signals.password import build_hygiene_events

router = APIRouter(prefix="/api", tags=["password"])

_PREFIX_RE = re.compile(r"^[0-9A-Fa-f]{5}$")

_HYGIENE_EVENT_TYPES = [
    "PASSWORD_REUSE", "MFA_MISSING", "PASSKEY_READY_NOT_ENABLED",
    "SIM_SWAP_VULNERABLE", "PUSH_BOMBING_REPORTED",
]


@router.get("/password-check/range/{prefix}")
def pwned_password_range(
    prefix: str,
    request: Request,
    settings: Settings = Depends(get_settings),
) -> dict:
    """Proxy a Pwned Passwords range query (k-anonymity). No authentication is
    required because no user data is involved — only a 5-char hash prefix."""
    enforce(password_check_limiter, request, limit=settings.password_check_rate_limit_per_minute)
    if not _PREFIX_RE.match(prefix):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Prefix must be exactly 5 hexadecimal characters.",
        )
    client = HIBPClient(settings.hibp_api_key)
    try:
        suffixes = client.pwned_password_range(prefix)
    except HIBPUnavailable as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    return {"prefix": prefix.upper(), "suffixes": suffixes, "k_anonymity": True}


def _find_provider(db: Session, name: str | None) -> ProviderMetadata | None:
    if not name:
        return None
    return db.scalar(
        select(ProviderMetadata).where(ProviderMetadata.service_name.ilike(name.strip()))
    )


@router.get("/providers")
def list_providers(db: Session = Depends(get_db)) -> dict:
    rows = db.scalars(select(ProviderMetadata).order_by(ProviderMetadata.service_name)).all()
    return {
        "provenance": "Curated static provider capabilities with source references.",
        "providers": [
            {
                "service_name": r.service_name,
                "supports_passkey": r.supports_passkey,
                "mfa_methods": r.mfa_methods,
                "recovery_methods": r.recovery_methods,
                "sms_recovery_possible": r.sms_recovery_possible,
                "notes": r.notes,
                "source": r.source,
                "last_verified_at": r.last_verified_at.isoformat(),
            }
            for r in rows
        ],
    }


@router.post("/signals/password-hygiene")
def run_password_hygiene(
    payload: PasswordHygieneRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> dict:
    enforce(password_check_limiter, request, limit=30)
    _get_owned_account(db, current_user.id, payload.account_id)
    provider = _find_provider(db, payload.provider)
    schemas = build_hygiene_events(
        user_id=current_user.id,
        payload=payload,
        passkey_supported_by_provider=bool(provider and provider.supports_passkey),
        provider_source=provider.source if provider else None,
    )
    rows = normalizer.replace_module_events(
        db, current_user.id, payload.account_id, _HYGIENE_EVENT_TYPES, schemas
    )
    audit.record(
        db, action="signal.password_hygiene", user_id=current_user.id,
        ip_address=client_ip(request),
        detail={"account_id": payload.account_id, "finding_count": len(schemas)},
    )
    return {
        "provider": {
            "service_name": provider.service_name,
            "supports_passkey": provider.supports_passkey,
            "source": provider.source,
            "last_verified_at": provider.last_verified_at.isoformat(),
        }
        if provider
        else None,
        "events": [normalizer.schema_to_response(normalizer.to_schema(row)) for row in rows],
    }