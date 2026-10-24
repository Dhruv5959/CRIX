"""Breach/exposure signal endpoint (§3.A).

The email is sent here, never to the provider from the browser. The lookup runs
server-side and only normalized results go back to the client. The address is
deliberately kept out of the audit record and out of provider error strings.
"""
from __future__ import annotations

from typing import Annotated

from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import audit
from app.config import Settings, get_settings
from app.db import get_db
from app.deps import get_current_user
from app.engine import normalizer
from app.models import User
from app.rate_limit import breach_check_limiter, client_ip, enforce
from app.routers.accounts import _get_owned_account
from app.schemas import BreachCheckRequest
from app.signals.breach import check_breach, placeholder_address_warning
from fastapi import Request

router = APIRouter(prefix="/api/signals", tags=["signals"])

_OWNED_EVENT_TYPES = ["BREACH_EXPOSURE", "IDENTITY_EXPOSED", "SESSION_EXPOSURE"]


@router.post("/breach")
def run_breach_check(
    payload: BreachCheckRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    # Inbound guard so a single client cannot exhaust the provider's small free
    # tier (the outbound throttle lives in the provider client).
    enforce(
        breach_check_limiter,
        request,
        limit=settings.breach_check_rate_limit_per_minute,
    )
    _get_owned_account(db, current_user.id, payload.account_id)
    schemas = check_breach(
        user_id=current_user.id,
        account_id=payload.account_id,
        email=str(payload.email),
        settings=settings,
        simulated_exposure_type=payload.simulated_exposure_type,
        simulated_mfa_bypass_capable=payload.simulated_mfa_bypass_capable,
    )
    rows = normalizer.replace_module_events(
        db, current_user.id, payload.account_id, _OWNED_EVENT_TYPES, schemas
    )
    if payload.account_id == "registered-email":
        # A manual check of the registered email IS a fresh auto-monitor result:
        # stamp it so the next login does not make the provider answer again
        # for a question just answered (Feature A cache semantics).
        current_user.last_breach_check_at = datetime.now(timezone.utc)
        db.commit()
    providers = sorted({s.source for s in schemas if s.event_type == "BREACH_EXPOSURE"})
    audit.record(
        db, action="signal.breach", user_id=current_user.id,
        ip_address=client_ip(request),
        # No address here on purpose: the audit trail does not need it.
        detail={
            "account_id": payload.account_id,
            "providers": providers,
            "statuses": [s.status.value for s in schemas],
        },
    )
    return {"events": [normalizer.schema_to_response(normalizer.to_schema(row)) for row in rows]}


# --------------------------------------------------------------------------- #
# Automatic breach monitoring of the REGISTERED work email (Feature A)
# --------------------------------------------------------------------------- #
_AUTO_REFRESH_AFTER = timedelta(hours=24)


def run_registered_email_check(db: Session, user, settings: Settings) -> None:
    """Re-check the registered work email and store normalized events.

    Shared by the on-demand endpoint and the login-time auto-refresh. Best
    effort by design: any failure is recorded on the user's stamp only and
    never blocks the caller (login MUST NOT fail because a provider was down).
    """
    try:
        schemas = check_breach(
            user_id=user.id,
            account_id="registered-email",
            email=user.email,
            settings=settings,
        )
        normalizer.replace_module_events(
            db, user.id, "registered-email", ["BREACH_EXPOSURE", "IDENTITY_EXPOSED"], schemas
        )
        audit.record(
            db,
            action="signal.breach.auto",
            user_id=user.id,
            detail={
                "account_id": "registered-email",
                "statuses": [s.status.value if hasattr(s.status, "value") else str(s.status) for s in schemas],
            },
        )
    finally:
        # The stamp is the cache key for the next auto-refresh whether the
        # lookup produced findings, came back clean, or was UNAVAILABLE.
        user.last_breach_check_at = datetime.now(timezone.utc)
        db.commit()


def _stale(user) -> bool:
    stamp = user.last_breach_check_at
    if stamp is None:
        return True
    if stamp.tzinfo is None:  # SQLite drops tzinfo
        stamp = stamp.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - stamp > _AUTO_REFRESH_AFTER


# Public alias: auth flows reuse the exact staleness rule.
is_breach_check_stale = _stale


class ConsentRequest(BaseModel):
    enabled: bool


@router.post("/breach/monitor/consent")
def set_breach_monitor_consent(
    payload: ConsentRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Affirmative opt-in/out for automatic monitoring of the registered email.

    Turning it ON performs the first check immediately; the stored results are
    what subsequent logins display.
    """
    now = datetime.now(timezone.utc)
    current_user.breach_monitor_consent = payload.enabled
    if payload.enabled and not current_user.breach_monitor_consent_at:
        current_user.breach_monitor_consent_at = now
    db.commit()
    if payload.enabled and _stale(current_user):
        run_registered_email_check(db, current_user, settings)
    return _monitor_status(current_user)


def _stamp_iso(value) -> str | None:
    """Stamp as ISO text; SQLite hands back naive UTC datetimes — label them."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _monitor_status(user) -> dict:
    """Shape shared with the login session response; NEVER includes a verdict
    on the password or the email, only state."""
    return {
        "enabled": user.breach_monitor_consent,
        "registered_email": user.email,
        "placeholder_domain": placeholder_address_warning(user.email) is not None,
        "last_breach_check_at": _stamp_iso(user.last_breach_check_at),
        "refresh_after_hours": 24,
    }


@router.get("/breach/monitor/status")
def breach_monitor_status(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    return _monitor_status(current_user)