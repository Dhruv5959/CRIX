"""Breach/exposure signal endpoint (§3.A).

The email is sent here, never to the provider from the browser. The lookup runs
server-side and only normalized results go back to the client. The address is
deliberately kept out of the audit record and out of provider error strings.
"""
from __future__ import annotations

from typing import Annotated

from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.config import Settings, get_settings
from app.db import get_db
from app.deps import get_current_user
from app.engine import normalizer
from app.models import SecurityEvent, User
from app.rate_limit import breach_check_limiter, client_ip, enforce
from app.routers.accounts import _get_owned_account
from app.schemas import BreachCheckRequest
from app.signals.breach import check_breach, placeholder_address_warning

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
    # CRIX-SMB monitors a verified employee's registered work email only. A
    # client cannot nominate an arbitrary address (or a personal Gmail address)
    # and make CRIX query a breach provider about it.
    if payload.account_id != "registered-email":
        raise HTTPException(
            status_code=403,
            detail="Email breach checks are available only for the verified registered work email.",
        )
    _get_owned_account(db, current_user.id, payload.account_id)
    if str(payload.email).lower() != current_user.email.lower():
        raise HTTPException(
            status_code=403,
            detail="The breach lookup target must match the registered work email.",
        )
    if not consent_can_run(current_user):
        raise HTTPException(
            status_code=403,
            detail=(
                "Verify this email address and explicitly enable breach monitoring before "
                "CRIX contacts a breach provider."
            ),
        )

    has_simulated_scenario = payload.simulated_exposure_type is not None
    if not has_simulated_scenario and not _stale(current_user):
        events = _stored_registered_email_events(db, current_user)
        audit.record(
            db,
            action="signal.breach.cache_hit",
            user_id=current_user.id,
            ip_address=client_ip(request),
            detail={"account_id": "registered-email"},
        )
        return {"events": events, "cached": True}

    schemas = check_breach(
        user_id=current_user.id,
        account_id=payload.account_id,
        email=current_user.email,
        settings=settings,
        simulated_exposure_type=payload.simulated_exposure_type,
        simulated_mfa_bypass_capable=payload.simulated_mfa_bypass_capable,
    )
    rows = normalizer.replace_module_events(
        db, current_user.id, payload.account_id, _OWNED_EVENT_TYPES, schemas
    )
    # A fresh manual check is also the cache entry used by the next login.
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
    return {
        "events": [normalizer.schema_to_response(normalizer.to_schema(row)) for row in rows],
        "cached": False,
    }


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


def _stored_registered_email_events(db: Session, user) -> list[dict]:
    """Return the most recent cached real-provider verdict for this employee."""
    rows = db.scalars(
        select(SecurityEvent).where(
            SecurityEvent.user_id == user.id,
            SecurityEvent.account_id == "registered-email",
            SecurityEvent.event_type.in_(["BREACH_EXPOSURE", "IDENTITY_EXPOSED"]),
        )
    ).all()
    return [normalizer.schema_to_response(normalizer.to_schema(row)) for row in rows]


def _stale(user) -> bool:
    stamp = user.last_breach_check_at
    if stamp is None:
        return True
    if stamp.tzinfo is None:  # SQLite drops tzinfo
        stamp = stamp.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - stamp > _AUTO_REFRESH_AFTER


def consent_can_run(user) -> bool:
    """The monitor's execution gate: an affirmative opt-in that has NOT been
    proven by a verified mailbox must never schedule provider lookups."""
    return bool(user.breach_monitor_consent and user.email_verified)


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

    Consent gate: automatic monitoring contacts a breach provider about the
    REGISTERED address on a schedule. Enabling that about an address the user
    has not proven control of would point the watchtower at the wrong mailbox,
    so an unverified address cannot start it (real-accounts mandate).
    """
    if payload.enabled and not current_user.email_verified:
        raise HTTPException(
            status_code=403,
            detail=(
                "Verify this email address before enabling automatic monitoring "
                "(request a verification email first)."
            ),
        )
    now = datetime.now(timezone.utc)
    current_user.breach_monitor_consent = payload.enabled
    if payload.enabled and not current_user.breach_monitor_consent_at:
        current_user.breach_monitor_consent_at = now
    db.commit()
    if consent_can_run(current_user) and _stale(current_user):
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
        "enabled": bool(user.breach_monitor_consent and user.email_verified),
        "registered_email": user.email,
        "email_verified": user.email_verified,
        "placeholder_domain": placeholder_address_warning(user.email) is not None,
        "last_breach_check_at": _stamp_iso(user.last_breach_check_at),
        "refresh_after_hours": 24,
    }


@router.get("/breach/monitor/status")
def breach_monitor_status(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    return _monitor_status(current_user)
