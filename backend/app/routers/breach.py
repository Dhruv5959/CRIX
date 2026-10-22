"""Breach/exposure signal endpoint (§3.A).

The email is sent here, never to the provider from the browser. The lookup runs
server-side and only normalized results go back to the client. The address is
deliberately kept out of the audit record and out of provider error strings.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
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
from app.signals.breach import check_breach
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