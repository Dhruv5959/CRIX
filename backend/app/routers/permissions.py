"""Permission auditor endpoint (§3.D)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.deps import get_current_user
from app.engine import normalizer
from app.models import User
from app.rate_limit import client_ip
from app.routers.accounts import _get_owned_account
from app.schemas import PermissionAuditRequest
from app.signals.permissions import build_permission_events, classify_permission

router = APIRouter(prefix="/api/signals", tags=["permissions"])

_PERMISSION_EVENT_TYPES = ["RISKY_PERMISSION_GRANTED", "STALE_PERMISSION_GRANTED"]


@router.post("/permissions/classify")
def classify(payload: dict) -> dict:
    """Stateless helper: explain a single permission's classification."""
    permission = str(payload.get("permission", "")).strip()
    return classify_permission(permission)


@router.post("/permissions/audit")
def audit_permissions(
    payload: PermissionAuditRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> dict:
    _get_owned_account(db, current_user.id, payload.account_id)
    schemas, report = build_permission_events(user_id=current_user.id, payload=payload)
    rows = normalizer.replace_module_events(
        db, current_user.id, payload.account_id, _PERMISSION_EVENT_TYPES, schemas
    )
    audit.record(
        db, action="signal.permission_audit", user_id=current_user.id,
        ip_address=client_ip(request),
        detail={"account_id": payload.account_id, "entry_count": len(payload.entries)},
    )
    return {
        "classification_report": report,
        "events": [normalizer.schema_to_response(normalizer.to_schema(row)) for row in rows],
    }