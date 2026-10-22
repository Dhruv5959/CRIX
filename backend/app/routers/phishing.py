"""Phishing / scam analysis endpoints (§3.C)."""
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
from app.schemas import PhishingAnalyzeRequest, PhishingAnalyzeResponse
from app.signals.phishing import analyze_text, artifacts_available, build_phishing_events

router = APIRouter(prefix="/api/signals", tags=["phishing"])

_PHISHING_EVENT_TYPES = ["PHISHING_MESSAGE_DETECTED", "AI_GENERATED_MESSAGE_DETECTED"]


@router.get("/phishing/status")
def phishing_status() -> dict:
    return {
        "artifacts_available": artifacts_available(),
        "note": "Run scripts/train_phishing.py to train the classifier before analysis.",
    }


@router.post("/phishing/analyze", response_model=PhishingAnalyzeResponse)
def analyze(
    payload: PhishingAnalyzeRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> PhishingAnalyzeResponse:
    result = analyze_text(payload.text)
    # We do NOT store the raw message text; only derived, structured signals.
    audit.record(
        db, action="signal.phishing.analyze", user_id=current_user.id,
        ip_address=client_ip(request),
        detail={"label": result.label, "model_version": result.model_version},
    )
    return result


@router.post("/phishing/{account_id}/record")
def record_analysis(
    account_id: str,
    payload: PhishingAnalyzeRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> dict:
    """Run analysis and persist it as normalized events for an account. Raw text
    is discarded after scoring; only structured signals are stored."""
    _get_owned_account(db, current_user.id, account_id)
    result = analyze_text(payload.text)
    schemas = build_phishing_events(
        user_id=current_user.id, account_id=account_id, text=payload.text, result=result
    )
    rows = normalizer.replace_module_events(
        db, current_user.id, account_id, _PHISHING_EVENT_TYPES, schemas
    )
    return {
        "result": result.model_dump(),
        "events": [normalizer.schema_to_response(normalizer.to_schema(row)) for row in rows],
    }