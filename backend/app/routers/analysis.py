"""Analysis pipeline endpoints: run, correlations, risk, attribution, what-if,
and the GraphRAG explanation panel (§4–§7, §10, §11)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.deps import get_current_user
from app.engine import graph, graphrag, pipeline, planner, risk
from app.engine.normalizer import schema_to_response, to_schema
from app.models import SecurityEvent, User
from app.rate_limit import client_ip
from app.schemas import WhatIfRequest

router = APIRouter(prefix="/api/analysis", tags=["analysis"])


def _serialize_correlation(c) -> dict:
    """One correlation result, explicit (Phase 3 §5).

    The payload states every fact the result rests on: which findings it
    combined (by id — never a copy), which company assets are involved, which
    rule version produced it, the evidence it cites, the reasoning in plain
    language, and what the confidence figure does and does not mean.
    """
    return {
        "correlation_id": c.correlation_id,
        "org_id": c.org_id,
        "rule_id": c.rule_id,
        "rule_version": c.rule_version,
        "title": c.title,
        "correlation_type": c.correlation_type,
        "severity": c.severity,
        "confidence": c.confidence,
        "uncertainty": c.uncertainty,
        "explanation": c.explanation,
        "chain": c.chain,
        "finding_ids": c.finding_ids,
        "asset_ids": c.asset_ids,
        "evidence": c.evidence,
        "evaluated_at": c.evaluated_at.isoformat(),
    }


def _serialize(result: dict) -> dict:
    risk_breakdown = result["risk"]
    return {
        "run_id": result["run_id"],
        "generated_at": result["generated_at"].isoformat(),
        "events": [schema_to_response(e) for e in result["events"]],
        "correlations": [_serialize_correlation(c) for c in result["correlations"]],
        "risk": {
            "score": risk_breakdown.score,
            "band": risk_breakdown.band,
            "confidence": risk_breakdown.confidence,
            "range_low": risk_breakdown.range_low,
            "range_high": risk_breakdown.range_high,
            "base_risk": risk_breakdown.base_risk,
            "interaction_risk": risk_breakdown.interaction_risk,
            "criticality_adjustment": risk_breakdown.criticality_adjustment,
            # Phase 6b additive graph term — shown as its own row so the
            # additive identity (base + interaction + adjustment +
            # dependency_exposure − mitigation = score) stays exactly visible.
            "dependency_exposure": risk_breakdown.dependency_exposure,
            "mitigation_credit": risk_breakdown.mitigation_credit,
            # Which formula ran and with which asset-importance input — the
            # score's own traceability, served next to the score (Phase 4).
            "model_version": risk_breakdown.components.get("model_version"),
            "criticality": risk_breakdown.components.get("criticality"),
            "components": risk_breakdown.components,
        },
        "attribution": result["attribution"],
        "planner": result["planner"],
        "features": result["features"],
        "criticality": result.get("criticality"),
    }


@router.post("/run")
def run(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> dict:
    result = pipeline.run_analysis(db, current_user.id, persist=True)
    audit.record(db, action="analysis.run", user_id=current_user.id, ip_address=client_ip(request))
    return _serialize(result)


@router.get("/summary")
def summary(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> dict:
    """Compute the full pipeline WITHOUT persisting (for read-only views)."""
    result = pipeline.run_analysis(db, current_user.id, persist=False)
    return _serialize(result)


@router.get("/events")
def events(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> dict:
    rows = db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.user_id == current_user.id)
        .order_by(SecurityEvent.detected_at.desc())
    ).all()
    return {"events": [schema_to_response(to_schema(row)) for row in rows]}


@router.get("/explanation")
def explanation(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> dict:
    explained = pipeline.explain_run(db, current_user.id)
    exp = explained["explanation"]
    return {
        "summary": exp.summary,
        "citations": exp.citations,
        "context": exp.context,
        "grounded": exp.grounded,
        "unsupported_claims": exp.unsupported_claims,
        "statements": [{"text": s.text, "citations": s.citations} for s in exp.statements],
    }


@router.post("/what-if")
def what_if(
    payload: WhatIfRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> dict:
    """Re-run the REAL pipeline on a hypothetical copy of the input.

    Historical facts (breach exposure, identity exposure) persist; toggled
    mitigations change the feature vector, which changes the computed score,
    attribution, and planner — nothing here is a frontend-faked number.
    """
    base = pipeline.run_analysis(db, current_user.id, persist=False)
    features = dict(base["features"])
    # Same asset-criticality context as the base run: a toggle changes what the
    # company controls, never which asset this run is about.
    criticality = base["criticality"]

    unknown = [t.action_key for t in payload.toggles if t.action_key not in planner.ACTIONS]
    if unknown:
        from fastapi import HTTPException, status

        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown action keys: {unknown}",
        )

    applied: list[str] = []
    for toggle in payload.toggles:
        if not toggle.enabled:
            continue
        applied.append(toggle.action_key)
    modified = planner.apply_actions(features, applied)

    score, breakdown = risk.risk_from_features(modified, criticality=criticality)
    from app.engine.shapley import attribute

    attribution = attribute(modified, criticality=criticality)

    events_for_confidence = base["events"]
    low, high = risk.sensitivity_range(modified, criticality=criticality)
    return {
        "applied_actions": applied,
        "criticality": criticality,
        "before": {
            "score": base["risk"].score,
            "band": base["risk"].band,
            "attribution": base["attribution"],
        },
        "after": {
            "score": score,
            "band": risk.band_for(score),
            "confidence": risk.confidence_for(events_for_confidence),
            "range_low": low,
            "range_high": high,
            "base_risk": breakdown["base_risk"],
            "interaction_risk": breakdown["interaction_risk"],
            "criticality_adjustment": breakdown["criticality_adjustment"],
            "mitigation_credit": breakdown["mitigation_credit"],
            "attribution": attribution,
            "features": modified,
        },
        "delta": round(base["risk"].score - score, 4),
    }