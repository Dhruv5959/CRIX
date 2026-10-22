"""Compromise propagation + simulate endpoint (live-OAuth scope, §6–§10).

The simulation is a **defensive what-if**: it sets a scenario state in memory,
recomputes downstream exposure and the real CRIX pipeline, and returns the
result. It does NOT touch, hack, or alter any real account; it does not disable
controls, send messages, or access other accounts (§16).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_user
from app.engine import pipeline, propagation, planner, risk
from app.engine.shapley import attribute
from app.models import (
    ConnectedSignal,
    PropagationResult,
    SecurityEvent,
    User,
)
from app.schemas import SourceMode

router = APIRouter(prefix="/api/propagation", tags=["propagation"])


def _owned_account(db: Session, user_id: str, account_id: str) -> ConnectedSignal:
    account = db.scalar(
        select(ConnectedSignal).where(
            ConnectedSignal.user_id == user_id, ConnectedSignal.account_id == account_id
        )
    )
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found.")
    return account


@router.get("/accounts")
def accounts(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> dict:
    """Accounts eligible to be selected as the simulated compromised root."""
    rows = db.scalars(
        select(ConnectedSignal).where(ConnectedSignal.user_id == current_user.id)
    ).all()
    from app.engine.propagation import _edges_for_user  # reuse adjacency build

    adjacency = _edges_for_user(db, current_user.id)
    out = []
    for row in rows:
        downstream = [t for t, _rel, _w in adjacency.get(row.account_id, [])]
        out.append(
            {
                "account_id": row.account_id,
                "label": row.label,
                "provider": row.service_name or row.platform,
                "source_mode": _source_mode(row),
                "downstream_count": len(set(downstream)),
            }
        )
    return {"accounts": out}


@router.post("/simulate")
def simulate(
    payload: dict,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> dict:
    """Run COMPROMISE PROPAGATION ANALYSIS for ``upstream_account_id``.

    Produces: downstream graph exposure + recomputed contextual risk + Shapley
    attribution + remediation priority, all from the real engine. The scenario
    is marked SIMULATED and is not persisted as a finding against the account.
    """
    upstream = payload.get("upstream_account_id")
    if not upstream or not isinstance(upstream, str):
        raise HTTPException(status_code=422, detail="upstream_account_id is required.")
    _owned_account(db, current_user.id, upstream)

    try:
        analysis = propagation.compute_downstream_exposure(
            db, current_user.id, upstream
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Account not found.")

    # Recompute the REAL CRIX pipeline with the simulated scenario applied:
    # the upstream account is treated as compromised for this what-if only.
    events = list(
        db.scalars(select(SecurityEvent).where(SecurityEvent.user_id == current_user.id)).all()
    )
    schemas = _to_schemas(events)
    scenario_features = risk.extract_features(schemas)

    # The SAME organization-scoped asset criticality the real run uses: a
    # simulated compromise changes the evidence, never which asset matters.
    criticality, _asset_context = pipeline.resolve_run_criticality(
        db, current_user.id, schemas
    )

    # A simulated compromise of a recovery-capable account raises exposure on
    # its dependency chain. We model it as full session+identity exposure on the
    # upstream account (documented, deterministic, SIMULATED).
    scenario_features["session"] = 1.0
    scenario_features["identity"] = max(scenario_features.get("identity", 0.0), 0.7)

    score, breakdown = risk.risk_from_features(scenario_features, criticality=criticality)
    low, high = risk.sensitivity_range(scenario_features, criticality=criticality)
    attribution = attribute(scenario_features, criticality=criticality)

    # Remediation priority under the scenario: the SAME planner (greedy baseline
    # vs. one exact branch-and-bound), re-run on the scenario's feature vector.
    scenario_plan = planner.compare(scenario_features, budget=6.0, criticality=criticality)
    base_plan = planner.compare(
        risk.extract_features(schemas), budget=6.0, criticality=criticality
    )

    # Persist the (optional) simulation record for the Evaluation/audit trail.
    run_id = uuid.uuid4().hex
    db.add(
        PropagationResult(
            user_id=current_user.id,
            run_id=run_id,
            upstream_account_id=upstream,
            source_mode=SourceMode.SIMULATED.value,
            affected_count=analysis["affected_count"],
            highest_exposure=analysis["overall_band"],
            highest_risk_account_id=analysis["highest_risk_account_id"],
            detail={
                "formula": analysis["formula"],
                "downstream": analysis["downstream"],
                "disclaimer": analysis["disclaimer"],
            },
            created_at=datetime.now(timezone.utc),
        )
    )
    db.commit()

    return {
        "run_id": run_id,
        "scenario": {
            "label": "SIMULATED COMPROMISE",
            "upstream_account_id": upstream,
            "upstream_label": analysis["upstream_label"],
            "source_mode": SourceMode.SIMULATED.value,
            "notice": (
                "This is a defensive what-if simulation. No real account was "
                "accessed, altered, or attacked."
            ),
        },
        "propagation": analysis,
        "scenario_risk": {
            "score": score,
            "band": risk.band_for(score),
            "range_low": low,
            "range_high": high,
            "base_risk": breakdown["base_risk"],
            "interaction_risk": breakdown["interaction_risk"],
            "criticality_adjustment": breakdown["criticality_adjustment"],
            "mitigation_credit": breakdown["mitigation_credit"],
            "criticality": criticality,
            "model_version": risk.RISK_MODEL_VERSION,
        },
        "scenario_attribution": attribution,
        "scenario_plan": {
            "budget": 6.0,
            "comparison": scenario_plan,
            "base_comparison": base_plan,
            "note": (
                "Remediation priority recomputed on the scenario's feature vector. "
                "Greedy is a baseline; the exact branch-and-bound plan is the "
                "reference. Neither is claimed to be optimal beyond what the "
                "measured gap shows."
            ),
        },
        "storyline": _storyline(analysis),
        "disclaimer": analysis["disclaimer"],
    }


def _storyline(analysis: dict) -> list[dict]:
    """Render the potential compromise chain as ordered nodes for the UI (§10)."""
    upstream_id = analysis["upstream_account_id"]
    nodes = [
        {
            "account_id": upstream_id,
            "label": analysis["upstream_label"],
            "band": "COMPROMISED",
            "is_upstream": True,
            "source_mode": SourceMode.SIMULATED.value,
        }
    ]
    for item in analysis["downstream"]:
        nodes.append(
            {
                "account_id": item["account_id"],
                "label": item["label"],
                "band": item["band"],
                "is_upstream": False,
                "path": item["path"],
                "path_length": item["path_length"],
                "source_mode": item["source_mode"],
            }
        )
    return nodes


def _to_schemas(rows: list[SecurityEvent]):
    from app.engine.normalizer import to_schema

    return [to_schema(row) for row in rows]


def _source_mode(row: ConnectedSignal) -> str:
    """Declared source_mode for an asset (REAL / FIXTURE / USER_PROVIDED)."""
    meta = row.metadata_json or {}
    if meta.get("source_mode"):
        return meta["source_mode"]
    if row.source == "oauth":
        return SourceMode.REAL.value
    if row.source == "fixture":
        return SourceMode.FIXTURE.value
    return SourceMode.USER_PROVIDED.value
