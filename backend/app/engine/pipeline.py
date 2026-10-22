"""End-to-end deterministic pipeline (§1).

    events -> dependency graph -> correlations -> contextual risk -> Shapley
           -> remediation planner -> GraphRAG explanation

Every authoritative value (correlation severity, risk score, attribution,
plans) is computed HERE, server-side, from stored events. Clients can never
inject or override them (§14).
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engine import correlation, graph, graphrag, planner, risk, shapley
from app.engine.normalizer import to_schema
from app.models import (
    AttributionResult,
    Correlation,
    RemediationPlan,
    RiskResult,
    SecurityEvent,
)

_COMPROMISE_TYPES = {"BREACH_EXPOSURE", "SESSION_EXPOSURE", "COMPROMISED_RECOVERY_ACCOUNT"}


def _load_events(db: Session, user_id: str) -> list[SecurityEvent]:
    return list(
        db.scalars(
            select(SecurityEvent).where(SecurityEvent.user_id == user_id)
        ).all()
    )


def build_input_events(db: Session, user_id: str) -> list:
    """Stored events + derived dependency-graph events for the same accounts."""
    rows = _load_events(db, user_id)
    events = [to_schema(row) for row in rows]

    # Determine which services show compromise signals, then let the graph emit
    # dependency / cascading-recovery events for those (and their dependents).
    service_by_account: dict[str, str] = {}
    for event in events:
        service = (event.metadata or {}).get("service_name") or event.account_id
        service_by_account[event.account_id] = service
    compromised_services = {
        service_by_account.get(event.account_id, event.account_id)
        for event in events
        if event.event_type in _COMPROMISE_TYPES and event.status == "FINDING"
    }
    if compromised_services:
        events.extend(
            graph.dependency_events(
                user_id=user_id, db=db, compromised_services=compromised_services
            )
        )
    return events


def run_analysis(db: Session, user_id: str, *, persist: bool = True) -> dict:
    """Run the full pipeline and (optionally) persist the run's results."""
    run_id = uuid.uuid4().hex
    events = build_input_events(db, user_id)

    correlations = correlation.evaluate(events)
    risk_breakdown = risk.compute_risk(events)
    features = risk.extract_features(events)
    attribution = shapley.attribute(features)

    # Planner comparison on the real feature vector (bounded action set).
    plan_comparison = planner.compare(features, budget=6.0)

    if persist:
        _persist_run(db, user_id, run_id, correlations, risk_breakdown, attribution, plan_comparison)

    return {
        "run_id": run_id,
        "events": events,
        "correlations": correlations,
        "risk": risk_breakdown,
        "attribution": attribution,
        "planner": plan_comparison,
        "features": features,
        "generated_at": dt.datetime.now(dt.timezone.utc),
    }


def _persist_run(db, user_id, run_id, correlations, risk_breakdown, attribution, plan_comparison):
    for corr in correlations:
        db.add(
            Correlation(
                user_id=user_id,
                run_id=run_id,
                rule_id=corr.rule_id,
                title=corr.title,
                severity=corr.severity,
                confidence=corr.confidence,
                explanation=corr.explanation,
                contributing_event_ids=corr.contributing_event_ids,
            )
        )
    db.add(
        RiskResult(
            user_id=user_id,
            run_id=run_id,
            score=risk_breakdown.score,
            band=risk_breakdown.band,
            confidence=risk_breakdown.confidence,
            range_low=risk_breakdown.range_low,
            range_high=risk_breakdown.range_high,
            base_risk=risk_breakdown.base_risk,
            interaction_risk=risk_breakdown.interaction_risk,
            mitigation_credit=risk_breakdown.mitigation_credit,
            components=risk_breakdown.components,
        )
    )
    db.add(
        AttributionResult(
            user_id=user_id,
            run_id=run_id,
            method=attribution["method"],
            total_risk=attribution["total_risk"],
            contributions=attribution["contributions"],
            compute_ms=attribution["compute_ms"],
        )
    )
    for method in ("greedy", "exact"):
        plan = plan_comparison[method]
        db.add(
            RemediationPlan(
                user_id=user_id,
                run_id=run_id,
                method=method,
                actions=plan["actions"],
                total_effort=plan["total_effort"],
                risk_after=plan["risk_after"],
                risk_reduction=plan["risk_reduction"],
                compute_ms=plan["compute_ms"],
                is_greedy_trap=bool(plan_comparison["is_greedy_trap"]) if method == "greedy" else False,
            )
        )
    db.commit()


def explain_run(db: Session, user_id: str) -> dict:
    """Run the pipeline and produce a grounded GraphRAG explanation."""
    result = run_analysis(db, user_id, persist=False)
    graph_edges = [
        {"from": e["source"], "to": e["target"]}
        for e in graph.graph_payload(db)["edges"]
    ]
    context = graphrag.sanitize_context(
        event_types=[e.event_type for e in result["events"]],
        correlations=[
            {"rule_id": c.rule_id, "severity": c.severity} for c in result["correlations"]
        ],
        risk={
            "score": result["risk"].score,
            "band": result["risk"].band,
            "range_low": result["risk"].range_low,
            "range_high": result["risk"].range_high,
        },
        graph_edges=graph_edges,
    )
    explanation = graphrag.explain(db, context)
    return {"result": result, "explanation": explanation}