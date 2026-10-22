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
from app.engine.normalizer import OrgScopeError, resolve_org_id, to_schema
from app.models import (
    AssetDependency,
    AttributionResult,
    Correlation,
    RemediationPlan,
    RiskResult,
    SecurityEvent,
)

_COMPROMISE_TYPES = {"BREACH_EXPOSURE", "SESSION_EXPOSURE", "COMPROMISED_RECOVERY_ACCOUNT"}


def _resolve_org_or_none(db: Session, user_id: str) -> str | None:
    """The organization the run belongs to, resolved server-side.

    Fail-closed: a user without an active membership has no organization, and a
    correlation with no organization must not exist (§5), so the run degrades
    to "no correlations" instead of guessing a tenant.
    """
    try:
        return resolve_org_id(db, user_id)
    except OrgScopeError:
        return None


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
        derived = graph.dependency_events(
            user_id=user_id, db=db, compromised_services=compromised_services
        )
        # The graph module stays organization-agnostic (Phase 3 keeps it
        # untouched); the pipeline — which resolved the organization
        # server-side — labels the events it derives, so they carry the same
        # tenant as the findings they were derived from. Derived events are
        # about accounts, not company assets, so asset_id stays NULL (an
        # explicit "not bound", never a guess).
        org_id = _resolve_org_or_none(db, user_id)
        if org_id:
            derived = [event.model_copy(update={"org_id": org_id}) for event in derived]
        events.extend(derived)
    return events


def _declared_asset_dependencies(db: Session, org_id: str | None) -> list[tuple[str, str, str]]:
    """``(org_id, from_asset_id, to_asset_id)`` for edges THIS organization's
    administrators declared.

    These triples are the only relationships a ``linked_assets`` correlation
    rule may use. They are read inside the caller's own organization, so an
    edge can never cross tenants — and CRIX never infers one from name
    similarity.
    """
    if not org_id:
        return []
    rows = db.scalars(
        select(AssetDependency).where(AssetDependency.org_id == org_id)
    ).all()
    return [(org_id, row.from_asset_id, row.to_asset_id) for row in rows]


def run_analysis(db: Session, user_id: str, *, persist: bool = True) -> dict:
    """Run the full pipeline and (optionally) persist the run's results."""
    run_id = uuid.uuid4().hex
    org_id = _resolve_org_or_none(db, user_id)
    events = build_input_events(db, user_id)

    correlations = correlation.evaluate(
        events,
        declared_asset_dependencies=_declared_asset_dependencies(db, org_id),
    )
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


def _persist_correlations(db, user_id, run_id, correlations) -> None:
    """Store correlation results, upserted by their stable ``correlation_id``.

    Re-running the pipeline on the same findings produces the same ids, so the
    row is refreshed (new run, new evaluation) instead of a duplicate being
    appended. This is what makes repeat evaluation deterministic in storage and
    not only in memory.

    A correlation is a *derived view* of findings, never a copy of them. When a
    re-check replaces findings (``replace_module_events`` mints new event ids),
    a correlation that referenced the old ids no longer describes anything real.
    Those stale rows are removed so they cannot linger as near-duplicates of the
    fresh ones. Only the correlation rows are touched — the findings themselves
    are never altered here.
    """
    for corr in correlations:
        row = db.scalar(
            select(Correlation).where(Correlation.correlation_id == corr.correlation_id)
        )
        if row is None:
            row = Correlation(correlation_id=corr.correlation_id, user_id=user_id)
            db.add(row)
        # Explicit result: organization, exact rule version, the finding ids
        # this correlation REFERENCES (never a copy of the findings), the
        # company assets involved, the evidence it cites, the plain-language
        # chain and the uncertainty statement.
        row.org_id = corr.org_id
        row.run_id = run_id
        row.rule_id = corr.rule_id
        row.rule_version = corr.rule_version
        row.title = corr.title
        row.correlation_type = corr.correlation_type
        row.severity = corr.severity
        row.confidence = corr.confidence
        row.uncertainty = corr.uncertainty
        row.explanation = corr.explanation
        row.chain = corr.chain
        row.finding_ids = corr.finding_ids
        row.asset_ids = corr.asset_ids
        row.evidence = corr.evidence
        row.evaluated_at = corr.evaluated_at

    # Remove stale correlations: a correlation is a derived view of findings.
    # When a re-check replaced findings (new event ids), a row that still
    # references the old ids describes nothing real. Drop only those rows —
    # never the findings themselves.
    current_finding_ids = {
        event_id
        for (event_id,) in db.execute(
            select(SecurityEvent.event_id).where(SecurityEvent.user_id == user_id)
        ).all()
    }
    for row in db.scalars(
        select(Correlation).where(Correlation.user_id == user_id)
    ).all():
        if not set(row.finding_ids) <= current_finding_ids:
            db.delete(row)


def _persist_run(db, user_id, run_id, correlations, risk_breakdown, attribution, plan_comparison):
    _persist_correlations(db, user_id, run_id, correlations)
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