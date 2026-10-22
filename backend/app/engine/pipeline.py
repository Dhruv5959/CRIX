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

from app.config import get_settings
from app.engine import correlation, graph, graphrag, org_graph, planner, risk, shapley
from app.engine.entities import assert_asset_in_org
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


def resolve_org_criticality(db: Session, org_id: str | None, events: list) -> tuple[int | None, dict]:
    """Resolve the affected assets' criticality for one analysis run (Phase 4).

    Organization-scoped by construction:

    * Only findings (``status == FINDING``) that are BOUND to an asset are
      considered — an unbound finding carries no asset importance, and that is
      recorded as such.
    * Every lookup goes through ``entities.assert_asset_in_org``, which filters
      on ``org_id``: an asset id belonging to another tenant resolves to
      ``None`` (rejected as a criticality input, never read cross-tenant), and
      the rejection is listed explicitly in the returned context.
    * The value used is the MAXIMUM criticality among the resolved assets — the
      most important affected asset drives prioritization. Ties break on the
      sorted asset id, so equal inputs always give the same answer.

    Returns ``(criticality, asset_context)``. ``criticality`` is ``None`` when
    nothing could be resolved (the score then stays unadjusted); the context is
    JSON-safe traceability data merged into the score's components.
    """
    empty = {
        "criticality_status": "UNBOUND",
        "asset_ids": [],
        "asset_criticalities": {},
        "primary_asset_id": None,
        "unresolved_assets": [],
    }
    if not org_id:
        return None, {**empty, "criticality_status": "NO_ORGANIZATION"}

    # Candidate assets: bound to a FINDING and written inside this organization.
    in_org: set[str] = set()
    foreign: set[str] = set()
    for event in events:
        # ``event.status`` may be an ``EventStatus`` member or a plain string
        # (rows round-trip as strings); compare on the value either way.
        status = getattr(event.status, "value", event.status)
        if status != "FINDING" or not event.asset_id:
            continue
        if event.org_id == org_id:
            in_org.add(event.asset_id)
        else:
            # A finding row that points outside the tenant: its asset reference
            # is rejected as an input (fail-closed), and the rejection is shown.
            foreign.add(event.asset_id)

    resolved: dict[str, int] = {}
    unresolved: list[dict] = []
    for asset_id in sorted(foreign):
        unresolved.append(
            {"asset_id": asset_id, "reason": "finding_not_in_this_organization"}
        )
    for asset_id in sorted(in_org):
        asset = assert_asset_in_org(db, org_id, asset_id)
        if asset is None:
            unresolved.append(
                {"asset_id": asset_id, "reason": "not_a_registered_asset_in_this_organization"}
            )
        else:
            resolved[asset.asset_id] = int(asset.criticality)

    if not resolved and not unresolved:
        return None, empty

    if not resolved:
        return None, {
            **empty,
            "criticality_status": "UNRESOLVED",
            "unresolved_assets": unresolved,
        }

    # Most important affected asset wins; ties break on the sorted id.
    primary = sorted(resolved.items(), key=lambda item: (-item[1], item[0]))[0][0]
    return max(resolved.values()), {
        "criticality_status": "REGISTERED",
        "asset_ids": sorted(resolved),
        "asset_criticalities": dict(sorted(resolved.items())),
        "primary_asset_id": primary,
        "unresolved_assets": unresolved,
    }


def resolve_run_criticality(db: Session, user_id: str, events: list) -> tuple[int | None, dict]:
    """Same resolution for callers outside ``run_analysis`` (the propagation
    simulation), resolving the caller's organization server-side first."""
    return resolve_org_criticality(db, _resolve_org_or_none(db, user_id), events)


# --------------------------------------------------------------------------- #
# Phase 6b — DependencyExposure: the org graph's contribution to the score
# --------------------------------------------------------------------------- #
def resolve_org_dependency_exposure(
    db: Session, org_id: str | None, asset_context: dict
) -> dict:
    """Resolve the documented DependencyExposure input for one analysis run.

    Server-side, organization-scoped, documented edges only (Rule §4, §6b):

    * Reads the caller's own graph via ``org_graph.build_org_graph`` (every
      query filters on ``org_id``; edges are the org's admin-declared
      ``AssetDependency`` rows restricted to documented relationship types).
      An edge from another tenant can never enter the input.
    * Runs the Phase 6 ``blast_radius`` query from the run's **primary
      affected asset** (the criticality resolution's server-side pick), with
      the documented default depth bound (``GRAPH_LIMITS["default_depth"]``).
    * Intensity ``d = raw / (raw + saturation)`` where
      ``raw = Σ ((criticality − 1) / 4) × (1 / depth)`` over reachable assets —
      criticality-weighted, depth-decayed, saturating, hence always in
      ``[0, 1)``. Points are ``100 × weight × d`` (bounded, see
      ``RISK_PARAMS["dependency_exposure"]``).

    Statuses (never coerced, never silently zeroed as if safe):

    ``AVAILABLE``          graph read + blast radius computed (``intensity`` set)
    ``NO_AFFECTED_ASSET``  no registered asset bound to this run's findings
    ``NO_ORGANIZATION``    the run has no org context (graph cannot be read)
    ``UNAVAILABLE``        graph build failed (e.g. ``GraphTooLargeError``)
    ``DISABLED``           config flag off — the term is excluded on purpose

    The returned dict is JSON-safe traceability merged into the score's
    ``components["dependency_exposure"]``.
    """
    weight = risk.RISK_PARAMS["dependency_exposure"]["weight"]
    saturation = risk.RISK_PARAMS["dependency_exposure"]["saturation"]
    formula = (
        "d = raw / (raw + saturation); "
        "raw = sum over blast-radius assets of ((criticality - 1) / 4) * (1 / depth); "
        "points = 100 * weight * d"
    )
    base_ctx: dict = {
        "source": "org_graph.blast_radius",
        "formula": formula,
        "weight": weight,
        "saturation": saturation,
        "intensity": None,
        "points": 0.0,
        "primary_asset_id": None,
        "reachable_count": 0,
        "critical_count": 0,
        "depth_used": org_graph.GRAPH_LIMITS["default_depth"],
        "truncated": False,
        "graph": {"nodes": 0, "edges": 0, "edges_provenance": "ADMIN_DECLARED"},
        "disclaimer": org_graph.DISCLAIMER,
    }

    if not get_settings().risk_dependency_exposure_enabled:
        return {
            **base_ctx,
            "status": "DISABLED",
            "note": (
                "The dependency-exposure term is disabled by configuration "
                "(ablation); the score excludes it on purpose — this is a "
                "configuration state, not an absence of exposure."
            ),
        }

    if not org_id:
        return {
            **base_ctx,
            "status": "NO_ORGANIZATION",
            "note": (
                "No organization context, so no dependency graph could be "
                "read; the term is 0 and this is an unknown input, not an "
                "absence of exposure."
            ),
        }

    primary = asset_context.get("primary_asset_id")
    if not primary:
        return {
            **base_ctx,
            "status": "NO_AFFECTED_ASSET",
            "note": (
                "No registered asset was bound to this run's findings, so "
                "there was no affected asset to reason from; the term is 0 "
                "for this run."
            ),
        }

    depth = org_graph.GRAPH_LIMITS["default_depth"]
    try:
        graph_obj, _stats = org_graph.build_org_graph(db, org_id)
    except org_graph.GraphTooLargeError as exc:
        return {
            **base_ctx,
            "status": "UNAVAILABLE",
            "reason": "graph_too_large",
            "note": (
                f"The dependency graph could not be built ({exc}); the term "
                "is 0 — unavailable is not the same as safe."
            ),
        }

    graph_ctx = {
        "nodes": graph_obj.number_of_nodes(),
        "edges": graph_obj.number_of_edges(),
        "edges_provenance": "ADMIN_DECLARED",
    }

    if primary not in graph_obj:
        # The criticality resolver proved this asset is registered in this org,
        # so a missing node means the row changed underneath the run: fail
        # closed to an unknown input rather than guessing.
        return {
            **base_ctx,
            "status": "UNAVAILABLE",
            "reason": "affected_asset_not_in_graph",
            "graph": graph_ctx,
            "primary_asset_id": primary,
            "note": (
                "The affected asset was not present in the dependency graph "
                "when it was built, so the term could not be evaluated; "
                "the score was not adjusted and this is an unknown input."
            ),
        }

    radius = org_graph.blast_radius(graph_obj, primary, max_depth=depth)
    entries = radius["potential_exposure"]
    raw = 0.0
    for entry in entries:
        criticality_weight = max(0.0, (int(entry["criticality"]) - 1) / 4)
        raw += criticality_weight * (1.0 / int(entry["depth"]))
    intensity = round(raw / (raw + saturation), 6) if raw > 0.0 else 0.0

    if entries:
        note = (
            f"Derived from {len(entries)} documented exposure path step(s) "
            f"from {primary} within depth {depth} (admin-declared "
            "relationships only). Potential exposure is not evidence that any "
            "compromise has occurred."
        )
    else:
        note = (
            f"No documented relationship leads from {primary} to another "
            f"registered asset within depth {depth}, so the term is 0. "
            "Absence of a declared relationship is not evidence that no "
            "exposure path exists."
        )

    return {
        **base_ctx,
        "status": "AVAILABLE",
        "intensity": intensity,
        "primary_asset_id": primary,
        "reachable_count": radius["count"],
        "critical_count": radius["critical_count"],
        "depth_used": radius["max_depth"],
        "truncated": bool(radius["truncated"]),
        "graph": graph_ctx,
        "note": note,
    }


def resolve_run_dependency_exposure(
    db: Session, user_id: str, asset_context: dict
) -> dict:
    """Same resolution for callers outside ``run_analysis`` (the propagation
    simulation), resolving the caller's organization server-side first."""
    return resolve_org_dependency_exposure(
        db, _resolve_org_or_none(db, user_id), asset_context
    )


def apply_dependency_feature(features: dict, dependency_context: dict) -> dict:
    """Merge a resolved graph context into a feature vector (pure, in place).

    Only an ``AVAILABLE`` context contributes an intensity; every other status
    leaves the vector at 0 — the recorded status carries the "why" (a caller
    that shows a score must show the context beside it, not just the points).
    """
    if (
        dependency_context.get("status") == "AVAILABLE"
        and dependency_context.get("intensity") is not None
    ):
        features[risk.DEPENDENCY_EXPOSURE_FEATURE] = float(
            dependency_context["intensity"]
        )
    else:
        features[risk.DEPENDENCY_EXPOSURE_FEATURE] = 0.0
    return features


def run_analysis(db: Session, user_id: str, *, persist: bool = True) -> dict:
    """Run the full pipeline and (optionally) persist the run's results."""
    run_id = uuid.uuid4().hex
    org_id = _resolve_org_or_none(db, user_id)
    events = build_input_events(db, user_id)

    correlations = correlation.evaluate(
        events,
        declared_asset_dependencies=_declared_asset_dependencies(db, org_id),
    )
    # Asset criticality: resolved HERE, server-side, inside this organization.
    criticality, asset_context = resolve_org_criticality(db, org_id, events)
    # Phase 6b: the organization's dependency-graph exposure, resolved HERE,
    # server-side, from admin-declared edges only (docs/RISK_MODEL.md §1.3).
    dependency_context = resolve_org_dependency_exposure(db, org_id, asset_context)
    risk_breakdown = risk.compute_risk(
        events, criticality=criticality, dependency=dependency_context
    )
    # THE feature vector of this run: extracted findings + the merged graph
    # intensity (whatever compute_risk actually scored with). Attribution and
    # the planner consume THIS vector, so every consumer explains/optimizes the
    # score that was actually shown — never a re-derived approximation.
    features = risk_breakdown.components["features"]
    # Attribution and planner run on the SAME value function context, so every
    # consumer of this run explains/optimizes the score that was actually shown.
    attribution = shapley.attribute(features, criticality=criticality)
    plan_comparison = planner.compare(features, budget=6.0, criticality=criticality)

    # Traceability (Phase 4 §3.5): what this score consumed and where it came
    # from, stored beside the score itself.
    risk_breakdown.components.update(asset_context)
    risk_breakdown.components["org_id"] = org_id
    risk_breakdown.components["correlations_consumed"] = {
        "ids": [],
        "note": (
            "Grouped-link results never feed the score; interaction terms are "
            "computed from the findings themselves (docs/RISK_MODEL.md)."
        ),
    }

    if persist:
        _persist_run(
            db, user_id, org_id, run_id, correlations, risk_breakdown,
            attribution, plan_comparison,
        )

    return {
        "run_id": run_id,
        "events": events,
        "correlations": correlations,
        "risk": risk_breakdown,
        "attribution": attribution,
        "planner": plan_comparison,
        "features": features,
        "criticality": criticality,
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


def _persist_run(db, user_id, org_id, run_id, correlations, risk_breakdown, attribution, plan_comparison):
    _persist_correlations(db, user_id, run_id, correlations)
    components = risk_breakdown.components
    db.add(
        RiskResult(
            user_id=user_id,
            org_id=org_id,
            run_id=run_id,
            # The most important affected asset (or None when no registered
            # asset was bound) — the asset this score is primarily "about".
            asset_id=components.get("primary_asset_id"),
            # Which formula produced THIS row. Old rows keep their own version:
            # a snapshot is inserted, never rewritten when the model changes.
            model_version=components.get("model_version", risk.RISK_MODEL_VERSION),
            score=risk_breakdown.score,
            band=risk_breakdown.band,
            confidence=risk_breakdown.confidence,
            range_low=risk_breakdown.range_low,
            range_high=risk_breakdown.range_high,
            base_risk=risk_breakdown.base_risk,
            interaction_risk=risk_breakdown.interaction_risk,
            criticality_adjustment=risk_breakdown.criticality_adjustment,
            mitigation_credit=risk_breakdown.mitigation_credit,
            components=components,
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