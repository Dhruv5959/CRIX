"""Phase 6b guarantees: the organization dependency graph feeds the score.

Phase 6b (docs/RISK_MODEL.md §1.3, master prompt §4) wires the Phase 6
blast-radius query into the contextual score as ONE documented, bounded,
additive term — DependencyExposure — so the product claim "graph-based risk
prioritization" is backed by the formula rather than by a slide.

What is pinned here, in the spec's own words:

 1. risk.py stays pure — the intensity is an INPUT, resolved by the pipeline
 2. the term is the documented bounded formula (100 * weight * d)
 3. additive identity stays exact; the term sits OUTSIDE m(c)
 4. the term alone never dominates (bounded by 100 * weight * m)
 5. the mitigation cap base includes the term
 6. compute_risk merges only an AVAILABLE context; every other status is
    recorded, zeroed, and never silently trusted; unknown statuses raise
 7. unknown graph inputs become uncertainty notes; evaluated zeros do not
 8. no graph input == the Phase 4 formula, bit-for-bit
 9. determinism (same rows -> same intensity, same score)
10. pipeline wiring: score + attribution (13 players, efficiency intact) +
    planner all consume the SAME vector
11. no bound findings -> no term, even with edges present
12. an evaluated 0 (edges absent) is distinct from an unknown (status shown)
13. tenant isolation: another organization's edges never reach the term
14. graph build failure -> UNAVAILABLE (never zero-as-safe)
15. config flag ablates the term and records DISABLED (for Phase 12)
16. new snapshots carry risk-2.1; historical rows are never rewritten
17. traversal bounds are recorded honestly (depth_used, truncated)
18. monotonicity: more criticality-weighted reachable mass -> higher term
19. sensitivity range brackets the score with the term present
20. Shapley baseline v(empty) = 0 and efficiency hold with the term present
21. the propagation-simulation helpers share the same resolved graph input
22. the API exposes the term and the exact composition (base + interaction +
    adjustment + dependency - mitigation = score)
23. wording stays inside the allowed vocabulary

Every asset, relationship and finding below is SYNTHETIC test data created by
the test itself (``seed_org_for_user`` / ``ev`` / ``OrgAsset`` /
``AssetDependency``), registered exactly the way the API stores it.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.engine import normalizer, org_graph, pipeline, risk, shapley
from app.engine.org_graph import GRAPH_LIMITS
from app.models import AssetDependency, Membership, OrgAsset, RiskResult
from tests.conftest import register_org_admin
from tests.helpers import ev, seed_org_for_user

WEIGHT = risk.RISK_PARAMS["dependency_exposure"]["weight"]          # 0.08
SATURATION = risk.RISK_PARAMS["dependency_exposure"]["saturation"]  # 4.0
DEP = risk.DEPENDENCY_EXPOSURE_FEATURE


def _points(intensity: float) -> float:
    """The documented term, computed from the documented literals only."""
    return round(100.0 * WEIGHT * intensity, 4)


# --------------------------------------------------------------------------- #
# SYNTHETIC fixtures (registered exactly like the API stores them)
# --------------------------------------------------------------------------- #
def _asset(db, org_id, asset_id, asset_type="WORK_EMAIL", criticality=3):
    asset = OrgAsset(
        org_id=org_id, asset_id=asset_id, asset_type=asset_type,
        label=f"SYNTHETIC {asset_id}", criticality=criticality,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def _edge(db, org_id, from_id, to_id, rel_type="USES"):
    edge = AssetDependency(
        org_id=org_id, from_asset_id=from_id, to_asset_id=to_id,
        relationship_type=rel_type,
        edge_source="ADMIN_DECLARED", weight=1.0, note="SYNTHETIC test edge",
    )
    db.add(edge)
    db.commit()
    db.refresh(edge)
    return edge


def _finding(db, user_id, account_id, event_id):
    normalizer.persist_events(db, [
        ev("BREACH_EXPOSURE", account_id=account_id, severity=0.7,
           event_id=event_id, user_id=user_id),
    ])


# --------------------------------------------------------------------------- #
# 1. Engine purity: risk.py computes, it never reads the graph
# --------------------------------------------------------------------------- #
def test_risk_module_still_imports_no_graph_db_or_network_code():
    tree = ast.parse(Path(risk.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[-1])
        elif isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[-1] for alias in node.names)
    forbidden = {"org_graph", "networkx", "models", "sqlalchemy", "pipeline", "graph"}
    assert not (imported & forbidden), sorted(imported & forbidden)


# --------------------------------------------------------------------------- #
# 2-5. The documented formula
# --------------------------------------------------------------------------- #
def test_term_is_the_documented_bounded_monotone_formula():
    assert risk.dependency_exposure_points(0.0) == 0.0
    assert risk.dependency_exposure_points(0.2) == pytest.approx(_points(0.2))
    assert risk.dependency_exposure_points(1.0) == pytest.approx(100.0 * WEIGHT)
    values = [risk.dependency_exposure_points(d / 10) for d in range(11)]
    assert values == sorted(values), "monotone in the intensity"
    assert max(values) <= 100.0 * WEIGHT, "bounded by 100 * weight by construction"
    for bad in (-0.01, 1.01, "0.5", True, None):
        with pytest.raises(ValueError):
            risk.dependency_exposure_points(bad)


def test_additive_identity_stays_exact_and_the_term_sits_outside_m():
    feats = {name: 0.0 for name in risk.ALL_FEATURES}
    feats.update({"breach": 0.7, "reuse": 0.5, DEP: 0.25})
    score, comp = risk.risk_from_features(feats, criticality=4)
    identity = (
        comp["base_risk"] + comp["interaction_risk"]
        + comp["criticality_adjustment"] + comp["dependency_exposure"]
        - comp["mitigation_credit"]
    )
    assert round(identity, 4) == pytest.approx(score)
    assert comp["dependency_exposure"] == pytest.approx(_points(0.25))
    # Outside m(c): the criticality adjustment is byte-identical with and
    # without the term — the multiplier's documented scope is unchanged.
    _, comp_no_dep = risk.risk_from_features({**feats, DEP: 0.0}, criticality=4)
    assert comp["criticality_adjustment"] == comp_no_dep["criticality_adjustment"]
    assert comp["criticality_multiplier"] == comp_no_dep["criticality_multiplier"]


def test_term_alone_is_bounded_and_never_dominates():
    feats = {name: 0.0 for name in risk.ALL_FEATURES}
    feats[DEP] = 1.0
    # Outside m(c): a saturated graph term is exactly 100 * weight points for
    # EVERY criticality — the multiplier's documented scope is the affected
    # asset, and the graph term carries its own criticality weighting (of the
    # reachable assets). Bounded, never dominant.
    for criticality in (None, 1, 3, 5):
        score, _ = risk.risk_from_features(feats, criticality=criticality)
        assert score == pytest.approx(100.0 * WEIGHT)  # 8.0
    # Even saturated, the term adds less than the top-weighted evidence group
    # at full intensity (session, 16 points): findings lead, the graph re-ranks.
    assert 100.0 * WEIGHT < 100.0 * risk.RISK_PARAMS["base_weights"]["session"]


def test_mitigation_cap_base_includes_the_dependency_term():
    feats = {name: 0.0 for name in risk.ALL_FEATURES}
    feats.update({"passkey": 1.0, "mfa": 1.0, DEP: 0.5})
    score, comp = risk.risk_from_features(feats)  # no criticality
    # raw credit 32 > cap 0.45 * (0 + 4.0) = 1.8 -> credit is the cap.
    assert comp["mitigation_credit"] == pytest.approx(1.8)
    assert score == pytest.approx(4.0 - 1.8)


# --------------------------------------------------------------------------- #
# 6-8. compute_risk status handling
# --------------------------------------------------------------------------- #
def _events():
    return [
        ev("BREACH_EXPOSURE", account_id="a@acme.example", severity=0.7,
           event_id="evt_dep_1", user_id="u-dep"),
        ev("MFA_MISSING", account_id="a@acme.example", severity=0.6,
           event_id="evt_dep_2", user_id="u-dep"),
    ]


def test_compute_risk_merges_only_an_available_context():
    events = _events()
    available = risk.compute_risk(
        events, criticality=4, dependency={"status": "AVAILABLE", "intensity": 0.3}
    )
    assert available.components["features"][DEP] == pytest.approx(0.3)
    assert available.dependency_exposure == pytest.approx(_points(0.3))
    assert available.components["dependency_exposure"]["points"] == pytest.approx(
        _points(0.3)
    )
    for status in ("NO_AFFECTED_ASSET", "NO_ORGANIZATION", "UNAVAILABLE", "DISABLED"):
        # A stray intensity must be DROPPED, so the recorded status and the
        # math can never disagree.
        other = risk.compute_risk(
            events, criticality=4, dependency={"status": status, "intensity": 0.9}
        )
        assert other.components["features"][DEP] == 0.0
        assert other.dependency_exposure == 0.0
        assert other.components["dependency_exposure"]["status"] == status
        assert other.components["dependency_exposure"]["intensity"] is None
    default = risk.compute_risk(events)
    assert default.components["dependency_exposure"]["status"] == "NOT_PROVIDED"
    assert default.dependency_exposure == 0.0
    with pytest.raises(ValueError):
        risk.compute_risk(events, dependency={"status": "SOMETHING_NEW"})
    with pytest.raises(ValueError):
        risk.compute_risk(events, dependency={"status": "AVAILABLE"})  # no intensity


def test_unknown_graph_inputs_become_notes_and_evaluated_zeros_do_not():
    events = _events()
    for status in ("UNAVAILABLE", "NO_ORGANIZATION"):
        breakdown = risk.compute_risk(events, dependency={"status": status})
        notes = " ".join(breakdown.components["uncertainty"]).lower()
        assert "could not be evaluated" in notes or "no organization context" in notes
    for dependency in (
        {"status": "AVAILABLE", "intensity": 0.0, "note": "evaluated"},
        {"status": "NO_AFFECTED_ASSET", "note": "n/a"},
        {"status": "DISABLED", "note": "ablation"},
        None,
    ):
        breakdown = risk.compute_risk(events, dependency=dependency)
        notes = " ".join(breakdown.components["uncertainty"]).lower()
        assert "could not be evaluated" not in notes
        assert "no organization context" not in notes


def test_absent_graph_bit_for_bit_equals_the_phase4_formula():
    events = _events()
    plain = risk.compute_risk(events, criticality=4)
    not_provided = risk.compute_risk(
        events, criticality=4, dependency={"status": "NOT_PROVIDED"}
    )
    evaluated_zero = risk.compute_risk(
        events, criticality=4,
        dependency={"status": "AVAILABLE", "intensity": 0.0, "note": "no edges"},
    )
    assert plain.score == not_provided.score == evaluated_zero.score
    assert plain.components["features"] == not_provided.components["features"]
    assert plain.dependency_exposure == 0.0


# --------------------------------------------------------------------------- #
# 9-12. Pipeline wiring on SYNTHETIC organizations
# --------------------------------------------------------------------------- #
def test_pipeline_wires_the_term_into_score_attribution_and_planner(db_session):
    user_id = "u-wire"
    org_id = seed_org_for_user(db_session, user_id)
    _asset(db_session, org_id, "mail@wire.example", "WORK_EMAIL", 4)
    _asset(db_session, org_id, "vault@wire.example", "CLOUD_STORAGE", 5)
    _edge(db_session, org_id, "mail@wire.example", "vault@wire.example", "HAS_ACCESS_TO")
    _finding(db_session, user_id, "mail@wire.example", "evt_wire_1")

    result = pipeline.run_analysis(db_session, user_id, persist=False)
    breakdown = result["risk"]
    ctx = breakdown.components["dependency_exposure"]

    # Documented math on documented inputs: one criticality-5 asset, one hop.
    # raw = (5 - 1) / 4 * 1 = 1  ->  d = 1 / (1 + 4) = 0.2
    assert ctx["status"] == "AVAILABLE"
    assert ctx["intensity"] == pytest.approx(0.2)
    assert breakdown.dependency_exposure == pytest.approx(_points(0.2))
    assert result["features"][DEP] == pytest.approx(0.2)
    # Provenance of the input is stated next to the points themselves.
    assert ctx["reachable_count"] == 1
    assert ctx["primary_asset_id"] == "mail@wire.example"
    assert ctx["graph"]["edges"] == 1
    assert ctx["graph"]["edges_provenance"] == "ADMIN_DECLARED"
    assert ctx["source"] == "org_graph.blast_radius"
    assert ctx["formula"] and ctx["note"] and ctx["disclaimer"]
    assert "potential exposure" in ctx["disclaimer"].lower()

    # Attribution: 13 players, efficiency intact, the graph's points are the
    # player's points.
    attribution = result["attribution"]
    assert len(attribution["contributions"]) == 13
    assert attribution["efficiency_error"] < 1e-6
    assert attribution["total_risk"] == pytest.approx(breakdown.score)
    assert attribution["contributions"][DEP] == pytest.approx(
        breakdown.dependency_exposure
    )
    # Planner explains/optimizes the score that was actually shown.
    assert result["planner"]["initial_risk"] == pytest.approx(breakdown.score)
    # Independent documented formula reproduces the score from the features.
    from tests.test_risk_phase4 import expected_score
    assert breakdown.score == pytest.approx(
        expected_score(result["features"], result["criticality"])
    )


def test_intensity_and_score_are_deterministic(db_session):
    user_id = "u-det"
    org_id = seed_org_for_user(db_session, user_id)
    _asset(db_session, org_id, "mail@det.example", "WORK_EMAIL", 4)
    _asset(db_session, org_id, "repo@det.example", "CODE_REPOSITORY", 4)
    _edge(db_session, org_id, "mail@det.example", "repo@det.example", "RESETS_PASSWORD")
    _finding(db_session, user_id, "mail@det.example", "evt_det_1")

    context = {"primary_asset_id": "mail@det.example"}
    first = pipeline.resolve_org_dependency_exposure(db_session, org_id, context)
    second = pipeline.resolve_org_dependency_exposure(db_session, org_id, context)
    assert first == second
    run_a = pipeline.run_analysis(db_session, user_id, persist=False)
    run_b = pipeline.run_analysis(db_session, user_id, persist=False)
    assert run_a["risk"].score == run_b["risk"].score
    assert run_a["features"] == run_b["features"]
    # Every trace component is identical EXCEPT finding_ids: the pipeline
    # derives fresh dependency-graph events per call (documented Phase 0
    # behavior) and mints a new UUID for each — the stored findings, their
    # severities and the score itself stay fixed.
    stable_a = {k: v for k, v in run_a["risk"].components.items() if k != "finding_ids"}
    stable_b = {k: v for k, v in run_b["risk"].components.items() if k != "finding_ids"}
    assert stable_a == stable_b
    assert "evt_det_1" in run_a["risk"].components["finding_ids"]
    assert "evt_det_1" in run_b["risk"].components["finding_ids"]


def test_no_bound_findings_means_no_term_even_with_edges_present(db_session):
    user_id = "u-none"
    org_id = seed_org_for_user(db_session, user_id)
    _asset(db_session, org_id, "mail@none.example", "WORK_EMAIL", 4)
    _asset(db_session, org_id, "repo@none.example", "CODE_REPOSITORY", 5)
    _edge(db_session, org_id, "mail@none.example", "repo@none.example", "DEPLOYS_TO")
    # CHECKED_SAFE is bound to the asset but is not a finding: nothing was
    # affected, so there is no asset to reason FROM (and criticality alone
    # never creates risk).
    normalizer.persist_events(db_session, [
        ev("BREACH_EXPOSURE", account_id="mail@none.example", severity=0.0,
           event_id="evt_none_safe", user_id=user_id, status="CHECKED_SAFE"),
    ])

    result = pipeline.run_analysis(db_session, user_id, persist=False)
    ctx = result["risk"].components["dependency_exposure"]
    assert ctx["status"] == "NO_AFFECTED_ASSET"
    assert result["risk"].dependency_exposure == 0.0
    assert result["risk"].score == 0.0


def test_evaluated_zero_is_recorded_as_such_and_is_not_unknown(db_session):
    user_id = "u-zero"
    org_id = seed_org_for_user(db_session, user_id)
    _asset(db_session, org_id, "mail@zero.example", "WORK_EMAIL", 4)
    _finding(db_session, user_id, "mail@zero.example", "evt_zero_1")

    result = pipeline.run_analysis(db_session, user_id, persist=False)
    ctx = result["risk"].components["dependency_exposure"]
    assert ctx["status"] == "AVAILABLE"
    assert ctx["intensity"] == 0.0
    assert ctx["reachable_count"] == 0
    assert "absence of a declared relationship" in ctx["note"].lower()
    notes = " ".join(result["risk"].components["uncertainty"]).lower()
    assert "could not be evaluated" not in notes, "an evaluated 0 is not unknown"
    # An organization without context is unknown, never zero-as-safe.
    no_org = pipeline.resolve_org_dependency_exposure(
        db_session, None, {"primary_asset_id": "mail@zero.example"}
    )
    assert no_org["status"] == "NO_ORGANIZATION"


# --------------------------------------------------------------------------- #
# 13-15. Isolation, failure, ablation
# --------------------------------------------------------------------------- #
def test_another_organizations_edges_never_reach_the_term(db_session):
    user_a, user_b = "u-iso-a", "u-iso-b"
    org_a = seed_org_for_user(db_session, user_a)
    org_b = seed_org_for_user(db_session, user_b)
    _asset(db_session, org_a, "mail@iso-a.example", "WORK_EMAIL", 4)
    _finding(db_session, user_a, "mail@iso-a.example", "evt_iso_a")
    _asset(db_session, org_b, "mail@iso-b.example", "WORK_EMAIL", 4)
    _asset(db_session, org_b, "vault@iso-b.example", "CLOUD_STORAGE", 5)
    _edge(db_session, org_b, "mail@iso-b.example", "vault@iso-b.example", "HAS_ACCESS_TO")
    _finding(db_session, user_b, "mail@iso-b.example", "evt_iso_b")

    run_a = pipeline.run_analysis(db_session, user_a, persist=False)
    run_b = pipeline.run_analysis(db_session, user_b, persist=False)
    ctx_a = run_a["risk"].components["dependency_exposure"]
    ctx_b = run_b["risk"].components["dependency_exposure"]
    # Tenant A has no edges of its own: B's rich graph can never leak in.
    assert ctx_a["graph"]["edges"] == 0
    assert ctx_a["intensity"] == 0.0
    assert run_a["risk"].dependency_exposure == 0.0
    assert ctx_b["intensity"] == pytest.approx(0.2)
    assert run_b["risk"].dependency_exposure > 0.0
    assert ctx_a["primary_asset_id"] != ctx_b["primary_asset_id"]


def test_graph_build_failure_is_unavailable_never_zero_as_safe(db_session, monkeypatch):
    user_id = "u-fail"
    org_id = seed_org_for_user(db_session, user_id)
    _asset(db_session, org_id, "mail@fail.example", "WORK_EMAIL", 4)
    _asset(db_session, org_id, "vault@fail.example", "CLOUD_STORAGE", 5)
    _edge(db_session, org_id, "mail@fail.example", "vault@fail.example", "HAS_ACCESS_TO")
    _finding(db_session, user_id, "mail@fail.example", "evt_fail_1")

    def _boom(*_args, **_kwargs):
        raise org_graph.GraphTooLargeError("synthetic build failure")

    monkeypatch.setattr(org_graph, "build_org_graph", _boom)
    result = pipeline.run_analysis(db_session, user_id, persist=False)
    ctx = result["risk"].components["dependency_exposure"]
    assert ctx["status"] == "UNAVAILABLE"
    assert ctx["reason"] == "graph_too_large"
    assert "unavailable is not the same as safe" in ctx["note"].lower()
    assert result["risk"].dependency_exposure == 0.0
    notes = " ".join(result["risk"].components["uncertainty"]).lower()
    assert "could not be evaluated" in notes, "unknown input must be stated"
    assert result["risk"].score == pytest.approx(
        result["risk"].base_risk + result["risk"].interaction_risk
        + result["risk"].criticality_adjustment - result["risk"].mitigation_credit
    )


def test_config_flag_ablates_the_term_and_says_so(db_session, monkeypatch):
    user_id = "u-ablate"
    org_id = seed_org_for_user(db_session, user_id)
    _asset(db_session, org_id, "mail@abl.example", "WORK_EMAIL", 4)
    _asset(db_session, org_id, "vault@abl.example", "CLOUD_STORAGE", 5)
    _edge(db_session, org_id, "mail@abl.example", "vault@abl.example", "HAS_ACCESS_TO")
    _finding(db_session, user_id, "mail@abl.example", "evt_abl_1")

    baseline = pipeline.run_analysis(db_session, user_id, persist=False)
    assert baseline["risk"].dependency_exposure > 0.0

    monkeypatch.setenv("CRIX_RISK_DEPENDENCY_EXPOSURE_ENABLED", "false")
    get_settings.cache_clear()
    try:
        ablated = pipeline.run_analysis(db_session, user_id, persist=False)
    finally:
        monkeypatch.delenv("CRIX_RISK_DEPENDENCY_EXPOSURE_ENABLED")
        get_settings.cache_clear()

    ctx = ablated["risk"].components["dependency_exposure"]
    assert ctx["status"] == "DISABLED"
    assert "disabled by configuration" in ctx["note"].lower()
    assert ablated["risk"].dependency_exposure == 0.0
    # Ablated score == baseline minus exactly the term (nothing else changes).
    assert ablated["risk"].score == pytest.approx(
        baseline["risk"].score - baseline["risk"].dependency_exposure
    )


# --------------------------------------------------------------------------- #
# 16-18. Versioning and honest bounds
# --------------------------------------------------------------------------- #
def test_new_snapshots_carry_risk_2_1_and_history_is_never_rewritten(db_session):
    user_id = "u-ver"
    org_id = seed_org_for_user(db_session, user_id)
    _asset(db_session, org_id, "mail@ver.example", "WORK_EMAIL", 4)
    _asset(db_session, org_id, "vault@ver.example", "CLOUD_STORAGE", 5)
    _edge(db_session, org_id, "mail@ver.example", "vault@ver.example", "HAS_ACCESS_TO")
    _finding(db_session, user_id, "mail@ver.example", "evt_ver_1")

    legacy = RiskResult(
        user_id=user_id, run_id="run-legacy", org_id=org_id,
        score=55.0, band="HIGH", confidence="MEDIUM",
        range_low=50.0, range_high=60.0, base_risk=40.0,
        interaction_risk=10.0, mitigation_credit=0.0, model_version="risk-2.0",
        components={"note": "computed before the dependency term existed"},
    )
    db_session.add(legacy)
    db_session.commit()

    result = pipeline.run_analysis(db_session, user_id, persist=True)
    fresh = db_session.scalars(
        select(RiskResult).where(
            RiskResult.user_id == user_id,
            RiskResult.model_version == risk.RISK_MODEL_VERSION,
        )
    ).all()
    assert risk.RISK_MODEL_VERSION == "risk-2.1"
    assert fresh, "the new run must be stamped with the new formula version"
    assert fresh[0].components["dependency_exposure"]["status"] == "AVAILABLE"

    db_session.refresh(legacy)
    assert legacy.model_version == "risk-2.0", "snapshots keep their formula"
    assert legacy.score == 55.0
    assert legacy.components == {"note": "computed before the dependency term existed"}
    assert result["risk"].score > 0.0


def test_traversal_bounds_are_recorded_honestly(db_session):
    user_id = "u-depth"
    org_id = seed_org_for_user(db_session, user_id)
    _asset(db_session, org_id, "mail@depth.example", "WORK_EMAIL", 4)
    chain = ["a1", "a2", "a3", "a4"]
    for name in chain:
        _asset(db_session, org_id, f"{name}@depth.example", "CLOUD_STORAGE", 5)
    # Forward-exposure edges, so the chain is reachable FROM the primary asset.
    _edge(db_session, org_id, "mail@depth.example", "a1@depth.example", "HAS_ACCESS_TO")
    _edge(db_session, org_id, "a1@depth.example", "a2@depth.example", "HAS_ACCESS_TO")
    _edge(db_session, org_id, "a2@depth.example", "a3@depth.example", "HAS_ACCESS_TO")
    _edge(db_session, org_id, "a3@depth.example", "a4@depth.example", "HAS_ACCESS_TO")

    ctx = pipeline.resolve_org_dependency_exposure(
        db_session, org_id, {"primary_asset_id": "mail@depth.example"}
    )
    assert ctx["status"] == "AVAILABLE"
    assert ctx["depth_used"] == GRAPH_LIMITS["default_depth"] == 3
    assert ctx["reachable_count"] == 3, "a4 sits beyond the documented bound"
    assert ctx["truncated"] is True, "and the bound is admitted, not hidden"
    expected_raw = 1.0 + 1.0 / 2 + 1.0 / 3
    assert ctx["intensity"] == pytest.approx(
        round(expected_raw / (expected_raw + SATURATION), 6), abs=1e-6
    )


def test_term_is_monotone_in_criticality_weighted_reachable_mass(db_session):
    user_id = "u-mono"
    org_id = seed_org_for_user(db_session, user_id)
    _asset(db_session, org_id, "mail@mono.example", "WORK_EMAIL", 4)
    _asset(db_session, org_id, "low@mono.example", "CLOUD_STORAGE", 2)
    _asset(db_session, org_id, "high@mono.example", "CLOUD_STORAGE", 5)
    _edge(db_session, org_id, "mail@mono.example", "low@mono.example", "HAS_ACCESS_TO")
    context = {"primary_asset_id": "mail@mono.example"}
    one_low = pipeline.resolve_org_dependency_exposure(db_session, org_id, context)
    _edge(db_session, org_id, "mail@mono.example", "high@mono.example", "HAS_ACCESS_TO")
    low_and_high = pipeline.resolve_org_dependency_exposure(db_session, org_id, context)
    # raw 0.25 -> d = 0.25/4.25, then raw 1.25 -> d = 1.25/5.25: strictly up.
    assert one_low["intensity"] < low_and_high["intensity"] < 1.0
    assert one_low["reachable_count"] == 1
    assert low_and_high["reachable_count"] == 2


# --------------------------------------------------------------------------- #
# 19-21. Attribution, sensitivity, propagation helpers
# --------------------------------------------------------------------------- #
def test_sensitivity_range_brackets_the_score_with_the_term_present():
    feats = {name: 0.4 for name in risk.ALL_FEATURES}
    feats[DEP] = 0.6
    for criticality in (None, 2, 4, 5):
        low, high = risk.sensitivity_range(feats, criticality=criticality)
        score, _ = risk.risk_from_features(feats, criticality=criticality)
        assert low <= score <= high


def test_shapley_baseline_and_efficiency_hold_with_the_term_present():
    feats = {name: 0.5 for name in risk.ALL_FEATURES}
    feats.update({DEP: 0.3, "passkey": 1.0, "mfa": 1.0, "session": 0.8})
    # v(empty) = 0 by the documented function, even with the graph in play.
    empty = {name: 0.0 for name in risk.ALL_FEATURES}
    assert risk.risk_from_features(empty, criticality=5)[0] == 0.0
    contributions, total = shapley.shapley_values(feats, criticality=5)
    expected, _ = risk.risk_from_features(feats, criticality=5)
    assert total == pytest.approx(expected)
    assert abs(sum(contributions.values()) - total) < 1e-6


def test_propagation_helpers_share_the_same_resolved_graph_input(db_session):
    user_id = "u-prop"
    org_id = seed_org_for_user(db_session, user_id)
    _asset(db_session, org_id, "mail@prop.example", "WORK_EMAIL", 4)
    _asset(db_session, org_id, "vault@prop.example", "CLOUD_STORAGE", 5)
    _edge(db_session, org_id, "mail@prop.example", "vault@prop.example", "HAS_ACCESS_TO")
    _finding(db_session, user_id, "mail@prop.example", "evt_prop_1")

    run = pipeline.run_analysis(db_session, user_id, persist=False)
    context = pipeline.resolve_run_dependency_exposure(
        db_session, user_id, {"primary_asset_id": "mail@prop.example"}
    )
    assert context["status"] == "AVAILABLE"
    merged = pipeline.apply_dependency_feature(
        {name: 0.0 for name in risk.ALL_FEATURES}, context
    )
    assert merged[DEP] == pytest.approx(run["features"][DEP])
    # A non-AVAILABLE context zeroes the key instead of inventing an intensity.
    for status in ("UNAVAILABLE", "NO_ORGANIZATION", "DISABLED", "NO_AFFECTED_ASSET"):
        zeroed = pipeline.apply_dependency_feature(
            {name: 0.0 for name in risk.ALL_FEATURES}, {"status": status, "intensity": 0.9}
        )
        assert zeroed[DEP] == 0.0


# --------------------------------------------------------------------------- #
# 22. API contract: the term and the exact composition are visible
# --------------------------------------------------------------------------- #
def test_api_risk_block_shows_the_term_and_the_exact_composition(client, db_session):
    from tests.test_risk_phase4 import expected_dependency_points, expected_score

    headers = register_org_admin(client, org_name="Graph Term Co")
    membership = db_session.scalar(select(Membership).where(Membership.is_active.is_(True)))
    org_id, user_id = membership.org_id, membership.user_id
    _asset(db_session, org_id, "alice@graph.example", "WORK_EMAIL", 4)
    _asset(db_session, org_id, "vault@graph.example", "CLOUD_STORAGE", 5)
    _edge(db_session, org_id, "alice@graph.example", "vault@graph.example", "HAS_ACCESS_TO")
    _finding(db_session, user_id, "alice@graph.example", "evt_api_dep")

    response = client.post("/api/analysis/run", json={}, headers=headers)
    assert response.status_code == 200, response.text
    risk_block = response.json()["risk"]

    dep_ctx = risk_block["components"]["dependency_exposure"]
    assert dep_ctx["status"] == "AVAILABLE"
    assert dep_ctx["intensity"] == pytest.approx(0.2)
    assert risk_block["dependency_exposure"] == pytest.approx(
        expected_dependency_points(response.json()["features"])
    )
    composition = (
        risk_block["base_risk"] + risk_block["interaction_risk"]
        + risk_block["criticality_adjustment"] + risk_block["dependency_exposure"]
        - risk_block["mitigation_credit"]
    )
    assert composition == pytest.approx(risk_block["score"])
    assert risk_block["score"] == pytest.approx(
        expected_score(response.json()["features"], risk_block["criticality"])
    )
    body = response.json()
    assert body["attribution"]["total_risk"] == pytest.approx(risk_block["score"])
    assert body["planner"]["initial_risk"] == pytest.approx(risk_block["score"])


# --------------------------------------------------------------------------- #
# 23. Wording stays inside the allowed vocabulary
# --------------------------------------------------------------------------- #
def test_new_code_uses_only_the_allowed_risk_vocabulary():
    forbidden = (
        "probability of compromise",
        "predicts hacking",
        "prevents takeover",
        "detected an attack",
    )
    for module in (risk, pipeline, org_graph):
        text = Path(module.__file__).read_text(encoding="utf-8").lower()
        for phrase in forbidden:
            assert phrase not in text, f"{module.__name__}: {phrase!r}"
