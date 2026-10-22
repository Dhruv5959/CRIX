"""Phase 4 contextual-risk guarantees (§3).

Every constraint the phase states is pinned here: the documented parameters are
the parameters the engine actually uses, severity normalizes linearly, asset
criticality moves the score ONLY through the single documented multiplier,
criticality alone never creates risk, interactions and mitigations follow the
formula (no hidden bonus), duplicates never double-count, out-of-range and
missing inputs behave honestly (unknown ≠ safe), identical inputs give
identical scores and traces, cross-organization asset references are rejected
fail-closed, snapshots are org-scoped and keep their model version, and the
API exposes the traceability fields the frontend relies on.

SYNTHETIC TEST DATA: every finding, asset and organization below is created by
the test itself (``tests.helpers.ev`` / ``seed_org_for_user`` / ``OrgAsset``)
and is labeled as such by its fixtures. Expected values are DERIVED from the
documented formula literals at the top of this file — never copied from the
engine's own output.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from app.engine import normalizer, pipeline, risk
from app.models import AssetDependency, OrgAsset, RiskResult
from tests.conftest import register_org_admin
from tests.helpers import ev, seed_org_for_user

# --------------------------------------------------------------------------- #
# The documented formula, written out independently of the engine.
# These literals mirror docs/RISK_MODEL.md; test_documented_parameters...
# fails if the engine drifts from them (or vice versa).
# --------------------------------------------------------------------------- #
DOC_BASE_WEIGHTS = {
    "breach": 0.15, "session": 0.16, "identity": 0.05, "reuse": 0.10,
    "no_mfa": 0.12, "sim_swap": 0.08, "push_bombing": 0.08,
    "phishing": 0.10, "permissions": 0.08, "dependency": 0.08,
}
DOC_INTERACTIONS = {
    ("breach", "reuse"): 0.10,
    ("breach", "no_mfa"): 0.10,
    ("session", "no_mfa"): 0.08,
    ("phishing", "identity"): 0.06,
    ("dependency", "session"): 0.08,
    ("reuse", "no_mfa"): 0.06,
    ("permissions", "phishing"): 0.05,
    ("sim_swap", "no_mfa"): 0.05,
}
DOC_MITIGATION_WEIGHTS = {"passkey": 0.20, "mfa": 0.12}
DOC_SESSION_DISCOUNT = 0.70
DOC_MITIGATION_CAP = 0.45
DOC_CRITICALITY = {"min": 1, "max": 5, "neutral": 3, "step_per_level": 0.10}
DOC_MODEL_VERSION = "risk-2.0"


def expected_score(features: dict, criticality: int | None = None) -> float:
    """The documented formula, computed from the literals above only.

    risk = clip( m(c) * (base + interaction) - mitigation, 0, 100 )
    m(c) = 1 + 0.10 * (c - 3);  mitigation = min(raw, 0.45 * scaled exposure)
    """
    f = {name: float(features.get(name, 0.0)) for name in DOC_BASE_WEIGHTS}
    base = 100.0 * sum(DOC_BASE_WEIGHTS[name] * f[name] for name in DOC_BASE_WEIGHTS)
    interaction = 100.0 * sum(
        coef * f[a] * f[b] for (a, b), coef in DOC_INTERACTIONS.items()
    )
    multiplier = (
        1.0
        if criticality is None
        else 1.0 + DOC_CRITICALITY["step_per_level"] * (criticality - DOC_CRITICALITY["neutral"])
    )
    exposure = multiplier * (base + interaction)
    discount = 1.0 - DOC_SESSION_DISCOUNT * f.get("session", 0.0)
    raw_credit = 100.0 * sum(
        DOC_MITIGATION_WEIGHTS[name] * float(features.get(name, 0.0))
        for name in DOC_MITIGATION_WEIGHTS
    ) * max(0.0, discount)
    credit = min(raw_credit, DOC_MITIGATION_CAP * exposure)
    return round(max(0.0, min(100.0, exposure - credit)), 4)


def expected_adjustment(features: dict, criticality: int | None) -> float:
    """criticality_adjustment = (m(c) - 1) * (base + interaction)."""
    f = {name: float(features.get(name, 0.0)) for name in DOC_BASE_WEIGHTS}
    base = 100.0 * sum(DOC_BASE_WEIGHTS[name] * f[name] for name in DOC_BASE_WEIGHTS)
    interaction = 100.0 * sum(
        coef * f[a] * f[b] for (a, b), coef in DOC_INTERACTIONS.items()
    )
    if criticality is None:
        return 0.0
    multiplier = 1.0 + DOC_CRITICALITY["step_per_level"] * (
        criticality - DOC_CRITICALITY["neutral"]
    )
    return round((multiplier - 1.0) * (base + interaction), 4)


def _features(**overrides) -> dict:
    base = {name: 0.0 for name in risk.ALL_FEATURES}
    base.update(overrides)
    return base


def _register_asset(db, org_id: str, asset_id: str, criticality: int) -> OrgAsset:
    """SYNTHETIC asset registration (admin-declared, exactly like the API)."""
    asset = OrgAsset(
        org_id=org_id,
        asset_id=asset_id,
        asset_type="EMAIL",
        label=f"synthetic asset {asset_id}",
        criticality=criticality,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


# --------------------------------------------------------------------------- #
# 1. Parameters, versioning, severity normalization
# --------------------------------------------------------------------------- #
def test_documented_parameters_are_exactly_what_the_engine_uses():
    assert risk.RISK_PARAMS["base_weights"] == DOC_BASE_WEIGHTS
    assert sum(DOC_BASE_WEIGHTS.values()) == pytest.approx(1.0)
    assert risk.RISK_PARAMS["interactions"] == DOC_INTERACTIONS
    assert risk.RISK_PARAMS["mitigation_weights"] == DOC_MITIGATION_WEIGHTS
    assert risk.RISK_PARAMS["session_mitigation_discount"] == DOC_SESSION_DISCOUNT
    assert risk.RISK_PARAMS["max_mitigation_credit"] == DOC_MITIGATION_CAP
    assert risk.RISK_PARAMS["criticality"] == DOC_CRITICALITY
    assert risk.RISK_MODEL_VERSION == DOC_MODEL_VERSION


def test_severity_normalizes_linearly_into_the_base_term():
    # SYNTHETIC: one breach finding at two severities, no criticality context.
    half = _features(breach=0.4)
    full = _features(breach=0.8)
    score_half, comp_half = risk.risk_from_features(half)
    score_full, comp_full = risk.risk_from_features(full)
    assert comp_half["base_risk"] == pytest.approx(100 * 0.15 * 0.4)  # 6.0
    assert comp_full["base_risk"] == pytest.approx(100 * 0.15 * 0.8)  # 12.0
    assert score_half == pytest.approx(expected_score(half))
    assert score_full == pytest.approx(expected_score(full))
    assert score_full == pytest.approx(2 * score_half)  # severity doubles ⇒ score doubles


def test_every_supported_finding_type_enters_its_documented_feature_group():
    # SYNTHETIC: one finding per supported type, severity 0.7.
    for event_type, group in risk.EVENT_TO_FEATURE.items():
        if group in risk.MITIGATION_FEATURES:
            continue  # mitigation types are covered by CHECKED_SAFE below
        features = risk.extract_features(
            [ev(event_type, severity=0.7, status="FINDING")]
        )
        assert features[group] == 0.7, event_type


def test_mitigation_controls_appear_only_as_checked_safe():
    # SYNTHETIC: MFA missing (a finding) and MFA enabled (checked safe).
    features = risk.extract_features(
        [ev("MFA_MISSING", severity=0.6, status="FINDING"),
         ev("MFA_ENABLED", status="CHECKED_SAFE")]
    )
    assert features["no_mfa"] == 0.6
    assert features["mfa"] == 1.0
    # A provider that could NOT answer must not read as a control being present.
    unavailable = risk.extract_features(
        [ev("MFA_ENABLED", status="UNAVAILABLE_THROUGH_PROVIDER")]
    )
    assert unavailable["mfa"] == 0.0


# --------------------------------------------------------------------------- #
# 2. Asset criticality: the single documented multiplier
# --------------------------------------------------------------------------- #
def test_asset_criticality_scales_the_score_exactly_as_documented():
    # SYNTHETIC: identical breach finding on assets of criticality 1..5.
    features = _features(breach=0.8)
    scores = [
        risk.risk_from_features(features, criticality=c)[0] for c in (1, 2, 3, 4, 5)
    ]
    # 12.0 × {0.8, 0.9, 1.0, 1.1, 1.2} — derived from the documented literals.
    assert scores == [9.6, 10.8, 12.0, 13.2, 14.4]
    for c, score in zip((1, 2, 3, 4, 5), scores):
        assert score == pytest.approx(expected_score(features, criticality=c))


def test_neutral_and_missing_criticality_leave_the_score_unadjusted():
    features = _features(breach=0.8)
    no_context, _ = risk.risk_from_features(features)
    neutral, _ = risk.risk_from_features(features, criticality=3)
    missing, _ = risk.risk_from_features(features, criticality=None)
    assert no_context == neutral == missing == pytest.approx(expected_score(features))


def test_criticality_alone_never_creates_risk():
    # A business-critical asset with zero findings still scores zero: importance
    # scales evidence, it is not evidence.
    assert risk.compute_risk([], criticality=5).score == 0.0
    assert risk.risk_from_features(_features(), criticality=5)[0] == 0.0
    breakdown = risk.compute_risk([], criticality=5)
    assert breakdown.criticality_adjustment == 0.0


def test_criticality_multiplier_bounds_and_rejections():
    assert risk.criticality_multiplier(None) == 1.0
    for c, expected in {1: 0.8, 2: 0.9, 3: 1.0, 4: 1.1, 5: 1.2}.items():
        assert risk.criticality_multiplier(c) == pytest.approx(expected)
    for bad in (0, 6, -1, 3.5, "3", True, False, [3]):
        with pytest.raises(ValueError, match="criticality"):
            risk.criticality_multiplier(bad)


def test_score_composition_is_an_exact_additive_identity():
    # SYNTHETIC: breach + missing MFA + an enabled MFA control on a level-5 asset.
    features = _features(breach=0.8, no_mfa=0.8, mfa=1.0)
    score, breakdown = risk.risk_from_features(features, criticality=5)
    assert breakdown["base_risk"] == pytest.approx(21.6)      # (0.15·0.8 + 0.12·0.8)·100
    assert breakdown["interaction_risk"] == pytest.approx(6.4)  # 0.10·0.8·0.8·100
    assert breakdown["criticality_adjustment"] == pytest.approx(5.6)  # 0.2·28
    assert breakdown["mitigation_credit"] == pytest.approx(12.0)
    identity = (
        breakdown["base_risk"]
        + breakdown["interaction_risk"]
        + breakdown["criticality_adjustment"]
        - breakdown["mitigation_credit"]
    )
    assert score == pytest.approx(identity) == pytest.approx(expected_score(features, 5))


# --------------------------------------------------------------------------- #
# 3. Interactions, double-counting, mitigations
# --------------------------------------------------------------------------- #
def test_interactions_fire_once_and_are_scaled_by_criticality_not_multiplied():
    # SYNTHETIC: breach + reuse compounding on a level-5 asset.
    features = _features(breach=0.8, reuse=0.8)
    plain, plain_b = risk.risk_from_features(features)
    scaled, scaled_b = risk.risk_from_features(features, criticality=5)
    assert plain_b["interaction_risk"] == pytest.approx(6.4)  # 0.10 · 0.8 · 0.8 · 100
    # The whole exposure scales by 1.2 exactly once; the interaction term itself
    # is unchanged and the scaling is visible as its own additive term.
    assert scaled_b["interaction_risk"] == pytest.approx(plain_b["interaction_risk"])
    assert scaled == pytest.approx(round(plain * 1.2, 4)) == pytest.approx(
        expected_score(features, 5)
    )


def test_duplicate_findings_do_not_double_count():
    # SYNTHETIC: the same breach observed twice (two event ids, one issue).
    once = [ev("BREACH_EXPOSURE", severity=0.7, event_id="evt_dup_1")]
    twice = once + [ev("BREACH_EXPOSURE", severity=0.7, event_id="evt_dup_2")]
    assert risk.extract_features(once) == risk.extract_features(twice)
    assert risk.compute_risk(once).score == risk.compute_risk(twice).score


def test_overlapping_findings_take_the_strongest_severity_in_the_group():
    # SYNTHETIC: two breaches of different strength in one feature group.
    features = risk.extract_features(
        [ev("BREACH_EXPOSURE", severity=0.4, event_id="evt_weak"),
         ev("BREACH_EXPOSURE", severity=0.9, event_id="evt_strong")]
    )
    assert features["breach"] == 0.9  # max, never a sum


def test_conflicting_evidence_resolves_by_documented_status_rules():
    # SYNTHETIC: a finding and a checked-safe result for the same control.
    features = risk.extract_features(
        [ev("MFA_MISSING", severity=0.6, status="FINDING"),
         ev("MFA_ENABLED", status="CHECKED_SAFE")]
    )
    # The finding states the gap; the control states the mitigation. Both are
    # inputs to the SAME documented formula — the score below is not a guess.
    score, breakdown = risk.risk_from_features(features, criticality=4)
    assert features["no_mfa"] == 0.6 and features["mfa"] == 1.0
    assert score == pytest.approx(expected_score(features, 4))
    assert breakdown["mitigation_credit"] > 0


def test_mitigation_credit_is_capped_at_45_percent_of_the_scaled_exposure():
    # SYNTHETIC: strong evidence with both controls present on a level-5 asset.
    features = _features(breach=0.9, no_mfa=0.8, passkey=1.0, mfa=1.0)
    score, breakdown = risk.risk_from_features(features, criticality=5)
    exposure = 1.2 * (23.1 + 7.2)  # 1.2 × (base 23.1 + interaction 7.2) = 36.36
    assert exposure == pytest.approx(36.36)
    # Raw credit would be 32.0 — the 45% cap binds instead.
    assert breakdown["mitigation_credit"] == pytest.approx(round(0.45 * exposure, 4))
    assert score == pytest.approx(expected_score(features, 5))


def test_a_stolen_session_still_discounts_mitigation_under_criticality():
    # SYNTHETIC: the same passkey credit with and without session exposure,
    # evaluated at criticality 4 (the multiplier scales both sides equally, so
    # the documented discount relationship must still hold).
    reduction_no_session = (
        risk.risk_from_features(_features(breach=0.8, no_mfa=0.8), criticality=4)[0]
        - risk.risk_from_features(
            _features(breach=0.8, no_mfa=0.8, passkey=1.0), criticality=4
        )[0]
    )
    reduction_with_session = (
        risk.risk_from_features(
            _features(breach=0.8, no_mfa=0.8, session=1.0), criticality=4
        )[0]
        - risk.risk_from_features(
            _features(breach=0.8, no_mfa=0.8, session=1.0, passkey=1.0), criticality=4
        )[0]
    )
    assert reduction_no_session > 0
    assert reduction_with_session > 0
    assert reduction_with_session < reduction_no_session


# --------------------------------------------------------------------------- #
# 4. Boundaries, out-of-range and missing information
# --------------------------------------------------------------------------- #
def test_score_boundaries_are_zero_and_one_hundred_at_every_criticality():
    # SYNTHETIC: every risk feature at full intensity.
    extreme = _features(**{name: 1.0 for name in risk.RISK_FEATURES})
    for c in (None, 1, 3, 5):
        score, _ = risk.risk_from_features(extreme, criticality=c)
        assert score == 100.0  # clipped, never 158 or 189.6
    assert risk.compute_risk([], criticality=1).score == 0.0


def test_out_of_range_feature_intensities_are_rejected_not_clipped():
    for bad in (1.5, -0.1, float("nan"), "0.5", None, True):
        with pytest.raises(ValueError, match="breach"):
            risk.risk_from_features(_features(breach=bad))


def test_missing_severity_is_rejected_by_the_schema_and_zero_is_explicit():
    payload = ev("BREACH_EXPOSURE", severity=0.6).model_dump()
    payload.pop("severity")
    with pytest.raises(ValidationError):
        type(ev("BREACH_EXPOSURE")).model_validate(payload)

    payload = ev("BREACH_EXPOSURE", severity=0.6).model_dump()
    payload["severity"] = 1.5  # out of the documented 0..1 range
    with pytest.raises(ValidationError):
        type(ev("BREACH_EXPOSURE")).model_validate(payload)

    # An explicit zero severity is a measured zero, not a missing value.
    assert risk.extract_features([ev("BREACH_EXPOSURE", severity=0.0)])["breach"] == 0.0


def test_missing_criticality_is_recorded_as_unknown_not_as_safety():
    # SYNTHETIC: findings with no registered asset bound to them.
    breakdown = risk.compute_risk([ev("BREACH_EXPOSURE", severity=0.6)])
    assert breakdown.components["criticality"] is None
    assert breakdown.components["criticality_multiplier"] == 1.0
    notes = " ".join(breakdown.components["uncertainty"]).lower()
    assert "not adjusted" in notes
    assert "not evidence" in notes
    # The score is still produced (prioritization continues on the evidence).
    assert breakdown.score == pytest.approx(expected_score(breakdown.components["features"]))


def test_unavailable_inputs_are_listed_next_to_the_score_and_never_scored():
    # SYNTHETIC: two provider failures and one check that never ran.
    events = [
        ev("BREACH_EXPOSURE", status="UNAVAILABLE", event_id="evt_un_breach"),
        ev("PASSWORD_REUSE", status="UNAVAILABLE_THROUGH_PROVIDER", event_id="evt_un_reuse"),
        ev("PHISHING_MESSAGE_DETECTED", status="NOT_CHECKED", event_id="evt_un_phish"),
    ]
    breakdown = risk.compute_risk(events)
    statuses = [(row["event_id"], row["status"]) for row in breakdown.components["unavailable_inputs"]]
    assert statuses == [
        ("evt_un_breach", "UNAVAILABLE"),
        ("evt_un_phish", "NOT_CHECKED"),
        ("evt_un_reuse", "UNAVAILABLE_THROUGH_PROVIDER"),
    ]  # sorted by event id — deterministic regardless of input order
    assert breakdown.score == 0.0  # no FINDING, but explicitly NOT "checked safe"
    notes = " ".join(breakdown.components["uncertainty"])
    assert "unavailable is not the same as safe" in notes


# --------------------------------------------------------------------------- #
# 5. Determinism and traceability
# --------------------------------------------------------------------------- #
def test_identical_inputs_produce_identical_scores_and_identical_traces():
    # SYNTHETIC: same findings, delivered in two different orders.
    events = [
        ev("BREACH_EXPOSURE", severity=0.7, event_id="evt_t2"),
        ev("MFA_MISSING", severity=0.6, event_id="evt_t1"),
        ev("PASSWORD_REUSE", status="UNAVAILABLE", event_id="evt_t3"),
    ]
    a = risk.compute_risk(events, criticality=4)
    b = risk.compute_risk(list(reversed(events)), criticality=4)
    assert a.score == b.score
    assert a.components == b.components  # finding ids sorted ⇒ order-independent
    assert a.criticality_adjustment == b.criticality_adjustment


def test_traceability_fields_name_every_input_the_score_consumed():
    # SYNTHETIC: a bound finding plus a non-answer.
    events = [
        ev("BREACH_EXPOSURE", severity=0.7, event_id="evt_trace_1"),
        ev("MFA_MISSING", status="UNAVAILABLE", event_id="evt_trace_2"),
    ]
    breakdown = risk.compute_risk(events, criticality=4)
    components = breakdown.components
    assert components["model_version"] == DOC_MODEL_VERSION
    assert components["criticality"] == 4
    assert components["finding_ids"] == ["evt_trace_1", "evt_trace_2"]
    # Interaction terms are TRACE rows only — their values are already inside
    # interaction_risk, they never add points.
    interaction_sum = sum(t["value"] for t in components["interaction_terms"])
    assert interaction_sum == pytest.approx(breakdown.interaction_risk)
    assert all("pair" in t and "coefficient" in t for t in components["interaction_terms"])


# --------------------------------------------------------------------------- #
# 6. Organization isolation (service level)
# --------------------------------------------------------------------------- #
def test_cross_organization_asset_references_are_rejected_fail_closed(db_session):
    org_a = seed_org_for_user(db_session, "user-a", org_name="Company A")
    org_b = seed_org_for_user(db_session, "user-b", org_name="Company B")
    # The asset lives in Company B with criticality 5 (SYNTHETIC).
    _register_asset(db_session, org_b, "bob@company-b.example", 5)

    # A finding row written by tenant B, fed into tenant A's resolution:
    # the reference is rejected because the FINDING is not in this org.
    foreign_finding = [
        ev("BREACH_EXPOSURE", asset_id="bob@company-b.example",
           org_id=org_b, user_id="user-b", event_id="evt_xorg_1")
    ]
    value, context = pipeline.resolve_org_criticality(db_session, org_a, foreign_finding)
    assert value is None, "another tenant's finding must never contribute"
    assert context["asset_criticalities"] == {}
    assert context["unresolved_assets"] == [
        {"asset_id": "bob@company-b.example",
         "reason": "finding_not_in_this_organization"}
    ]

    # A finding genuinely owned by org A, but naming an asset only B registered:
    # resolution is org-scoped, so B's criticality-5 row is invisible here.
    own_finding_foreign_asset = [
        ev("BREACH_EXPOSURE", asset_id="bob@company-b.example",
           org_id=org_a, user_id="user-a", event_id="evt_xorg_2")
    ]
    value, context = pipeline.resolve_org_criticality(
        db_session, org_a, own_finding_foreign_asset
    )
    assert value is None, "a cross-tenant asset id must resolve to nothing"
    assert context["asset_criticalities"] == {}
    assert context["criticality_status"] == "UNRESOLVED"
    assert context["unresolved_assets"] == [
        {"asset_id": "bob@company-b.example",
         "reason": "not_a_registered_asset_in_this_organization"}
    ]


def test_criticality_resolution_takes_the_most_important_affected_asset(db_session):
    org_id = seed_org_for_user(db_session, "user-1")
    _register_asset(db_session, org_id, "low@company.example", 1)
    _register_asset(db_session, org_id, "critical@company.example", 5)
    events = [
        ev("BREACH_EXPOSURE", asset_id="low@company.example", org_id=org_id,
           event_id="evt_low"),
        ev("MFA_MISSING", asset_id="critical@company.example", org_id=org_id,
           event_id="evt_crit"),
    ]
    value, context = pipeline.resolve_org_criticality(db_session, org_id, events)
    assert value == 5
    assert context["criticality_status"] == "REGISTERED"
    assert context["asset_ids"] == ["critical@company.example", "low@company.example"]
    assert context["asset_criticalities"] == {"critical@company.example": 5,
                                              "low@company.example": 1}
    assert context["primary_asset_id"] == "critical@company.example"


def test_unbound_findings_resolve_to_no_criticality_with_an_explicit_status(db_session):
    org_id = seed_org_for_user(db_session, "user-1")
    events = [ev("BREACH_EXPOSURE", asset_id=None, org_id=org_id, event_id="evt_unbound")]
    value, context = pipeline.resolve_org_criticality(db_session, org_id, events)
    assert value is None
    assert context["criticality_status"] == "UNBOUND"


def test_resolution_without_an_organization_reads_nothing(db_session):
    events = [ev("BREACH_EXPOSURE", asset_id="someone@example.com", event_id="evt_noorg")]
    value, context = pipeline.resolve_org_criticality(db_session, None, events)
    assert value is None
    assert context["criticality_status"] == "NO_ORGANIZATION"
    assert context["asset_criticalities"] == {}


# --------------------------------------------------------------------------- #
# 7. Pipeline integration: one context for risk, attribution, planner, storage
# --------------------------------------------------------------------------- #
def _seed_bound_findings(db, user_id: str, org_id: str, asset_id: str,
                         severity: float = 0.7) -> None:
    """SYNTHETIC: register the asset, then persist findings bound to it."""
    _register_asset(db, org_id, asset_id, criticality=4)
    normalizer.persist_events(db, [
        ev("BREACH_EXPOSURE", account_id=asset_id, severity=severity,
           event_id=f"evt_{user_id}_breach", user_id=user_id),
        ev("MFA_MISSING", account_id=asset_id, severity=0.6,
           event_id=f"evt_{user_id}_mfa", user_id=user_id),
    ])


def test_run_analysis_stamps_one_criticality_context_on_every_consumer(db_session):
    user_id = "user-1"
    org_id = seed_org_for_user(db_session, user_id)
    _seed_bound_findings(db_session, user_id, org_id, "alice@company.example")

    result = pipeline.run_analysis(db_session, user_id, persist=False)
    features = result["features"]

    # One authoritative score, explained by the same context everywhere.
    assert result["criticality"] == 4
    assert result["risk"].score == pytest.approx(expected_score(features, 4))
    assert result["attribution"]["total_risk"] == pytest.approx(result["risk"].score)
    assert result["attribution"]["efficiency_error"] < 1e-6
    assert result["planner"]["initial_risk"] == pytest.approx(result["risk"].score)

    components = result["risk"].components
    assert components["org_id"] == org_id
    assert components["primary_asset_id"] == "alice@company.example"
    assert components["asset_criticalities"] == {"alice@company.example": 4}
    # The honest boundary: grouped-link results are consumed by NOTHING here.
    assert components["correlations_consumed"]["ids"] == []
    assert "never feed the score" in components["correlations_consumed"]["note"]


def test_a_declared_dependency_edge_changes_correlations_but_never_the_score(db_session):
    user_id = "user-1"
    org_id = seed_org_for_user(db_session, user_id)
    _register_asset(db_session, org_id, "alice@company.example", 4)
    _register_asset(db_session, org_id, "github.com/acme/api", 4)
    normalizer.persist_events(db_session, [
        ev("BREACH_EXPOSURE", account_id="alice@company.example", severity=0.7,
           event_id="evt_edge_1", user_id=user_id),
        ev("MFA_MISSING", account_id="github.com/acme/api", severity=0.6,
           event_id="evt_edge_2", user_id=user_id),
    ])

    before = pipeline.run_analysis(db_session, user_id, persist=False)
    db_session.add(AssetDependency(
        org_id=org_id, from_asset_id="alice@company.example",
        to_asset_id="github.com/acme/api", relationship_type="RESETS_PASSWORD",
        edge_source="ADMIN_DECLARED",
    ))
    db_session.commit()
    after = pipeline.run_analysis(db_session, user_id, persist=False)

    # The declared edge may create a link result...
    before_rules = {c.rule_id for c in before["correlations"]}
    after_rules = {c.rule_id for c in after["correlations"]}
    assert after_rules >= before_rules
    # ...but the score is identical: the formula does not consume edges.
    assert after["risk"].score == before["risk"].score
    assert after["risk"].score == pytest.approx(expected_score(after["features"], 4))


def test_risk_snapshots_are_org_scoped_and_keep_their_model_version(db_session):
    # Two tenants, two runs, one deliberately historical (risk-1.0) row.
    for user_id, org_name, asset in (
        ("user-a", "Company A", "alice@company-a.example"),
        ("user-b", "Company B", "bob@company-b.example"),
    ):
        org_id = seed_org_for_user(db_session, user_id, org_name=org_name)
        _seed_bound_findings(db_session, user_id, org_id, asset)

    # A snapshot from the pre-Phase-4 formula (historical record).
    legacy = RiskResult(
        user_id="user-a", org_id=None, run_id="legacy_run",
        model_version="risk-1.0", score=61.7, band="HIGH", confidence="high",
        range_low=60.0, range_high=63.0, base_risk=48.5, interaction_risk=13.2,
        criticality_adjustment=0.0, mitigation_credit=0.0,
        components={"note": "computed before the criticality term existed"},
    )
    db_session.add(legacy)
    db_session.commit()

    pipeline.run_analysis(db_session, "user-a", persist=True)
    pipeline.run_analysis(db_session, "user-b", persist=True)

    rows_a = db_session.scalars(
        select(RiskResult).where(RiskResult.user_id == "user-a")
    ).all()
    rows_b = db_session.scalars(
        select(RiskResult).where(RiskResult.user_id == "user-b")
    ).all()

    fresh_a = [r for r in rows_a if r.model_version == DOC_MODEL_VERSION]
    fresh_b = [r for r in rows_b if r.model_version == DOC_MODEL_VERSION]
    assert fresh_a and fresh_b
    org_a = fresh_a[0].org_id
    org_b = fresh_b[0].org_id
    assert org_a and org_b and org_a != org_b
    assert {r.org_id for r in rows_b} == {org_b}, "tenant B may not see tenant A's rows"
    assert fresh_a[0].asset_id == "alice@company-a.example"
    assert fresh_a[0].criticality_adjustment != 0.0
    assert fresh_a[0].components["org_id"] == org_a

    # The historical row is byte-for-byte untouched: snapshots are inserted,
    # never re-scored when the model changes.
    db_session.refresh(legacy)
    assert legacy.model_version == "risk-1.0"
    assert legacy.score == 61.7
    assert legacy.criticality_adjustment == 0.0
    assert legacy.components == {"note": "computed before the criticality term existed"}
    assert legacy.org_id is None, "the backfill runs in the migration, not at runtime"


# --------------------------------------------------------------------------- #
# 8. API contract (server is the only authority)
# --------------------------------------------------------------------------- #
@pytest.fixture()
def analysis_setup(client, db_session):
    """SYNTHETIC org + admin + level-4 asset + two bound findings, via the API
    registration path and the server-side normalizer."""
    headers = register_org_admin(client, org_name="Acme Context Co")
    from app.models import Membership

    membership = db_session.scalar(
        select(Membership).where(Membership.is_active.is_(True))
    )
    org_id, user_id = membership.org_id, membership.user_id
    _register_asset(db_session, org_id, "alice@company.example", 4)
    normalizer.persist_events(db_session, [
        ev("BREACH_EXPOSURE", account_id="alice@company.example", severity=0.7,
           event_id="evt_api_breach", user_id=user_id),
        ev("MFA_MISSING", account_id="alice@company.example", severity=0.6,
           event_id="evt_api_mfa", user_id=user_id),
    ])
    return headers, org_id, user_id


def test_analysis_api_exposes_the_traceable_risk_contract(client, analysis_setup):
    headers, org_id, _user_id = analysis_setup
    response = client.post("/api/analysis/run", json={}, headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    risk_block = body["risk"]

    # Contract fields the frontend (RiskPage/OverviewPage) consumes.
    assert risk_block["model_version"] == DOC_MODEL_VERSION
    assert risk_block["criticality"] == 4
    components = risk_block["components"]
    for key in ("features", "finding_ids", "interaction_terms", "uncertainty",
                "unavailable_inputs", "criticality_status", "asset_ids",
                "asset_criticalities", "primary_asset_id", "org_id",
                "correlations_consumed", "criticality_multiplier"):
        assert key in components, key
    assert components["org_id"] == org_id
    assert components["criticality_status"] == "REGISTERED"

    # The score itself is derived, not asserted from a recorded number.
    expected = expected_score(body["features"], criticality=4)
    assert risk_block["score"] == pytest.approx(expected)
    assert risk_block["criticality_adjustment"] == pytest.approx(
        expected_adjustment(body["features"], 4)
    )
    composition = (
        risk_block["base_risk"] + risk_block["interaction_risk"]
        + risk_block["criticality_adjustment"] - risk_block["mitigation_credit"]
    )
    assert composition == pytest.approx(risk_block["score"])
    assert risk_block["range_low"] <= risk_block["score"] <= risk_block["range_high"]

    # Attribution explains THIS score; the planner optimizes THIS score.
    assert body["attribution"]["total_risk"] == pytest.approx(risk_block["score"])
    assert body["attribution"]["efficiency_error"] < 1e-6
    assert body["planner"]["initial_risk"] == pytest.approx(risk_block["score"])
    # A group rule fired over the two same-asset findings — and consumed nothing.
    assert any(c["rule_id"] == "company_asset_compound_exposure"
               for c in body["correlations"])
    assert components["correlations_consumed"]["ids"] == []


def test_client_supplied_risk_inputs_are_ignored(client, analysis_setup):
    headers, _org_id, _user_id = analysis_setup
    # A client trying to dictate criticality/score: the server never reads it.
    response = client.post(
        "/api/analysis/run",
        json={"criticality": 1, "score": 0.0, "org_id": "org_someone_else"},
        headers=headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["risk"]["criticality"] == 4  # still the registered asset's level
    assert body["risk"]["score"] == pytest.approx(
        expected_score(body["features"], criticality=4)
    )


def test_what_if_keeps_the_same_criticality_context(client, analysis_setup):
    headers, _org_id, _user_id = analysis_setup
    # Derive the expected "after" from the documented formula + the documented
    # toggle semantics (strengthen_mfa: no_mfa → 0, mfa → 1) — NOT from output.
    base_features = dict(
        client.get("/api/analysis/summary", headers=headers).json()["features"]
    )
    modified_features = dict(base_features)
    modified_features["no_mfa"] = 0.0
    modified_features["mfa"] = 1.0

    response = client.post(
        "/api/analysis/what-if",
        json={"toggles": [{"action_key": "strengthen_mfa", "enabled": True}]},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["criticality"] == 4
    after = body["after"]
    # The toggle changes the controls the company can change — never which
    # asset the run is about, and never by how much importance scales it.
    assert after["criticality_adjustment"] == pytest.approx(
        expected_adjustment(modified_features, 4)
    )
    assert after["score"] == pytest.approx(expected_score(modified_features, 4))
    # Strengthening MFA must actually lower the authoritative score.
    assert after["score"] < expected_score(base_features, 4)


def test_risk_snapshots_endpoint_exposure_is_none_yet_and_org_owned(client, db_session):
    """Stored snapshots are not served by any endpoint yet; when read they are
    filtered by org — this pins the column contract the readers will use."""
    headers = register_org_admin(client, org_name="Snapshot Co")
    from app.models import Membership

    membership = db_session.scalar(
        select(Membership).where(Membership.is_active.is_(True))
    )
    _register_asset(db_session, membership.org_id, "alice@company.example", 4)
    normalizer.persist_events(db_session, [
        ev("BREACH_EXPOSURE", account_id="alice@company.example", severity=0.7,
           event_id="evt_snap", user_id=membership.user_id),
    ])
    assert client.post("/api/analysis/run", json={}, headers=headers).status_code == 200

    rows = db_session.scalars(
        select(RiskResult).where(RiskResult.org_id == membership.org_id)
    ).all()
    assert rows, "the snapshot must be queryable inside its organization"
    # No route in the app returns raw risk_results rows (checked explicitly).
    from app.main import app as main_app

    exposed = [
        route.path for route in main_app.routes
        if "risk" in getattr(route, "path", "").lower()
    ]
    assert exposed == [], f"unexpected raw snapshot route(s): {exposed}"


# --------------------------------------------------------------------------- #
# 9. Modified-behavior checks (regressions around the change)
# --------------------------------------------------------------------------- #
def test_sensitivity_range_brackets_the_point_estimate_under_criticality():
    features = _features(breach=0.6, reuse=0.5, no_mfa=0.6)
    for c in (None, 1, 5):
        score, _ = risk.risk_from_features(features, criticality=c)
        low, high = risk.sensitivity_range(features, criticality=c)
        assert low <= score <= high
        # The multiplier is an input held fixed: the range scales with it too.
        low_plain, high_plain = risk.sensitivity_range(features)
        if c == 5:
            assert low >= low_plain  # 1.2 × a positive plain range


def test_compute_risk_without_criticality_keeps_the_pre_phase4_behavior():
    # The default call path (no context) must equal the documented formula with
    # m = 1 — i.e. the historical scores are reproducible.
    events = [ev("BREACH_EXPOSURE", severity=0.7), ev("PASSWORD_REUSE", severity=0.6)]
    breakdown = risk.compute_risk(events)
    assert breakdown.score == pytest.approx(expected_score(breakdown.components["features"]))
    assert breakdown.criticality_adjustment == 0.0
    assert breakdown.components["model_version"] == DOC_MODEL_VERSION
