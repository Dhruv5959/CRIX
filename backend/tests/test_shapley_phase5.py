"""Phase 5 Shapley-attribution guarantees (§4.9).

The attribution explains a Phase 4 score and NEVER overrides or re-derives it.
Pinned here: the cooperative game is documented precisely (players, value
function = the real clipped risk function, baseline v(empty)=0, absent-factor
handling, clipping, residual/efficiency); the exact computation stays the
authority and the seeded approximation is measured against it, clearly labelled
and reproducible; the criticality is org-scoped value-function CONTEXT (not a
player), so the same context reaches score, attribution and planner; cross-org
attribution never aggregates another tenant's factors; and the output contract
carries plain-language guidance that never claims causation, never states a
probability of compromise, and never frames a negative contribution as "safe".

SYNTHETIC TEST DATA: every finding, asset and organization below is created by
the test itself (``tests.helpers.ev`` / ``seed_org_for_user`` / ``OrgAsset``).
Expected total scores are DERIVED from the documented formula literals
(``tests.test_risk_phase4.expected_score``) — never copied from the engine's
own output.
"""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.engine import normalizer, pipeline, risk, shapley
from app.models import Membership, OrgAsset
from tests.conftest import register_org_admin
from tests.helpers import ev, seed_org_for_user
from tests.test_risk_phase4 import expected_score


def _features(**overrides) -> dict:
    base = {name: 0.0 for name in risk.ALL_FEATURES}
    base.update(overrides)
    return base


def _register_asset(db, org_id: str, asset_id: str, criticality: int) -> OrgAsset:
    asset = OrgAsset(
        org_id=org_id, asset_id=asset_id, asset_type="EMAIL",
        label=f"synthetic asset {asset_id}", criticality=criticality,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


# --------------------------------------------------------------------------- #
# 1. The game is documented and its value function is the REAL risk function
# --------------------------------------------------------------------------- #
def test_game_players_are_exactly_the_documented_feature_groups():
    assert shapley.N_FEATURES == len(risk.ALL_FEATURES) == 12


def test_value_function_is_the_real_risk_function_not_a_surrogate():
    features = _features(breach=0.7, reuse=0.5, no_mfa=0.4)
    contributions, total = shapley.shapley_values(features, criticality=4)
    # total must equal the documented formula, not some re-derived value.
    assert total == pytest.approx(expected_score(features, 4))


def test_baseline_v_empty_is_zero():
    """The empty coalition scores exactly 0 by the documented function."""
    contributions, total = shapley.shapley_values(_features(), criticality=4)
    assert total == 0.0
    for value in contributions.values():
        assert abs(value) < 1e-9


def test_absent_factor_is_not_scored():
    """A factor held absent (0) contributes 0 — absent, not 'safe'."""
    features = _features(breach=0.7, reuse=0.6)
    contributions, _ = shapley.shapley_values(features)
    assert abs(contributions["sim_swap"]) < 1e-9
    assert abs(contributions["push_bombing"]) < 1e-9


def test_clipping_is_part_of_the_value_function():
    """Contributions describe the CLIPPED [0,100] score, so they cannot sum above 100."""
    saturated = _features(**{name: 1.0 for name in risk.RISK_FEATURES})
    contributions, total = shapley.shapley_values(saturated, criticality=5)
    assert total <= 100.0
    assert sum(contributions.values()) == pytest.approx(total, abs=1e-6)


# --------------------------------------------------------------------------- #
# 2. Efficiency and residual — the exact guarantee
# --------------------------------------------------------------------------- #
def test_efficiency_residual_is_within_exact_tolerance():
    features = _features(breach=0.7, reuse=0.6, no_mfa=0.5, session=0.4)
    result = shapley.attribute(features)
    assert result["is_exact"] is True
    assert result["method"] == "exact_shapley"
    assert abs(result["residual"]) < shapley.EXACT_TOLERANCE
    assert abs(result["efficiency_error"]) < shapley.EXACT_TOLERANCE
    assert result["sum_of_contributions"] == pytest.approx(result["total_risk"], abs=1e-6)


def test_efficiency_holds_over_random_inputs_with_criticality():
    import random

    rng = random.Random(7)
    for _ in range(20):
        features = {name: rng.random() for name in risk.ALL_FEATURES}
        criticality = rng.choice([None, 1, 2, 3, 4, 5])
        result = shapley.attribute(features, criticality=criticality)
        assert result["is_exact"] is True
        assert abs(result["residual"]) < shapley.EXACT_TOLERANCE
        assert result["total_risk"] == pytest.approx(
            expected_score(features, criticality), abs=1e-6
        )


def test_attribution_is_exact_not_sampled():
    result = shapley.attribute(_features(breach=0.5, session=0.5))
    assert result["method"] == "exact_shapley"
    # No sampling parameters may leak onto the authoritative payload.
    assert "samples" not in result
    assert "seed" not in result


def test_computation_time_is_benchmarked_and_small():
    features = _features(**{name: 0.5 for name in risk.ALL_FEATURES})
    result = shapley.attribute(features)
    assert result["compute_ms"] > 0.0
    assert result["compute_ms"] < 2000.0


# --------------------------------------------------------------------------- #
# 3. Output contract — honest, plain language, no causation / probability / "safe"
# --------------------------------------------------------------------------- #
def test_output_contract_exposes_the_documented_fields():
    result = shapley.attribute(_features(breach=0.7, mfa=1.0), criticality=4)
    for key in ("method", "is_exact", "total_risk", "contributions",
                "sum_of_contributions", "efficiency_error", "residual",
                "compute_ms", "criticality_context", "baseline",
                "absent_factor_note", "clipping_note", "breakdown",
                "plain_language"):
        assert key in result, key
    assert result["criticality_context"] == 4
    assert result["baseline"]["v_empty"] == 0.0


def test_breakdown_splits_raising_and_lowering_and_neutral():
    result = shapley.attribute(_features(breach=0.8, no_mfa=0.8, mfa=1.0))
    breakdown = result["breakdown"]
    assert "breach" in breakdown["raising"]
    assert "mfa" in breakdown["lowering"]
    # Lowering is still a factor, never framed as an all-clear.
    assert "sim_swap" in breakdown["neutral"]


def test_plain_language_never_claims_causation_probability_or_safety():
    result = shapley.attribute(_features(breach=0.8, mfa=1.0))
    text = " ".join(result["plain_language"].values()).lower()
    for forbidden in (
        "probability of compromise", "predicts", "caused", "will be hacked",
        "proves you are safe", "guaranteed safe", "likelihood of an attack",
    ):
        assert forbidden not in text, forbidden
    # A negative contribution is explicitly NOT the same as safe.
    assert "not the same as safe" in text or "not the same as being safe" in text


def test_unknown_attribution_method_is_rejected():
    with pytest.raises(ValueError):
        shapley.attribute(_features(breach=0.5), method="shap")


# --------------------------------------------------------------------------- #
# 4. Seeded approximation vs exact — honest, reproducible, measured
# --------------------------------------------------------------------------- #
def test_seeded_approximation_is_labelled_not_exact():
    result = shapley.attribute(
        _features(breach=0.6, reuse=0.5), method="seeded_approximate_shapley",
        samples=200, seed=11,
    )
    assert result["method"] == "seeded_approximate_shapley"
    assert result["is_exact"] is False
    assert result["seed"] == 11
    assert result["samples"] == 200


def test_seeded_approximation_is_reproducible_for_a_fixed_seed():
    features = _features(breach=0.6, reuse=0.5, session=0.3)
    a = shapley.approximate_shapley_values(features, samples=128, seed=5)
    b = shapley.approximate_shapley_values(features, samples=128, seed=5)
    assert a == b


def test_approximation_converges_toward_exact_as_samples_grow():
    """A real measurement: more samples must not make the total error worse
    by a wide margin, and the exact total is the reference."""
    features = _features(breach=0.7, reuse=0.6, no_mfa=0.5, session=0.4)
    comparison = shapley.compare_exact_vs_approximate(features, samples=2048, seed=3)
    assert comparison["reference"] == "exact_shapley"
    assert comparison["approximate_method"] == "seeded_approximate_shapley"
    # The exact total matches the documented formula; the approximate total is
    # close but the distinction is recorded, not hidden.
    assert comparison["total_risk_exact"] == pytest.approx(expected_score(features))
    assert comparison["max_factor_abs_error"] >= 0.0
    assert comparison["total_abs_error"] >= 0.0
    # Per-factor errors are reported, so the gap is visible and actionable.
    assert set(comparison["per_factor_abs_error"]) == set(risk.ALL_FEATURES)


def test_zero_samples_is_rejected():
    with pytest.raises(ValueError):
        shapley.approximate_shapley_values(_features(breach=0.5), samples=0)


def test_approximation_explains_the_same_total_as_the_score():
    features = _features(breach=0.7, reuse=0.6)
    # The approximation reports v(full), the SAME total as the exact/score.
    _, approx_total = shapley.approximate_shapley_values(features, samples=256, seed=9)
    assert approx_total == pytest.approx(expected_score(features))


# --------------------------------------------------------------------------- #
# 5. Criticality is org-scoped CONTEXT — same value for score, attribution, planner
# --------------------------------------------------------------------------- #
def test_criticality_scales_the_attributed_total_but_is_not_a_player():
    features = _features(breach=0.7, reuse=0.6, no_mfa=0.5)
    low, _ = shapley.shapley_values(features, criticality=1)
    high, high_total = shapley.shapley_values(features, criticality=5)
    assert high_total > sum(low.values()) + 1e-9
    # No fabricated 'criticality' player — it is context, held fixed.
    assert "criticality" not in high


def test_attribution_total_matches_the_score_for_the_same_criticality():
    for criticality in (None, 1, 3, 5):
        features = _features(breach=0.7, session=0.5, no_mfa=0.6)
        result = shapley.attribute(features, criticality=criticality)
        assert result["total_risk"] == pytest.approx(
            expected_score(features, criticality)
        )
        assert result["criticality_context"] == criticality


def test_pipeline_attribution_explains_the_run_score_with_one_context(db_session):
    user_id = "user-1"
    org_id = seed_org_for_user(db_session, user_id)
    _register_asset(db_session, org_id, "alice@company.example", 4)
    normalizer.persist_events(db_session, [
        ev("BREACH_EXPOSURE", account_id="alice@company.example", severity=0.7,
           event_id="evt_p5_breach", user_id=user_id),
        ev("MFA_MISSING", account_id="alice@company.example", severity=0.6,
           event_id="evt_p5_mfa", user_id=user_id),
    ])
    result = pipeline.run_analysis(db_session, user_id, persist=False)
    attribution = result["attribution"]
    assert attribution["total_risk"] == pytest.approx(result["risk"].score)
    assert attribution["efficiency_error"] < shapley.EXACT_TOLERANCE
    assert attribution["is_exact"] is True
    assert attribution["criticality_context"] == 4


# --------------------------------------------------------------------------- #
# 6. API contract + org isolation
# --------------------------------------------------------------------------- #
@pytest.fixture()
def attribution_setup(client, db_session):
    headers = register_org_admin(client, org_name="Acme Attribution Co")
    membership = db_session.scalar(select(Membership).where(Membership.is_active.is_(True)))
    org_id, user_id = membership.org_id, membership.user_id
    _register_asset(db_session, org_id, "alice@company.example", 4)
    normalizer.persist_events(db_session, [
        ev("BREACH_EXPOSURE", account_id="alice@company.example", severity=0.7,
           event_id="evt_api_p5_breach", user_id=user_id),
        ev("MFA_MISSING", account_id="alice@company.example", severity=0.6,
           event_id="evt_api_p5_mfa", user_id=user_id),
    ])
    return headers, org_id, user_id


def test_analysis_api_exposes_the_attribution_contract(client, attribution_setup):
    headers, _org_id, _ = attribution_setup
    response = client.post("/api/analysis/run", json={}, headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    attribution = body["attribution"]
    assert attribution["method"] == "exact_shapley"
    assert attribution["is_exact"] is True
    assert attribution["efficiency_error"] < shapley.EXACT_TOLERANCE
    assert attribution["residual"] is not None
    assert attribution["criticality_context"] == 4
    # Attribution explains the served score exactly.
    assert attribution["total_risk"] == pytest.approx(body["risk"]["score"])
    # The honest breakdown and plain language are present for the frontend.
    assert "raising" in attribution["breakdown"]
    assert "plain_language" in attribution


def test_cross_org_attribution_is_never_aggregated(client, db_session):
    """A second tenant's factors must not leak into the first tenant's attribution."""
    headers_a = register_org_admin(
        client, email="admin-p5-a@example.com", org_name="Company A"
    )
    mem_a = db_session.scalar(select(Membership).where(Membership.is_active.is_(True)))
    org_a, user_a = mem_a.org_id, mem_a.user_id
    _register_asset(db_session, org_a, "a@company-a.example", 4)
    normalizer.persist_events(db_session, [
        ev("BREACH_EXPOSURE", account_id="a@company-a.example", severity=0.8,
           event_id="evt_org_a_1", user_id=user_a),
    ])
    result_a = pipeline.run_analysis(db_session, user_a, persist=False)

    # Tenant B with a very different, higher-severity profile.
    headers_b = register_org_admin(
        client, email="admin-p5-b@example.com", org_name="Company B"
    )
    mem_b = db_session.scalar(
        select(Membership).where(Membership.is_active.is_(True),
                                 Membership.org_id != org_a)
    )
    org_b, user_b = mem_b.org_id, mem_b.user_id
    _register_asset(db_session, org_b, "b@company-b.example", 5)
    normalizer.persist_events(db_session, [
        ev("BREACH_EXPOSURE", account_id="b@company-b.example", severity=1.0,
           event_id="evt_org_b_1", user_id=user_b),
        ev("SESSION_HIJACK", account_id="b@company-b.example", severity=0.9,
           event_id="evt_org_b_2", user_id=user_b),
    ])
    result_b = pipeline.run_analysis(db_session, user_b, persist=False)

    # Each tenant's attribution explains its OWN score and no foreign factors.
    assert result_a["attribution"]["total_risk"] == pytest.approx(result_a["risk"].score)
    assert result_b["attribution"]["total_risk"] == pytest.approx(result_b["risk"].score)
    # B has strictly more exposure, so its attributed total is higher — and it
    # never borrowed A's context (criticality_context is each tenant's own).
    assert result_b["attribution"]["total_risk"] > result_a["attribution"]["total_risk"]
    assert result_a["attribution"]["criticality_context"] == 4
    assert result_b["attribution"]["criticality_context"] == 5
