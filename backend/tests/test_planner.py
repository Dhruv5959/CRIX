"""Remediation planner tests: greedy vs. exact, measured gap, greedy trap (§9)."""
from __future__ import annotations

from app.engine import planner, risk


def _features(**overrides):
    base = {name: 0.0 for name in risk.ALL_FEATURES}
    base.update(overrides)
    return base


def test_two_methods_only():
    comparison = planner.compare(_features(breach=0.6, reuse=0.5), budget=6.0)
    assert set(comparison.keys()) >= {"greedy", "exact", "optimality_gap", "is_greedy_trap"}
    assert comparison["greedy"]["method"] == "greedy"
    assert comparison["exact"]["method"] == "exact"


def test_exact_is_at_least_as_good_as_greedy():
    features = _features(breach=0.8, reuse=0.8, no_mfa=0.8, session=0.7, sim_swap=0.6)
    comparison = planner.compare(features, budget=6.0)
    assert comparison["exact"]["risk_after"] <= comparison["greedy"]["risk_after"] + 1e-6


def test_gap_is_measured_relative_to_exact_improvement():
    features = _features(breach=0.8, reuse=0.8, no_mfa=0.8)
    comparison = planner.compare(features, budget=6.0)
    assert 0.0 <= comparison["optimality_gap"] <= 1.0


def test_greedy_trap_scenario_exists():
    """A deliberately constructed scenario where greedy does strictly worse than
    exact, demonstrating greedy's weakness concretely.

    Construction: with only 2 units of budget and two affordable actions
    (change_reused_password effort 1, strengthen_mfa effort 2), greedy takes the
    cheap password change first and cannot then afford strengthen_mfa; exact sees
    that strengthen_mfa alone removes the breach+no_mfa interaction and does
    strictly better.
    """
    features = _features(breach=0.8, reuse=0.8, no_mfa=0.8)
    comparison = planner.compare(
        features,
        budget=2.0,
        candidate_actions=["change_reused_password", "strengthen_mfa"],
    )
    assert comparison["is_greedy_trap"] is True
    assert comparison["exact"]["risk_after"] < comparison["greedy"]["risk_after"]
    assert comparison["optimality_gap"] > 0


def test_greedy_is_never_labelled_optimal():
    comparison = planner.compare(_features(breach=0.5, reuse=0.5), budget=6.0)
    # There is no "optimal" field anywhere in the greedy result.
    assert "optimal" not in comparison["greedy"]
    assert comparison["greedy"]["method"] != "optimal"


def test_exact_matches_brute_force():
    """Regression: exact must never be beaten by exhaustive enumeration.

    (A prior branch-and-bound bug used a bound derived from the original feature
    vector instead of the current state, which pruned the true optimum.)
    """
    import itertools
    import random

    rng = random.Random(2024)
    actions = list(planner.ACTIONS)
    for _ in range(200):
        features = {name: round(rng.random(), 2) for name in risk.ALL_FEATURES}
        for name in risk.RISK_FEATURES:
            if rng.random() < 0.5:
                features[name] = 0.0
        budget = rng.choice([2, 3, 4, 5, 6, 8])
        exact = planner.exact_plan(features, budget=budget, candidate_actions=actions)
        best = min(
            planner._risk(planner.apply_actions(features, list(combo)))
            for r in range(len(actions) + 1)
            for combo in itertools.combinations(actions, r)
            if sum(planner.ACTIONS[a].effort for a in combo) <= budget + 1e-9
        )
        assert abs(exact["risk_after"] - best) < 1e-6, (features, budget)


def test_greedy_never_beats_exact():
    import random

    rng = random.Random(55)
    for _ in range(200):
        features = {name: round(rng.random(), 2) for name in risk.ALL_FEATURES}
        comparison = planner.compare(features, budget=rng.choice([2, 3, 4, 5, 6]))
        assert comparison["greedy"]["risk_after"] >= comparison["exact"]["risk_after"] - 1e-6


def test_budget_is_respected():
    features = _features(breach=0.8, reuse=0.8, no_mfa=0.8, sim_swap=0.7)
    comparison = planner.compare(features, budget=3.0)
    assert comparison["greedy"]["total_effort"] <= 3.0 + 1e-9
    assert comparison["exact"]["total_effort"] <= 3.0 + 1e-9


def test_actions_are_pure():
    base = _features(reuse=0.8)
    _ = planner.apply_action(base, "change_reused_password")
    assert base["reuse"] == 0.8  # original untouched


def test_passkey_action_also_removes_sim_swap():
    result = planner.apply_action(_features(no_mfa=0.8, sim_swap=0.7), "enable_passkey")
    assert result["passkey"] == 1.0
    assert result["no_mfa"] == 0.0
    assert result["sim_swap"] == 0.0