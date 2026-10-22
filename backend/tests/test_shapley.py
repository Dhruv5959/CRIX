"""Exact Shapley attribution tests: efficiency, null players, timing (§7)."""
from __future__ import annotations

import time

from app.engine import risk, shapley


def _features(**overrides):
    base = {name: 0.0 for name in risk.ALL_FEATURES}
    base.update(overrides)
    return base


def test_efficiency_property():
    """Contributions must sum to the total risk within numerical tolerance."""
    features = _features(breach=0.7, reuse=0.6, no_mfa=0.5, session=0.4)
    result = shapley.attribute(features)
    assert abs(result["efficiency_error"]) < 1e-6
    assert abs(result["sum_of_contributions"] - result["total_risk"]) < 1e-6


def test_efficiency_over_random_inputs():
    import random

    rng = random.Random(7)
    for _ in range(25):
        features = {name: rng.random() for name in risk.ALL_FEATURES}
        result = shapley.attribute(features)
        assert abs(result["efficiency_error"]) < 1e-6, features


def test_null_player_gets_zero():
    # A feature that is zero and never interacts should contribute ~0.
    features = _features(breach=0.7)
    contributions, _ = shapley.shapley_values(features)
    assert abs(contributions["sim_swap"]) < 1e-9
    assert abs(contributions["push_bombing"]) < 1e-9


def test_interaction_creates_positive_contributions_on_both_parties():
    features = _features(breach=0.8, reuse=0.8)
    contributions, _ = shapley.shapley_values(features)
    # Both interacting players share the interaction surplus positively.
    assert contributions["breach"] > 0
    assert contributions["reuse"] > 0


def test_attribution_is_exact_not_sampled():
    result = shapley.attribute(_features(breach=0.5, session=0.5))
    assert result["method"] == "exact_shapley"


def test_computation_time_is_benchmarked_and_small():
    """Exact enumeration over 12 features must complete quickly (real benchmark)."""
    features = _features(**{name: 0.5 for name in risk.ALL_FEATURES})
    result = shapley.attribute(features)
    # Generous ceiling: exact 2^12 enumeration should be well under 2 seconds.
    assert result["compute_ms"] < 2000.0
    assert result["compute_ms"] > 0.0


def test_mitigation_features_get_negative_contributions():
    features = _features(breach=0.8, no_mfa=0.8, mfa=1.0)
    contributions, _ = shapley.shapley_values(features)
    # Enabling MFA lowers risk, so its Shapley contribution should be negative.
    assert contributions["mfa"] < 0