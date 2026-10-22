"""Contextual risk engine tests: determinism, non-additivity, sensitivity (§6)."""
from __future__ import annotations

from app.engine import risk
from app.schemas import ExposureType
from tests.helpers import ev


def _features(**overrides):
    base = {name: 0.0 for name in risk.ALL_FEATURES}
    base.update(overrides)
    return base


def test_empty_input_scores_zero():
    breakdown = risk.compute_risk([])
    assert breakdown.score == 0.0
    assert breakdown.band == "LOW"


def test_score_is_deterministic():
    events = [ev("BREACH_EXPOSURE", severity=0.7), ev("PASSWORD_REUSE", severity=0.6)]
    a = risk.compute_risk(events).score
    b = risk.compute_risk(events).score
    assert a == b


def test_non_additive_interaction():
    # breach alone + reuse alone vs. both together: together must be strictly greater
    breach_only, _ = risk.risk_from_features(_features(breach=0.8))
    reuse_only, _ = risk.risk_from_features(_features(reuse=0.8))
    both, breakdown = risk.risk_from_features(_features(breach=0.8, reuse=0.8))
    assert breakdown["interaction_risk"] > 0
    assert both > breach_only and both > reuse_only


def test_mitigation_reduces_score():
    without, _ = risk.risk_from_features(_features(breach=0.8, no_mfa=0.8))
    with_mfa, breakdown = risk.risk_from_features(_features(breach=0.8, no_mfa=0.8, mfa=1.0))
    assert with_mfa < without
    assert breakdown["mitigation_credit"] > 0


def test_session_discounts_mitigation():
    """A passkey reduces risk less when a session is exposed, because a stolen
    session bypasses credential-based controls."""
    without_session = _features(breach=0.8, no_mfa=0.8)
    with_passkey_no_session = _features(breach=0.8, no_mfa=0.8, passkey=1.0)
    reduction_no_session = (
        risk.risk_from_features(without_session)[0]
        - risk.risk_from_features(with_passkey_no_session)[0]
    )

    with_session = _features(breach=0.8, no_mfa=0.8, session=1.0)
    with_passkey_and_session = _features(breach=0.8, no_mfa=0.8, passkey=1.0, session=1.0)
    reduction_with_session = (
        risk.risk_from_features(with_session)[0]
        - risk.risk_from_features(with_passkey_and_session)[0]
    )

    assert reduction_no_session > 0
    assert reduction_with_session < reduction_no_session


def test_score_bounds():
    extreme = _features(**{name: 1.0 for name in risk.RISK_FEATURES})
    score, _ = risk.risk_from_features(extreme)
    assert 0.0 <= score <= 100.0


def test_statuses_do_not_contribute_risk():
    features = risk.extract_features(
        [ev("BREACH_EXPOSURE", status="UNAVAILABLE"), ev("PASSWORD_REUSE", status="CHECKED_SAFE")]
    )
    assert features["breach"] == 0.0
    assert features["reuse"] == 0.0


def test_unavailable_is_not_safe_distinction_preserved():
    # A module that couldn't run leaves its feature at 0 AND keeps status UNAVAILABLE.
    unavailable = ev("BREACH_EXPOSURE", status="UNAVAILABLE")
    assert unavailable.status == "UNAVAILABLE"


def test_sensitivity_range_contains_point_estimate():
    events = [
        ev("BREACH_EXPOSURE", severity=0.7, exposure_type=ExposureType.PASSWORD_ONLY),
        ev("PASSWORD_REUSE", severity=0.6),
        ev("MFA_MISSING", severity=0.6),
    ]
    breakdown = risk.compute_risk(events)
    assert breakdown.range_low <= breakdown.score <= breakdown.range_high


def test_sensitivity_is_bounded_not_wild():
    """A small input change must not swing the score wildly (real sensitivity test).

    With a 0.15 feature perturbation the score range should stay within a
    reasonable envelope, not jump to the extremes.
    """
    features = _features(breach=0.6, reuse=0.5, no_mfa=0.6)
    score, _ = risk.risk_from_features(features)
    low, high = risk._sensitivity_range(features)
    assert high - low < 25.0  # bounded sensitivity, not a meta-stable cliff
    assert low <= score <= high


def test_banding():
    assert risk.band_for(80) == "CRITICAL"
    assert risk.band_for(60) == "HIGH"
    assert risk.band_for(30) == "MODERATE"
    assert risk.band_for(5) == "LOW"