"""One test per declarative correlation rule (§5) plus engine behaviour."""
from __future__ import annotations

from app.engine.correlation import evaluate
from app.schemas import ExposureType
from tests.helpers import ev


def _rule_ids(events):
    return {c.rule_id for c in evaluate(events)}


def test_rule_credential_stuffing_risk():
    events = [ev("BREACH_EXPOSURE"), ev("PASSWORD_REUSE")]
    assert "credential_stuffing_risk" in _rule_ids(events)


def test_rule_targeted_credential_theft():
    events = [ev("PHISHING_MESSAGE_DETECTED"), ev("IDENTITY_EXPOSED")]
    assert "targeted_credential_theft" in _rule_ids(events)


def test_rule_cascading_recovery_risk():
    events = [ev("COMPROMISED_RECOVERY_ACCOUNT"), ev("ACCOUNT_DEPENDENCY")]
    assert "cascading_recovery_risk" in _rule_ids(events)


def test_rule_elevated_takeover_risk():
    events = [ev("BREACH_EXPOSURE"), ev("MFA_MISSING")]
    assert "elevated_takeover_risk" in _rule_ids(events)


def test_rule_mfa_ineffective_session_exposure():
    events = [
        ev("SESSION_EXPOSURE", exposure_type=ExposureType.SESSION_ONLY,
           metadata={"mfa_bypass_capable": True})
    ]
    correlations = evaluate(events)
    assert "mfa_ineffective_session_exposure" in {c.rule_id for c in correlations}
    # The rule carries critical severity.
    corr = next(c for c in correlations if c.rule_id == "mfa_ineffective_session_exposure")
    assert corr.severity >= 0.85


def test_session_exposure_requires_mfa_bypass_flag():
    # Without the metadata flag the rule must NOT fire.
    events = [ev("SESSION_EXPOSURE", exposure_type=ExposureType.SESSION_ONLY,
                 metadata={"mfa_bypass_capable": False})]
    assert "mfa_ineffective_session_exposure" not in _rule_ids(events)


def test_rule_identity_reuse_blend():
    events = [ev("BREACH_EXPOSURE"), ev("PASSWORD_REUSE"), ev("MFA_MISSING")]
    assert "identity_reuse_blend" in _rule_ids(events)


def test_rule_sim_swap_recovery_exposure():
    events = [ev("SIM_SWAP_VULNERABLE"), ev("MFA_MISSING")]
    assert "sim_swap_recovery_exposure" in _rule_ids(events)


def test_rule_oversharing_and_phishing():
    events = [ev("RISKY_PERMISSION_GRANTED"), ev("PHISHING_MESSAGE_DETECTED")]
    assert "oversharing_and_phishing" in _rule_ids(events)


def test_rules_are_declarative_and_have_explanations():
    from app.data.loader import correlation_rules

    rules = correlation_rules()
    assert len(rules) >= 5
    for rule in rules:
        assert rule["rule_id"]
        assert rule["predicates"]
        assert rule["explanation"].strip()
        assert "severity" in rule


def test_correlations_do_not_cross_accounts():
    # Breach on acct-1, reuse on acct-2 must NOT correlate.
    events = [ev("BREACH_EXPOSURE", account_id="acct-1"), ev("PASSWORD_REUSE", account_id="acct-2")]
    assert "credential_stuffing_risk" not in _rule_ids(events)


def test_checked_safe_and_unavailable_do_not_contribute():
    events = [ev("BREACH_EXPOSURE", status="CHECKED_SAFE"), ev("PASSWORD_REUSE", status="UNAVAILABLE")]
    assert _rule_ids(events) == set()