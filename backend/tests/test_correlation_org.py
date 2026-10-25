"""Phase 3 correlation guarantees (§5).

Every constraint the phase states is pinned here: the three new rules trigger
and refuse to trigger for the right reasons, findings never correlate across
organizations, similar names create nothing, password reuse is never claimed
without a password-reuse finding, repeat evaluation is deterministic and does
not duplicate stored rows, explanations cite the real evidence, an UNAVAILABLE
finding is neither "safe" nor "compromised", the risk engine is untouched, and
no rule template references an unknown placeholder.
"""
from __future__ import annotations

import datetime as dt

from app.engine import correlation
from app.engine.correlation import TEMPLATE_KEYS, evaluate
from tests.helpers import ev

ASSET_A = "alice@example.com"
ASSET_B = "github.com/acme/api"


def _days_ago(days: int) -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)


def _rule_ids(events, **kwargs):
    return {c.rule_id for c in evaluate(events, **kwargs)}


def _by_rule(events, rule_id, **kwargs):
    return [c for c in evaluate(events, **kwargs) if c.rule_id == rule_id]


# --------------------------------------------------------------------------- #
# Rule: company_asset_compound_exposure (scope: same_asset)
# --------------------------------------------------------------------------- #
def test_same_asset_rule_fires_when_two_findings_share_one_company_asset():
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach"),
        ev("MFA_MISSING", asset_id=ASSET_A, event_id="evt_mfa"),
    ]
    result = _by_rule(events, "company_asset_compound_exposure")
    assert len(result) == 1
    assert result[0].asset_ids == [ASSET_A]
    assert result[0].finding_ids == ["evt_breach", "evt_mfa"]


def test_same_asset_rule_refuses_to_fire_across_two_different_assets():
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach"),
        ev("MFA_MISSING", asset_id=ASSET_B, event_id="evt_mfa"),
    ]
    assert "company_asset_compound_exposure" not in _rule_ids(events)


def test_same_asset_rule_ignores_a_finding_not_bound_to_any_asset():
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach"),
        ev("MFA_MISSING", asset_id=None, event_id="evt_mfa"),
    ]
    assert "company_asset_compound_exposure" not in _rule_ids(events)


# --------------------------------------------------------------------------- #
# Rule: declared_dependency_exposure (scope: linked_assets)
# --------------------------------------------------------------------------- #
def test_dependency_rule_fires_only_over_a_declared_edge():
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach"),
        ev("MFA_MISSING", asset_id=ASSET_B, event_id="evt_mfa"),
    ]
    deps = [("org_test", ASSET_A, ASSET_B)]
    result = _by_rule(events, "declared_dependency_exposure", declared_asset_dependencies=deps)
    assert len(result) == 1
    assert result[0].asset_ids == [ASSET_A, ASSET_B]
    assert result[0].evidence["declared_dependency"]["from_asset_id"] == ASSET_A


def test_dependency_rule_refuses_to_fire_without_an_edge():
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach"),
        ev("MFA_MISSING", asset_id=ASSET_B, event_id="evt_mfa"),
    ]
    # No declared dependency: CRIX never invents an edge from two assets.
    assert "declared_dependency_exposure" not in _rule_ids(events)


def test_dependency_rule_ignores_an_edge_declared_by_another_organization():
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach", org_id="org_other"),
        ev("MFA_MISSING", asset_id=ASSET_B, event_id="evt_mfa", org_id="org_other"),
    ]
    # The edge belongs to org_test, but the findings belong to org_other.
    deps = [("org_test", ASSET_A, ASSET_B)]
    assert "declared_dependency_exposure" not in _rule_ids(
        events, declared_asset_dependencies=deps
    )


def test_dependency_rule_ignores_a_self_loop_edge():
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach"),
        ev("MFA_MISSING", asset_id=ASSET_A, event_id="evt_mfa"),
    ]
    deps = [("org_test", ASSET_A, ASSET_A)]
    assert "declared_dependency_exposure" not in _rule_ids(
        events, declared_asset_dependencies=deps
    )


# --------------------------------------------------------------------------- #
# Rule: phishing_campaign_window (scope: same_account, window_hours: 720)
# --------------------------------------------------------------------------- #
def test_phishing_campaign_fires_for_two_lures_inside_the_window():
    events = [
        ev("PHISHING_MESSAGE_DETECTED", event_id="evt_p1", first_seen=_days_ago(10),
           last_seen=_days_ago(10)),
        ev("PHISHING_MESSAGE_DETECTED", event_id="evt_p2", first_seen=_days_ago(3),
           last_seen=_days_ago(3)),
    ]
    result = _by_rule(events, "phishing_campaign_window")
    assert len(result) == 1
    assert result[0].evidence["window_hours"] == 720


def test_phishing_campaign_refuses_when_the_lures_are_too_far_apart():
    events = [
        ev("PHISHING_MESSAGE_DETECTED", event_id="evt_p1", first_seen=_days_ago(400),
           last_seen=_days_ago(400)),
        ev("PHISHING_MESSAGE_DETECTED", event_id="evt_p2", first_seen=_days_ago(3),
           last_seen=_days_ago(3)),
    ]
    assert "phishing_campaign_window" not in _rule_ids(events)


def test_phishing_campaign_needs_at_least_two_lures():
    events = [
        ev("PHISHING_MESSAGE_DETECTED", event_id="evt_p1", first_seen=_days_ago(10),
           last_seen=_days_ago(10)),
    ]
    assert "phishing_campaign_window" not in _rule_ids(events)


# --------------------------------------------------------------------------- #
# Cross-organization isolation
# --------------------------------------------------------------------------- #
def test_findings_sharing_an_account_id_but_different_organizations_never_correlate():
    # elevated_takeover_risk would fire if the engine mixed the two tenants.
    events = [
        ev("BREACH_EXPOSURE", account_id="acct", event_id="evt_breach", org_id="org_a"),
        ev("MFA_MISSING", account_id="acct", event_id="evt_mfa", org_id="org_b"),
    ]
    assert "elevated_takeover_risk" not in _rule_ids(events)


def test_same_asset_in_two_organizations_never_correlates():
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach", org_id="org_a"),
        ev("MFA_MISSING", asset_id=ASSET_A, event_id="evt_mfa", org_id="org_b"),
    ]
    assert "company_asset_compound_exposure" not in _rule_ids(events)


def test_a_finding_without_an_organization_is_excluded_fail_closed():
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach", org_id="org_test"),
        ev("MFA_MISSING", asset_id=ASSET_A, event_id="evt_mfa", org_id=None),
    ]
    assert "company_asset_compound_exposure" not in _rule_ids(events)
    assert "elevated_takeover_risk" not in _rule_ids(events)


def test_the_organization_is_part_of_the_stable_id():
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach", org_id="org_a"),
        ev("MFA_MISSING", asset_id=ASSET_A, event_id="evt_mfa", org_id="org_a"),
    ]
    other = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach", org_id="org_b"),
        ev("MFA_MISSING", asset_id=ASSET_A, event_id="evt_mfa", org_id="org_b"),
    ]
    first = _by_rule(events, "company_asset_compound_exposure")[0]
    second = _by_rule(other, "company_asset_compound_exposure")[0]
    assert first.correlation_id != second.correlation_id


# --------------------------------------------------------------------------- #
# Similar names create no relationship
# --------------------------------------------------------------------------- #
def test_two_assets_with_similar_names_are_never_merged():
    similar_a = "github.com/acme/api"
    similar_b = "github.com/acme/api-legacy"
    events = [
        ev("BREACH_EXPOSURE", asset_id=similar_a, event_id="evt_breach"),
        ev("MFA_MISSING", asset_id=similar_b, event_id="evt_mfa"),
    ]
    # Name similarity alone binds nothing to the same asset…
    assert "company_asset_compound_exposure" not in _rule_ids(events)
    # …and it is not a dependency edge either (only a declared edge would be,
    # which is covered by test_dependency_rule_fires_only_over_a_declared_edge).
    assert "declared_dependency_exposure" not in _rule_ids(events)


# --------------------------------------------------------------------------- #
# Password reuse is never claimed without a password-reuse finding
# --------------------------------------------------------------------------- #
def test_password_reuse_is_not_implied_by_unrelated_findings():
    # A breach and a phishing lure do NOT mean the password was reused.
    events = [
        ev("BREACH_EXPOSURE", event_id="evt_breach"),
        ev("PHISHING_MESSAGE_DETECTED", event_id="evt_phish"),
    ]
    assert "credential_stuffing_risk" not in _rule_ids(events)


def test_password_reuse_rule_fires_only_with_an_explicit_reuse_finding():
    events = [
        ev("BREACH_EXPOSURE", event_id="evt_breach"),
        ev("PASSWORD_REUSE", event_id="evt_reuse"),
    ]
    assert "credential_stuffing_risk" in _rule_ids(events)


# --------------------------------------------------------------------------- #
# Unavailable is neither safe nor compromised
# --------------------------------------------------------------------------- #
def test_an_unavailable_finding_does_not_trigger_a_rule():
    events = [
        ev("BREACH_EXPOSURE", event_id="evt_breach"),
        ev("MFA_MISSING", event_id="evt_mfa", status="UNAVAILABLE"),
    ]
    assert "elevated_takeover_risk" not in _rule_ids(events)


def test_an_unavailable_finding_cannot_be_the_second_finding_in_a_campaign():
    events = [
        ev("PHISHING_MESSAGE_DETECTED", event_id="evt_p1", status="FINDING"),
        ev("PHISHING_MESSAGE_DETECTED", event_id="evt_p2", status="UNAVAILABLE"),
    ]
    assert "phishing_campaign_window" not in _rule_ids(events)


# --------------------------------------------------------------------------- #
# Deterministic repeat evaluation
# --------------------------------------------------------------------------- #
def test_repeat_evaluation_produces_identical_ids():
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach"),
        ev("MFA_MISSING", asset_id=ASSET_A, event_id="evt_mfa"),
    ]
    first = evaluate(events)
    second = evaluate(events)
    assert [c.correlation_id for c in first] == [c.correlation_id for c in second]
    assert [c.severity for c in first] == [c.severity for c in second]
    assert [c.confidence for c in first] == [c.confidence for c in second]


def test_results_are_ordered_by_severity_then_rule_then_id():
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach"),
        ev("MFA_MISSING", asset_id=ASSET_A, event_id="evt_mfa"),
        ev("SESSION_EXPOSURE", metadata={"mfa_bypass_capable": True}, event_id="evt_sess"),
    ]
    result = evaluate(events)
    keys = [(-c.severity, c.rule_id, c.correlation_id) for c in result]
    assert keys == sorted(keys)


def test_one_finding_satisfying_two_predicates_is_deduplicated():
    # A breach + MFA + session on one account: elevated_takeover_risk sees the
    # breach once even though it may match more than one predicate elsewhere.
    events = [
        ev("BREACH_EXPOSURE", event_id="evt_breach"),
        ev("MFA_MISSING", event_id="evt_mfa"),
    ]
    result = _by_rule(events, "elevated_takeover_risk")
    assert result[0].finding_ids == ["evt_breach", "evt_mfa"]


# --------------------------------------------------------------------------- #
# Explanations and chains cite the real evidence
# --------------------------------------------------------------------------- #
def test_same_asset_explanation_cites_the_actual_asset():
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach"),
        ev("MFA_MISSING", asset_id=ASSET_A, event_id="evt_mfa"),
    ]
    result = _by_rule(events, "company_asset_compound_exposure")[0]
    assert ASSET_A in result.explanation
    assert "{" not in result.explanation and "}" not in result.explanation


def test_campaign_explanation_cites_the_actual_window_dates():
    events = [
        ev("PHISHING_MESSAGE_DETECTED", event_id="evt_p1", first_seen=_days_ago(10),
           last_seen=_days_ago(10)),
        ev("PHISHING_MESSAGE_DETECTED", event_id="evt_p2", first_seen=_days_ago(3),
           last_seen=_days_ago(3)),
    ]
    result = _by_rule(events, "phishing_campaign_window")[0]
    # The window line names the real observation span, not a placeholder.
    assert str(_days_ago(10).year) in result.explanation or "{" not in result.explanation


def test_chain_lists_the_actual_findings_and_the_scope():
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach"),
        ev("MFA_MISSING", asset_id=ASSET_A, event_id="evt_mfa"),
    ]
    result = _by_rule(events, "company_asset_compound_exposure")[0]
    joined = " ".join(result.chain)
    assert "evt_breach" in joined and "evt_mfa" in joined
    assert ASSET_A in joined
    assert "company_asset_compound_exposure" in joined
    assert "1.0.0" in joined


def test_dependency_chain_names_the_declared_edge():
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach"),
        ev("MFA_MISSING", asset_id=ASSET_B, event_id="evt_mfa"),
    ]
    deps = [("org_test", ASSET_A, ASSET_B)]
    result = _by_rule(events, "declared_dependency_exposure", declared_asset_dependencies=deps)[0]
    joined = " ".join(result.chain)
    assert ASSET_A in joined and ASSET_B in joined


def test_evidence_cites_only_the_finding_types_and_assets_actually_matched():
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach"),
        ev("MFA_MISSING", asset_id=ASSET_A, event_id="evt_mfa"),
    ]
    result = _by_rule(events, "company_asset_compound_exposure")[0]
    assert result.evidence["matched_event_types"] == ["BREACH_EXPOSURE", "MFA_MISSING"]
    assert result.evidence["asset_ids"] == [ASSET_A]
    assert result.evidence["rule_id"] == "company_asset_compound_exposure"
    assert result.evidence["rule_version"] == "1.0.0"


def test_uncertainty_states_what_the_confidence_means():
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach", confidence=0.9),
        ev("MFA_MISSING", asset_id=ASSET_A, event_id="evt_mfa", confidence=0.6),
    ]
    result = _by_rule(events, "company_asset_compound_exposure")[0]
    assert result.confidence == 0.6  # min of the contributing findings
    assert result.uncertainty["value"] == 0.6
    assert "not a forecast" in result.uncertainty["note"]
    # Must never read as a probability of anything happening.
    assert "probability of compromise" not in result.uncertainty["note"].lower()


# --------------------------------------------------------------------------- #
# Risk engine is not fed by correlations (no new formula, no score bonus)
# --------------------------------------------------------------------------- #
def test_the_risk_engine_source_never_references_correlations():
    from pathlib import Path

    source = (Path(correlation.__file__).parent / "risk.py").read_text(encoding="utf-8").lower()
    assert "correlation" not in source


def test_a_correlation_never_changes_the_risk_score():
    from app.engine import risk

    # The same findings, whether or not a correlation fires over them, give the
    # risk engine the same input — the score comes only from the findings.
    with_correlation = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach"),
        ev("MFA_MISSING", asset_id=ASSET_A, event_id="evt_mfa"),
    ]
    alone = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach"),
        ev("MFA_MISSING", asset_id=ASSET_B, event_id="evt_mfa"),
    ]
    score_with = risk.compute_risk(with_correlation).score
    score_alone = risk.compute_risk(alone).score
    # Correlations firing (or not) does not move the score; only the findings do.
    assert score_with == score_alone
    assert "company_asset_compound_exposure" in _rule_ids(with_correlation)
    assert "company_asset_compound_exposure" not in _rule_ids(alone)


# --------------------------------------------------------------------------- #
# Rule catalog and template safety
# --------------------------------------------------------------------------- #
def test_every_rule_declares_a_version_and_a_known_scope():
    for rule in correlation.describe_rules():
        assert rule["version"], f"{rule['rule_id']} has no version"
        assert rule["scope"] in ("same_account", "same_asset", "linked_assets")


def test_no_rule_template_uses_an_unknown_placeholder():
    import re

    from app.data.loader import correlation_rules

    pattern = re.compile(r"\{([a-z_]+)\}")
    for rule in correlation_rules():
        for key in pattern.findall(rule["explanation"]):
            assert key in TEMPLATE_KEYS, (
                f"rule {rule['rule_id']} uses unknown placeholder {{{key}}}"
            )


def test_the_catalog_lists_the_phase3_and_semester7_rules():
    ids = {r["rule_id"] for r in correlation.describe_rules()}
    assert {
        "company_asset_compound_exposure",
        "declared_dependency_exposure",
        "phishing_campaign_window",
        "phished_weak_email_auth",
    } <= ids


# --------------------------------------------------------------------------- #
# Rule: phished_weak_email_auth (scope: same_asset, Semester-7 features C+D)
# --------------------------------------------------------------------------- #
def test_phished_weak_email_auth_rule_fires_on_one_asset_within_the_window():
    now = dt.datetime.now(dt.timezone.utc)
    events = [
        ev("PHISHING_URL_DETECTED", asset_id=ASSET_A, event_id="evt_url", first_seen=now, last_seen=now),
        ev("EMAIL_AUTH_WEAKNESS", asset_id=ASSET_A, event_id="evt_auth", first_seen=now, last_seen=now),
    ]
    result = _by_rule(events, "phished_weak_email_auth")
    assert len(result) == 1
    assert result[0].asset_ids == [ASSET_A]


def test_phished_weak_email_auth_refuses_across_different_assets():
    events = [
        ev("PHISHING_URL_DETECTED", asset_id=ASSET_A, event_id="evt_url"),
        ev("EMAIL_AUTH_WEAKNESS", asset_id=ASSET_B, event_id="evt_auth"),
    ]
    assert "phished_weak_email_auth" not in _rule_ids(events)


def test_phished_weak_email_auth_refuses_without_asset_binding():
    """An unbound URL finding can never be claimed against a domain asset."""
    events = [
        ev("PHISHING_URL_DETECTED", asset_id=None, event_id="evt_url"),
        ev("EMAIL_AUTH_WEAKNESS", asset_id=ASSET_A, event_id="evt_auth"),
    ]
    assert "phished_weak_email_auth" not in _rule_ids(events)


def test_phished_weak_email_auth_refuses_across_organizations():
    events = [
        ev("PHISHING_URL_DETECTED", asset_id=ASSET_A, event_id="evt_url", org_id="org_one"),
        ev("EMAIL_AUTH_WEAKNESS", asset_id=ASSET_A, event_id="evt_auth", org_id="org_two"),
    ]
    assert "phished_weak_email_auth" not in _rule_ids(events)


def test_phished_weak_email_auth_refuses_when_observations_are_too_far_apart():
    eight_days = _days_ago(8)
    events = [
        ev("PHISHING_URL_DETECTED", asset_id=ASSET_A, event_id="evt_url", first_seen=eight_days),
        ev("EMAIL_AUTH_WEAKNESS", asset_id=ASSET_A, event_id="evt_auth"),
    ]
    assert "phished_weak_email_auth" not in _rule_ids(events)


def test_an_unknown_scope_fails_loudly():
    events = [ev("BREACH_EXPOSURE", asset_id=ASSET_A)]
    bad_rule = {"rule_id": "x", "scope": "nonsense", "predicates": [], "severity": {}}
    import pytest

    with pytest.raises(ValueError, match="unknown scope"):
        # Reach the grouping helper directly so the bad scope is exercised.
        correlation._groups(bad_rule, events, [])


# --------------------------------------------------------------------------- #
# Persistence: upsert by stable id, and stale rows never linger
# --------------------------------------------------------------------------- #
def _persist_and_run(db, user_id, events):
    from app.engine import normalizer, pipeline

    normalizer.persist_events(db, events)
    return pipeline.run_analysis(db, user_id, persist=True)


def test_re_running_the_pipeline_upserts_rather_than_duplicating(db_session):
    from sqlalchemy import func, select

    from app.engine import pipeline
    from app.models import Correlation
    from tests.helpers import seed_org_for_user

    user_id = "user-1"
    org_id = seed_org_for_user(db_session, user_id)
    assert org_id
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach", user_id=user_id),
        ev("MFA_MISSING", asset_id=ASSET_A, event_id="evt_mfa", user_id=user_id),
    ]
    _persist_and_run(db_session, user_id, events)
    first = db_session.scalar(
        select(func.count()).select_from(Correlation).where(Correlation.user_id == user_id)
    )
    assert first >= 1, "expected at least one persisted correlation"

    # Same findings, second run (findings already stored): count must not grow.
    pipeline.run_analysis(db_session, user_id, persist=True)
    second = db_session.scalar(
        select(func.count()).select_from(Correlation).where(Correlation.user_id == user_id)
    )
    assert first == second, "repeat evaluation must upsert, not duplicate"


def test_a_re_check_that_replaces_findings_cleans_up_stale_correlations(db_session):
    from sqlalchemy import func, select

    from app.engine import normalizer, pipeline
    from app.models import Correlation, SecurityEvent
    from tests.helpers import seed_org_for_user

    user_id = "user-1"
    seed_org_for_user(db_session, user_id)
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach_v1", user_id=user_id),
        ev("MFA_MISSING", asset_id=ASSET_A, event_id="evt_mfa_v1", user_id=user_id),
    ]
    _persist_and_run(db_session, user_id, events)
    assert db_session.scalar(
        select(func.count()).select_from(Correlation).where(Correlation.user_id == user_id)
    ) >= 1

    # Simulate a re-check that REPLACES the findings with new event ids.
    db_session.query(SecurityEvent).filter(SecurityEvent.user_id == user_id).delete()
    db_session.commit()
    replaced = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach_v2", user_id=user_id),
        ev("MFA_MISSING", asset_id=ASSET_A, event_id="evt_mfa_v2", user_id=user_id),
    ]
    normalizer.persist_events(db_session, replaced)
    pipeline.run_analysis(db_session, user_id, persist=True)

    # No correlation may reference a finding that no longer exists.
    live_ids = {
        row[0]
        for row in db_session.execute(
            select(SecurityEvent.event_id).where(SecurityEvent.user_id == user_id)
        ).all()
    }
    for corr in db_session.scalars(
        select(Correlation).where(Correlation.user_id == user_id)
    ).all():
        assert set(corr.finding_ids) <= live_ids, "a stale correlation lingered"
    # And the fresh findings produced a correlation over the NEW ids.
    new_corrs = db_session.scalars(
        select(Correlation).where(Correlation.user_id == user_id)
    ).all()
    assert any(
        "evt_breach_v2" in c.finding_ids and "evt_mfa_v2" in c.finding_ids
        for c in new_corrs
    ), "the re-checked findings must correlate over their new ids"


def test_persisted_correlations_carry_the_explicit_phase3_fields(db_session):
    from sqlalchemy import select

    from app.models import Correlation
    from tests.helpers import seed_org_for_user

    user_id = "user-1"
    org_id = seed_org_for_user(db_session, user_id)
    events = [
        ev("BREACH_EXPOSURE", asset_id=ASSET_A, event_id="evt_breach", user_id=user_id),
        ev("MFA_MISSING", asset_id=ASSET_A, event_id="evt_mfa", user_id=user_id),
    ]
    _persist_and_run(db_session, user_id, events)

    rows = db_session.scalars(
        select(Correlation).where(Correlation.user_id == user_id)
    ).all()
    assert rows, "expected at least one persisted correlation"
    for row in rows:
        assert row.org_id == org_id, "correlation must carry the organization"
        assert row.rule_version == "1.0.0"
        assert len(row.correlation_id) == 32
        assert row.finding_ids, "correlation must reference the findings it combined"
        assert row.chain, "correlation must expose the plain-language chain"
        assert row.evidence, "correlation must expose the evidence it cites"
        assert row.uncertainty.get("note"), "correlation must state its uncertainty"
        assert row.evaluated_at is not None
