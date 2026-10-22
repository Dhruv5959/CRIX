"""Phase 7 guarantees: remediation planning under budget + honest verification.

Phase 7 (master prompt §5) pins, in the spec's own words:

  1. the shared budget packer (greedy by score/effort) exists and is labelled
     approximate — reusable by Phase 12, never called optimal
  2. prerequisites are respected; actions whose prerequisites can never hold
     are reported infeasible with a reason, never silently dropped
  3. deterministic tie-breaks (ratio, then effort, then key) and repeatable
     plans independent of candidate order
  4. exact branch-and-bound equals brute force on bounded instances, WITH
     prerequisites
  5. partial-budget results are honest (unspent_budget)
  6. per-task effort overrides are validated and change plans deterministically
  7. expected_reduction is COMPUTED by the real risk model, never invented
  8. task states: OPEN -> DONE (attestation, never verification) ->
     VERIFIED_MODELED | VERIFIED_OBSERVED (never merged) with reopen
  9. VERIFIED_OBSERVED is rejected for SYNTHETIC/FIXTURE data by construction
 10. failed verification keeps DONE and appends a FAIL history row
 11. history is append-only and survives reopening
 12. RBAC + tenant isolation on every endpoint; audit log on
     create/assign/update/verify/read/complete/reopen/plan
 13. the admin-set effort budget drives planning; plans map back to task ids
 14. Alembic up AND down (test_migrations.py: phase7 test)

Every asset, finding and recheck event below is SYNTHETIC test data created by
the test itself, except where a test deliberately stamps ``source_mode="REAL"``
to model what a live provider recheck would return.
"""
from __future__ import annotations

import random

import pytest
from sqlalchemy import select

from app.engine import normalizer, pipeline, planner, risk
from app.models import AuditLog, Membership, RemediationAction, RemediationTaskHistory
from tests.conftest import login_headers, register_org_admin
from tests.helpers import ev

PASSWORD = "correct horse battery"


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #
def _add_member(client, admin_headers, email: str, role: str) -> dict:
    created = client.post(
        "/api/invitations", headers=admin_headers, json={"email": email, "role": role}
    )
    assert created.status_code == 201, created.text
    token = created.json()["invite_link"].split("token=", 1)[1]
    accepted = client.post(
        "/api/invitations/accept", json={"token": token, "password": PASSWORD}
    )
    assert accepted.status_code == 200, accepted.text
    return login_headers(client, email, PASSWORD)


def _membership(db, email: str) -> Membership:
    from app.models import User

    row = db.scalar(
        select(Membership).join(User, User.id == Membership.user_id).where(User.email == email)
    )
    assert row is not None
    return row


def _feat(**kw) -> dict[str, float]:
    base = {name: 0.0 for name in risk.ALL_FEATURES}
    base.update(kw)
    return base


def _seed_findings(db, user_id: str) -> None:
    """Give the org a realistic weakness set (SYNTHETIC, labeled)."""
    normalizer.persist_events(
        db,
        [
            ev("BREACH_EXPOSURE", account_id="work", severity=0.7, event_id="p7-breach",
               user_id=user_id),
            ev("PASSWORD_REUSE", account_id="work", severity=0.8, event_id="p7-reuse",
               user_id=user_id),
            ev("MFA_MISSING", account_id="work", severity=0.8, event_id="p7-mfa",
               user_id=user_id),
        ],
    )


def _create_task(client, headers, **payload) -> dict:
    body = {"action_key": "strengthen_mfa", **payload}
    response = client.post("/api/remediation/tasks", headers=headers, json=body)
    assert response.status_code == 201, response.text
    return response.json()


def _real_event(db, user_id: str, event_id: str, *, event_type: str, status: str,
                source_mode: str = "REAL") -> str:
    """Persist a recheck event with an explicit source_mode; returns event_id."""
    normalizer.persist_events(
        db,
        [
            ev(event_type, account_id="work", severity=0.5, event_id=event_id,
               user_id=user_id, status=status, source_mode=source_mode),
        ],
    )
    return event_id


# --------------------------------------------------------------------------- #
# Engine: packer, prerequisites, infeasibility, determinism, tie-breaks
# --------------------------------------------------------------------------- #
def test_pack_budget_is_the_shared_greedy_packer_and_labelled_approximate():
    plan = planner.pack_budget(_feat(breach=0.8, reuse=0.8), budget=4.0)
    assert plan["packer"] == "greedy_by_score_per_effort"
    assert plan["approximate"] is True
    assert plan["method"] == "greedy"
    assert "optimal" not in plan["note"].lower() or "never" in plan["note"].lower()
    # It is literally greedy_plan plus the shared-packer labels.
    plain = planner.greedy_plan(_feat(breach=0.8, reuse=0.8), budget=4.0)
    assert plan["actions"] == plain["actions"]
    assert plan["risk_after"] == plain["risk_after"]


def test_pack_budget_respects_budget_and_prerequisites():
    plan = planner.pack_budget(
        _feat(breach=0.7, reuse=0.7, no_mfa=0.8, sim_swap=0.6),
        budget=6.0,
        candidate_actions=["strengthen_mfa", "enable_passkey", "change_reused_password"],
        prerequisites={"enable_passkey": ["strengthen_mfa"]},
    )
    assert plan["total_effort"] <= 6.0 + 1e-9
    if "enable_passkey" in plan["actions"]:
        assert plan["actions"].index("enable_passkey") > plan["actions"].index(
            "strengthen_mfa"
        ), "a prerequisite must be chosen before its dependent"


def test_prerequisite_that_is_not_a_candidate_is_reported_infeasible():
    features = _feat(breach=0.7, reuse=0.7, no_mfa=0.8)
    candidates = ["enable_passkey", "change_reused_password"]
    prereqs = {"enable_passkey": ["strengthen_mfa"]}
    for plan in (
        planner.greedy_plan(features, budget=6.0, candidate_actions=candidates,
                            prerequisites=prereqs),
        planner.exact_plan(features, budget=6.0, candidate_actions=candidates,
                           prerequisites=prereqs),
    ):
        assert "enable_passkey" not in plan["actions"], (
            "an action whose prerequisite can never hold must never be planned"
        )
        entry = next(i for i in plan["infeasible"] if i["action"] == "enable_passkey")
        assert entry["reason"] == "prerequisite_not_a_candidate"
        assert entry["detail"] == ["strengthen_mfa"]
        # The rest still plans honestly.
        assert "change_reused_password" in plan["actions"]


def test_prerequisite_cycle_is_reported_and_the_rest_still_plans():
    features = _feat(breach=0.7, reuse=0.7, session=0.7)
    candidates = ["change_reused_password", "revoke_session", "strengthen_mfa"]
    prereqs = {
        "change_reused_password": ["revoke_session"],
        "revoke_session": ["change_reused_password"],
    }
    comparison = planner.compare(
        features, budget=6.0, candidate_actions=candidates, prerequisites=prereqs
    )
    for plan in (comparison["greedy"], comparison["exact"]):
        cycle_actions = {
            i["action"] for i in plan["infeasible"] if i["reason"] == "prerequisite_cycle"
        }
        assert cycle_actions == {"change_reused_password", "revoke_session"}
        assert set(plan["actions"]) == {"strengthen_mfa"}, (
            "cycle members are excluded; the feasible candidate still plans"
        )


def test_plans_are_deterministic_and_order_independent():
    features = _feat(breach=0.8, reuse=0.7, no_mfa=0.6, session=0.5, permissions=0.4)
    keys = list(planner.ACTIONS)
    shuffled = keys[:]
    random.Random(7).shuffle(shuffled)
    a = planner.compare(features, budget=6.0, candidate_actions=keys)
    b = planner.compare(features, budget=6.0, candidate_actions=shuffled)
    assert a["greedy"]["actions"] == b["greedy"]["actions"]
    assert a["exact"]["actions"] == b["exact"]["actions"]
    assert a["optimality_gap"] == b["optimality_gap"]
    # And repeating the same call is bit-identical (aside from timing).
    again = planner.compare(features, budget=6.0, candidate_actions=keys)
    assert again["exact"]["actions"] == a["exact"]["actions"]


def test_tie_break_prefers_cheaper_then_lexicographic():
    # Equal ratio AND equal effort -> lexicographic key decides.
    # reuse=0.8 -> reduction 100*0.10*0.8 = 8.0 (effort 1.0)
    # session=0.5 -> reduction 100*0.16*0.5 = 8.0 (effort 1.0)
    features = _feat(reuse=0.8, session=0.5)
    plan = planner.greedy_plan(
        features, budget=2.0,
        candidate_actions=["revoke_session", "change_reused_password"],
    )
    assert plan["actions"][0] == "change_reused_password", (
        "on an exact tie the lexicographically smaller key wins, always"
    )
    # Equal ratio, unequal effort -> the cheaper one wins (helper unit check).
    assert planner._select_better(0.5, 1.0, "b", 0.5, 2.0, "a") is True
    assert planner._select_better(0.5, 2.0, "a", 0.5, 1.0, "b") is False


def test_exact_matches_brute_force_with_prerequisites():
    rng = random.Random(4242)
    for _ in range(12):
        features = {name: round(rng.random(), 3) for name in risk.ALL_FEATURES}
        candidates = ["strengthen_mfa", "enable_passkey", "revoke_session",
                      "change_reused_password"]
        prereqs = {"enable_passkey": ["strengthen_mfa"]}
        budget = rng.choice([2.0, 4.0, 6.0, 9.0])
        exact = planner.exact_plan(
            features, budget=budget, candidate_actions=candidates,
            prerequisites=prereqs,
        )
        # Brute force over every subset, keeping only prerequisite-feasible ones.
        best = None
        for mask in range(1 << len(candidates)):
            chosen = [candidates[i] for i in range(len(candidates)) if mask >> i & 1]
            chosen_set = set(chosen)
            if any(
                not set(prereqs.get(k, ())) <= chosen_set for k in chosen
            ):
                continue
            effort = sum(planner.ACTIONS[k].effort for k in chosen)
            if effort > budget + 1e-9:
                continue
            score = planner._risk(planner.apply_actions(features, chosen))
            if best is None or score < best - 1e-9:
                best = score
        assert best is not None
        assert exact["risk_after"] == pytest.approx(best, abs=1e-3), (
            "exact must equal brute force over prerequisite-feasible subsets"
        )


def test_exact_never_beats_greedy_and_partial_budget_is_honest():
    rng = random.Random(99)
    for _ in range(10):
        features = {name: round(rng.random(), 3) for name in risk.ALL_FEATURES}
        budget = rng.choice([1.0, 3.0, 5.0])
        comparison = planner.compare(features, budget=budget)
        assert comparison["exact"]["risk_after"] <= comparison["greedy"]["risk_after"] + 1e-6
        for plan in (comparison["greedy"], comparison["exact"]):
            assert plan["total_effort"] <= budget + 1e-9
            assert plan["unspent_budget"] >= 0.0
            assert plan["unspent_budget"] == pytest.approx(
                budget - plan["total_effort"], abs=1e-3
            )


def test_effort_override_is_validated_and_changes_plans_deterministically():
    features = _feat(reuse=0.8, session=0.8)
    candidates = ["change_reused_password", "revoke_session"]
    # Default: session (weight 0.16) has the better ratio -> revoke_session first.
    base = planner.greedy_plan(features, budget=2.0, candidate_actions=candidates)
    assert base["actions"][0] == "revoke_session"
    # With an org-specific override, revoke_session becomes expensive (ratio
    # drops below change_reused_password) and no longer fits the budget.
    overridden = planner.greedy_plan(
        features, budget=2.0, candidate_actions=candidates,
        efforts={"revoke_session": 8.0},
    )
    assert overridden["actions"] == ["change_reused_password"]
    assert overridden["total_effort"] == 1.0
    # Invalid overrides are rejected, never silently accepted.
    for bad in ({"revoke_session": 0}, {"revoke_session": -1.0},
                {"revoke_session": "1"}, {"revoke_session": True}):
        with pytest.raises(ValueError):
            planner.greedy_plan(features, budget=2.0, efforts=bad)


def test_expected_reduction_is_computed_by_the_real_risk_model():
    features = _feat(breach=0.7, reuse=0.6, no_mfa=0.5)
    got = planner.expected_reduction(features, "change_reused_password")
    before, _ = risk.risk_from_features(features)
    after, _ = risk.risk_from_features(
        planner.apply_action(features, "change_reused_password")
    )
    assert got == pytest.approx(round(before - after, 4), abs=1e-6)
    # With nothing to fix the modeled reduction is an honest zero.
    clean = _feat()
    assert planner.expected_reduction(clean, "change_reused_password") == 0.0
    with pytest.raises(KeyError):
        planner.expected_reduction(features, "not_a_catalog_action")


def test_explicit_empty_candidates_plan_empty_not_the_full_catalog():
    comparison = planner.compare(_feat(breach=0.8), budget=6.0, candidate_actions=[])
    assert comparison["greedy"]["actions"] == []
    assert comparison["exact"]["actions"] == []
    assert comparison["optimality_gap"] == 0.0


# --------------------------------------------------------------------------- #
# Settings: the admin-set effort budget
# --------------------------------------------------------------------------- #
def test_settings_default_and_admin_update(client):
    admin = register_org_admin(client, org_name="Budget Co")
    response = client.get("/api/remediation/settings", headers=admin)
    assert response.status_code == 200
    assert response.json()["effort_budget"] == 6.0

    updated = client.patch(
        "/api/remediation/settings", headers=admin, json={"effort_budget": 12.5}
    )
    assert updated.status_code == 200
    assert updated.json()["effort_budget"] == 12.5
    again = client.get("/api/remediation/settings", headers=admin)
    assert again.json()["effort_budget"] == 12.5
    assert "relative unit" in again.json()["note"]


def test_settings_rbac_and_validation(client):
    admin = register_org_admin(client, org_name="Rbac Budget Co")
    member = _add_member(client, admin, "member@budget.example.com", "MEMBER")
    viewer = _add_member(client, admin, "viewer@budget.example.com", "VIEWER")
    for headers in (member, viewer):
        assert client.patch(
            "/api/remediation/settings", headers=headers,
            json={"effort_budget": 10.0},
        ).status_code == 403
        assert client.get("/api/remediation/settings", headers=headers).status_code == 200
    # Bounds are enforced server-side.
    for bad in (0, -3, 5000):
        assert client.patch(
            "/api/remediation/settings", headers=admin, json={"effort_budget": bad}
        ).status_code == 422


# --------------------------------------------------------------------------- #
# Task creation: catalog authority, computed reduction, validation
# --------------------------------------------------------------------------- #
def test_create_task_computes_expected_reduction_with_the_real_engine(client, db_session):
    admin = register_org_admin(client, org_name="Task Co")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)

    task = _create_task(
        client, admin, action_key="change_reused_password",
        target_asset_id=None, finding_ids=["p7-reuse"],
        required_evidence=["password rotated confirmation"],
        verification_method="MODELED",
    )
    assert task["status"] == "OPEN"
    assert task["expected_reduction"] is not None and task["expected_reduction"] > 0

    # Cross-check against the engine directly: same features, same math.
    result = pipeline.run_analysis(db_session, membership.user_id, persist=False)
    independently = planner.expected_reduction(
        result["features"], "change_reused_password", criticality=result["criticality"]
    )
    assert task["expected_reduction"] == pytest.approx(independently, abs=1e-3)
    assert task["required_evidence"] == ["password rotated confirmation"]
    assert task["finding_ids"] == ["p7-reuse"]

    # The CREATED history row records the model version and the computation.
    detail = client.get(
        f"/api/remediation/tasks/{task['id']}", headers=admin
    ).json()
    created = detail["history"][0]
    assert created["method"] == "CREATED"
    assert created["from_status"] is None and created["to_status"] == "OPEN"
    assert created["model_version"] == risk.RISK_MODEL_VERSION
    assert created["detail"]["expected_reduction"] == task["expected_reduction"]


def test_create_task_validation_is_fail_closed(client, db_session):
    admin = register_org_admin(client, org_name="Validation Co")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)

    # Unknown action key: the catalog is the authority.
    bad = client.post(
        "/api/remediation/tasks", headers=admin,
        json={"action_key": "do_a_magic_hack"},
    )
    assert bad.status_code == 422
    assert "catalog" in bad.text

    # Unknown verification method: only the two documented paths exist.
    bad = client.post(
        "/api/remediation/tasks", headers=admin,
        json={"action_key": "strengthen_mfa", "verification_method": "VIBES"},
    )
    assert bad.status_code == 422

    # Unknown finding id (also covers cross-tenant: not in this org).
    bad = client.post(
        "/api/remediation/tasks", headers=admin,
        json={"action_key": "strengthen_mfa", "finding_ids": ["p7-reuse", "ghost"]},
    )
    assert bad.status_code == 422
    assert bad.json()["detail"]["unknown"] == ["ghost"]

    # Unknown prerequisite action.
    bad = client.post(
        "/api/remediation/tasks", headers=admin,
        json={"action_key": "strengthen_mfa", "prerequisites": ["ghost_action"]},
    )
    assert bad.status_code == 422

    # Cross-org / unknown asset is a 404, never a guess.
    bad = client.post(
        "/api/remediation/tasks", headers=admin,
        json={"action_key": "strengthen_mfa", "target_asset_id": "no-such-asset"},
    )
    assert bad.status_code == 404


def test_task_rbac_and_tenant_isolation(client, db_session):
    admin = register_org_admin(client, org_name="Iso Co")
    member = _add_member(client, admin, "member@iso.example.com", "MEMBER")
    viewer = _add_member(client, admin, "viewer@iso.example.com", "VIEWER")
    other_admin = register_org_admin(client, "attacker@other.example.com",
                                     org_name="Other Co")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)

    task = _create_task(client, admin)

    # Viewer/member read but cannot create; unauthenticated cannot read.
    for headers in (member, viewer):
        assert client.get("/api/remediation/tasks", headers=headers).status_code == 200
        assert client.post(
            "/api/remediation/tasks", headers=headers,
            json={"action_key": "strengthen_mfa"},
        ).status_code == 403
    assert client.get("/api/remediation/tasks").status_code == 401

    # Another tenant cannot see, read, patch or plan it: 404, indistinguishable
    # from missing.
    assert client.get(
        f"/api/remediation/tasks/{task['id']}", headers=other_admin
    ).status_code == 404
    assert client.patch(
        f"/api/remediation/tasks/{task['id']}", headers=other_admin,
        json={"effort": 9.0},
    ).status_code == 404
    assert client.post(
        f"/api/remediation/tasks/{task['id']}/complete", headers=other_admin
    ).status_code == 404
    assert client.post(
        f"/api/remediation/tasks/{task['id']}/verify", headers=other_admin,
        json={"method": "VERIFIED_MODELED", "attested": True},
    ).status_code == 404
    other_plan = client.post("/api/remediation/plan", headers=other_admin)
    assert other_plan.status_code == 200
    assert other_plan.json()["task_map"] == {}, "plans never cross tenants"


def test_assignment_requires_an_active_member_and_is_audited(client, db_session):
    admin = register_org_admin(client, org_name="Assign Co")
    member = _add_member(client, admin, "member@assign.example.com", "MEMBER")
    outsider = register_org_admin(client, "outsider@assign.example.com",
                                  org_name="Outsider Co")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)
    task = _create_task(client, admin)

    bad = client.patch(
        f"/api/remediation/tasks/{task['id']}", headers=admin,
        json={"assigned_to": "not-a-member"},
    )
    assert bad.status_code == 422

    member_id = _membership(db_session, "member@assign.example.com").user_id
    ok = client.patch(
        f"/api/remediation/tasks/{task['id']}", headers=admin,
        json={"assigned_to": member_id, "effort": 3.0},
    )
    assert ok.status_code == 200
    assert ok.json()["assigned_to"] == member_id
    assert ok.json()["effort"] == 3.0

    history = client.get(f"/api/remediation/tasks/{task['id']}", headers=admin).json()
    methods = [h["method"] for h in history["history"]]
    assert "UPDATED" in methods
    updated = next(h for h in history["history"] if h["method"] == "UPDATED")
    assert set(updated["detail"]["changed"]) == {"assigned_to", "effort"}

    listing = client.get("/api/remediation/tasks", headers=admin)
    assert listing.status_code == 200
    actions = {
        row[0]
        for row in db_session.execute(
            select(AuditLog.action).where(AuditLog.user_id == _membership(
                db_session, "admin@example.com").user_id)
        ).all()
    }
    assert "remediation.task_created" in actions
    assert "remediation.task_updated" in actions
    assert "remediation.tasks_read" in actions
    assert "remediation.task_read" in actions
    # An outsider cannot assign.
    assert client.patch(
        f"/api/remediation/tasks/{task['id']}", headers=outsider,
        json={"assigned_to": member_id},
    ).status_code == 404


# --------------------------------------------------------------------------- #
# State machine: OPEN -> DONE (attestation) -> VERIFIED_* with reopen
# --------------------------------------------------------------------------- #
def test_complete_is_an_attestation_and_never_verifies(client, db_session):
    admin = register_org_admin(client, org_name="Done Co")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)
    task = _create_task(client, admin, action_key="change_reused_password")

    done = client.post(
        f"/api/remediation/tasks/{task['id']}/complete", headers=admin
    )
    assert done.status_code == 200
    body = done.json()
    assert body["status"] == "DONE", "clicking Done claims, it never verifies"
    assert body["status"] not in ("VERIFIED_MODELED", "VERIFIED_OBSERVED")
    assert body["completed_at"] is not None

    # No verification row exists; only the COMPLETED transition.
    detail = client.get(f"/api/remediation/tasks/{task['id']}", headers=admin).json()
    assert [h["method"] for h in detail["history"]] == ["CREATED", "COMPLETED"]
    assert detail["history"][-1]["from_status"] == "OPEN"
    assert detail["history"][-1]["to_status"] == "DONE"
    assert "attestation" in detail["history"][-1]["detail"]["note"]

    # Conflicts are 409, never silent state changes.
    assert client.post(
        f"/api/remediation/tasks/{task['id']}/complete", headers=admin
    ).status_code == 409


def test_complete_rbac_member_yes_viewer_no(client, db_session):
    admin = register_org_admin(client, org_name="Complete Rbac Co")
    member = _add_member(client, admin, "member@cmp.example.com", "MEMBER")
    viewer = _add_member(client, admin, "viewer@cmp.example.com", "VIEWER")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)

    member_task = _create_task(client, admin)
    viewer_task = _create_task(client, admin)
    assert client.post(
        f"/api/remediation/tasks/{member_task['id']}/complete", headers=member
    ).status_code == 200
    assert client.post(
        f"/api/remediation/tasks/{viewer_task['id']}/complete", headers=viewer
    ).status_code == 403


def test_verify_modeled_requires_attestation_and_passes_on_real_reduction(client, db_session):
    admin = register_org_admin(client, org_name="Modeled Co")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)
    task = _create_task(client, admin, action_key="change_reused_password")
    client.post(f"/api/remediation/tasks/{task['id']}/complete", headers=admin)

    # Without an explicit attestation the engine refuses to guess.
    no_attest = client.post(
        f"/api/remediation/tasks/{task['id']}/verify", headers=admin,
        json={"method": "VERIFIED_MODELED"},
    )
    assert no_attest.status_code == 422
    assert "attested" in no_attest.text

    verified = client.post(
        f"/api/remediation/tasks/{task['id']}/verify", headers=admin,
        json={
            "method": "VERIFIED_MODELED",
            "attested": True,
            "evidence_refs": ["user-says-rotated"],
        },
    )
    assert verified.status_code == 200
    body = verified.json()
    assert body["status"] == "VERIFIED_MODELED"
    row = body["history"][-1]
    assert row["method"] == "VERIFICATION_ATTEMPTED"
    assert row["from_status"] == "DONE" and row["to_status"] == "VERIFIED_MODELED"
    assert row["result"] == "OK"
    assert row["model_version"] == risk.RISK_MODEL_VERSION
    assert row["detail"]["modeled_reduction"] > 0
    assert row["created_at"], "a timestamp is recorded"

    # Verified states are terminal until reopened.
    assert client.post(
        f"/api/remediation/tasks/{task['id']}/verify", headers=admin,
        json={"method": "VERIFIED_MODELED", "attested": True},
    ).status_code == 409
    assert client.post(
        f"/api/remediation/tasks/{task['id']}/complete", headers=admin
    ).status_code == 409


def test_verify_modeled_failure_keeps_done_and_records_fail(client, db_session):
    admin = register_org_admin(client, org_name="Modeled Fail Co")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)
    # This action addresses `permissions`, which the org does not have: the
    # re-run shows no modeled reduction, so the claim is NOT confirmed.
    task = _create_task(client, admin, action_key="revoke_risky_permission")
    client.post(f"/api/remediation/tasks/{task['id']}/complete", headers=admin)
    response = client.post(
        f"/api/remediation/tasks/{task['id']}/verify", headers=admin,
        json={"method": "VERIFIED_MODELED", "attested": True},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "DONE", "a failed verification never verifies"
    row = body["history"][-1]
    assert row["result"] == "FAIL"
    assert row["to_status"] == "DONE"
    assert "failure_reason" in row["detail"]
    assert row["detail"]["modeled_reduction"] == 0.0


def test_verify_observed_rejects_synthetic_fixture_and_user_data(client, db_session):
    admin = register_org_admin(client, org_name="Observed Reject Co")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)
    task = _create_task(client, admin, action_key="change_reused_password")
    client.post(f"/api/remediation/tasks/{task['id']}/complete", headers=admin)

    refs = [
        _real_event(db_session, membership.user_id, f"p7-sim-{i}", event_type="PASSWORD_REUSE",
                    status="CHECKED_SAFE", source_mode=mode)
        for i, mode in enumerate(["SIMULATED", "FIXTURE", "USER_PROVIDED"])
    ]
    rejected = client.post(
        f"/api/remediation/tasks/{task['id']}/verify", headers=admin,
        json={"method": "VERIFIED_OBSERVED", "evidence_refs": refs},
    )
    assert rejected.status_code == 422
    detail = rejected.json()["detail"]
    assert detail["error"] == "evidence_not_live"
    assert set(detail["source_modes_seen"]) == {"SIMULATED", "FIXTURE", "USER_PROVIDED"}
    # Still DONE — a rejection is not a state change.
    assert client.get(
        f"/api/remediation/tasks/{task['id']}", headers=admin
    ).json()["status"] == "DONE"

    # No evidence at all is also rejected.
    empty = client.post(
        f"/api/remediation/tasks/{task['id']}/verify", headers=admin,
        json={"method": "VERIFIED_OBSERVED"},
    )
    assert empty.status_code == 422
    # Evidence refs that do not exist in this org are rejected (tenant-safe).
    ghost = client.post(
        f"/api/remediation/tasks/{task['id']}/verify", headers=admin,
        json={"method": "VERIFIED_OBSERVED", "evidence_refs": ["ghost-ref"]},
    )
    assert ghost.status_code == 422


def test_verify_observed_pass_and_fail_with_live_recheck(client, db_session):
    admin = register_org_admin(client, org_name="Observed Co")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)
    task = _create_task(client, admin, action_key="change_reused_password")
    client.post(f"/api/remediation/tasks/{task['id']}/complete", headers=admin)

    # A live recheck still reports the weakness: FAIL, stays DONE.
    still = _real_event(db_session, membership.user_id, "p7-recheck-still",
                        event_type="PASSWORD_REUSE", status="FINDING", source_mode="REAL")
    failed = client.post(
        f"/api/remediation/tasks/{task['id']}/verify", headers=admin,
        json={"method": "VERIFIED_OBSERVED", "evidence_refs": [still]},
    )
    assert failed.status_code == 200
    assert failed.json()["status"] == "DONE"
    row = failed.json()["history"][-1]
    assert row["result"] == "FAIL"
    assert row["detail"]["still_observed"] == [still]
    assert row["model_version"] is None, "an observation involves no model"

    # A later live recheck confirms it: PASS, and the states stay distinct.
    clear = _real_event(db_session, membership.user_id, "p7-recheck-clear",
                        event_type="PASSWORD_REUSE", status="CHECKED_SAFE", source_mode="REAL")
    passed = client.post(
        f"/api/remediation/tasks/{task['id']}/verify", headers=admin,
        json={"method": "VERIFIED_OBSERVED", "evidence_refs": [clear]},
    )
    assert passed.status_code == 200
    body = passed.json()
    assert body["status"] == "VERIFIED_OBSERVED"
    assert body["status"] != "VERIFIED_MODELED", "the two verified states never merge"
    row = body["history"][-1]
    assert row["result"] == "OK"
    assert row["to_status"] == "VERIFIED_OBSERVED"
    assert row["model_version"] is None


def test_verified_states_are_never_overwritten(client, db_session):
    admin = register_org_admin(client, org_name="Merge Co")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)
    task = _create_task(client, admin, action_key="change_reused_password")
    client.post(f"/api/remediation/tasks/{task['id']}/complete", headers=admin)
    client.post(
        f"/api/remediation/tasks/{task['id']}/verify", headers=admin,
        json={"method": "VERIFIED_MODELED", "attested": True},
    )
    # Re-verify with the other method: 409 — reopen first, never merge.
    assert client.post(
        f"/api/remediation/tasks/{task['id']}/verify", headers=admin,
        json={"method": "VERIFIED_OBSERVED", "evidence_refs": ["x"]},
    ).status_code == 409


def test_verify_from_open_is_rejected_and_rbac_gates_it(client, db_session):
    admin = register_org_admin(client, org_name="Verify Rbac Co")
    member = _add_member(client, admin, "member@ver.example.com", "MEMBER")
    viewer = _add_member(client, admin, "viewer@ver.example.com", "VIEWER")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)
    task = _create_task(client, admin)

    # Verify an OPEN task: 409 (must be claimed done first).
    assert client.post(
        f"/api/remediation/tasks/{task['id']}/verify", headers=admin,
        json={"method": "VERIFIED_MODELED", "attested": True},
    ).status_code == 409
    # Only ORG_ADMIN verifies/reopens; MEMBER and VIEWER never can.
    client.post(f"/api/remediation/tasks/{task['id']}/complete", headers=admin)
    for headers in (member, viewer):
        assert client.post(
            f"/api/remediation/tasks/{task['id']}/verify", headers=headers,
            json={"method": "VERIFIED_MODELED", "attested": True},
        ).status_code == 403
        assert client.post(
            f"/api/remediation/tasks/{task['id']}/reopen", headers=headers,
            json={},
        ).status_code == 403
        assert client.patch(
            f"/api/remediation/tasks/{task['id']}", headers=headers,
            json={"effort": 5.0},
        ).status_code == 403


def test_reopen_preserves_history_and_resets_completion(client, db_session):
    admin = register_org_admin(client, org_name="Reopen Co")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)
    task = _create_task(client, admin, action_key="change_reused_password")
    client.post(f"/api/remediation/tasks/{task['id']}/complete", headers=admin)
    client.post(
        f"/api/remediation/tasks/{task['id']}/verify", headers=admin,
        json={"method": "VERIFIED_MODELED", "attested": True},
    )
    before = client.get(
        f"/api/remediation/tasks/{task['id']}", headers=admin
    ).json()["history"]
    assert [h["method"] for h in before] == ["CREATED", "COMPLETED", "VERIFICATION_ATTEMPTED"]

    reopened = client.post(
        f"/api/remediation/tasks/{task['id']}/reopen", headers=admin,
        json={"reason": "regression found"},
    )
    assert reopened.status_code == 200
    body = reopened.json()
    assert body["status"] == "OPEN"
    assert body["completed_at"] is None, "a reopened task is not completed"

    after = client.get(
        f"/api/remediation/tasks/{task['id']}", headers=admin
    ).json()["history"]
    # Append-only: every earlier row survives byte-for-byte, plus REOPENED.
    assert len(after) == len(before) + 1
    assert after[: len(before)] == before
    assert after[-1]["method"] == "REOPENED"
    assert after[-1]["from_status"] == "VERIFIED_MODELED"
    assert after[-1]["to_status"] == "OPEN"
    assert after[-1]["detail"]["reason"] == "regression found"

    # From OPEN, reopening is a 409; the task can then be completed again.
    assert client.post(
        f"/api/remediation/tasks/{task['id']}/reopen", headers=admin, json={}
    ).status_code == 409
    assert client.post(
        f"/api/remediation/tasks/{task['id']}/complete", headers=admin
    ).status_code == 200


def test_failed_verification_then_successful_retry_keeps_both_rows(client, db_session):
    admin = register_org_admin(client, org_name="Retry Co")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)
    task = _create_task(client, admin, action_key="change_reused_password")
    client.post(f"/api/remediation/tasks/{task['id']}/complete", headers=admin)

    still = _real_event(db_session, membership.user_id, "p7-retry-still",
                        event_type="PASSWORD_REUSE", status="FINDING", source_mode="REAL")
    clear = _real_event(db_session, membership.user_id, "p7-retry-clear",
                        event_type="PASSWORD_REUSE", status="CHECKED_SAFE", source_mode="REAL")
    client.post(
        f"/api/remediation/tasks/{task['id']}/verify", headers=admin,
        json={"method": "VERIFIED_OBSERVED", "evidence_refs": [still]},
    )
    client.post(
        f"/api/remediation/tasks/{task['id']}/verify", headers=admin,
        json={"method": "VERIFIED_OBSERVED", "evidence_refs": [clear]},
    )
    history = client.get(
        f"/api/remediation/tasks/{task['id']}", headers=admin
    ).json()["history"]
    attempts = [h for h in history if h["method"] == "VERIFICATION_ATTEMPTED"]
    assert [a["result"] for a in attempts] == ["FAIL", "OK"], (
        "the failed attempt is preserved, not overwritten by the retry"
    )
    assert attempts[0]["evidence_refs"] == [still]
    assert attempts[1]["evidence_refs"] == [clear]


def test_audit_log_covers_the_full_lifecycle(client, db_session):
    admin = register_org_admin(client, org_name="Audit Co")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)
    task = _create_task(client, admin, action_key="change_reused_password")
    client.patch(
        f"/api/remediation/tasks/{task['id']}", headers=admin, json={"effort": 2.5}
    )
    client.post(f"/api/remediation/tasks/{task['id']}/complete", headers=admin)
    client.post(
        f"/api/remediation/tasks/{task['id']}/verify", headers=admin,
        json={"method": "VERIFIED_MODELED", "attested": True},
    )
    client.post(f"/api/remediation/tasks/{task['id']}/reopen", headers=admin, json={})
    client.post("/api/remediation/plan", headers=admin)
    client.get("/api/remediation/tasks", headers=admin)
    client.patch("/api/remediation/settings", headers=admin, json={"effort_budget": 7.0})

    actions = {
        row[0]
        for row in db_session.execute(
            select(AuditLog.action).where(AuditLog.user_id == membership.user_id)
        ).all()
    }
    assert {
        "remediation.task_created",
        "remediation.task_updated",
        "remediation.task_completed",
        "remediation.task_verified",
        "remediation.task_reopened",
        "remediation.plan_computed",
        "remediation.tasks_read",
        "remediation.settings_updated",
    } <= actions


# --------------------------------------------------------------------------- #
# Planning endpoint: org budget, real initial risk, task mapping
# --------------------------------------------------------------------------- #
def test_plan_endpoint_uses_org_budget_and_maps_tasks(client, db_session):
    admin = register_org_admin(client, org_name="Plan Co")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)
    reuse_task = _create_task(client, admin, action_key="change_reused_password")
    mfa_task = _create_task(client, admin, action_key="strengthen_mfa")

    response = client.post("/api/remediation/plan", headers=admin)
    assert response.status_code == 200
    body = response.json()
    assert body["budget"] == 6.0, "the default is the admin-set org budget"
    assert body["budget_source"] == "organization_setting"
    assert body["candidate_action_keys"] == ["change_reused_password", "strengthen_mfa"]
    assert body["task_map"]["change_reused_password"] == [reuse_task["id"]]
    assert body["task_map"]["strengthen_mfa"] == [mfa_task["id"]]
    # The planner's initial risk IS the run's score (same vector, same engine).
    assert body["initial_risk"] == pytest.approx(body["run_score"], abs=1e-3)
    # Plans are mapped back to task ids deterministically.
    assert set(body["greedy"]["task_ids"]) <= {reuse_task["id"], mfa_task["id"]}
    assert "approximate baseline" in body["labels"]["greedy"]
    assert "proven optimal over these candidates" in body["labels"]["exact"]
    assert "never" in body["note"]

    # The admin-set budget is what the org actually uses.
    client.patch("/api/remediation/settings", headers=admin, json={"effort_budget": 1.0})
    tight = client.post("/api/remediation/plan", headers=admin).json()
    assert tight["budget"] == 1.0
    assert tight["greedy"]["total_effort"] <= 1.0 + 1e-9


def test_plan_endpoint_budget_override_and_member_access(client, db_session):
    admin = register_org_admin(client, org_name="Override Co")
    member = _add_member(client, admin, "member@plan.example.com", "MEMBER")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)
    _create_task(client, admin, action_key="change_reused_password")

    response = client.post("/api/remediation/plan?budget=1.0", headers=member)
    assert response.status_code == 200
    body = response.json()
    assert body["budget"] == 1.0
    assert body["budget_source"] == "request"
    assert body["greedy"]["total_effort"] <= 1.0 + 1e-9

    # Bounds are enforced.
    assert client.post(
        "/api/remediation/plan?budget=0", headers=admin
    ).status_code == 422
    assert client.post("/api/remediation/plan").status_code == 401


def test_plan_endpoint_with_no_open_tasks_is_an_empty_plan(client, db_session):
    admin = register_org_admin(client, org_name="Empty Plan Co")
    membership = _membership(db_session, "admin@example.com")
    _seed_findings(db_session, membership.user_id)

    body = client.post("/api/remediation/plan", headers=admin).json()
    assert body["candidate_action_keys"] == []
    assert body["greedy"]["actions"] == [] and body["exact"]["actions"] == []
    assert body["optimality_gap"] == 0.0
    assert body["initial_risk"] == pytest.approx(body["run_score"], abs=1e-3)

    # Done/verified tasks are not candidates — only OPEN tasks plan.
    task = _create_task(client, admin, action_key="strengthen_mfa")
    client.post(f"/api/remediation/tasks/{task['id']}/complete", headers=admin)
    after = client.post("/api/remediation/plan", headers=admin).json()
    assert after["candidate_action_keys"] == []
    assert after["task_map"] == {}
