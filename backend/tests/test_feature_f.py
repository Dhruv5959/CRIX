"""Feature F (§9.F): organization access audit.

Covers: admin CRUD on declared member→asset access records, exact tenant/RBAC
behavior, remove-with-history, review stamping, the review-candidate engine
(departed / stale / elevated), one aggregated per-asset event with module
replace semantics (including across DIFFERENT admins of the same org), and
the pinned risk-model mapping (ACCESS_REVIEW_NEEDED → permissions pool).

No deactivation endpoint exists (deliberate — member deactivation is not an
implemented feature): departed-member scenarios model the departure directly
through the ORM, exactly as the real production state would be.
"""
from __future__ import annotations

import datetime as dt
from urllib.parse import parse_qs, urlsplit

from sqlalchemy import select

from app.engine.risk import EVENT_TO_FEATURE
from app.models import AssetAccessRecord, AssetAccessRecordHistory, Membership, SecurityEvent, User
from tests.conftest import login_headers, register_org_admin

PASSWORD = "correct horse battery"
TARGET = "f-target@example.com"
ASSET = "vault.acme.internal"


def _seed_asset(client, headers: dict, asset_id: str = ASSET) -> None:
    response = client.post(
        "/api/assets",
        json={
            "asset_id": asset_id, "asset_type": "CLOUD_STORAGE",
            "label": "Client vault", "criticality": 5,
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text


def _invite_member(client, admin_headers: dict, email: str, role: str = "MEMBER") -> dict:
    invitation = client.post(
        "/api/invitations", json={"email": email, "role": role}, headers=admin_headers
    )
    assert invitation.status_code == 201, invitation.text
    token = parse_qs(urlsplit(invitation.json()["invite_link"]).query)["token"][0]
    accept = client.post("/api/invitations/accept", json={"token": token, "password": PASSWORD})
    assert accept.status_code == 200, accept.text
    return accept.json()


def _membership_id(client, headers: dict, email: str) -> str:
    members = client.get("/api/members", headers=headers).json()
    return next(m["membership_id"] for m in members if m["email"] == email)


def _create_record(client, admin_headers: dict, membership_id: str, level="VIEW", asset=ASSET):
    return client.post(
        "/api/access/records",
        json={"membership_id": membership_id, "asset_id": asset, "level": level},
        headers=admin_headers,
    )


def _find_membership(db, email: str) -> Membership:
    return db.scalars(
        select(Membership).join(User, User.id == Membership.user_id).where(User.email == email)
    ).one()


def _stored_candidates(db) -> list[SecurityEvent]:
    return list(db_session_rows(db))


def db_session_rows(db):
    return db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.event_type == "ACCESS_REVIEW_NEEDED")
        .order_by(SecurityEvent.created_at.asc(), SecurityEvent.id.asc())
    ).all()


# --------------------------------------------------------------------------- #
# CRUD + isolation
# --------------------------------------------------------------------------- #
def test_admin_can_create_and_list_access_records(client, db_session):
    admin = register_org_admin(client, "f-admin@example.com")
    _seed_asset(client, admin)
    _invite_member(client, admin, TARGET)
    member_id = _membership_id(client, admin, TARGET)

    response = _create_record(client, admin, member_id)
    assert response.status_code == 201, response.text
    row = response.json()
    assert row["level"] == "VIEW"
    assert row["status"] == "ACTIVE"
    assert row["provenance"] == "ADMIN_DECLARED"
    assert row["asset_id"] == ASSET
    assert row["member_email"] == TARGET
    assert row["last_reviewed_at"] is None

    listing = client.get("/api/access/records", headers=admin).json()
    assert listing["scope"] == "org"
    assert listing["count"] == 1
    assert listing["records"][0]["membership_id"] == member_id

    # The membership the record points at is the invited member's row.
    history = list(db_session.scalars(
        select(AssetAccessRecordHistory).where(
            AssetAccessRecordHistory.record_id == row["id"]
        )
    ).all())
    assert len(history) == 1 and history[0].method == "CREATED"
    assert history[0].actor_user_id is not None


def test_create_rejects_unknown_membership_invalid_level_and_duplicates(client):
    admin = register_org_admin(client, "f-admin2@example.com")
    _seed_asset(client, admin)
    _invite_member(client, admin, TARGET)
    member_id = _membership_id(client, admin, TARGET)

    missing = _create_record(client, admin, "not-a-real-membership")
    assert missing.status_code == 422, missing.text
    assert "not a member" in missing.json()["detail"]

    bad_level = _create_record(client, admin, member_id, level="WRITE")
    assert bad_level.status_code == 422, bad_level.text

    assert _create_record(client, admin, member_id).status_code == 201
    duplicate = _create_record(client, admin, member_id)
    assert duplicate.status_code == 409, duplicate.text


def test_cross_tenant_asset_and_membership_are_refused_loudly(client):
    admin_a = register_org_admin(client, "f-orga@example.com")
    admin_b = register_org_admin(client, "f-orgb@example.com")
    _seed_asset(client, admin_a)  # exists ONLY in org A
    _invite_member(client, admin_a, TARGET)
    member_a = _membership_id(client, admin_a, TARGET)

    # Org B does not see org A's asset: declaring access for it is 404.
    response = _create_record(client, admin_b, member_a)
    assert response.status_code == 404, response.text

    # Org B admin cannot declare access for a membership that is not theirs.
    _seed_asset(client, admin_b)  # same asset id string, org B's own row
    other_membership = _create_record(client, admin_b, member_a)
    assert other_membership.status_code == 422, other_membership.text
    assert "not a member" in other_membership.json()["detail"]

    # Records listing never leaks org A rows into org B (or vice versa).
    assert client.get("/api/access/records", headers=admin_b).json()["count"] == 0


def test_member_sees_only_own_records(client):
    admin = register_org_admin(client, "f-admin3@example.com")
    _seed_asset(client, admin)
    _invite_member(client, admin, TARGET)
    _invite_member(client, admin, "f-other@example.com")
    target_id = _membership_id(client, admin, TARGET)
    other_id = _membership_id(client, admin, "f-other@example.com")
    assert _create_record(client, admin, target_id).status_code == 201
    assert _create_record(client, admin, other_id).status_code == 201

    member_headers = login_headers(client, TARGET, PASSWORD)
    view = client.get("/api/access/records", headers=member_headers).json()
    assert view["scope"] == "own"
    assert view["count"] == 1
    assert view["records"][0]["membership_id"] == target_id
    # another member's identity stays out of the payload
    assert view["records"][0]["member_email"] is None


def test_member_is_denied_admin_operations(client, db_session):
    admin = register_org_admin(client, "f-admin4@example.com")
    _seed_asset(client, admin)
    _invite_member(client, admin, TARGET)
    member_id = _membership_id(client, admin, TARGET)
    create = _create_record(client, admin, member_id)
    assert create.status_code == 201
    record_id = create.json()["id"]

    member_headers = login_headers(client, TARGET, PASSWORD)
    assert client.post(
        "/api/access/records",
        json={"membership_id": member_id, "asset_id": ASSET, "level": "VIEW"},
        headers=member_headers,
    ).status_code == 403
    assert client.delete(f"/api/access/records/{record_id}", headers=member_headers).status_code == 403
    assert client.post(f"/api/access/records/{record_id}/review", headers=member_headers).status_code == 403
    assert client.get("/api/access/candidates", headers=member_headers).status_code == 403
    record = db_session.get(AssetAccessRecord, record_id)
    assert record.status == "ACTIVE"


def test_removal_is_soft_and_history_is_preserved(client, db_session):
    admin = register_org_admin(client, "f-admin5@example.com")
    _seed_asset(client, admin)
    _invite_member(client, admin, "f-gone@example.com")
    member_id = _membership_id(client, admin, "f-gone@example.com")
    create = _create_record(client, admin, member_id, level="USE")
    assert create.status_code == 201
    record_id = create.json()["id"]

    removed = client.delete(f"/api/access/records/{record_id}", headers=admin)
    assert removed.status_code == 200, removed.text
    assert removed.json()["status"] == "REMOVED"

    record = db_session.get(AssetAccessRecord, record_id)
    assert record is not None and record.status == "REMOVED"
    # Retire in place, never delete: the evidence chain survives.
    assert client.delete(f"/api/access/records/{record_id}", headers=admin).status_code == 409
    history = list(db_session.scalars(
        select(AssetAccessRecordHistory)
        .where(AssetAccessRecordHistory.record_id == record_id)
        .order_by(AssetAccessRecordHistory.method.asc())
    ).all())
    methods = sorted(h.method for h in history)
    assert methods == ["CREATED", "REMOVED"]
    assert all(h.actor_user_id and h.org_id for h in history)


def test_review_stamp_and_history(client, db_session):
    admin = register_org_admin(client, "f-admin6@example.com")
    _seed_asset(client, admin)
    _invite_member(client, admin, "f-review@example.com")
    member_id = _membership_id(client, admin, "f-review@example.com")
    record_id = _create_record(client, admin, member_id).json()["id"]

    stamped = client.post(f"/api/access/records/{record_id}/review", headers=admin)
    assert stamped.status_code == 200, stamped.text
    assert stamped.json()["last_reviewed_at"] is not None

    listing = client.get("/api/access/records", headers=admin).json()
    assert listing["records"][0]["last_reviewed_at"] is not None
    methods = [h.method for h in db_session.scalars(
        select(AssetAccessRecordHistory).where(AssetAccessRecordHistory.record_id == record_id)
    ).all()]
    assert "REVIEWED" in methods


def test_cross_tenant_record_is_404_for_other_admin(client):
    admin_a = register_org_admin(client, "f-admin7@example.com")
    _seed_asset(client, admin_a)
    _invite_member(client, admin_a, "f-iso@example.com")
    member_id = _membership_id(client, admin_a, "f-iso@example.com")
    record_id = _create_record(client, admin_a, member_id).json()["id"]

    admin_b = register_org_admin(client, "f-admin8@example.com")
    review = client.post(f"/api/access/records/{record_id}/review", headers=admin_b)
    delete = client.delete(f"/api/access/records/{record_id}", headers=admin_b)
    assert review.status_code == 404 and delete.status_code == 404


# --------------------------------------------------------------------------- #
# Candidate engine
# --------------------------------------------------------------------------- #
def test_no_candidates_generate_no_events(client, db_session):
    admin = register_org_admin(client, "f-clean@example.com")
    _seed_asset(client, admin)
    _invite_member(client, admin, "f-tidy@example.com")
    member_id = _membership_id(client, admin, "f-tidy@example.com")
    assert _create_record(client, admin, member_id).status_code == 201

    response = client.get("/api/access/candidates", headers=admin)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["assets"] == []
    assert body["events"] == []
    assert db_session_rows(db_session) == []


def test_departed_member_is_a_candidate(client, db_session):
    admin = register_org_admin(client, "f-departed@example.com")
    _seed_asset(client, admin)
    _invite_member(client, admin, TARGET)
    member_id = _membership_id(client, admin, TARGET)
    assert _create_record(client, admin, member_id).status_code == 201

    membership = _find_membership(db_session, TARGET)
    membership.is_active = False
    db_session.commit()

    body = client.get("/api/access/candidates", headers=admin).json()
    assert len(body["assets"]) == 1
    asset = body["assets"][0]
    assert asset["asset_id"] == ASSET
    assert asset["severity"] == 0.7
    assert len(asset["candidates"]) == 1
    reasons = [r["code"] for r in asset["candidates"][0]["reasons"]]
    assert "departed" in reasons

    assert len(body["events"]) == 1
    event = body["events"][0]
    assert event["event_type"] == "ACCESS_REVIEW_NEEDED"
    assert event["status"] == "FINDING"
    assert event["account_id"] == ASSET
    assert event["asset_id"] == ASSET
    assert event["source_mode"] == "USER_PROVIDED"
    assert event["source"] == "access_audit"
    assert abs(event["severity"] - 0.7) < 1e-9
    assert event["evidence"]["candidates"][0]["membership_id"] == member_id
    # emails never enter persistent evidence
    assert TARGET not in str(event["evidence"])


def test_stale_and_elevated_candidates(client, db_session):
    admin = register_org_admin(client, "f-stale@example.com")
    _seed_asset(client, admin)
    _invite_member(client, admin, "f-elevated@example.com")
    member_id = _membership_id(client, admin, "f-elevated@example.com")
    created = _create_record(client, admin, member_id, level="ADMIN")
    assert created.status_code == 201
    record_id = created.json()["id"]

    def _reasons(body):
        return {
            r["code"]
            for asset in body["assets"]
            for c in asset["candidates"]
            for r in c["reasons"]
        }

    # Fresh, just-granted ADMIN record: elevated only — the stale clock is
    # anchored at the grant (a review due date is the interval AFTER it).
    body = client.get("/api/access/candidates", headers=admin).json()
    assert _reasons(body) == {"elevated"}
    assert body["assets"][0]["severity"] == 0.6

    # Age the last review beyond the interval → stale joins elevated.
    record = db_session.get(AssetAccessRecord, record_id)
    record.last_reviewed_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=100)
    db_session.commit()
    aged = client.get("/api/access/candidates", headers=admin).json()
    assert _reasons(aged) == {"elevated", "stale"}
    assert aged["assets"][0]["severity"] == 0.6  # suspicion wins: max severity

    # A review stamps NOW → staleness clears; elevation remains by design.
    record.last_reviewed_at = dt.datetime.now(dt.timezone.utc)
    db_session.commit()
    fresh = client.get("/api/access/candidates", headers=admin).json()
    assert _reasons(fresh) == {"elevated"}
    # …and a non-ADMIN record in the same state is no candidate at all.
    record.level = "VIEW"
    db_session.commit()
    plain = client.get("/api/access/candidates", headers=admin).json()
    assert plain["assets"] == []


def test_candidates_replace_never_stack_within_or_across_admins(client, db_session):
    admin = register_org_admin(client, "f-replace@example.com")
    _seed_asset(client, admin)
    _invite_member(client, admin, TARGET)
    second_admin_email = "f-second@example.com"
    _invite_member(client, admin, second_admin_email, role="ORG_ADMIN")
    member_id = _membership_id(client, admin, TARGET)
    assert _create_record(client, admin, member_id).status_code == 201

    membership = _find_membership(db_session, TARGET)
    membership.is_active = False
    db_session.commit()

    first = client.get("/api/access/candidates", headers=admin).json()
    assert len(first["events"]) == 1

    # A DIFFERENT admin of the SAME org re-runs: rows replaced, not stacked.
    second_headers = login_headers(client, second_admin_email, PASSWORD)
    second = client.get("/api/access/candidates", headers=second_headers).json()
    assert len(second["events"]) == 1
    rows = db_session_rows(db_session)
    assert len(rows) == 1

    # The candidate is resolved (member reactivated) → the NEXT generation
    # replaces the module's events with none: no persistent stale finding.
    membership.is_active = True
    db_session.commit()
    third = client.get("/api/access/candidates", headers=second_headers).json()
    assert third["events"] == []
    assert db_session_rows(db_session) == []

    # …and yet the org's audit trail still holds what that scan produced.
    assert first["events"][0]["evidence"]["candidate_count"] == 1


# --------------------------------------------------------------------------- #
# Model boundary (risk mapping pinned by docs/RISK_MODEL.md §10)
# --------------------------------------------------------------------------- #
def test_access_review_event_is_mapped_to_the_permissions_pool():
    assert EVENT_TO_FEATURE.get("ACCESS_REVIEW_NEEDED") == "permissions"
