"""Invitations: single-use, expiring, admin-only (§4)."""
from __future__ import annotations

import datetime as dt

from app.models import Invitation
from tests.conftest import login_headers, register_org_admin

PASSWORD = "correct horse battery"


def _token_from(link: str) -> str:
    return link.split("token=", 1)[1]


def test_invitation_accept_creates_membership_with_role(client):
    admin = register_org_admin(client, "own@inv.example.com", org_name="Inv Co")
    created = client.post(
        "/api/invitations",
        headers=admin,
        json={"email": "new@inv.example.com", "role": "MEMBER"},
    )
    assert created.status_code == 201, created.text
    token = _token_from(created.json()["invite_link"])

    accepted = client.post(
        "/api/invitations/accept", json={"token": token, "password": PASSWORD}
    )
    assert accepted.status_code == 200
    assert accepted.json()["role"] == "MEMBER"

    headers = login_headers(client, "new@inv.example.com", PASSWORD)
    rows = client.get("/api/members", headers=headers).json()
    assert any(m["email"] == "new@inv.example.com" and m["role"] == "MEMBER" for m in rows)


def test_invitation_requires_password_for_new_account(client):
    admin = register_org_admin(client, "own2@inv.example.com", org_name="Inv Co 2")
    created = client.post(
        "/api/invitations", headers=admin, json={"email": "np@inv.example.com", "role": "MEMBER"}
    )
    token = _token_from(created.json()["invite_link"])
    resp = client.post("/api/invitations/accept", json={"token": token})
    assert resp.status_code == 422


def test_invitation_is_single_use(client):
    admin = register_org_admin(client, "own3@inv.example.com", org_name="Inv Co 3")
    created = client.post(
        "/api/invitations", headers=admin, json={"email": "once@inv.example.com", "role": "MEMBER"}
    )
    token = _token_from(created.json()["invite_link"])

    assert (
        client.post(
            "/api/invitations/accept", json={"token": token, "password": PASSWORD}
        ).status_code
        == 200
    )
    # Second use is rejected.
    assert (
        client.post(
            "/api/invitations/accept", json={"token": token, "password": PASSWORD}
        ).status_code
        == 400
    )


def test_invitation_expiry_is_enforced(client, db_session):
    admin = register_org_admin(client, "own4@inv.example.com", org_name="Inv Co 4")
    created = client.post(
        "/api/invitations", headers=admin, json={"email": "late@inv.example.com", "role": "MEMBER"}
    )
    invitation_id = created.json()["id"]
    token = _token_from(created.json()["invite_link"])

    # Force the invitation into the past.
    row = db_session.get(Invitation, invitation_id)
    row.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    db_session.commit()

    assert (
        client.post(
            "/api/invitations/accept", json={"token": token, "password": PASSWORD}
        ).status_code
        == 400
    )


def test_unknown_or_revoked_invitation_is_rejected(client):
    admin = register_org_admin(client, "own5@inv.example.com", org_name="Inv Co 5")
    created = client.post(
        "/api/invitations", headers=admin, json={"email": "rev@inv.example.com", "role": "MEMBER"}
    )
    token = _token_from(created.json()["invite_link"])
    invitation_id = created.json()["id"]

    assert client.delete(f"/api/invitations/{invitation_id}", headers=admin).status_code == 204
    assert (
        client.post(
            "/api/invitations/accept", json={"token": token, "password": PASSWORD}
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/invitations/accept", json={"token": "not-a-real-token-0000", "password": PASSWORD}
        ).status_code
        == 400
    )


def test_cannot_invite_an_existing_member(client):
    admin = register_org_admin(client, "own6@inv.example.com", org_name="Inv Co 6")
    resp = client.post(
        "/api/invitations",
        headers=admin,
        json={"email": "own6@inv.example.com", "role": "MEMBER"},
    )
    assert resp.status_code == 409


def test_only_admins_may_invite_or_list(client):
    admin = register_org_admin(client, "own7@inv.example.com", org_name="Inv Co 7")
    created = client.post(
        "/api/invitations", headers=admin, json={"email": "v7@inv.example.com", "role": "VIEWER"}
    )
    token = _token_from(created.json()["invite_link"])
    client.post("/api/invitations/accept", json={"token": token, "password": PASSWORD})
    viewer = login_headers(client, "v7@inv.example.com", PASSWORD)

    assert client.get("/api/invitations", headers=viewer).status_code == 403
    assert (
        client.post(
            "/api/invitations",
            headers=viewer,
            json={"email": "x@inv.example.com", "role": "MEMBER"},
        ).status_code
        == 403
    )
    # Admin can list the pending invitations.
    assert client.get("/api/invitations", headers=admin).status_code == 200


def test_invitation_response_never_includes_a_password(client):
    """The schema simply has no password field; guard against regressions."""
    admin = register_org_admin(client, "own8@inv.example.com", org_name="Inv Co 8")
    created = client.post(
        "/api/invitations", headers=admin, json={"email": "safe@inv.example.com", "role": "MEMBER"}
    )
    body = created.json()
    assert "password" not in body and "password_hash" not in body