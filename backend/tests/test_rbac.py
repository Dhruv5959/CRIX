"""Role-based access control (§4): the role is enforced server-side.

The matrix under test is documented in ``docs/RBAC.md``:

* ORG_ADMIN  — manages assets, criticality, dependencies, invitations, org.
* MEMBER     — reads organization aggregates and its own member detail.
* VIEWER     — read-only access to aggregates.
"""
from __future__ import annotations

from tests.conftest import login_headers, register_org_admin

PASSWORD = "correct horse battery"


def _add_member(client, admin_headers, email: str, role: str) -> dict:
    """Invite someone, accept the invitation, and return their auth headers."""
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


def test_viewer_cannot_write(client):
    admin = register_org_admin(client, "admin@rbac.example.com", org_name="RBAC Co")
    viewer = _add_member(client, admin, "viewer@rbac.example.com", "VIEWER")

    # Read is allowed.
    assert client.get("/api/assets", headers=viewer).status_code == 200
    assert client.get("/api/org", headers=viewer).status_code == 200

    # Every write is denied.
    assert (
        client.post(
            "/api/assets",
            headers=viewer,
            json={"asset_id": "x", "asset_type": "DOMAIN", "label": "x"},
        ).status_code
        == 403
    )
    assert client.patch("/api/org", headers=viewer, json={"name": "Nope"}).status_code == 403
    assert (
        client.post(
            "/api/invitations",
            headers=viewer,
            json={"email": "someone@rbac.example.com", "role": "MEMBER"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/dependencies",
            headers=viewer,
            json={"from_asset_id": "a", "to_asset_id": "b", "relationship_type": "uses"},
        ).status_code
        == 403
    )


def test_member_cannot_manage_assets_or_invite(client):
    admin = register_org_admin(client, "admin2@rbac.example.com", org_name="RBAC Co 2")
    member = _add_member(client, admin, "member@rbac.example.com", "MEMBER")

    assert (
        client.post(
            "/api/assets",
            headers=member,
            json={"asset_id": "repo", "asset_type": "CODE_REPOSITORY", "label": "Repo"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/invitations",
            headers=member,
            json={"email": "x@rbac.example.com", "role": "MEMBER"},
        ).status_code
        == 403
    )
    # But a member may read aggregates.
    assert client.get("/api/members", headers=member).status_code == 200


def test_member_cannot_read_another_members_detail(client):
    admin = register_org_admin(client, "admin3@rbac.example.com", org_name="RBAC Co 3")
    member_a = _add_member(client, admin, "m1@rbac.example.com", "MEMBER")
    _add_member(client, admin, "m2@rbac.example.com", "MEMBER")

    members = client.get("/api/members", headers=member_a).json()
    m2 = next(m for m in members if m["email"] == "m2@rbac.example.com")

    denied = client.get(f"/api/members/{m2['membership_id']}", headers=member_a)
    assert denied.status_code == 403

    # A member may always read their own detail.
    m1 = next(m for m in members if m["email"] == "m1@rbac.example.com")
    assert client.get(f"/api/members/{m1['membership_id']}", headers=member_a).status_code == 200


def test_admin_role_cannot_be_self_assigned_by_client(client):
    """Registration always yields ORG_ADMIN for the FIRST member only; a client
    cannot escalate a later membership through an invitation either."""
    admin = register_org_admin(client, "admin4@rbac.example.com", org_name="RBAC Co 4")
    viewer = _add_member(client, admin, "v4@rbac.example.com", "VIEWER")

    # The viewer cannot promote themselves.
    me = client.get("/api/members", headers=viewer).json()
    self_row = next(m for m in me if m["email"] == "v4@rbac.example.com")
    assert self_row["role"] == "VIEWER"
    assert self_row["role"] != "ORG_ADMIN"


def test_unauthenticated_cannot_reach_org_endpoints(client):
    assert client.get("/api/org").status_code == 401
    assert client.get("/api/assets").status_code == 401
    assert client.get("/api/members").status_code == 401