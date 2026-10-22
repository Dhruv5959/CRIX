"""Admin access to member-level data is audit-logged and member-visible (§2).

Privacy boundary:
* Admins see member-level data ONLY as aggregates unless they open a specific
  member, and every such access writes an ``AdminViewAuditLog`` row.
* The member can see every admin access to their own data via
  ``GET /api/org/admin-views``.
"""
from __future__ import annotations

from tests.conftest import login_headers, register_org_admin

PASSWORD = "correct horse battery"


def _add_member(client, admin_headers, email, role="MEMBER") -> dict:
    created = client.post(
        "/api/invitations", headers=admin_headers, json={"email": email, "role": role}
    )
    token = created.json()["invite_link"].split("token=", 1)[1]
    client.post("/api/invitations/accept", json={"token": token, "password": PASSWORD})
    return login_headers(client, email, PASSWORD)


def _membership_id(client, headers, email) -> str:
    return next(m for m in client.get("/api/members", headers=headers).json() if m["email"] == email)[
        "membership_id"
    ]


def test_admin_viewing_member_writes_audit_row_visible_to_member(client):
    admin = register_org_admin(client, "boss@audit.example.com", org_name="Audit Co")
    member = _add_member(client, admin, "dev@audit.example.com")
    mid = _membership_id(client, admin, "dev@audit.example.com")

    # Initially the member has no admin views of their data.
    assert client.get("/api/org/admin-views", headers=member).json() == []

    # The admin opens the member's detail.
    detail = client.get(f"/api/members/{mid}", headers=admin)
    assert detail.status_code == 200
    assert detail.json()["email"] == "dev@audit.example.com"

    # The member can now see that access, including who did it and why it is visible.
    views = client.get("/api/org/admin-views", headers=member).json()
    assert len(views) == 1
    assert views[0]["admin_email"] == "boss@audit.example.com"
    assert views[0]["action"] == "member_detail.viewed"
    assert views[0]["resource"] == f"membership:{mid}"


def test_viewing_own_detail_is_not_audited(client):
    admin = register_org_admin(client, "boss2@audit.example.com", org_name="Audit Co 2")
    admin_mid = _membership_id(client, admin, "boss2@audit.example.com")

    assert client.get(f"/api/members/{admin_mid}", headers=admin).status_code == 200
    # Reading your own detail never records an "admin viewed member" event.
    assert client.get("/api/org/admin-views", headers=admin).json() == []


def test_member_list_is_aggregate_only(client):
    """The directory exposes counts, never another member's findings."""
    admin = register_org_admin(client, "boss3@audit.example.com", org_name="Audit Co 3")
    _add_member(client, admin, "dev3@audit.example.com")

    row = next(
        m
        for m in client.get("/api/members", headers=admin).json()
        if m["email"] == "dev3@audit.example.com"
    )
    # Aggregate fields only — no events, findings, or risk detail.
    assert set(row) == {
        "membership_id",
        "user_id",
        "email",
        "role",
        "is_active",
        "joined_at",
        "assets_owned",
    }


def test_admin_cannot_see_other_orgs_admin_views(client):
    admin_a = register_org_admin(client, "a@audit.example.com", org_name="Audit A")
    member_a = _add_member(client, admin_a, "ma@audit.example.com")
    admin_b = register_org_admin(client, "b@audit.example.com", org_name="Audit B")
    member_b = _add_member(client, admin_b, "mb@audit.example.com")

    mid_a = _membership_id(client, admin_a, "ma@audit.example.com")
    client.get(f"/api/members/{mid_a}", headers=admin_a)

    # Member B sees none of organization A's audit rows.
    assert client.get("/api/org/admin-views", headers=member_b).json() == []
    # Member A sees exactly their own.
    assert len(client.get("/api/org/admin-views", headers=member_a).json()) == 1