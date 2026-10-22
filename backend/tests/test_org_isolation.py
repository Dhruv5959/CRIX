"""Organization isolation (§4, §14 IDOR): no cross-organization access.

Two independent organizations are registered in the same database. Every test
proves that organization B cannot read or modify organization A's rows, and that
an id belonging to another tenant is indistinguishable from a missing one.
"""
from __future__ import annotations

from tests.conftest import register_org_admin

ASSET = {
    "asset_id": "github-acme-app",
    "asset_type": "CODE_REPOSITORY",
    "label": "Acme App repository",
    "criticality": 5,
}


def _two_orgs(client):
    a = register_org_admin(client, "alice@alpha.example.com", org_name="Alpha Ltd")
    b = register_org_admin(client, "bob@beta.example.com", org_name="Beta Ltd")
    return a, b


def test_assets_are_invisible_across_orgs(client):
    a, b = _two_orgs(client)
    created = client.post("/api/assets", headers=a, json=ASSET)
    assert created.status_code == 201, created.text

    # Beta sees an empty asset list, not Alpha's asset.
    assert client.get("/api/assets", headers=b).json() == []
    # And the asset id is simply not found for Beta (no existence leak).
    assert client.get("/api/assets/github-acme-app", headers=b).status_code == 404


def test_cross_org_asset_write_is_denied(client):
    a, b = _two_orgs(client)
    client.post("/api/assets", headers=a, json=ASSET)

    assert (
        client.patch(
            "/api/assets/github-acme-app", headers=b, json={"criticality": 1}
        ).status_code
        == 404
    )
    assert client.delete("/api/assets/github-acme-app", headers=b).status_code == 404

    # Alpha's criticality is untouched.
    assert client.get("/api/assets/github-acme-app", headers=a).json()["criticality"] == 5


def test_cross_org_member_detail_is_not_found(client):
    a, b = _two_orgs(client)
    alpha_members = client.get("/api/members", headers=a).json()
    alpha_membership_id = alpha_members[0]["membership_id"]

    # Beta cannot resolve an Alpha membership id at all.
    assert client.get(f"/api/members/{alpha_membership_id}", headers=b).status_code == 404


def test_cross_org_dependency_is_rejected(client):
    """An admin cannot link to an asset that lives in another organization."""
    a, b = _two_orgs(client)
    client.post("/api/assets", headers=a, json=ASSET)
    client.post(
        "/api/assets",
        headers=b,
        json={"asset_id": "beta-ci", "asset_type": "CI_SYSTEM", "label": "Beta CI"},
    )

    # Beta tries to depend on Alpha's asset id -> rejected (not found in Beta).
    resp = client.post(
        "/api/dependencies",
        headers=b,
        json={
            "from_asset_id": "beta-ci",
            "to_asset_id": "github-acme-app",
            "relationship_type": "deploys_to",
        },
    )
    assert resp.status_code == 404


def test_org_endpoint_is_scoped_to_caller(client):
    a, b = _two_orgs(client)
    assert client.get("/api/org", headers=a).json()["name"] == "Alpha Ltd"
    assert client.get("/api/org", headers=b).json()["name"] == "Beta Ltd"


def test_member_list_never_crosses_orgs(client):
    a, b = _two_orgs(client)
    emails_a = {m["email"] for m in client.get("/api/members", headers=a).json()}
    emails_b = {m["email"] for m in client.get("/api/members", headers=b).json()}
    assert emails_a == {"alice@alpha.example.com"}
    assert emails_b == {"bob@beta.example.com"}