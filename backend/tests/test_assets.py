"""Company-asset model: criticality, dependency declaration, and scope (§2, §4, §7).

CRIX assesses COMPANY-OWNED assets only. Personal accounts and BYOD devices are
out of scope and must be rejected by the API, not silently accepted.
"""
from __future__ import annotations

from tests.conftest import register_org_admin


def _admin(client, email="own@assets.example.com", org="Assets Co"):
    return register_org_admin(client, email, org_name=org)


def test_asset_created_with_criticality(client):
    admin = _admin(client)
    resp = client.post(
        "/api/assets",
        headers=admin,
        json={
            "asset_id": "aws-prod-storage",
            "asset_type": "CLOUD_STORAGE",
            "label": "Production S3",
            "criticality": 5,
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["criticality"] == 5
    assert body["asset_type"] == "CLOUD_STORAGE"
    assert body["source_mode"] == "USER_PROVIDED"


def test_personal_assets_are_rejected(client):
    """BYOD / personal accounts are out of scope (§2)."""
    admin = _admin(client, "own2@assets.example.com", "Assets Co 2")
    for bad_type in ("PERSONAL_ACCOUNT", "PERSONAL_DEVICE", "PERSONAL_EMAIL", "BYOD"):
        resp = client.post(
            "/api/assets",
            headers=admin,
            json={"asset_id": f"p-{bad_type}", "asset_type": bad_type, "label": "Personal"},
        )
        assert resp.status_code == 422, f"{bad_type} must be rejected"
        assert "out of scope" in resp.text


def test_unknown_asset_type_is_rejected(client):
    admin = _admin(client, "own3@assets.example.com", "Assets Co 3")
    resp = client.post(
        "/api/assets",
        headers=admin,
        json={"asset_id": "x", "asset_type": "TOTALLY_MADE_UP", "label": "x"},
    )
    assert resp.status_code == 422


def test_criticality_bounds_are_enforced(client):
    admin = _admin(client, "own4@assets.example.com", "Assets Co 4")
    for value in (0, 6, -1):
        resp = client.post(
            "/api/assets",
            headers=admin,
            json={
                "asset_id": f"c{value}",
                "asset_type": "DOMAIN",
                "label": "d",
                "criticality": value,
            },
        )
        assert resp.status_code == 422


def test_duplicate_asset_id_is_rejected(client):
    admin = _admin(client, "own5@assets.example.com", "Assets Co 5")
    payload = {"asset_id": "dup", "asset_type": "DOMAIN", "label": "d"}
    assert client.post("/api/assets", headers=admin, json=payload).status_code == 201
    assert client.post("/api/assets", headers=admin, json=payload).status_code == 409


def test_dependency_is_admin_declared_and_requires_known_assets(client):
    admin = _admin(client, "own6@assets.example.com", "Assets Co 6")
    client.post(
        "/api/assets",
        headers=admin,
        json={"asset_id": "repo", "asset_type": "CODE_REPOSITORY", "label": "Repo", "criticality": 5},
    )
    client.post(
        "/api/assets",
        headers=admin,
        json={"asset_id": "ci", "asset_type": "CI_SYSTEM", "label": "CI"},
    )

    ok = client.post(
        "/api/dependencies",
        headers=admin,
        json={
            "from_asset_id": "ci",
            "to_asset_id": "repo",
            "relationship_type": "deploys_to",
            "weight": 0.9,
        },
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["edge_source"] == "ADMIN_DECLARED"

    # Unknown target asset -> rejected; CRIX never invents edges.
    bad = client.post(
        "/api/dependencies",
        headers=admin,
        json={"from_asset_id": "ci", "to_asset_id": "does-not-exist", "relationship_type": "uses"},
    )
    assert bad.status_code == 404


def test_asset_owner_must_be_in_same_org(client):
    admin = _admin(client, "own7@assets.example.com", "Assets Co 7")
    resp = client.post(
        "/api/assets",
        headers=admin,
        json={
            "asset_id": "owned",
            "asset_type": "WORK_EMAIL",
            "label": "Work email",
            "owner_membership_id": "not-a-real-membership",
        },
    )
    assert resp.status_code == 422


def test_asset_update_changes_criticality_and_is_audited(client, db_session):
    admin = _admin(client, "own8@assets.example.com", "Assets Co 8")
    client.post(
        "/api/assets",
        headers=admin,
        json={"asset_id": "svc", "asset_type": "BUSINESS_APP", "label": "Svc", "criticality": 2},
    )
    patched = client.patch("/api/assets/svc", headers=admin, json={"criticality": 5})
    assert patched.status_code == 200
    assert patched.json()["criticality"] == 5

    from app.models import AuditLog

    actions = [row.action for row in db_session.query(AuditLog).all()]
    assert "asset.updated" in actions