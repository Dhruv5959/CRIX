"""Feature E (§8): repository archive secret scanner.

Everything is offline: archives are built in-memory with ``zipfile`` and no
test touches the network. Honesty invariants asserted: ingestion safety
(traversal/symlink/bomb/limits), matched values never stored or echoed, no
silent skipping, non-zip input explicitly claims nothing, exact asset binding
and organization isolation, admin-only RBAC, dedupe on repeat scans.
"""
from __future__ import annotations

import io
import zipfile

from fastapi.testclient import TestClient

from app.engine.risk import EVENT_TO_FEATURE
from tests.conftest import TEST_SETTINGS, login_headers, register_org_admin

PASSWORD = "correct horse battery"

# Exactly AKIA + 16 chars of [0-9A-Z] (the documented length).
_AWS_KEY = "AKIAAAAAAAAAAAAAAAAA"


def _zip_builder(
    entries: dict[str, bytes],
    *,
    link_path: str | None = None,
    link_mode: int = 0o120777,
    compress: bool = True,
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            info = zipfile.ZipInfo(name)
            if compress:
                # ZipInfo defaults to ZIP_STORED regardless of the file-level
                # default — set it explicitly or ratio tests lie.
                info.compress_type = zipfile.ZIP_DEFLATED
            if link_path and name == link_path:
                info.external_attr = link_mode << 16
            archive.writestr(info, data)
    return buf.getvalue()


def _upload(client: TestClient, headers: dict, asset_id: str, blob: bytes, name="repo.zip"):
    return client.post(
        "/api/repo-scan",
        data={"asset_id": asset_id},
        files={"file": (name, blob, "application/zip")},
        headers=headers,
    )


def _make_repo_asset(client: TestClient, headers: dict, asset_id: str) -> None:
    response = client.post(
        "/api/assets",
        json={
            "asset_id": asset_id, "asset_type": "CODE_REPOSITORY",
            "label": "backend repo", "criticality": 4,
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
def test_pattern_hits_private_keys_tokens_and_assignments(client):
    admin = register_org_admin(client, "e-admin@example.com")
    _make_repo_asset(client, admin, "acme/api-repo")
    archive = _zip_builder({
        "acme/api-repo/pem/legacy.py": (
            b"AWS_KEY_MARKER = 'kept'\n"
            b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
            b"b3BlbnNzaC1rZXktdjEAAAAA\n"
        ),
        "acme/api-repo/config/settings.py": (
            b'AWS_ACCESS_KEY_ID = "' + b"AKIA" + b"ABCDEFGHIJKLMNOP" + b'"\n'
            b'db = create_engine("postgresql://deploy:S3cretPw99@db.internal/acme")\n'
            b'token = "' + b"ghp_" + b"1234567890abcdefghij1234567890ABCD" + b'"\n'
            b'SLACK = "' + b"xoxb-" + b"123456789012-abcdefghijklmn" + b'"\n'
        ),
        "acme/api-repo/README.md": b"# acme backend\n",
    })
    response = _upload(client, admin, "acme/api-repo", archive)
    assert response.status_code == 200, response.text
    body = response.json()
    categories = {f["category"] for f in body["findings"]}
    assert "private_key_block" in categories
    assert "aws_access_key_id" in categories
    assert "secret_in_url" in categories
    assert "github_token" in categories
    assert "slack_token" in categories
    assert body["files_scanned"] == 3
    assert len(body["events"]) == 1, "one aggregated event per scan"
    event = body["events"][0]
    assert event["event_type"] == "SECRET_PATTERN_MATCHED"
    assert event["status"] == "FINDING"
    assert event["asset_id"] == "acme/api-repo"
    assert event["source_mode"] == "USER_PROVIDED"
    # every finding hides the value: fingerprints only
    for finding in body["findings"]:
        assert finding["value_stored"] is False
        assert finding["fingerprint"].startswith("sha256:")


def test_values_never_appear_in_any_response_or_event(client):
    admin = register_org_admin(client, "e-no-leak@example.com")
    _make_repo_asset(client, admin, "leaky/repo")
    archive = _zip_builder({
        "leaky/repo/app.py": b'ADMIN_PASSWORD = "SuperSecretBreached42"\n'
        b'aws_key = "AKIABADBADBADBADBADB"\n',
    })
    body = _upload(client, admin, "leaky/repo", archive).json()
    blob = str(body)
    assert "SuperSecretBreached42" not in blob
    assert "AKIABADBADBADBADBADB" not in blob
    # the LHS key name is allowed (structure, not a secret)
    categories = {f["category"] for f in body["findings"]}
    assert "credential_assignment" in categories
    assert "aws_access_key_id" in categories
    event = body["events"][0]
    assert event["evidence"]["values_stored"] is False
    assert "SuperSecretBreached42" not in str(event["evidence"]["findings"])


def test_false_positives_refused(client):
    admin = register_org_admin(client, "e-fp@example.com")
    _make_repo_asset(client, admin, "clean/repo")
    archive = _zip_builder({
        "clean/repo/settings.py": (
            b'password = os.environ["PASSWORD"]\n'
            b'API_KEY = "${VAULT_API_KEY}"\n'
            b'secret = "your-api-key-here"\n'
            b'client_secret = "{{ templated }}"\n'
            b'recover = "changeme"\n'
        ),
    })
    body = _upload(client, admin, "clean/repo", archive).json()
    assert body["findings"] == []
    assert body["events"] == []
    assert "not a statement about the repository's history" in body["note"]


def test_clean_scan_claims_nothing_beyond_its_scope(client):
    admin = register_org_admin(client, "e-clean@example.com")
    _make_repo_asset(client, admin, "calm/repo")
    archive = _zip_builder({"calm/repo/main.py": b"print('hello')\n"})
    body = _upload(client, admin, "calm/repo", archive).json()
    assert body["files_scanned"] == 1
    assert body["findings"] == []
    assert body["events"] == []


# --------------------------------------------------------------------------- #
# Ingestion safety
# --------------------------------------------------------------------------- #
def test_path_traversal_and_absolute_entries_are_never_scanned(client):
    admin = register_org_admin(client, "e-trav@example.com")
    _make_repo_asset(client, admin, "trav/repo")
    archive = _zip_builder({
        "../escape/deploy.py": b'aws_key = "AKIAFEEDFACE00000000"\n',
        "C:\\user\\keys.py": b'aws_key = "AKIAFEEDFACE11111111"\n',
        "acme/okay.py": b"# nothing here\n",
    })
    body = _upload(client, admin, "trav/repo", archive).json()
    skipped = {s["path"]: s["reason"] for s in body["skipped_entries"]}
    assert any(
        ("traversal" in reason or "backslash" in reason or "drive" in reason)
        for reason in skipped.values()
    )
    # planted keys inside refused entries were never read:
    assert body["findings"] == []
    assert "AKIAFEEDFACE" not in str(body)


def test_symlink_entries_are_refused(client):
    admin = register_org_admin(client, "e-sym@example.com")
    _make_repo_asset(client, admin, "links/repo")
    archive = _zip_builder(
        {
            "normal/main.py": b"x = 1\n",
            "etc/passwd_link": b"AWS_KEY = 'AKIAFEEDFACE22222222'\n",
        },
        link_path="etc/passwd_link",
        link_mode=0o120777,
    )
    body = _upload(client, admin, "links/repo", archive).json()
    reasons = [s["reason"] for s in body["skipped_entries"]]
    assert any("link entry" in reason for reason in reasons)
    assert body["findings"] == []  # the link target was never dereferenced


def test_decompression_bomb_entry_is_refused(client):
    admin = register_org_admin(client, "e-bomb@example.com")
    _make_repo_asset(client, admin, "bomb/repo")
    archive = _zip_builder({"bomb/stuff.py": b"#" + b"A" * 400000})
    body = _upload(client, admin, "bomb/repo", archive).json()
    reasons = [s["reason"] for s in body["skipped_entries"]]
    assert any("ratio" in reason for reason in reasons)
    assert body["findings"] == []


def test_per_file_size_cap_is_enforced(client):
    admin = register_org_admin(client, "e-size@example.com")
    _make_repo_asset(client, admin, "big/repo")
    archive = _zip_builder({"big/huge.py": b"A" * (2 * 1024 * 1024 + 32)})
    body = _upload(client, admin, "big/repo", archive).json()
    reasons = [s["reason"] for s in body["skipped_entries"]]
    assert any("per-file" in reason for reason in reasons)
    assert body["files_scanned"] == 0


def test_upload_cap_returns_413(client):
    admin = register_org_admin(client, "e-cap@example.com")
    _make_repo_asset(client, admin, "cap/repo")
    blob = _zip_builder({"cap/main.py": b"x = 1\n"}) + b"\x00" * (20 * 1024 * 1024 + 1)
    response = _upload(client, admin, "cap/repo", blob)
    assert response.status_code == 413, response.text


def test_entry_count_cap_runs_no_scan(client):
    admin = register_org_admin(client, "e-count@example.com")
    _make_repo_asset(client, admin, "many/repo")
    entries = {f"many/file_{i:05}.py": b"x = 1\n" for i in range(2001)}
    archive = _zip_builder(entries)
    response = _upload(client, admin, "many/repo", archive)
    assert response.status_code == 422, response.text
    assert "no scan was run" in response.json()["detail"]


def test_non_zip_input_explicitly_claims_nothing(client):
    admin = register_org_admin(client, "e-tar@example.com")
    _make_repo_asset(client, admin, "weird/repo")
    response = _upload(client, admin, "weird/repo", b"Some archive text, definitively not a zip")
    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert "readable ZIP" in detail
    assert "no clean result is claimed" in detail


# --------------------------------------------------------------------------- #
# Storage, dedupe, isolation, RBAC
# --------------------------------------------------------------------------- #
def test_repeat_scan_replaces_not_accumulates(client):
    admin = register_org_admin(client, "e-dedupe@example.com")
    _make_repo_asset(client, admin, "dedupe/repo")
    with_key = _zip_builder({"dedupe/app.py": f'aws = "{_AWS_KEY}"\n'.encode()})
    first = _upload(client, admin, "dedupe/repo", with_key).json()
    assert len(first["events"]) == 1
    clean = _zip_builder({"dedupe/app.py": b"x = 1\n"})
    second = _upload(client, admin, "dedupe/repo", clean).json()
    assert second["events"] == []  # the earlier finding was replaced, not stacked


def test_scan_binds_findings_to_the_admins_org_asset_only(client):
    admin = register_org_admin(client, "e-iso@example.com")
    other = register_org_admin(client, "e-other@example.com")
    _make_repo_asset(client, admin, "only/mine")
    archive = _zip_builder({"only/mine/app.py": b'aws = "AKIAISOISO0000000000"\n'})

    # Unknown id for the other admin → 404 (never treated as "mine").
    assert _upload(client, other, "only/mine", archive).status_code == 404
    # Both orgs register the same asset id; results stay tenant-scoped.
    _make_repo_asset(client, other, "only/mine")
    theirs = _upload(client, other, "only/mine", archive).json()
    mine = _upload(client, admin, "only/mine", archive).json()
    assert theirs["events"][0]["org_id"] != mine["events"][0]["org_id"]
    assert mine["events"][0]["asset_id"] == "only/mine"


def test_members_cannot_scan(client):
    from urllib.parse import parse_qs, urlsplit

    admin = register_org_admin(client, "e-rbac@example.com")
    invitation = client.post(
        "/api/invitations", json={"email": "e-member@example.com", "role": "MEMBER"},
        headers=admin,
    )
    assert invitation.status_code == 201
    token = parse_qs(urlsplit(invitation.json()["invite_link"]).query)["token"][0]
    assert client.post(
        "/api/invitations/accept", json={"token": token, "password": PASSWORD}
    ).status_code == 200
    member = login_headers(client, "e-member@example.com", PASSWORD)

    blob = _zip_builder({"x/app.py": b'aws = "AKIARBAC0000000000AA"\n'})
    response = client.post(
        "/api/repo-scan",
        data={"asset_id": "whatever"},
        files={"file": ("x.zip", blob, "application/zip")},
        headers=member,
    )
    assert response.status_code == 403, response.text


def test_rate_limit_per_org(client, monkeypatch):
    admin = register_org_admin(client, "e-limit@example.com")
    _make_repo_asset(client, admin, "limit/repo")
    archive = _zip_builder({"limit/app.py": b"x = 1\n"})
    monkeypatch.setattr(TEST_SETTINGS, "repo_scan_rate_limit_per_minute", 1)
    assert _upload(client, admin, "limit/repo", archive).status_code == 200
    assert _upload(client, admin, "limit/repo", archive).status_code == 429


def test_finding_cap_marks_the_scan_truncated(client):
    admin = register_org_admin(client, "e-flood@example.com")
    _make_repo_asset(client, admin, "flood/repo")
    content = "\n".join(f'a{i} = "AKIA{str(i).zfill(16)}"' for i in range(250)).encode()
    archive = _zip_builder({"flood/app.py": content})
    body = _upload(client, admin, "flood/repo", archive).json()
    assert body["truncated_scan"] is True
    assert len(body["events"]) == 1
    assert len(body["findings"]) <= 200


# --------------------------------------------------------------------------- #
# Model-boundary guards
# --------------------------------------------------------------------------- #
def test_secret_pattern_event_is_deliberately_unmapped_in_risk():
    """The risk-model addendum (§10) pins repo findings OUT of the score."""
    assert "SECRET_PATTERN_MATCHED" not in EVENT_TO_FEATURE


def test_audit_log_never_contains_secret_values(client, db_session):
    from sqlalchemy import select

    from app.models import AuditLog

    admin = register_org_admin(client, "e-audit@example.com")
    _make_repo_asset(client, admin, "audited/repo")
    archive = _zip_builder({"audited/app.py": b'A_P = "NotARealSecretXYZ"\n'})
    _upload(client, admin, "audited/repo", archive)
    rows = list(db_session.scalars(select(AuditLog)).all())
    blob = str(rows)
    assert "NotARealSecretXYZ" not in blob
    assert any(row.action == "repo_scan.run" for row in rows)
