"""Regression tests for the October 2026 security-hardening pass.

Each test pins ONE finding from the security review so a future change can
never silently reintroduce it:

* Invitation pre-registration takeover (binding an already-registered account
  by invite-token possession alone).
* Rate limits on /register, /password-reset/request, /invitations/accept.
* A new password-reset request invalidates previously issued unused tokens.
"""
from __future__ import annotations

import re
from pathlib import Path

from tests.conftest import register_and_login, register_org_admin

PASSWORD = "correct horse battery"


def _token_from(link: str) -> str:
    return link.split("token=", 1)[1]


def test_pre_registered_account_cannot_be_bound_by_invitation_token_alone(client):
    """Attack: attacker pre-registers the invited address, admin invites it,
    and the real recipient accepts the emailed link. The membership must NOT
    silently land on the (attacker-controlled) pre-existing account."""
    attacker = register_and_login(client, email="victim@bind.example.com")
    admin = register_org_admin(client, "admin@bind.example.com", org_name="Bind Co")
    created = client.post(
        "/api/invitations",
        headers=admin,
        json={"email": "victim@bind.example.com", "role": "ORG_ADMIN"},
    )
    assert created.status_code == 201, created.text
    token = _token_from(created.json()["invite_link"])

    # Unauthenticated accept with token + any password must be REJECTED.
    resp = client.post(
        "/api/invitations/accept", json={"token": token, "password": "attacker-password-1"}
    )
    assert resp.status_code == 403, resp.text
    detail = resp.json()["detail"]
    assert "already exists" in detail and "log in" in detail.lower()

    # The invitation is NOT consumed and NO membership was created, so the
    # legitimate owner can still accept properly afterwards.
    memberships = client.get("/api/members", headers=admin).json()
    assert all(m["email"] != "victim@bind.example.com" for m in memberships)

    # The pre-existing user can accept from their own authenticated session.
    headers = {"Authorization": f"Bearer {attacker['access_token']}"}
    accepted = client.post("/api/invitations/accept", json={"token": token}, headers=headers)
    assert accepted.status_code == 200, accepted.text
    # ...and the attacker-chosen credentials never became the account password:
    relogin = client.post(
        "/api/auth/login", json={"email": "victim@bind.example.com", "password": "attacker-password-1"}
    )
    assert relogin.status_code == 401


def test_register_is_rate_limited(client, settings):
    statuses = []
    for i in range(settings.register_rate_limit_per_minute + 3):
        response = client.post(
            "/api/auth/register",
            json={"email": f"rrl-{i}@example.com", "password": "a-long-password-1"},
        )
        statuses.append(response.status_code)
        if response.status_code == 429:
            break
    assert 429 in statuses


def test_password_reset_request_is_rate_limited(client, settings):
    statuses = []
    for i in range(settings.password_reset_rate_limit_per_minute + 2):
        response = client.post(
            "/api/auth/password-reset/request", json={"email": f"prs-{i}@example.com"}
        )
        statuses.append(response.status_code)
    assert 429 in statuses


def test_invite_accept_is_rate_limited(client, settings, db_session):
    from app.models import Membership

    admin = register_org_admin(client, "ial@inv.example.com", org_name="Rate Co")
    created = client.post(
        "/api/invitations", headers=admin, json={"email": "fresh@inv.example.com", "role": "MEMBER"}
    )
    token = _token_from(created.json()["invite_link"])
    statuses = []
    for _ in range(settings.invite_accept_rate_limit_per_minute + 1):
        # Bogus tokens: each attempt is cheap (no bcrypt) but still consumes a
        # rate-limit bucket, which is exactly what the limiter must cumulate.
        response = client.post("/api/invitations/accept", json={"token": "nope-not-real"})
        statuses.append(response.status_code)
    assert 429 in statuses
    # Nothing extra was created by the doomed attempts: only the admin's own
    # membership exists (the invitation was never successfully accepted).
    assert db_session.query(Membership).count() == 1


def test_new_password_reset_request_invalidates_older_unused_tokens(client):
    email = "stale-token@example.com"
    register_and_login(client, email=email)
    outbox = Path(__file__).resolve().parents[1] / "artifacts" / "outbox"
    pattern = "*stale-token_at_example.com.eml"
    for stale in outbox.glob(pattern):
        stale.unlink()

    client.post("/api/auth/password-reset/request", json={"email": email})
    client.post("/api/auth/password-reset/request", json={"email": email})
    files = sorted(outbox.glob(pattern), key=lambda p: p.stat().st_mtime)
    assert len(files) >= 2, "expected two reset emails"
    tokens = [re.search(r"token=([A-Za-z0-9_\-]+)", f.read_text(encoding="utf-8"))
              for f in files[-2:]]
    assert all(tokens), "reset link missing a token"
    older, newer = tokens  # sorted oldest-first by mtime

    # The OLDER token was invalidated by the second request.
    old_confirm = client.post(
        "/api/auth/password-reset/confirm",
        json={"token": older.group(1), "new_password": "a-brand-new-password"},
    )
    assert old_confirm.status_code == 400

    # The newest token still works and the reset actually applies.
    new_confirm = client.post(
        "/api/auth/password-reset/confirm",
        json={"token": newer.group(1), "new_password": "a-brand-new-password"},
    )
    assert new_confirm.status_code == 200, new_confirm.text
    login = client.post(
        "/api/auth/login", json={"email": email, "password": "a-brand-new-password"}
    )
    assert login.status_code == 200
