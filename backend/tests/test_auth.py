"""Auth + IDOR tests (§2, §14)."""
from __future__ import annotations

import pytest

from tests.conftest import register_and_login


def test_register_login_me(client, auth_headers):
    me = client.get("/api/auth/me", headers=auth_headers)
    assert me.status_code == 200
    assert me.json()["email"] == "user@example.com"


def test_duplicate_registration_rejected(client):
    client.post("/api/auth/register", json={"email": "dup@example.com", "password": "a-long-password-1"})
    second = client.post(
        "/api/auth/register", json={"email": "dup@example.com", "password": "a-long-password-2"}
    )
    assert second.status_code == 409


def test_weak_password_rejected(client):
    response = client.post("/api/auth/register", json={"email": "weak@example.com", "password": "short"})
    assert response.status_code == 422


def test_login_wrong_password(client):
    client.post("/api/auth/register", json={"email": "x@example.com", "password": "a-long-password-1"})
    response = client.post("/api/auth/login", json={"email": "x@example.com", "password": "wrong-password"})
    assert response.status_code == 401


def test_unauthenticated_access_denied(client):
    assert client.get("/api/accounts").status_code == 401
    assert client.post("/api/analysis/run").status_code == 401


def test_refresh_rotation(client):
    data = register_and_login(client, email="rot@example.com")
    csrf = data["csrf_token"]
    refreshed = client.post("/api/auth/refresh", headers={"X-CSRF-Token": csrf})
    assert refreshed.status_code == 200
    new_csrf = refreshed.json()["csrf_token"]
    # Reusing the old CSRF should fail (rotation produced a new session token).
    replay = client.post("/api/auth/refresh", headers={"X-CSRF-Token": csrf})
    assert replay.status_code == 403


def test_refresh_requires_csrf(client):
    register_and_login(client, email="csrf@example.com")
    response = client.post("/api/auth/refresh")
    assert response.status_code == 403


def test_logout_clears_session(client):
    data = register_and_login(client, email="lo@example.com")
    response = client.post("/api/auth/logout", headers={"X-CSRF-Token": data["csrf_token"]})
    assert response.status_code == 204
    assert client.post("/api/auth/refresh").status_code == 401


def test_idor_user_cannot_read_other_account(client):
    # User A creates an account.
    a = register_and_login(client, email="a@example.com")
    a_headers = {"Authorization": f"Bearer {a['access_token']}"}
    created = client.post(
        "/api/accounts",
        json={"account_id": "acct-A", "label": "A's Gmail", "service_name": "Google",
              "email": "a@example.com"},
        headers=a_headers,
    )
    assert created.status_code == 201

    # User B logs in (overwriting the client cookie jar) and must not see A's data.
    b = register_and_login(client, email="b@example.com")
    b_headers = {"Authorization": f"Bearer {b['access_token']}"}
    listing = client.get("/api/accounts", headers=b_headers)
    assert listing.status_code == 200
    # B legitimately has exactly their own registered-email account (Feature A);
    # the IDOR invariant is that nothing belonging to A leaks to B.
    assert [row["account_id"] for row in listing.json()] == ["registered-email"]
    assert all(row["email"] == "b@example.com" for row in listing.json())

    direct = client.get("/api/accounts/acct-A", headers=b_headers)
    assert direct.status_code == 404  # not found for B, existence not confirmed


def test_idor_user_cannot_modify_other_account(client):
    a = register_and_login(client, email="a2@example.com")
    a_headers = {"Authorization": f"Bearer {a['access_token']}"}
    client.post(
        "/api/accounts",
        json={"account_id": "acct-A2", "label": "A's account", "email": "a2@example.com"},
        headers=a_headers,
    )
    b = register_and_login(client, email="b2@example.com")
    b_headers = {"Authorization": f"Bearer {b['access_token']}"}
    assert client.delete("/api/accounts/acct-A2", headers=b_headers).status_code == 404


def test_login_rate_limited(client, settings):
    client.post("/api/auth/register", json={"email": "rl@example.com", "password": "a-long-password-1"})
    statuses = []
    for _ in range(settings.login_rate_limit_per_minute + 3):
        response = client.post(
            "/api/auth/login", json={"email": "rl@example.com", "password": "wrong"}
        )
        statuses.append(response.status_code)
    assert 429 in statuses


def test_password_reset_token_single_use(client):
    import re
    from pathlib import Path

    email = "pr-reset-single@example.com"
    client.post("/api/auth/register", json={"email": email, "password": "a-long-password-1"})
    resp = client.post("/api/auth/password-reset/request", json={"email": email})
    assert resp.status_code == 202

    # Read the raw token from the dev outbox (it is deliberately NOT logged).
    outbox = Path(__file__).resolve().parents[1] / "artifacts" / "outbox"
    pattern = "*pr-reset-single_at_example.com.eml"
    for stale in outbox.glob(pattern):
        stale.unlink()
    # Re-request now that the outbox is clean, so we read exactly one file.
    client.post("/api/auth/password-reset/request", json={"email": email})
    files = sorted(outbox.glob(pattern), key=lambda p: p.stat().st_mtime)
    assert files, "reset email was not written to the dev outbox"
    text = files[-1].read_text(encoding="utf-8")
    match = re.search(r"token=([A-Za-z0-9_\-]+)", text)
    assert match, "reset link missing a token"
    raw_token = match.group(1)

    first = client.post(
        "/api/auth/password-reset/confirm",
        json={"token": raw_token, "new_password": "a-brand-new-password"},
    )
    assert first.status_code == 200, first.text

    # Single-use: the same token cannot be used again.
    second = client.post(
        "/api/auth/password-reset/confirm",
        json={"token": raw_token, "new_password": "another-password-99"},
    )
    assert second.status_code == 400

    # The new password actually works.
    login = client.post(
        "/api/auth/login", json={"email": email, "password": "a-brand-new-password"}
    )
    assert login.status_code == 200


def test_password_reset_unknown_email_does_not_enumerate(client):
    resp = client.post("/api/auth/password-reset/request", json={"email": "nobody@example.com"})
    assert resp.status_code == 202
    assert "reset link" in resp.json()["detail"]


def test_seeded_demo_email_is_accepted_by_the_api(client):
    """The demo account must be able to log in through the real API.

    Regression guard: the seed once defaulted to ``demo@crix.local``, which
    Pydantic's ``EmailStr`` rejects as an RFC 6761 special-use domain — so the
    documented demo login returned 422 while the seed happily created the user.
    Seed and API must always agree on what an address is.
    """
    import re
    from pathlib import Path

    seed = Path(__file__).resolve().parents[1] / "scripts" / "seed_demo.py"
    match = re.search(r'--email",\s*default="([^"]+)"', seed.read_text(encoding="utf-8"))
    assert match, "seed_demo.py no longer declares a default demo email"
    demo_email = match.group(1)

    # The API's own registration schema must accept it (email AND password).
    from app.schemas import RegisterRequest

    password = "a-long-password-1"
    RegisterRequest(email=demo_email, password=password)

    # And an end-to-end register + login round-trip must succeed.
    registered = client.post("/api/auth/register", json={"email": demo_email, "password": password})
    assert registered.status_code in (201, 409), registered.text

    login = client.post("/api/auth/login", json={"email": demo_email, "password": password})
    if registered.status_code == 409:
        # Already seeded in this DB — just prove the address is login-shaped.
        assert login.status_code in (200, 401), login.text
    else:
        assert login.status_code == 200, login.text