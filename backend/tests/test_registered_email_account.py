"""The registered work email is always available as a signal account (Feature A).

CRIX already knows the authenticated user's email from the database, so every
user must have a "self" signal account — all four signal features work at login
without manually connecting anything, and extra accounts can still be added.
"""
from __future__ import annotations

from sqlalchemy import select

from app.models import ConnectedSignal, User
from tests.conftest import register_and_login

SELF_ACCOUNT_ID = "registered-email"


def test_register_creates_the_registered_email_account_first(client, db_session):
    admin = register_and_login(client, email="self-a@example.com")
    headers = {"Authorization": f"Bearer {admin['access_token']}"}
    rows = client.get("/api/accounts", headers=headers).json()
    assert rows, "no accounts returned"
    assert rows[0]["account_id"] == SELF_ACCOUNT_ID
    assert rows[0]["email"] == "self-a@example.com"
    assert rows[0]["label"] == "Your work email"
    assert rows[0]["source"] == "registered"


def test_login_backfills_the_account_for_legacy_users(client, db_session):
    email = "legacy@example.com"
    register_and_login(client, email=email)
    # Simulate a user who was registered before this feature existed.
    row = db_session.scalar(
        select(ConnectedSignal).where(
            ConnectedSignal.account_id == SELF_ACCOUNT_ID,
            ConnectedSignal.email == email,
        )
    )
    assert row is not None
    db_session.delete(row)
    db_session.commit()

    login = client.post("/api/auth/login", json={"email": email, "password": "correct horse battery"})
    assert login.status_code == 200
    rows = client.get("/api/accounts", headers={"Authorization": f"Bearer {login.json()['access_token']}"}).json()
    assert any(a["account_id"] == SELF_ACCOUNT_ID and a["email"] == email for a in rows)


def test_registered_email_account_is_deletable_but_restored_on_login(client):
    admin = register_and_login(client, email="self-c@example.com")
    headers = {"Authorization": f"Bearer {admin['access_token']}"}
    assert (
        client.delete(f"/api/accounts/{SELF_ACCOUNT_ID}", headers=headers).status_code == 204
    )
    rows = client.get("/api/accounts", headers=headers).json()
    assert all(a["account_id"] != SELF_ACCOUNT_ID for a in rows)
    # A fresh login restores it (not silently on every read: GET stays pure).
    login = client.post("/api/auth/login", json={"email": "self-c@example.com", "password": "correct horse battery"})
    rows = client.get(
        "/api/accounts", headers={"Authorization": f"Bearer {login.json()['access_token']}"}
    ).json()
    assert rows[0]["account_id"] == SELF_ACCOUNT_ID


def test_breach_check_runs_against_the_registered_email_account(client, db_session):
    """The self account is a real target for signal runs (offline: provider
    lookup fails loudly as UNAVAILABLE — never fabricated SAFE results)."""
    admin = register_and_login(client, email="self-d@example.com")
    headers = {"Authorization": f"Bearer {admin['access_token']}"}
    user = db_session.scalar(select(User).where(User.email == "self-d@example.com"))
    assert user is not None
    user.email_verified = True
    user.breach_monitor_consent = True
    db_session.commit()
    resp = client.post(
        "/api/signals/breach",
        headers=headers,
        json={"account_id": SELF_ACCOUNT_ID, "email": "self-d@example.com"},
    )
    assert resp.status_code == 200, resp.text
    events = resp.json()["events"]
    assert events, "breach run must record events even when the provider is unreachable"
    assert all(e["status"] in {"UNAVAILABLE"} for e in events if e["event_type"] == "BREACH_EXPOSURE")
    # Events are stored against the self account, so a later GET of the page
    # can show the stored result.
    listed = client.get("/api/analysis/events", headers=headers).json()["events"]
    assert any(e["account_id"] == SELF_ACCOUNT_ID for e in listed)
