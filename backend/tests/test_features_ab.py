"""Feature A + B wiring: consent-based auto breach monitoring at login, and
the password-exposure outcome recorded at registration and login.

Only the sockets are faked (see xon_stubs and the HIBP guard in conftest); the
router, provider clients, normalizer and DB round-trips run for real.
"""
from __future__ import annotations

import hashlib

import pytest

from tests.conftest import register_and_login
from tests.xon_stubs import FakeResponse, patch_transport


@pytest.fixture()
def auth(client):
    return register_and_login(client, email="ab@example.com")


def _headers(data) -> dict:
    return {"Authorization": f"Bearer {data['access_token']}", "X-CSRF-Token": data["csrf_token"]}


def _suffix_for(password: str) -> str:
    """SHA-1 suffix (chars 6-40) used by the Pwned Passwords range response."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()[5:]


class _TextResponse:
    """Minimal stand-in for the raw Pwned Passwords ``range`` text response."""

    def __init__(self, text: str) -> None:
        self.status_code = 200
        self.text = text


# --------------------------------------------------------------------------- #
# Feature B — password exposure at registration and login
# --------------------------------------------------------------------------- #
def test_register_rejects_a_password_found_in_the_corpus(client, monkeypatch):
    """A matching suffix with count>0 blocks registration server-side with a
    clear, actionable message — not just a client-side hint."""
    password = "a-pwned-registration-password-99"
    text = f"{_suffix_for(password)}:23\n00000AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:5"

    def fake_range_get(url, **_kwargs):
        return _TextResponse(text)

    monkeypatch.setattr("app.signals.hibp.httpx.get", fake_range_get)
    resp = client.post(
        "/api/auth/register",
        json={"email": "pwned@example.com", "password": password},
    )
    assert resp.status_code == 422, resp.text
    assert "23 times" in resp.json()["detail"]
    assert "choose a different password" in resp.json()["detail"].lower()
    # No half-created account: login must not succeed either.
    login = client.post(
        "/api/auth/login", json={"email": "pwned@example.com", "password": password}
    )
    assert login.status_code in (400, 401, 403)


def test_register_proceeds_and_records_unavailable_when_provider_is_down(client):
    """No network (conftest forbids it) → UNAVAILABLE is recorded and
    registration follows the password-policy fallback: never labeled safe."""
    resp = client.post(
        "/api/auth/register",
        json={"email": "down@example.com", "password": "a-long-password-1"},
    )
    assert resp.status_code == 201, resp.text
    login = client.post(
        "/api/auth/login", json={"email": "down@example.com", "password": "a-long-password-1"}
    )
    assert login.status_code == 200, login.text  # login NEVER blocks on the provider
    me = client.get("/api/auth/me", headers=_headers(login.json()))
    body = me.json()
    outcome = body["last_password_exposure"]
    assert outcome["status"] == "UNAVAILABLE"
    assert outcome["provider"] == "hibp-pwned-passwords"
    assert outcome["count"] is None


def test_login_records_the_exposure_outcome_of_the_verified_password(client, monkeypatch):
    """Registration happens with the provider down; the NEXT login checks the
    just-verified password and overwrites the outcome with PWNED + count."""
    data = register_and_login(client, email="exposed@example.com")
    me_before = client.get("/api/auth/me", headers=_headers(data))
    assert me_before.json()["last_password_exposure"]["status"] == "UNAVAILABLE"

    password = "correct horse battery"
    text = f"00000AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:5\n{_suffix_for(password)}:7"
    monkeypatch.setattr("app.signals.hibp.httpx.get", lambda url, **kw: _TextResponse(text))

    login = client.post(
        "/api/auth/login", json={"email": "exposed@example.com", "password": password}
    )
    assert login.status_code == 200, login.text  # PWNED warns; it never blocks auth
    me = client.get("/api/auth/me", headers=_headers(login.json()))
    body = me.json()
    assert body["last_password_exposure"]["status"] == "PWNED"
    assert body["last_password_exposure"]["count"] == 7
    import json as _json

    assert "correct horse" not in _json.dumps(body).lower()  # plaintext stored nowhere


# --------------------------------------------------------------------------- #
# Feature A — consented automatic monitoring of the registered work email
# --------------------------------------------------------------------------- #
def test_consent_endpoint_records_opt_in_with_timestamp_and_runs_first_check(
    client, auth, monkeypatch
):
    patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    me = client.get("/api/auth/me", headers=_headers(auth))
    assert me.json()["breach_monitor_consent"] is False  # never on by default

    resp = client.post(
        "/api/signals/breach/monitor/consent", headers=_headers(auth), json={"enabled": True}
    )
    assert resp.status_code == 200, resp.text
    status = resp.json()
    assert status["enabled"] is True
    assert status["registered_email"] == "ab@example.com"
    assert status["last_breach_check_at"] is not None
    # The first check ran immediately and stored events for the self account.
    events = client.get("/api/analysis/events", headers=_headers(auth)).json()["events"]
    assert any(e["account_id"] == "registered-email" for e in events)


def test_consent_can_be_revoked(client, auth, monkeypatch):
    patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    client.post(
        "/api/signals/breach/monitor/consent", headers=_headers(auth), json={"enabled": True}
    )
    resp = client.post(
        "/api/signals/breach/monitor/consent", headers=_headers(auth), json={"enabled": False}
    )
    assert resp.json()["enabled"] is False
    me = client.get("/api/auth/me", headers=_headers(auth))
    assert me.json()["breach_monitor_consent"] is False


def test_login_auto_refreshes_only_when_consented_and_stale(
    client, db_session, auth, monkeypatch
):
    """Opt-in performs the first check; a fresh stamp suppresses the login-time
    refresh (provider quota respected); a 24h+ stale stamp re-checks."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import select

    from app.models import User

    calls = patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    email_calls = lambda: [u for u in calls if "xposedornot.com" in u]  # noqa: E731
    # (patch_transport swaps the shared httpx module's ``get``, so login-time
    # Pwned-Passwords range calls land in ``calls`` too — filter them out.)
    client.post(
        "/api/signals/breach/monitor/consent", headers=_headers(auth), json={"enabled": True}
    )
    assert email_calls(), "opt-in consent performs the first check immediately"
    calls.clear()

    client.post(
        "/api/auth/login", json={"email": "ab@example.com", "password": "correct horse battery"}
    )
    assert email_calls() == [], "fresh stamp must suppress the auto-refresh (no provider call)"

    user = db_session.scalar(select(User).where(User.email == "ab@example.com"))
    user.last_breach_check_at = datetime.now(timezone.utc) - timedelta(hours=25)
    db_session.commit()

    client.post(
        "/api/auth/login", json={"email": "ab@example.com", "password": "correct horse battery"}
    )
    assert email_calls(), "stale (>24h) stamp triggers the login-time auto-refresh"


def test_placeholder_email_is_labeled_not_meaningful(client, auth, monkeypatch):
    """The no-real-email case: any provider answer about a placeholder-style
    address carries an explicit not-meaningful warning on every event."""
    patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    resp = client.post(
        "/api/signals/breach",
        headers=_headers(auth),
        json={"account_id": "registered-email", "email": "someone@example.com"},
    )
    assert resp.status_code == 200, resp.text
    labeled = [
        e
        for e in resp.json()["events"]
        if e["event_type"] in {"BREACH_EXPOSURE", "IDENTITY_EXPOSED"}
    ]
    assert labeled  # events are still produced — the lookup really happened
    for e in labeled:
        assert "placeholder-style" in e["metadata"]["address_warning"]
