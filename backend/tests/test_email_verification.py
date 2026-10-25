"""Registered-email verification (consent gate for breach monitoring).

The verification round-trip follows the password-reset pattern: only the
SHA-256 hash is stored; the raw token exists ONLY in the outbound email (the
dev outbox file, read by these tests — never in any API response); tokens are
single-use, expiring, and replaced on re-request. The consent gate refuses to
start automatic monitoring of an address no one has proven control of.
"""
from __future__ import annotations

import re
from pathlib import Path

from sqlalchemy import select

from app.models import EmailVerificationToken, User
from app.services.email import EmailDeliveryError
from tests.conftest import TEST_SETTINGS, login_headers, register_and_login

PASSWORD = "correct horse battery"
OUTBOX = Path(__file__).resolve().parents[1] / "artifacts" / "outbox"


def _headers(client, email: str) -> dict:
    data = login_headers(client, email, PASSWORD)
    return data


def _register(client, email: str) -> dict:
    return register_and_login(client, email, PASSWORD)


def _latest_verify_token(to_email: str) -> str | None:
    """Read the raw token from the dev outbox (the only place it exists)."""
    candidates = sorted(
        OUTBOX.glob(f"*-{to_email.replace('@', '_at_')}.eml"),
        key=lambda p: p.stat().st_mtime,
    )
    if not candidates:
        return None
    content = candidates[-1].read_text(encoding="utf-8", errors="replace")
    match = re.search(r"/verify-email\?token=([A-Za-z0-9_\-]+)", content)
    return match.group(1) if match else None


def _tokens_for(db, email: str) -> list[EmailVerificationToken]:
    rows = db.scalars(
        select(EmailVerificationToken).join(User, User.id == EmailVerificationToken.user_id)
        .where(User.email == email)
    ).all()
    return list(rows)


def test_consent_gate_blocks_unverified_email(client):
    email = "gate@example.com"  # unique per test: outbox pollution-free
    _register(client, email)
    data = _headers(client, email)

    response = client.post("/api/signals/breach/monitor/consent", json={"enabled": True}, headers=data)
    assert response.status_code == 403, response.text
    assert "verify" in response.json()["detail"].lower()


def test_request_never_returns_the_token_and_replaces_pending(client, db_session):
    email = "ev-request@example.com"
    _register(client, email)
    data = _headers(client, email)

    first = client.post("/api/auth/email/verify/request", headers=data)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["sent_to"] == email
    assert body["transport"] == "dev-outbox"
    # The raw token exists in exactly one place: the outbound email.
    assert "?token" not in str(body) and "/verify-email" not in str(body)
    token_outbox = _latest_verify_token(email)
    assert token_outbox, "the dev outbox must carry the verification link"

    # A second request replaces the pending token (one live challenge per inbox).
    second = client.post("/api/auth/email/verify/request", headers=data).json()
    assert second["sent_to"] == email
    rows = _tokens_for(db_session, email)
    pending = [r for r in rows if r.used_at is None]
    assert len(pending) == 1
    token_outbox_2 = _latest_verify_token(email)
    assert token_outbox_2 and token_outbox_2 != token_outbox

    # The REVOKED first token no longer verifies anything.
    gone = client.post("/api/auth/email/verify/confirm", json={"token": token_outbox})
    assert gone.status_code == 400, gone.text
    assert "expired" in gone.json()["detail"].lower() or "invalid" in gone.json()["detail"].lower()
    assert db_session.scalar(
        select(User).where(User.email == email)
    ).email_verified is False


def test_confirm_verifies_once_and_enables_consent(client, db_session):
    email = "ev-confirm@example.com"
    _register(client, email)
    data = _headers(client, email)

    request = client.post("/api/auth/email/verify/request", headers=data)
    assert request.status_code == 200, request.text
    raw = _latest_verify_token(email)
    assert raw, "verification link must be delivered by email"

    confirmed = client.post("/api/auth/email/verify/confirm", json={"token": raw})
    assert confirmed.status_code == 200, confirmed.text
    user = db_session.scalar(select(User).where(User.email == email))
    assert user.email_verified is True

    # Single use: the same link cannot verify again.
    replay = client.post("/api/auth/email/verify/confirm", json={"token": raw})
    assert replay.status_code == 400, replay.text

    # Consent gate now passes; the monitor flow runs as usual.
    consent = client.post("/api/signals/breach/monitor/consent", json={"enabled": True}, headers=data)
    assert consent.status_code == 200, consent.text
    status = client.get("/api/signals/breach/monitor/status", headers=data).json()
    assert status["email_verified"] is True

    # Requesting verification again is an explicit conflict.
    already = client.post("/api/auth/email/verify/request", headers=data)
    assert already.status_code == 409, already.text


def test_unknown_or_expired_token_is_an_honest_failure(client, db_session):
    email = "ev-expired@example.com"
    _register(client, email)
    data = _headers(client, email)
    client.post("/api/auth/email/verify/request", headers=data)

    wrong = client.post("/api/auth/email/verify/confirm", json={"token": "x" * 43})
    assert wrong.status_code == 400, wrong.text

    import datetime as dt

    row = _tokens_for(db_session, email)[0]
    row.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    db_session.commit()
    raw = _latest_verify_token(email)
    expired = client.post("/api/auth/email/verify/confirm", json={"token": raw})
    assert expired.status_code == 400, expired.text
    user = db_session.scalar(select(User).where(User.email == email))
    assert user.email_verified is False


def test_send_rate_limit_per_user(client, monkeypatch):
    email = "ev-limit@example.com"
    _register(client, email)
    data = _headers(client, email)
    monkeypatch.setattr(TEST_SETTINGS, "email_send_rate_limit_per_hour", 1)
    assert client.post("/api/auth/email/verify/request", headers=data).status_code == 200
    second = client.post("/api/auth/email/verify/request", headers=data)
    assert second.status_code == 429, second.text


def test_delivery_failure_is_honest_and_consumes_the_undelivered_token(
    client, db_session, monkeypatch
):
    email = "ev-delivery-failure@example.com"
    _register(client, email)
    data = _headers(client, email)

    def unavailable(**_kwargs):
        raise EmailDeliveryError("SMTP unavailable")

    monkeypatch.setattr("app.routers.auth.send_email", unavailable)
    response = client.post("/api/auth/email/verify/request", headers=data)
    assert response.status_code == 503
    assert "could not be delivered" in response.json()["detail"].lower()
    rows = _tokens_for(db_session, email)
    assert len(rows) == 1
    assert rows[0].used_at is not None


def test_no_token_leaks_into_audit(client, db_session):
    from app.models import AuditLog

    email = "ev-audit@example.com"
    _register(client, email)
    data = _headers(client, email)
    client.post("/api/auth/email/verify/request", headers=data)
    raw = _latest_verify_token(email)
    assert raw
    client.post("/api/auth/email/verify/confirm", json={"token": raw})

    rows = list(db_session.scalars(select(AuditLog)).all())
    actions = {r.action for r in rows}
    # audit rows carry actions + short detail (transport, expiry) — never tokens
    details = str([getattr(r, "detail", None) for r in rows])
    assert raw not in details
    assert "email_verification.requested" in actions
    assert "email_verification.completed" in actions
