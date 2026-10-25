"""Breach endpoint integration tests (§3.A, integration spec §3–§9).

Only the socket is faked. Everything else runs for real: the router, the provider
client, the normalizer, the DB round-trip and the JSON contract the frontend
consumes. So these tests assert what the UI will actually receive.
"""
from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from app.models import User
from app.signals.xposedornot import reset_provider_state
from tests.xon_stubs import FakeResponse, patch_transport

ACCOUNT = "registered-email"
EMAIL = "user@example.com"


@pytest.fixture(autouse=True)
def _clean_provider_state():
    """Both the inbound limiter and the outbound throttle are process-wide."""
    reset_provider_state()
    yield
    reset_provider_state()


@pytest.fixture()
def account(auth_headers, db_session):
    """Breach lookups require the real registered-email consent gate."""
    user = db_session.scalar(select(User).where(User.email == EMAIL))
    assert user is not None
    user.email_verified = True
    user.breach_monitor_consent = True
    db_session.commit()
    return ACCOUNT


def run_breach(client, auth_headers, email: str = EMAIL, **extra):
    return client.post(
        "/api/signals/breach",
        headers=auth_headers,
        json={"account_id": ACCOUNT, "email": email, **extra},
    )


def breach_event(response) -> dict:
    events = response.json()["events"]
    return next(e for e in events if e["event_type"] == "BREACH_EXPOSURE")


# --------------------------------------------------------------------------- #
# Success + negative
# --------------------------------------------------------------------------- #
def test_successful_lookup_returns_a_normalized_result(client, auth_headers, account, monkeypatch):
    patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe", "Chegg"]]}))
    response = run_breach(client, auth_headers)
    assert response.status_code == 200

    # The response is re-read from the database, so this also proves the
    # provider metadata survives the JSON-column round-trip.
    event = breach_event(response)
    assert event["status"] == "FINDING"
    assert event["source"] == "xposedornot"
    assert event["source_mode"] == "REAL"
    assert event["severity"] > 0
    assert event["metadata"]["provider"] == "xposedornot"
    assert event["metadata"]["provider_label"] == "XposedOrNot (free community API)"
    assert event["metadata"]["breaches"] == ["Adobe", "Chegg"]
    assert event["metadata"]["breach_count"] == 2
    assert event["metadata"]["checked_at"]
    # Same instant: SQLite stores DATETIME at whole-second precision without the
    # tz suffix, so compare both at that precision.
    assert event["detected_at"][:19] == event["metadata"]["checked_at"][:19]
    # XON does not report which data classes leaked, so no exposure claim is made.
    assert event["exposure_type"] is None
    assert any(e["event_type"] == "IDENTITY_EXPOSED" for e in response.json()["events"])


def test_long_breach_lists_are_capped_but_counted_fully(client, auth_headers, account, monkeypatch):
    names = [f"Breach{i}" for i in range(40)]
    patch_transport(monkeypatch, FakeResponse(200, {"breaches": [names]}))

    event = breach_event(run_breach(client, auth_headers))
    assert event["metadata"]["breach_count"] == 40
    assert len(event["metadata"]["breaches"]) == 20
    assert event["metadata"]["breaches_truncated"] is True


def test_no_reported_breach_is_checked_safe(client, auth_headers, account, monkeypatch):
    patch_transport(monkeypatch, FakeResponse(200, {"Error": "Not found", "email": None}))
    event = breach_event(run_breach(client, auth_headers))

    assert event["status"] == "CHECKED_SAFE"
    assert event["severity"] == 0.0
    assert event["metadata"]["breach_count"] == 0
    assert event["metadata"]["breaches"] == []


# --------------------------------------------------------------------------- #
# Failure paths (§6, §7)
# --------------------------------------------------------------------------- #
def test_provider_outage_is_unavailable_never_safe(client, auth_headers, account, monkeypatch):
    patch_transport(monkeypatch, FakeResponse(503, {}))
    event = breach_event(run_breach(client, auth_headers))

    assert event["status"] == "UNAVAILABLE"
    assert event["status"] != "CHECKED_SAFE"
    assert event["severity"] == 0.0
    assert event["metadata"]["provider"] == "xposedornot"
    assert event["metadata"]["reason"]


def test_error_body_on_http_200_is_unavailable_never_safe(client, auth_headers, account, monkeypatch):
    """The live trap: an error can arrive with HTTP 200."""
    patch_transport(monkeypatch, FakeResponse(200, {"Error": "Service degraded"}))
    event = breach_event(run_breach(client, auth_headers))

    assert event["status"] == "UNAVAILABLE"


def test_timeout_is_unavailable(client, auth_headers, account, monkeypatch):
    patch_transport(monkeypatch, exc=httpx.ConnectTimeout("boom"))
    event = breach_event(run_breach(client, auth_headers))

    assert event["status"] == "UNAVAILABLE"
    assert "ConnectTimeout" in event["metadata"]["reason"]
    assert EMAIL not in event["metadata"]["reason"]


def test_rate_limited_provider_is_unavailable(client, auth_headers, account, monkeypatch):
    patch_transport(monkeypatch, FakeResponse(429, {}, headers={"Retry-After": "60"}))
    event = breach_event(run_breach(client, auth_headers))

    assert event["status"] == "UNAVAILABLE"
    assert "rate limit" in event["metadata"]["reason"].lower()


def test_invalid_email_is_rejected_before_any_provider_call(client, auth_headers, account, monkeypatch):
    calls = patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    response = run_breach(client, auth_headers, email="not-an-email")

    assert response.status_code == 422
    assert calls == []  # no quota spent, and no verdict invented


# --------------------------------------------------------------------------- #
# Replace semantics + real/simulated separation
# --------------------------------------------------------------------------- #
def test_rechecking_replaces_the_previous_verdict(
    client, auth_headers, account, db_session, monkeypatch
):
    patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    assert breach_event(run_breach(client, auth_headers))["status"] == "FINDING"

    # A fresh result is cached; expire it deliberately to exercise the next
    # provider lookup and its replace semantics.
    user = db_session.scalar(select(User).where(User.email == EMAIL))
    user.last_breach_check_at = None
    db_session.commit()
    patch_transport(monkeypatch, FakeResponse(200, {"Error": "Not found"}))
    assert breach_event(run_breach(client, auth_headers))["status"] == "CHECKED_SAFE"

    events = client.get("/api/analysis/events", headers=auth_headers).json()["events"]
    assert len([e for e in events if e["event_type"] == "BREACH_EXPOSURE"]) == 1


def test_provider_result_is_scoped_to_the_requesting_user(db_session, client, auth_headers, account, monkeypatch):
    """A second user must never see the first user's breach events (§13)."""
    from tests.conftest import register_and_login

    patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    assert breach_event(run_breach(client, auth_headers))["status"] == "FINDING"

    other = register_and_login(client, email="other-person@example.com", password="another-long-password")
    other_headers = {"Authorization": f"Bearer {other['access_token']}", "X-CSRF-Token": other["csrf_token"]}
    events = client.get("/api/analysis/events", headers=other_headers).json()["events"]
    assert events == []


def test_simulated_scenario_stays_labeled_and_separate(client, auth_headers, account, monkeypatch):
    patch_transport(monkeypatch, FakeResponse(200, {"Error": "Not found"}))
    response = run_breach(
        client,
        auth_headers,
        simulated_exposure_type="SESSION_ONLY",
        simulated_mfa_bypass_capable=True,
    )
    events = response.json()["events"]

    simulated = next(e for e in events if e["event_type"] == "SESSION_EXPOSURE")
    assert simulated["source"] == "simulated"
    assert simulated["source_mode"] == "SIMULATED"
    assert "SIMULATED" in simulated["provenance"]
    # The real lookup and the constructed scenario are distinct events.
    assert breach_event(response)["status"] == "CHECKED_SAFE"


def test_arbitrary_address_is_rejected_without_contacting_the_provider(
    client, auth_headers, account, monkeypatch
):
    calls = patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    response = run_breach(client, auth_headers, email="other-person@example.com")

    assert response.status_code == 403
    assert calls == []


def test_fresh_registered_result_is_served_from_cache(
    client, auth_headers, account, monkeypatch
):
    calls = patch_transport(monkeypatch, FakeResponse(200, {"Error": "Not found"}))
    first = run_breach(client, auth_headers)
    assert first.status_code == 200
    assert first.json()["cached"] is False
    provider_calls = list(calls)

    second = run_breach(client, auth_headers)
    assert second.status_code == 200
    assert second.json()["cached"] is True
    assert calls == provider_calls
