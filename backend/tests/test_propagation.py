"""Tests for live account connections + compromise propagation (scope change).

Covers the acceptance criteria that must hold without live provider credentials:
- Capability matrix: unavailable capabilities are UNAVAILABLE_THROUGH_PROVIDER,
  never SAFE. Connections never imply capability.
- Relationships are USER_CONFIRMED and weighted; no recovery edge is invented.
- Propagation score is computed by the documented formula (no hard-coded score),
  respects edge weights, and is labeled a relative exposure measure (never a
  probability of being hacked).
- The simulation endpoint marks source_mode=SIMULATED and never mutates real
  events.
- Tokens are encrypted at rest and never returned to the client or logged.
- Provider secrets are never exposed.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.engine import propagation
from app.main import app
from app.models import (
    AccountRelationship,
    ConnectedSignal,
    SecurityEvent,
)
from app.schemas import SourceMode
from app import token_crypto

from tests.conftest import TEST_SETTINGS


# --------------------------------------------------------------------------- #
# Capability matrix
# --------------------------------------------------------------------------- #
def test_capabilities_mark_unavailable_not_safe(client):
    resp = client.get("/api/oauth/capabilities")
    assert resp.status_code == 200
    body = resp.json()
    caps = body["capabilities"]
    assert caps, "capability matrix must not be empty"

    unavailable = [c for c in caps if not c["available"]]
    assert unavailable, "there must be capabilities the provider APIs do not expose"
    for cap in unavailable:
        assert cap["status"] == "UNAVAILABLE_THROUGH_PROVIDER"
        assert cap["status"] != "SAFE"

    # Every unavailable capability names its provenance.
    for cap in unavailable:
        assert cap["source"], "each unavailable capability needs a source note"


def test_connection_does_not_imply_capability(client, auth_headers):
    """Connecting must not flip an unavailable capability to available."""
    before = client.get("/api/oauth/capabilities").json()["capabilities"]
    unavailable_before = {
        (c["provider"], c["capability"]) for c in before if not c["available"]
    }

    resp = client.post("/api/oauth/fixtures/google", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["source_mode"] == "FIXTURE"

    after = client.get("/api/oauth/capabilities").json()["capabilities"]
    unavailable_after = {
        (c["provider"], c["capability"]) for c in after if not c["available"]
    }
    assert unavailable_before == unavailable_after


def test_unconfigured_provider_reports_not_configured(client):
    body = client.get("/api/oauth/providers").json()
    for provider in ("google", "linkedin", "instagram"):
        assert body["providers"][provider]["status"] == "NOT_CONFIGURED"
        assert body["providers"][provider]["configured"] is False


def test_unconfigured_authorize_is_unavailable_not_silent(client, auth_headers):
    resp = client.get("/api/oauth/google/authorize", headers=auth_headers)
    assert resp.status_code == 503
    assert "NOT_CONFIGURED" in resp.json()["detail"]


def test_provider_payload_has_no_secrets(client):
    body = client.get("/api/oauth/providers").text
    assert TEST_SETTINGS.google_client_secret not in body or not TEST_SETTINGS.google_client_secret
    assert "client_secret" not in body


# --------------------------------------------------------------------------- #
# Relationships (USER_CONFIRMED, never invented)
# --------------------------------------------------------------------------- #
def _connect_fixture(client, auth_headers, provider="google"):
    resp = client.post(f"/api/oauth/fixtures/{provider}", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["account_id"]


def test_fixture_connection_is_labeled_fixture(client, auth_headers):
    account_id = _connect_fixture(client, auth_headers, "google")
    conns = client.get("/api/oauth/connections", headers=auth_headers).json()["connections"]
    assert any(c["account_id"] == account_id and c["source_mode"] == "FIXTURE" for c in conns)

    accounts = client.get("/api/propagation/accounts", headers=auth_headers).json()["accounts"]
    assert any(a["account_id"] == account_id and a["source_mode"] == "FIXTURE" for a in accounts)


def test_relationship_requires_known_accounts(client, auth_headers):
    _connect_fixture(client, auth_headers, "google")
    resp = client.post(
        "/api/relationships",
        headers=auth_headers,
        json={
            "from_account_id": "google_fixture_missing",
            "to_account_id": "nope",
            "relationship_type": "recovery_email",
        },
    )
    assert resp.status_code == 404


def test_relationship_source_is_user_confirmed_and_weighted(client, auth_headers):
    src = _connect_fixture(client, auth_headers, "google")
    dst = _connect_fixture(client, auth_headers, "instagram")

    resp = client.post(
        "/api/relationships",
        headers=auth_headers,
        json={
            "from_account_id": src,
            "to_account_id": dst,
            "relationship_type": "recovery_email",
            "confidence": 1.0,
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["source"] == "USER_CONFIRMED"
    assert body["source_mode"] == "USER_PROVIDED"
    assert body["weight"] > 0


def test_relationship_rejects_unknown_type(client, auth_headers):
    src = _connect_fixture(client, auth_headers, "google")
    dst = _connect_fixture(client, auth_headers, "instagram")
    resp = client.post(
        "/api/relationships",
        headers=auth_headers,
        json={
            "from_account_id": src,
            "to_account_id": dst,
            "relationship_type": "totally_made_up",
        },
    )
    assert resp.status_code == 422


def test_relationship_rejects_self_edge(client, auth_headers):
    src = _connect_fixture(client, auth_headers, "google")
    resp = client.post(
        "/api/relationships",
        headers=auth_headers,
        json={
            "from_account_id": src,
            "to_account_id": src,
            "relationship_type": "recovery_email",
        },
    )
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# Propagation scoring (documented formula, weighted edges)
# --------------------------------------------------------------------------- #
def _seed_signal(db, user_id, account_id, label="Acct", service="Acct", source_mode="USER_PROVIDED"):
    db.add(
        ConnectedSignal(
            user_id=user_id,
            account_id=account_id,
            label=label,
            service_name=service,
            platform="test",
            source="manual",
            metadata_json={"service_name": service, "source_mode": source_mode},
        )
    )
    db.commit()


def _seed_event(db, user_id, account_id, event_type, status="FINDING", severity=0.6):
    import uuid

    db.add(
        SecurityEvent(
            event_id=f"evt_{uuid.uuid4().hex[:12]}",
            user_id=user_id,
            account_id=account_id,
            event_type=event_type,
            severity=severity,
            confidence=0.8,
            source="test",
            source_mode="USER_PROVIDED",
            status=status,
            metadata_json={},
            provenance="test",
        )
    )
    db.commit()


def test_propagation_score_is_computed_not_hardcoded(db_session, client, auth_headers):
    """Prove exposure varies with inputs — it cannot be a fixed constant."""
    me = client.get("/api/auth/me", headers=auth_headers).json()["id"]

    _seed_signal(db_session, me, "gmail")
    _seed_signal(db_session, me, "insta")
    _seed_signal(db_session, me, "linkedin")

    # Weak downstream: no weakness findings -> low exposure.
    db_session.add(
        AccountRelationship(
            user_id=me,
            from_account_id="gmail",
            to_account_id="insta",
            relationship_type="recovery_email",
            source="USER_CONFIRMED",
            source_mode="USER_PROVIDED",
            confidence=1.0,
            weight=1.0,
        )
    )
    db_session.commit()

    weak = propagation.compute_downstream_exposure(db_session, me, "gmail")
    assert weak["affected_count"] == 1

    # Add real weakness findings to the downstream account -> exposure rises.
    _seed_event(db_session, me, "insta", "PASSWORD_REUSE")
    _seed_event(db_session, me, "insta", "MFA_MISSING")
    strong = propagation.compute_downstream_exposure(db_session, me, "gmail")

    weak_score = weak["downstream"][0]["exposure"]
    strong_score = strong["downstream"][0]["exposure"]
    assert strong_score > weak_score, "weakness must increase exposure"
    assert 0.0 <= weak_score <= 100.0
    assert 0.0 <= strong_score <= 100.0


def test_propagation_component_breakdown_multiplies_factors(db_session, auth_headers, client):
    me = client.get("/api/auth/me", headers=auth_headers).json()["id"]
    _seed_signal(db_session, me, "up")
    _seed_signal(db_session, me, "down")
    db_session.add(
        AccountRelationship(
            user_id=me,
            from_account_id="up",
            to_account_id="down",
            relationship_type="recovery_email",
            source="USER_CONFIRMED",
            source_mode="USER_PROVIDED",
            confidence=1.0,
            weight=1.0,
        )
    )
    db_session.commit()
    _seed_event(db_session, me, "down", "PASSWORD_REUSE")

    out = propagation.compute_downstream_exposure(db_session, me, "up")
    comp = out["downstream"][0]["components"]
    for key in (
        "dependency_strength",
        "account_criticality",
        "credential_auth_weakness",
        "path_exposure",
        "mitigation_credit",
    ):
        assert key in comp
    # Weighted path strength for a single direct edge with decay < 1.
    assert 0 < comp["dependency_strength"] <= 1.0
    assert 0.5 <= comp["account_criticality"] <= 1.0
    assert out["formula"].startswith("exposure =")


def test_propagation_reduces_with_mitigation(db_session, auth_headers, client):
    me = client.get("/api/auth/me", headers=auth_headers).json()["id"]
    _seed_signal(db_session, me, "up")
    _seed_signal(db_session, me, "down")
    db_session.add(
        AccountRelationship(
            user_id=me,
            from_account_id="up",
            to_account_id="down",
            relationship_type="recovery_email",
            source="USER_CONFIRMED",
            source_mode="USER_PROVIDED",
            confidence=1.0,
            weight=1.0,
        )
    )
    db_session.commit()
    _seed_event(db_session, me, "down", "PASSWORD_REUSE")

    before = propagation.compute_downstream_exposure(db_session, me, "up")
    _seed_event(db_session, me, "down", "PASSKEY_ENABLED", status="CHECKED_SAFE")
    after = propagation.compute_downstream_exposure(db_session, me, "up")

    assert after["downstream"][0]["exposure"] < before["downstream"][0]["exposure"]


def test_multi_hop_path_decays(db_session, auth_headers, client):
    """A 2-hop path must expose less than a direct 1-hop path, all else equal."""
    me = client.get("/api/auth/me", headers=auth_headers).json()["id"]
    for aid in ("a", "b", "c"):
        _seed_signal(db_session, me, aid)
    for frm, to in (("a", "b"), ("b", "c")):
        db_session.add(
            AccountRelationship(
                user_id=me,
                from_account_id=frm,
                to_account_id=to,
                relationship_type="recovery_email",
                source="USER_CONFIRMED",
                source_mode="USER_PROVIDED",
                confidence=1.0,
                weight=1.0,
            )
        )
    db_session.commit()
    for aid in ("b", "c"):
        _seed_event(db_session, me, aid, "PASSWORD_REUSE")

    out = propagation.compute_downstream_exposure(db_session, me, "a")
    by_id = {d["account_id"]: d for d in out["downstream"]}
    assert "b" in by_id and "c" in by_id
    assert by_id["c"]["path_length"] == 2
    assert by_id["c"]["components"]["dependency_strength"] < by_id["b"]["components"]["dependency_strength"]


def test_propagation_disclaimer_not_a_probability(db_session, auth_headers, client):
    me = client.get("/api/auth/me", headers=auth_headers).json()["id"]
    _seed_signal(db_session, me, "up")
    _seed_signal(db_session, me, "down")
    db_session.add(
        AccountRelationship(
            user_id=me,
            from_account_id="up",
            to_account_id="down",
            relationship_type="recovery_email",
            source="USER_CONFIRMED",
            source_mode="USER_PROVIDED",
            confidence=1.0,
            weight=1.0,
        )
    )
    db_session.commit()
    out = propagation.compute_downstream_exposure(db_session, me, "up")
    assert "Not a probability" in out["disclaimer"]
    assert "not a prediction" in out["disclaimer"]


def test_unchecked_account_is_not_scored_as_safe(db_session, auth_headers, client):
    """couldn't check != safe — an account with no telemetry is never 0 exposure.

    Weakness is a multiplier, so a naive implementation scores an account with
    zero recorded events as exposure 0.0 (i.e. "nothing can reach it"), which is
    an unsupported claim of safety. It must instead be treated as unknown.
    """
    me = client.get("/api/auth/me", headers=auth_headers).json()["id"]
    _seed_signal(db_session, me, "up")
    _seed_signal(db_session, me, "unreviewed")
    db_session.add(
        AccountRelationship(
            user_id=me,
            from_account_id="up",
            to_account_id="unreviewed",
            relationship_type="recovery_email",
            source="USER_CONFIRMED",
            source_mode="USER_PROVIDED",
            confidence=1.0,
            weight=1.0,
        )
    )
    db_session.commit()

    unreviewed = propagation.compute_downstream_exposure(db_session, me, "up")
    item = unreviewed["downstream"][0]
    assert item["components"]["weakness_unknown"] is True
    assert item["exposure"] > 0.0, "an unchecked account must not score zero exposure"
    assert any("unknown, not safe" in r for r in item["reasons"])

    # Now the account IS reviewed — and reviewed clean. Evidence, not a floor.
    _seed_event(db_session, me, "unreviewed", "PASSKEY_ENABLED", status="CHECKED_SAFE")
    reviewed = propagation.compute_downstream_exposure(db_session, me, "up")
    reviewed_item = reviewed["downstream"][0]
    assert reviewed_item["components"]["weakness_unknown"] is False
    assert reviewed_item["components"]["credential_auth_weakness"] == 0.0
    # Checked-and-clean scores below un-checked-unknown (evidence lowers exposure).
    assert reviewed_item["exposure"] < item["exposure"]


def test_known_weakness_still_dominates_unknown_floor(db_session, auth_headers, client):
    """A real finding must score higher than the neutral unknown default."""
    me = client.get("/api/auth/me", headers=auth_headers).json()["id"]
    _seed_signal(db_session, me, "up")
    _seed_signal(db_session, me, "weak")
    _seed_signal(db_session, me, "unreviewed")
    for dst in ("weak", "unreviewed"):
        db_session.add(
            AccountRelationship(
                user_id=me,
                from_account_id="up",
                to_account_id=dst,
                relationship_type="recovery_email",
                source="USER_CONFIRMED",
                source_mode="USER_PROVIDED",
                confidence=1.0,
                weight=1.0,
            )
        )
    db_session.commit()
    _seed_event(db_session, me, "weak", "PASSWORD_REUSE")
    _seed_event(db_session, me, "weak", "MFA_MISSING")

    out = propagation.compute_downstream_exposure(db_session, me, "up")
    by_id = {d["account_id"]: d for d in out["downstream"]}
    # 0.35 + 0.25 = 0.60 known weakness beats the 0.50 unknown floor.
    assert by_id["weak"]["exposure"] > by_id["unreviewed"]["exposure"]


# --------------------------------------------------------------------------- #
# Simulate endpoint
# --------------------------------------------------------------------------- #
def test_simulate_endpoint_runs_and_marks_simulated(client, auth_headers):
    src = _connect_fixture(client, auth_headers, "google")
    dst = _connect_fixture(client, auth_headers, "instagram")
    client.post(
        "/api/relationships",
        headers=auth_headers,
        json={
            "from_account_id": src,
            "to_account_id": dst,
            "relationship_type": "recovery_email",
            "confidence": 1.0,
        },
    )

    resp = client.post(
        "/api/propagation/simulate",
        headers=auth_headers,
        json={"upstream_account_id": src},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["scenario"]["source_mode"] == "SIMULATED"
    assert body["scenario"]["label"] == "SIMULATED COMPROMISE"
    assert "No real account was" in body["scenario"]["notice"]
    assert body["propagation"]["affected_count"] >= 1
    assert body["disclaimer"]
    # Storyline includes the upstream as COMPROMISED and downstream bands.
    assert body["storyline"][0]["band"] == "COMPROMISED"
    assert "scenario_risk" in body
    assert "scenario_attribution" in body
    # Remediation priority is recomputed by the real planner (greedy vs exact).
    plan = body["scenario_plan"]["comparison"]
    assert plan["exact"]["risk_after"] <= plan["initial_risk"] + 1e-6
    assert plan["exact"]["risk_after"] <= plan["greedy"]["risk_after"] + 1e-6
    assert "baseline" in body["scenario_plan"]["note"].lower()
    assert "budget" in body["scenario_plan"]


def test_simulate_does_not_mutate_real_events(client, auth_headers, db_session):
    src = _connect_fixture(client, auth_headers, "google")
    before = db_session.query(SecurityEvent).count()
    client.post(
        "/api/propagation/simulate",
        headers=auth_headers,
        json={"upstream_account_id": src},
    )
    after = db_session.query(SecurityEvent).count()
    assert before == after, "simulation must not create real security events"


def test_simulate_requires_owned_account(client, auth_headers):
    resp = client.post(
        "/api/propagation/simulate",
        headers=auth_headers,
        json={"upstream_account_id": "google_someone_else"},
    )
    assert resp.status_code == 404


def test_simulate_rejects_missing_account(client, auth_headers):
    resp = client.post(
        "/api/propagation/simulate", headers=auth_headers, json={}
    )
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# Token encryption
# --------------------------------------------------------------------------- #
def test_tokens_are_encrypted_at_rest(db_session, auth_headers, client, monkeypatch):
    from app.oauth import flow

    class FakeTokens:
        access_token = "SUPER-SECRET-ACCESS-TOKEN"
        refresh_token = "SUPER-SECRET-REFRESH-TOKEN"
        expires_in = 3600
        scope = "openid email"
        token_type = "Bearer"

    class FakeProfile:
        provider_account_id = "acct-123"
        identifier = "demo@example.com"
        display_name = "Demo"
        extra = {}

    monkeypatch.setattr(flow, "exchange_code", lambda *a, **k: FakeTokens())
    monkeypatch.setattr(flow, "fetch_profile", lambda *a, **k: FakeProfile())

    # Drive the store path directly to avoid a real network exchange.
    from app.routers.oauth import _store_connection
    from app.config import get_settings as _gs

    settings = _gs()
    me = client.get("/api/auth/me", headers=auth_headers).json()["id"]
    _store_connection(
        db=db_session,
        user_id=me,
        provider="google",
        tokens=FakeTokens(),
        profile=FakeProfile(),
        settings=settings,
    )

    row = db_session.query(
        __import__("app.models", fromlist=["ProviderConnection"]).ProviderConnection
    ).filter_by(user_id=me, provider="google").one()

    # Stored values are ciphertext, not plaintext.
    assert row.access_token_enc
    assert "SUPER-SECRET" not in row.access_token_enc
    assert row.refresh_token_enc and "SUPER-SECRET" not in row.refresh_token_enc
    # And they decrypt back to the original.
    assert token_crypto.decrypt_token(row.access_token_enc) == "SUPER-SECRET-ACCESS-TOKEN"


def test_connections_endpoint_never_returns_tokens(client, auth_headers, db_session):
    from app.routers.oauth import _store_connection
    from app.config import get_settings as _gs

    class T:
        access_token = "SECRET-TOKEN-VALUE"
        refresh_token = "SECRET-REFRESH"
        expires_in = 3600
        scope = "openid"

    class P:
        provider_account_id = "acct-9"
        identifier = "a@example.com"
        display_name = "A"
        extra = {}

    me = client.get("/api/auth/me", headers=auth_headers).json()["id"]
    _store_connection(
        db=db_session, user_id=me, provider="linkedin", tokens=T(), profile=P(),
        settings=_gs(),
    )
    text = client.get("/api/oauth/connections", headers=auth_headers).text
    assert "SECRET-TOKEN-VALUE" not in text
    assert "SECRET-REFRESH" not in text
    assert "access_token_enc" not in text


def test_token_crypto_roundtrip():
    ct = token_crypto.encrypt_token("abc123")
    assert ct != "abc123"
    assert token_crypto.decrypt_token(ct) == "abc123"
    assert token_crypto.encrypt_token(None) is None


def test_token_decryption_error_not_leaking():
    from app.token_crypto import TokenDecryptionError

    with pytest.raises(TokenDecryptionError):
        token_crypto.decrypt_token("not-a-valid-fernet-token")


def test_audit_never_logs_tokens(client, auth_headers, db_session):
    from app.audit import redact

    redacted = redact({"detail": {"access_token": "xyz", "refresh_token": "abc"}})
    assert redacted["detail"]["access_token"] == "[REDACTED]"
    assert redacted["detail"]["refresh_token"] == "[REDACTED]"


def test_connection_audit_records_event_without_token(client, auth_headers, db_session):
    """Connection lifecycle is audited, and the entry can never contain a token."""
    from app.audit import record
    from app.models import AuditLog
    from app.routers.oauth import _store_connection
    from app.config import get_settings as _gs

    class T:
        access_token = "AUDIT-SECRET-TOKEN"
        refresh_token = "AUDIT-SECRET-REFRESH"
        expires_in = 3600
        scope = "openid email"

    class P:
        provider_account_id = "audit-acct"
        identifier = "audit@example.com"
        display_name = "Audit"
        extra = {}

    me = client.get("/api/auth/me", headers=auth_headers).json()["id"]
    _store_connection(
        db=db_session, user_id=me, provider="google", tokens=T(), profile=P(),
        settings=_gs(), ip_address="127.0.0.1",
    )

    entries = (
        db_session.query(AuditLog)
        .filter(AuditLog.user_id == me, AuditLog.action == "oauth.connection_established")
        .all()
    )
    assert entries, "establishing a connection must be audited"
    raw = str([e.detail for e in entries])
    assert "AUDIT-SECRET" not in raw, "audit detail must never carry a token"
    assert entries[-1].detail["provider"] == "google"

    # Redaction holds even if a caller passes a token-shaped detail.
    entry = record(
        db_session,
        action="oauth.test",
        user_id=me,
        detail={"access_token": "LEAK", "provider": "google"},
    )
    assert entry.detail["access_token"] == "[REDACTED]"
    assert "LEAK" not in str(entry.detail)
