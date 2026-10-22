"""Phase 2 — one normalized finding schema, stable assets, organization scope.

What these tests pin down:

* **Schema contract**: bounds and enum statuses are enforced, a malformed event is
  rejected, and missing evidence stays explicitly "nothing recorded" instead of
  being fabricated. Sensitive content is *redacted*, never persisted (a live check
  must not fail because an error string contained an address).
* **Stable asset identity**: canonicalization, exact-match resolution, distinct
  assets never merged, a mail account never merged with its domain, and labels
  never used as identity.
* **Organization ownership**: ``org_id`` is resolved server-side (a client-sent
  value is overwritten), a finding never binds to another tenant's asset, and
  tenant reads only see their own organization's findings.
* **Honest labeling**: live provider answers keep ``REAL``, a provider failure
  stays ``UNAVAILABLE`` (never ``CHECKED_SAFE``), and source dates are only
  reported when the source actually provides them.
* **Round-trip**: no secrets in persisted rows, re-checks do not duplicate
  findings, ``first_seen`` survives a re-check, and the API exposes the whole
  standardized field set.
"""
from __future__ import annotations

import datetime as dt
import json

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from app.engine import entities, normalizer
from app.engine.normalizer import OrgScopeError
from app.models import Membership, SecurityEvent
from app.schemas import SecurityEventSchema
from tests.conftest import register_org_admin
from tests.helpers import ev
from tests.xon_stubs import FakeResponse, patch_transport

ACCOUNT = "phase2-account"
# ``example.com`` is already used across the suite, so EmailStr accepts it.
WORK_EMAIL = "alice@example.com"


def _schema(**overrides) -> SecurityEventSchema:
    base = dict(
        event_id="evt_unit",
        user_id="u1",
        account_id="a1",
        event_type="BREACH_EXPOSURE",
        severity=0.5,
        confidence=0.8,
        source="hibp",
    )
    base.update(overrides)
    return SecurityEventSchema(**base)


def _me(client, headers) -> str:
    return client.get("/api/auth/me", headers=headers).json()["id"]


def _org_id(db, user_id: str) -> str:
    membership = db.scalar(
        select(Membership).where(Membership.user_id == user_id, Membership.is_active.is_(True))
    )
    assert membership is not None, "registered users have an organization"
    return membership.org_id


def _connect_account(client, headers, account_id=ACCOUNT, email=WORK_EMAIL):
    response = client.post(
        "/api/accounts",
        headers=headers,
        json={
            "account_id": account_id,
            "label": "Work address",
            "service_name": "Acme",
            "email": email,
        },
    )
    assert response.status_code == 201, response.text
    return response


def _run_breach(client, headers, account_id=ACCOUNT, email=WORK_EMAIL):
    return client.post(
        "/api/signals/breach",
        headers=headers,
        json={"account_id": account_id, "email": email},
    )


def _breach_event(response) -> dict:
    events = response.json()["events"]
    return next(e for e in events if e["event_type"] == "BREACH_EXPOSURE")


# --------------------------------------------------------------------------- #
# §4 — the normalized schema itself
# --------------------------------------------------------------------------- #
def test_severity_and_confidence_must_be_within_bounds():
    with pytest.raises(ValidationError):
        _schema(severity=1.5)
    with pytest.raises(ValidationError):
        _schema(confidence=-0.01)


def test_unknown_event_status_is_rejected_rather_than_coerced():
    with pytest.raises(ValidationError):
        _schema(status="LOOKS_FINE")


def test_blank_event_type_is_rejected():
    with pytest.raises(ValidationError):
        _schema(event_type="   ")


def test_missing_evidence_is_explicitly_empty_not_fabricated():
    assert _schema().evidence == {}


def test_credential_like_evidence_keys_are_never_stored():
    event = _schema(
        evidence={"password": "hunter2", "api_key": "abc123", "mfa_enabled": False}
    )
    assert event.evidence == {"mfa_enabled": False}


def test_secret_and_address_values_in_evidence_are_redacted():
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abcdefghij"
    event = _schema(
        evidence={"session_material": fake_jwt, "note": "mail bob@acme.test", "count": 3}
    )
    assert event.evidence["session_material"] == "[REDACTED]"
    assert event.evidence["note"] == "[REDACTED]"
    assert event.evidence["count"] == 3


def test_oversized_evidence_is_rejected():
    with pytest.raises(ValidationError):
        _schema(evidence={"blob": "x" * 5000})


# --------------------------------------------------------------------------- #
# §3 — stable asset identity (canonical, exact, never name-similarity)
# --------------------------------------------------------------------------- #
def test_email_identity_is_trimmed_and_lowercased():
    ident = entities.identity_of("  Alice@Example.COM ")
    assert ident == ("email", "alice@example.com")


def test_repository_urls_share_one_identity():
    a = entities.identity_of("HTTPS://GitHub.com/Acme/Project.git/")
    b = entities.identity_of("github.com/Acme/Project")
    assert a.value == b.value == "github.com/Acme/Project"


def test_similar_repository_paths_stay_distinct():
    a = entities.identity_of("https://github.com/Acme/Project")
    b = entities.identity_of("https://github.com/Acme/Other-Project")
    assert a.value != b.value


def test_display_labels_are_not_identities():
    assert entities.identity_of("Primary Gmail") is None
    assert entities.identity_of("") is None
    assert entities.identity_of(None) is None


def test_opaque_asset_ids_are_kept_verbatim():
    assert entities.canonical_asset_id("  github-acme-app ") == "github-acme-app"


def test_asset_id_is_canonicalized_when_registered(client, auth_headers):
    created = client.post(
        "/api/assets",
        headers=auth_headers,
        json={
            "asset_id": "HTTPS://GitHub.com/Acme/Project.git",
            "asset_type": "CODE_REPOSITORY",
            "label": "Product repo",
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["asset_id"] == "github.com/Acme/Project"

    # The same repository written differently is the same asset -> conflict.
    again = client.post(
        "/api/assets",
        headers=auth_headers,
        json={
            "asset_id": "GitHub.com/Acme/Project",
            "asset_type": "CODE_REPOSITORY",
            "label": "Duplicate",
        },
    )
    assert again.status_code == 409


def test_assets_are_not_matched_by_display_name(client, auth_headers, db_session):
    client.post(
        "/api/assets",
        headers=auth_headers,
        json={"asset_id": "Gmail", "asset_type": "WORKSPACE_IDENTITY", "label": "Gmail"},
    )
    # An identity in the same organization must not resolve to a similarly
    # named asset: only exact canonical equality counts.
    assert entities.resolve_asset(db_session, _org_id(db_session, _me(client, auth_headers)),
                                  [WORK_EMAIL]) is None


def test_assets_in_another_organization_are_invisible_to_resolution(
    client, auth_headers, db_session
):
    other = register_org_admin(client, "owner@other.example.com", org_name="Other Co")
    created = client.post(
        "/api/assets",
        headers=other,
        json={"asset_id": WORK_EMAIL, "asset_type": "WORK_EMAIL", "label": "Elsewhere"},
    )
    assert created.status_code == 201, created.text

    my_org = _org_id(db_session, _me(client, auth_headers))
    assert entities.resolve_asset(db_session, my_org, [WORK_EMAIL]) is None
    assert entities.assert_asset_in_org(db_session, my_org, WORK_EMAIL) is None


# --------------------------------------------------------------------------- #
# §2/§4 — organization ownership of findings
# --------------------------------------------------------------------------- #
def test_a_finding_without_an_organization_is_refused(db_session):
    with pytest.raises(OrgScopeError):
        normalizer.resolve_org_id(db_session, "no-such-user")


def test_client_supplied_org_id_is_overwritten_server_side(
    db_session, client, auth_headers
):
    me = _me(client, auth_headers)
    real_org = _org_id(db_session, me)

    rows = normalizer.persist_events(
        db_session,
        [ev("MFA_MISSING", user_id=me, event_id="evt_spoofed", org_id="org_controlled_by_client")],
    )
    assert rows[0].org_id == real_org
    assert rows[0].org_id != "org_controlled_by_client"


def test_findings_belong_to_exactly_one_organization(db_session, client, auth_headers):
    me = _me(client, auth_headers)
    org_a = _org_id(db_session, me)

    other = register_org_admin(client, "second@owner.example.com", org_name="Second Co")
    other_me = _me(client, other)
    org_b = _org_id(db_session, other_me)
    assert org_a != org_b

    normalizer.persist_events(
        db_session,
        [
            ev("MFA_MISSING", user_id=me, event_id="evt_org_a"),
            ev("MFA_MISSING", user_id=other_me, event_id="evt_org_b"),
        ],
    )

    in_a = {row.event_id for row in normalizer.list_org_events(db_session, org_a)}
    in_b = {row.event_id for row in normalizer.list_org_events(db_session, org_b)}
    assert in_a == {"evt_org_a"}
    assert in_b == {"evt_org_b"}

    # No row is ever stored without an organization.
    assert all(row.org_id in {org_a, org_b} for row in db_session.scalars(
        select(SecurityEvent)
    ).all())


def test_a_finding_never_binds_to_another_organizations_asset(
    client, auth_headers, db_session, monkeypatch
):
    # Another company registered exactly this identity as its asset.
    other = register_org_admin(client, "admin@elsewhere.example.com", org_name="Elsewhere Co")
    assert client.post(
        "/api/assets",
        headers=other,
        json={"asset_id": WORK_EMAIL, "asset_type": "WORK_EMAIL", "label": "Elsewhere work"},
    ).status_code == 201

    _connect_account(client, auth_headers)
    patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    event = _breach_event(_run_breach(client, auth_headers))

    assert event["org_id"] == _org_id(db_session, _me(client, auth_headers))
    assert event["asset_id"] is None  # cross-tenant candidate -> no match


def test_a_finding_binds_to_the_matching_asset_in_the_same_organization(
    client, auth_headers, db_session, monkeypatch
):
    assert client.post(
        "/api/assets",
        headers=auth_headers,
        json={"asset_id": WORK_EMAIL, "asset_type": "WORK_EMAIL", "label": "Alice work address"},
    ).status_code == 201
    _connect_account(client, auth_headers)

    patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    event = _breach_event(_run_breach(client, auth_headers))

    assert event["asset_id"] == WORK_EMAIL
    assert event["org_id"] == _org_id(db_session, _me(client, auth_headers))
    assert event["evidence"]["breach_count"] == 1


def test_a_mail_account_is_not_the_service_domain(
    client, auth_headers, db_session, monkeypatch
):
    """A Gmail address and the gmail.com domain are different assets (§3)."""
    assert client.post(
        "/api/assets",
        headers=auth_headers,
        json={"asset_id": "gmail.com", "asset_type": "DOMAIN", "label": "Google domain"},
    ).status_code == 201
    _connect_account(client, auth_headers, account_id="gmail-person", email="alice@gmail.com")

    patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    event = _breach_event(_run_breach(client, auth_headers, account_id="gmail-person",
                                      email="alice@gmail.com"))
    assert event["asset_id"] is None  # not the domain asset


# --------------------------------------------------------------------------- #
# §2 — honest labeling: live, fixture, unavailable
# --------------------------------------------------------------------------- #
def test_live_provider_answer_keeps_the_real_label_and_its_evidence(
    client, auth_headers, monkeypatch
):
    _connect_account(client, auth_headers)
    patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    event = _breach_event(_run_breach(client, auth_headers))

    assert event["source_mode"] == "REAL"
    assert event["status"] == "FINDING"
    assert event["evidence"]["provider"] == "xposedornot"
    assert event["evidence"]["breach_count"] == 1
    assert event["evidence"]["breaches"] == ["Adobe"]


def test_provider_failure_stays_unavailable_and_says_why(
    client, auth_headers, monkeypatch
):
    _connect_account(client, auth_headers)
    patch_transport(monkeypatch, FakeResponse(503, {}))
    event = _breach_event(_run_breach(client, auth_headers))

    assert event["status"] == "UNAVAILABLE"
    assert event["status"] != "CHECKED_SAFE"
    assert event["source_mode"] == "UNAVAILABLE"
    assert event["evidence"]["outcome"] == "UNAVAILABLE"
    assert event["evidence"]["reason"]


def test_provider_without_dates_does_not_invent_them(client, auth_headers, monkeypatch):
    _connect_account(client, auth_headers)
    patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    event = _breach_event(_run_breach(client, auth_headers))

    # XposedOrNot reports no breach dates: the source window is unknown...
    assert event["evidence"]["first_breach_date"] is None
    assert event["evidence"]["last_breach_date"] is None
    # ...so first_seen falls back to the observation CRIX actually recorded.
    assert event["first_seen"] == event["detected_at"]


def test_source_supplied_breach_dates_become_the_observation_window():
    class _FakeHibp:
        def breached_account(self, email):
            return [
                {"Name": "Adobe", "BreachDate": "2013-10-04"},
                {"Name": "Older", "BreachDate": "2011-12-04"},
            ]

    from app.signals import breach as breach_module

    lookup = breach_module._lookup_hibp(WORK_EMAIL, _FakeHibp())
    assert lookup.outcome == breach_module.FINDING
    assert lookup.first_breach_date.date() == dt.date(2011, 12, 4)
    assert lookup.last_breach_date.date() == dt.date(2013, 10, 4)

    event = breach_module._breach_event("u1", "acct", lookup)
    assert event.first_seen == lookup.first_breach_date
    assert event.last_seen == lookup.last_breach_date
    assert event.evidence["first_breach_date"].startswith("2011-12-04")


# --------------------------------------------------------------------------- #
# §4 — round-trip: no secrets, no duplicates, stable window, API surface
# --------------------------------------------------------------------------- #
def test_no_secret_reaches_a_persisted_row(db_session, client, auth_headers):
    me = _me(client, auth_headers)
    secret = "hunter2-not-a-real-password"
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abcdefghij"

    rows = normalizer.persist_events(
        db_session,
        [
            ev(
                "MFA_MISSING",
                user_id=me,
                event_id="evt_secret",
                evidence={"password": secret, "token": fake_jwt,
                          "contact": WORK_EMAIL, "mfa_enabled": False},
                metadata={"note": "no secrets here"},
            )
        ],
    )
    row = rows[0]
    blob = json.dumps(
        {"evidence": row.evidence, "metadata": row.metadata_json, "provenance": row.provenance}
    )
    assert secret not in blob
    assert fake_jwt not in blob
    assert WORK_EMAIL not in json.dumps(row.evidence)


def test_rechecking_a_module_does_not_duplicate_findings(
    db_session, client, auth_headers
):
    me = _me(client, auth_headers)
    event_types = ["MFA_MISSING"]

    first_rows = normalizer.replace_module_events(
        db_session, me, ACCOUNT, event_types,
        [ev("MFA_MISSING", user_id=me, event_id="evt_first", account_id=ACCOUNT)],
    )
    first = first_rows[0]
    assert first.first_seen == first.detected_at  # first observation of this finding

    second_rows = normalizer.replace_module_events(
        db_session, me, ACCOUNT, event_types,
        [ev("MFA_MISSING", user_id=me, event_id="evt_second", account_id=ACCOUNT)],
    )
    second = second_rows[0]

    stored = db_session.scalars(
        select(SecurityEvent).where(
            SecurityEvent.user_id == me,
            SecurityEvent.account_id == ACCOUNT,
            SecurityEvent.event_type.in_(event_types),
        )
    ).all()
    assert len(stored) == 1  # deterministic replace, no duplicate
    assert second.event_id == "evt_second"
    # The originally recorded observation is kept, the window end advances.
    assert second.first_seen == first.first_seen
    assert second.last_seen >= first.last_seen


def test_events_endpoint_exposes_the_standardized_finding(
    client, auth_headers, monkeypatch
):
    _connect_account(client, auth_headers)
    patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    _run_breach(client, auth_headers)

    events = client.get("/api/analysis/events", headers=auth_headers).json()["events"]
    assert events, "the check should have produced findings"
    required = {
        "event_id", "user_id", "account_id", "org_id", "asset_id", "event_type",
        "source", "source_mode", "severity", "confidence", "status",
        "detected_at", "first_seen", "last_seen", "evidence", "metadata",
        "provenance", "created_at", "updated_at",
    }
    for event in events:
        assert required <= set(event), required - set(event)
        assert event["org_id"]  # every finding carries its organization
