"""Semester-7 pipeline wiring: Features C–F events reach the ONE pipeline.

Each feature's own suite already asserts its endpoints in isolation. This
module proves the pieces fit: events created through the REAL routers
(domain checks, repo scan, access audit, phishing record) for ONE
organization's admin are

1) listed by ``/api/analysis/events`` with the right org/asset binding,
2) consumed by ``pipeline.run_analysis`` — the planner features carry the
   pools the pinned ``EVENT_TO_FEATURE`` map promises (phishing / permissions;
   DNS-TLS posture and secret hits are deliberately unmapped and stay out of
   the score),
3) correlated by the declarative engine — ``phished_weak_email_auth`` fires
   across Features C+D on the SAME registered asset within the window, and
4) never duplicated: the access-audit module-replace semantics hold when
   observed through the analysis listing, not just through the module.
"""
from __future__ import annotations

import pytest

from app.engine.risk import EVENT_TO_FEATURE
from app.signals.url_intel import reset_provider_state
from tests.conftest import register_org_admin
from tests.test_feature_c import FeedStub, _phish_body
from tests.test_feature_d import DohStub, _txt
from tests.test_feature_e import _AWS_KEY, _make_repo_asset, _upload, _zip_builder
from tests.xon_stubs import FakeResponse

PASSWORD = "correct horse battery"
DOMAIN = "wired.example"
REPO = "acme/wired-repo"


@pytest.fixture()
def admin(client):
    return register_org_admin(client, email="w-root@example.com")


def _feature_d_weak_email_auth(client, admin, monkeypatch) -> None:
    """Register + verify + run defect checks on ``DOMAIN`` (Feature D)."""
    from tests.conftest import TEST_SETTINGS

    monkeypatch.setattr(TEST_SETTINGS, "domain_checks_enabled", True)
    data = client.post(
        "/api/domains/register",
        json={"domain": DOMAIN, "label": "we", "criticality": 4},
        headers=admin,
    ).json()
    DohStub(monkeypatch).answer(DOMAIN, "TXT", [_txt(data["verify_token"])]).patch()
    ok = client.post(
        f"/api/domains/{DOMAIN}/ownership/verify", json={"token": data["verify_token"]},
        headers=admin,
    ).json()
    assert ok["verified"] is True, ok

    stub = DohStub(monkeypatch)
    stub.answer(DOMAIN, "TXT", ["not-spf"])
    stub.answer(f"_dmarc.{DOMAIN}", "TXT", ["v=DMARC1; p=none;"])
    stub.patch()
    monkeypatch.setattr(
        "app.routers.domains._probe_https",
        lambda domain_, settings_: {
            "check": "tls", "status": "FINDING",
            "observed": "certificate expired", "cert_days_left": -3,
        },
    )
    response = client.post(
        f"/api/domains/{DOMAIN}/checks", json={"dkim_selector": "sel1"}, headers=admin
    )
    assert response.status_code == 200, response.text
    types = {e["event_type"] for e in response.json()["events"]}
    assert "EMAIL_AUTH_WEAKNESS" in types


def _feature_e_secret_hit(client, admin) -> None:
    """Upload a leaking archive against ``REPO`` (Feature E)."""
    _make_repo_asset(client, admin, REPO)
    leak_line = f"AWS_ACCESS_KEY_ID = '{_AWS_KEY}'\n".encode()
    archive = _zip_builder({
        "acme/wired-repo/conf/settings.py": (
            b"AWS_KEY_MARKER = 'kept'\n" + leak_line
        ),
    })
    response = _upload(client, admin, REPO, archive)
    assert response.status_code == 200, response.text
    assert any(e["event_type"] == "SECRET_PATTERN_MATCHED" for e in response.json()["events"])


def _feature_f_departed_admin(client, admin, db_session) -> None:
    """Declare ADMIN access for a member, then model their departure (Feature F)."""
    from urllib.parse import parse_qs, urlsplit

    from sqlalchemy import select

    from app.models import Membership, User

    invitation = client.post(
        "/api/invitations",
        json={"email": "w-member@example.com", "role": "MEMBER"},
        headers=admin,
    )
    assert invitation.status_code == 201, invitation.text
    token = parse_qs(urlsplit(invitation.json()["invite_link"]).query)["token"][0]
    accept = client.post(
        "/api/invitations/accept", json={"token": token, "password": PASSWORD}
    )
    assert accept.status_code == 200, accept.text

    members = client.get("/api/members", headers=admin).json()
    member_id = next(m["membership_id"] for m in members if m["email"] == "w-member@example.com")
    record = client.post(
        "/api/access/records",
        json={"membership_id": member_id, "asset_id": DOMAIN, "level": "ADMIN"},
        headers=admin,
    )
    assert record.status_code == 201, record.text

    membership = db_session.scalars(
        select(Membership).join(User, User.id == Membership.user_id)
        .where(User.email == "w-member@example.com")
    ).one()
    membership.is_active = False
    db_session.commit()

    scan = client.get("/api/access/candidates", headers=admin)
    assert scan.status_code == 200, scan.text
    body = scan.json()
    assert len(body["events"]) == 1 and body["events"][0]["event_type"] == "ACCESS_REVIEW_NEEDED"


def _feature_c_phished_url_on_domain(client, admin, monkeypatch) -> None:
    """A live-feed-flagged URL whose host IS the registered domain asset."""
    reset_provider_state()
    FeedStub(monkeypatch).script(_phish_body(True))
    data = client.post(
        "/api/signals/phishing/registered-email/record",
        json={"url": f"https://{DOMAIN}/payload"},
        headers=admin,
    ).json()
    url_event = next(e for e in data["events"] if e["event_type"] == "PHISHING_URL_DETECTED")
    assert url_event["asset_id"] == DOMAIN  # exact canonical-identity binding


def _events_by_type(client, admin):
    listing = client.get("/api/analysis/events", headers=admin).json()["events"]
    grouped: dict[str, list[dict]] = {}
    for event in listing:
        grouped.setdefault(event["event_type"], []).append(event)
    return grouped


def test_semester7_events_feed_the_one_pipeline(client, admin, db_session, monkeypatch):
    # Domain registration itself creates the DOMAIN org-asset (Feature D),
    # so URLs, access records and posture checks all bind to the same id.
    _feature_d_weak_email_auth(client, admin, monkeypatch)
    _feature_e_secret_hit(client, admin)
    _feature_f_departed_admin(client, admin, db_session)
    _feature_c_phished_url_on_domain(client, admin, monkeypatch)

    # 1) analysis listing: every feature's persisted findings, bound as claimed
    grouped = _events_by_type(client, admin)
    assert set(grouped) >= {
        "EMAIL_AUTH_WEAKNESS", "SECRET_PATTERN_MATCHED",
        "ACCESS_REVIEW_NEEDED", "PHISHING_URL_DETECTED",
    }
    assert len(grouped["ACCESS_REVIEW_NEEDED"]) == 1
    for event_type in ("EMAIL_AUTH_WEAKNESS", "PHISHING_URL_DETECTED", "ACCESS_REVIEW_NEEDED"):
        assert grouped[event_type][0]["asset_id"] == DOMAIN, event_type
    assert grouped["SECRET_PATTERN_MATCHED"][0]["asset_id"] == REPO
    assert grouped["ACCESS_REVIEW_NEEDED"][0]["org_id"] == grouped["EMAIL_AUTH_WEAKNESS"][0]["org_id"]

    # 2) dedupe through the whole pipeline: a repeat access-audit scan must not
    #    stack rows in the analysis listing (module replace, org-scoped)
    repeat = client.get("/api/access/candidates", headers=admin)
    assert repeat.status_code == 200, repeat.text
    grouped = _events_by_type(client, admin)
    assert len(grouped["ACCESS_REVIEW_NEEDED"]) == 1, "candidates must replace, never stack"

    # 3) the ONE deterministic run consumed all of it
    run = client.post("/api/analysis/run", json={}, headers=admin)
    assert run.status_code == 200, run.text
    body = run.json()
    types_in_run = {e["event_type"] for e in body["events"]}
    assert types_in_run >= {
        "EMAIL_AUTH_WEAKNESS", "SECRET_PATTERN_MATCHED",
        "ACCESS_REVIEW_NEEDED", "PHISHING_URL_DETECTED",
    }
    assert body["risk"]["model_version"], "the score must name the model version that computed it"

    # Pools per the PINNED map (docs/RISK_MODEL.md §10): the phishing finding
    # and the access-review candidate raise their EXISTING pools; the
    # deliberately unmapped DNS/TLS + secret findings change nothing directly.
    features = body["features"]
    assert features["phishing"] >= 0.6
    assert features["permissions"] >= 0.7  # departed-member severity dominates the pool

    # 4) the declarative engine correlates C+D on the SAME asset
    rule = next((c for c in body["correlations"] if c["rule_id"] == "phished_weak_email_auth"), None)
    assert rule is not None, body["correlations"]
    assert rule["org_id"] == grouped["EMAIL_AUTH_WEAKNESS"][0]["org_id"]
    contributing_types = {
        grouped_type
        for grouped_type, rows in grouped.items()
        for row in rows
        if row["event_id"] in rule["finding_ids"]
    }
    assert contributing_types == {"EMAIL_AUTH_WEAKNESS", "PHISHING_URL_DETECTED"}
    assert rule["uncertainty"], "a correlation always states what its confidence is not"


def test_unmapped_semester7_types_stay_out_of_the_score():
    """The deliberate §10 boundary: DNS/TLS posture and secret hits are
    correlation SIGNALS, not score inputs — regressions must scream."""
    assert "EMAIL_AUTH_WEAKNESS" not in EVENT_TO_FEATURE
    assert "TLS_POSTURE_WEAK" not in EVENT_TO_FEATURE
    assert "SECRET_PATTERN_MATCHED" not in EVENT_TO_FEATURE
