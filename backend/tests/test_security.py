"""Security checklist — one or more automated tests per §14 item.

These tests are the build gate: they fail if a security invariant regresses.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app import audit
from app.engine import graphrag


# --------------------------------------------------------------------------- #
# §14 [1] Plaintext password never appears in any outgoing network request
# --------------------------------------------------------------------------- #
def test_outgoing_requests_never_contain_plaintext_password(client, auth_headers, monkeypatch):
    """Instrument every outbound HTTP call made by the backend and prove the
    plaintext password (and its full SHA-1) never appears in any of them."""
    import app.signals.hibp as hibp_module

    captured: list[str] = []

    class _Resp:
        status_code = 200
        text = "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n"
        def json(self):  # pragma: no cover - not used here
            return []

    def spy_get(url, *args, **kwargs):
        captured.append(str(url))
        captured.append(str(args))
        captured.append(str(kwargs))
        return _Resp()

    # This is the ONLY outbound call path in the backend.
    monkeypatch.setattr(hibp_module.httpx, "get", spy_get)

    secret_password = "SuperSecretPlaintext-Password-42!"
    import hashlib

    full_sha1 = hashlib.sha1(secret_password.encode()).hexdigest().upper()
    prefix = full_sha1[:5]

    # Drive the k-anonymity range proxy with ONLY the 5-char prefix.
    resp = client.get(f"/api/password-check/range/{prefix}", headers=auth_headers)
    assert resp.status_code == 200

    blob = " ".join(captured)
    assert secret_password not in blob, "PLAINTEXT PASSWORD LEAKED IN OUTBOUND REQUEST"
    assert full_sha1 not in blob, "FULL PASSWORD HASH LEAKED IN OUTBOUND REQUEST"
    # Only the 5-char prefix should have been sent.
    assert prefix in blob


def test_range_endpoint_rejects_full_hash(client):
    full_sha1 = "A" * 40
    resp = client.get(f"/api/password-check/range/{full_sha1}")
    assert resp.status_code == 422


def test_range_endpoint_rejects_non_hex(client):
    assert client.get("/api/password-check/range/zzzzz").status_code == 422


def test_malformed_password_range_response_is_unavailable(client, monkeypatch):
    """A 200 HTML/error body cannot be interpreted as a password not found."""
    import app.signals.hibp as hibp_module

    class _Resp:
        status_code = 200
        text = "<html>upstream error</html>"

    monkeypatch.setattr(hibp_module.httpx, "get", lambda *_args, **_kwargs: _Resp())
    response = client.get("/api/password-check/range/ABCDE")
    assert response.status_code == 503
    assert "malformed" in response.json()["detail"].lower()


def test_password_endpoint_schema_has_no_hash_fields():
    """The hygiene request schema must not carry a password or full hash."""
    from app.schemas import PasswordHygieneRequest, PasswordReuseItem

    fields = set(PasswordHygieneRequest.model_fields.keys())
    assert "password" not in fields
    assert "sha1_suffix" not in fields
    assert "sha1" not in fields
    reuse_fields = set(PasswordReuseItem.model_fields.keys())
    assert reuse_fields == {"label", "reused"}


# --------------------------------------------------------------------------- #
# §14 [2] IDOR — covered in test_auth.py (read + modify)
# --------------------------------------------------------------------------- #
def test_idor_endpoint_matrix(client, auth_headers):
    """Every user-scoped endpoint must be auth-gated."""
    for method, path in [
        ("get", "/api/accounts"),
        ("get", "/api/analysis/events"),
        ("get", "/api/analysis/explanation"),
        ("post", "/api/analysis/run"),
        ("post", "/api/analysis/what-if"),
        ("get", "/api/graph"),
        ("get", "/api/planner/plan"),
    ]:
        response = getattr(client, method)(path)
        assert response.status_code == 401, f"{path} was not auth-gated"


# --------------------------------------------------------------------------- #
# §14 [3] Client cannot inject/override risk or severity
# --------------------------------------------------------------------------- #
def test_client_cannot_inject_severity(client, auth_headers, db_session):
    """Extra fields (like severity/score) sent by a client are ignored; the
    server computes authoritative values."""
    from sqlalchemy import select

    from app.models import User

    user = db_session.scalar(select(User).where(User.email == "user@example.com"))
    assert user is not None
    user.email_verified = True
    user.breach_monitor_consent = True
    db_session.commit()
    # Try to smuggle a severity into the breach check payload.
    resp = client.post(
        "/api/signals/breach",
        json={
            "account_id": "registered-email",
            "email": "user@example.com",
            "severity": 999.0,
            "score": 100,
            "status": "CHECKED_SAFE",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    # Tests never contact a live provider (conftest forbids the socket), so the
    # lookup is UNAVAILABLE — never the injected severity/score/status.
    event = resp.json()["events"][0]
    assert event["status"] == "UNAVAILABLE"
    assert event["severity"] == 0.0


def test_risk_is_recomputed_server_side(client, auth_headers):
    run = client.post("/api/analysis/run", headers=auth_headers)
    assert run.status_code == 200
    # Sending a request with no body must still produce a server-computed score.
    assert "score" in run.json()["risk"]


def test_what_if_rejects_unknown_action(client, auth_headers, db_session):
    # Ensure at least one account/event exists.
    client.post(
        "/api/accounts",
        json={"account_id": "wi", "label": "wi", "service_name": "Google",
              "email": "wi@example.com"},
        headers=auth_headers,
    )
    resp = client.post(
        "/api/analysis/what-if",
        json={"toggles": [{"action_key": "totally_made_up", "enabled": True}]},
        headers=auth_headers,
    )
    assert resp.status_code in (400, 422)


# --------------------------------------------------------------------------- #
# §14 [4] Secrets/tokens never appear in logs / audit rows
# --------------------------------------------------------------------------- #
def test_audit_redaction_removes_secrets():
    redacted = audit.redact(
        {
            "password": "hunter2hunter2",
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def",
            "note": "Bearer eyJhbGciOiJIUzI1NiJ9.xyz.payload",
            "nested": {"refresh_token": "supersecrettokenvalue"},
        }
    )
    blob = str(redacted).lower()
    assert "hunter2" not in blob
    assert "supersecrettokenvalue" not in blob
    assert "[redacted]" in blob
    # JWT-shaped strings are scrubbed even inside free text.
    assert "eyJhbGci" not in blob


def test_login_audit_has_no_token(client, db_session):
    from app.models import AuditLog
    from sqlalchemy import select

    client.post("/api/auth/register", json={"email": "log@example.com", "password": "a-long-password-1"})
    data = client.post("/api/auth/login", json={"email": "log@example.com", "password": "a-long-password-1"}).json()
    access_token = data["access_token"]
    rows = db_session.scalars(select(AuditLog)).all()
    blob = " ".join(str(r.detail) for r in rows)
    assert access_token not in blob


# --------------------------------------------------------------------------- #
# §14 [5] GraphRAG receives only pre-sanitized context
# --------------------------------------------------------------------------- #
def test_graphrag_context_whitelist():
    context = graphrag.sanitize_context(
        event_types=["SESSION_EXPOSURE"],
        correlations=[{"rule_id": "r", "severity": 0.5, "explanation": "secret text"}],
        risk={"score": 50, "band": "HIGH", "range_low": 40, "range_high": 60},
        graph_edges=[{"from": "Google", "to": "GitHub", "source": "doc"}],
    )
    # Only whitelisted keys survive; raw explanations/metadata are dropped.
    assert set(context.keys()) == {
        "event_types", "correlations", "risk", "graph_edges", "sanitized"
    }
    assert context["sanitized"] is True
    assert "explanation" not in str(context["correlations"])
    assert "secret text" not in str(context)


# --------------------------------------------------------------------------- #
# §14 [6] Rate limiting on login + password-check endpoints
# --------------------------------------------------------------------------- #
def test_login_rate_limited(client, settings):
    client.post("/api/auth/register", json={"email": "rl2@example.com", "password": "a-long-password-1"})
    codes = [
        client.post("/api/auth/login", json={"email": "rl2@example.com", "password": "bad"}).status_code
        for _ in range(settings.login_rate_limit_per_minute + 2)
    ]
    assert 429 in codes


def test_password_check_rate_limited(client, settings):
    codes = []
    for _ in range(settings.password_check_rate_limit_per_minute + 2):
        codes.append(client.get("/api/password-check/range/ABCDE").status_code)
    assert 429 in codes


# --------------------------------------------------------------------------- #
# §14 [7] CORS is restrictive, not wildcard
# --------------------------------------------------------------------------- #
def test_cors_not_wildcard(client):
    resp = client.get("/api/health", headers={"Origin": "http://evil.example.com"})
    allow = resp.headers.get("access-control-allow-origin")
    assert allow != "*"


def test_cors_allows_configured_origin(client):
    resp = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_readiness_checks_the_database_connection(client, db_session, monkeypatch):
    """The deploy health check must probe the DB, not merely report process up."""
    monkeypatch.setattr("app.routers.health.get_engine", lambda: db_session.bind)
    response = client.get("/api/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


# --------------------------------------------------------------------------- #
# §14 [8] Secrets only in env; .env not committed; .env.example exists
# --------------------------------------------------------------------------- #
def test_env_example_present_and_env_gitignored():
    root = Path(__file__).resolve().parents[2]
    assert (root / ".env.example").exists()
    gitignore = (root / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in gitignore


def test_env_file_locations_are_not_cwd_dependent():
    """`.env` must be found regardless of where uvicorn was launched from.

    Regression guard: ``env_file=".env"`` is resolved against the process cwd,
    so launching from ``backend/`` silently ignored the repo-root ``.env`` the
    README tells you to create — credentials filled in there were never read.
    """
    from app.config import ENV_FILES

    root = Path(__file__).resolve().parents[2]
    resolved = [Path(p) for p in ENV_FILES]

    # Every candidate is anchored to an absolute path, never cwd-relative.
    assert all(p.is_absolute() for p in resolved), resolved
    # The documented repo-root location is among them.
    assert root / ".env" in resolved
    # And it is a real directory, so the path is meaningful.
    assert all(p.parent.is_dir() for p in resolved)


def test_env_example_parses_when_copied_verbatim(monkeypatch):
    """`Copy-Item .env.example .env` must produce a loadable Settings().

    Regression guard: the example once declared
    ``CRIX_CORS_ORIGINS=http://localhost:5173`` while pydantic-settings
    JSON-decodes list-typed fields, so copying the file verbatim made
    ``Settings()`` raise ``JSONDecodeError`` on startup.
    """
    import os

    from app.config import Settings

    root = Path(__file__).resolve().parents[2]
    example = root / ".env.example"
    text = example.read_text(encoding="utf-8")

    # Every non-comment, non-blank line must be KEY=VALUE.
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            assert "=" in line, f".env.example line is not KEY=VALUE: {line!r}"

    # Load only the example's values — strip ambient CRIX_ overrides.
    for key in list(os.environ):
        if key.startswith("CRIX_"):
            monkeypatch.delenv(key)

    settings = Settings(_env_file=str(example))
    assert settings.cors_origins == ["http://localhost:5173"]
    assert settings.env == "development"
    # Unset provider credentials must stay unset, not be invented.
    assert settings.google_client_id == ""
    assert settings.linkedin_client_secret == ""
    # OAuth is frozen: the connector flag defaults OFF, and Instagram (removed)
    # no longer exists as a setting at all.
    assert settings.oauth_connectors_enabled is False
    assert not hasattr(settings, "instagram_client_secret")


def test_cors_origins_accepts_json_array_and_csv(monkeypatch):
    """Both documented spellings must parse; neither may crash config loading."""
    import os

    from app.config import Settings

    for key in list(os.environ):
        if key.startswith("CRIX_"):
            monkeypatch.delenv(key)

    monkeypatch.setenv("CRIX_CORS_ORIGINS", "http://a.example, http://b.example")
    assert Settings().cors_origins == ["http://a.example", "http://b.example"]

    monkeypatch.setenv("CRIX_CORS_ORIGINS", '["http://c.example"]')
    assert Settings().cors_origins == ["http://c.example"]


def test_production_requires_secret():
    from app.config import Settings

    prod = Settings(env="production", jwt_secret="dev-only-insecure-change-me")
    with pytest.raises(RuntimeError):
        prod.assert_production_safe()


def test_production_configuration_requires_postgres_tls_and_real_delivery():
    """The deploy-time guard must reject the common unsafe production shape."""
    from app.config import Settings

    safe = dict(
        env="production",
        jwt_secret="test-production-secret-not-for-use-0123456789",
        database_url="postgresql+psycopg://crix:password@pooler.example:5432/postgres?sslmode=require",
        cors_origins=["https://app.example.com"],
        public_base_url="https://app.example.com",
        trust_proxy_headers=True,
        token_encryption_key="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        email_from="CRIX <no-reply@example.com>",
        smtp_host="smtp.example.com",
        smtp_user="smtp-user",
        smtp_password="smtp-password",
        oauth_connectors_enabled=False,
        allow_fixture_connectors=False,
    )
    Settings(**safe).assert_production_safe()

    resend = {**safe, "email_provider": "resend", "resend_api_key": "test-resend-key"}
    Settings(**resend).assert_production_safe()
    with pytest.raises(RuntimeError, match="RESEND_API_KEY"):
        Settings(**{**resend, "resend_api_key": ""}).assert_production_safe()

    unsafe = Settings(**{**safe, "database_url": "sqlite:///./crix.db"})
    with pytest.raises(RuntimeError, match="PostgreSQL"):
        unsafe.assert_production_safe()

    unsafe = Settings(**{**safe, "allow_fixture_connectors": True})
    with pytest.raises(RuntimeError, match="Fixture"):
        unsafe.assert_production_safe()

    unsafe = Settings(**{**safe, "token_encryption_key": "not-a-fernet-key"})
    with pytest.raises(RuntimeError, match="valid Fernet"):
        unsafe.assert_production_safe()

    unsafe = Settings(**{**safe, "cors_origins": ["https://app.example.com/path"]})
    with pytest.raises(RuntimeError, match="exact HTTPS origin"):
        unsafe.assert_production_safe()
