"""OAuth is FROZEN (§1.4): the connector surface is OFF by default *in code*.

These tests assert the freeze directly against the real defaults and against an
API client whose flag is off — independent of whatever an individual test's
``TEST_SETTINGS`` chooses.
"""
from __future__ import annotations

from app.config import Settings
from app.oauth.providers import PROVIDERS
from tests.conftest import TEST_SETTINGS


def test_flag_defaults_off_in_code(monkeypatch):
    import os

    for key in list(os.environ):
        if key.startswith("CRIX_"):
            monkeypatch.delenv(key)
    settings = Settings(_env_file=None)
    assert settings.oauth_connectors_enabled is False


def test_instagram_provider_is_removed():
    assert "instagram" not in PROVIDERS
    assert set(PROVIDERS) <= {"google", "linkedin"}


def test_instagram_settings_no_longer_exist():
    for key in list(dict(Settings.model_fields)):
        assert "instagram" not in key


def test_connector_surface_is_absent_when_flag_off(client, monkeypatch, auth_headers):
    monkeypatch.setattr(TEST_SETTINGS, "oauth_connectors_enabled", False)

    assert client.get("/api/oauth/providers").status_code == 404
    assert client.get("/api/oauth/capabilities").status_code == 404
    assert client.get("/api/oauth/connections", headers=auth_headers).status_code == 404
    assert client.post("/api/oauth/fixtures/google", headers=auth_headers).status_code == 404
    assert client.get("/api/oauth/google/authorize", headers=auth_headers).status_code == 404


def test_oauth_callback_reports_disabled_when_flag_off(client, monkeypatch):
    monkeypatch.setattr(TEST_SETTINGS, "oauth_connectors_enabled", False)
    resp = client.get("/api/oauth/google/callback?code=x&state=y", follow_redirects=False)
    assert resp.status_code in (302, 307)
    assert "connectors_disabled" in resp.headers.get("location", "")