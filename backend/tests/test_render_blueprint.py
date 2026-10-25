"""Regression checks for the repository's Render Free Blueprint."""
from __future__ import annotations

from pathlib import Path

import yaml


def test_render_blueprint_uses_only_free_web_service_and_supabase_database():
    root = Path(__file__).resolve().parents[2]
    blueprint = yaml.safe_load((root / "render.yaml").read_text(encoding="utf-8"))

    assert "databases" not in blueprint
    assert len(blueprint["services"]) == 1
    service = blueprint["services"][0]
    assert service["type"] == "web"
    assert service["plan"] == "free"
    assert service["rootDir"] == "backend"
    assert service["healthCheckPath"] == "/api/ready"
    assert "alembic upgrade head" in service["startCommand"]
    assert "seed_reference_data.py" in service["startCommand"]
    assert "seed_demo" not in service["startCommand"]
    assert "disk" not in service
    assert service.get("runtime") != "private"

    variables = {item["key"]: item for item in service["envVars"]}
    assert variables["CRIX_DATABASE_URL"]["sync"] is False
    assert variables["CRIX_EMAIL_PROVIDER"]["value"] == "resend"
    assert variables["CRIX_RESEND_API_KEY"]["sync"] is False
    assert variables["CRIX_EMAIL_FROM"]["sync"] is False
    assert not any(key.startswith("CRIX_SMTP_") for key in variables)
