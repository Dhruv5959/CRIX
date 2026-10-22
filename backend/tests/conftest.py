"""Shared test fixtures.

Uses in-memory SQLite by default (StaticPool so every connection shares one DB).
Setting ``CRIX_TEST_DATABASE_URL`` runs the same suite against PostgreSQL
(``docker compose up -d postgres`` first) — SQLite stays the default. Overrides
the DB + settings dependencies, seeds curated reference data, and resets the
rate limiters between tests.
"""
from __future__ import annotations

import os

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import Settings, get_settings
from app.data.loader import seed_all
from app.db import Base, get_db
from app.main import app
from app.rate_limit import breach_check_limiter, login_limiter, password_check_limiter
from app.signals import xposedornot
from app.signals.xposedornot import reset_provider_state

# Default is in-memory SQLite; a postgresql:// URL switches the whole suite.
TEST_DATABASE_URL = os.environ.get("CRIX_TEST_DATABASE_URL", "sqlite://")

TEST_SETTINGS = Settings(
    env="test",
    database_url=TEST_DATABASE_URL,
    jwt_secret="test-secret-not-for-production-0123456789",
    bcrypt_rounds=12,
    access_token_expire_minutes=15,
    refresh_token_expire_days=7,
    cors_origins=["http://localhost:5173"],
    hibp_api_key="",
    # Pinned explicitly so a stray value in the environment or .env cannot
    # change what these tests exercise.
    breach_email_provider="auto",
    login_rate_limit_per_minute=5,
    password_check_rate_limit_per_minute=30,
    breach_check_rate_limit_per_minute=10,
    # The connector-layer tests exercise the OAuth code paths, so they enable the
    # (otherwise OFF) freeze flag here. The freeze itself is asserted separately
    # against the real defaults in tests/test_oauth_freeze.py.
    oauth_connectors_enabled=True,
)


@pytest.fixture(autouse=True)
def _forbid_live_provider(monkeypatch):
    """Network safety net: no test may contact a real breach provider.

    The free tier is tiny (25 lookups/hour/IP) and a suite must never depend on
    the public internet, so the client's HTTP transport is swapped for one that
    fails loudly. Tests that want a specific response override it with
    ``tests.xon_stubs.patch_transport``.
    """

    def _forbidden(url, **_kwargs):
        raise httpx.ConnectError(f"tests must not contact the network: {url}")

    monkeypatch.setattr(xposedornot.httpx, "get", _forbidden)
    reset_provider_state()
    yield
    reset_provider_state()


@pytest.fixture()
def engine():
    url = TEST_DATABASE_URL
    kwargs: dict = {"future": True}
    if url.startswith("sqlite"):
        kwargs.update(connect_args={"check_same_thread": False}, poolclass=StaticPool)
    engine = create_engine(url, **kwargs)
    # Clean slate per test (matters for a persistent PostgreSQL database).
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture()
def db_session(engine):
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    session = TestingSession()
    seed_all(session)
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    def override_get_settings():
        return TEST_SETTINGS

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = override_get_settings
    login_limiter.reset()
    password_check_limiter.reset()
    breach_check_limiter.reset()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def settings() -> Settings:
    return TEST_SETTINGS


def register_and_login(client, email="user@example.com", password="correct horse battery") -> dict:
    client.post("/api/auth/register", json={"email": email, "password": password})
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    data = response.json()
    # Refresh cookie is set automatically by TestClient's cookie jar.
    return data


def register_org_admin(
    client,
    email="admin@example.com",
    password="correct horse battery",
    org_name="Example Company",
) -> dict:
    """Register a fresh organization; the registrant becomes its ORG_ADMIN.

    Returns auth headers for the new admin.
    """
    response = client.post(
        "/api/auth/register",
        json={"email": email, "password": password, "org_name": org_name},
    )
    assert response.status_code == 201, response.text
    data = register_and_login(client, email, password)
    return {"Authorization": f"Bearer {data['access_token']}", "X-CSRF-Token": data["csrf_token"]}


def login_headers(client, email: str, password: str) -> dict:
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    data = response.json()
    return {"Authorization": f"Bearer {data['access_token']}", "X-CSRF-Token": data["csrf_token"]}


@pytest.fixture()
def auth_headers(client):
    data = register_and_login(client)
    return {"Authorization": f"Bearer {data['access_token']}", "X-CSRF-Token": data["csrf_token"]}