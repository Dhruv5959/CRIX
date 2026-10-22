"""The Alembic chain must build a schema from scratch, match the ORM, and reverse.

These tests run the real migrations against a throwaway SQLite file. They exist
because the original chain could NOT build from an empty database (the first
revision was empty, so ``upgrade head`` failed with ``NoSuchTableError``); see the
docstring of ``migrations/versions/17855d545687_initial_schema.py``.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from app.config import get_settings
from app.db import Base

BACKEND = Path(__file__).resolve().parents[1]


def _tables(db_path: Path) -> set[str]:
    conn = sqlite3.connect(db_path)
    try:
        return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()


def _columns(db_path: Path, table: str) -> set[str]:
    conn = sqlite3.connect(db_path)
    try:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    finally:
        conn.close()


def _alembic_config(db_path: Path) -> Config:
    url = f"sqlite:///{db_path.as_posix()}"
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


@pytest.fixture()
def migrated_db(tmp_path, monkeypatch):
    """Point CRIX settings at a temp file and run ``upgrade head``."""
    db_path = tmp_path / "migration_check.db"
    monkeypatch.setenv("CRIX_DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    get_settings.cache_clear()
    cfg = _alembic_config(db_path)
    try:
        yield db_path, cfg
    finally:
        get_settings.cache_clear()


def test_upgrade_head_builds_a_complete_schema(migrated_db):
    db_path, cfg = migrated_db
    command.upgrade(cfg, "head")

    tables = _tables(db_path)
    for expected in (
        "users",
        "security_events",
        "organizations",
        "memberships",
        "invitations",
        "org_assets",
        "asset_dependencies",
        "admin_view_audit_log",
        "provider_connections",
        "provider_capabilities",
        "account_relationships",
        "propagation_results",
    ):
        assert expected in tables, f"{expected} missing after upgrade head"

    # The incremental column from the second revision is present too.
    assert "source_mode" in _columns(db_path, "security_events")


def test_migrated_schema_matches_orm_metadata(migrated_db):
    """Guards against schema drift between the migrations and the ORM models."""
    db_path, cfg = migrated_db
    command.upgrade(cfg, "head")

    migrated = _tables(db_path) - {"alembic_version"}
    assert migrated == set(Base.metadata.tables.keys())


def test_upgrade_is_reversible(migrated_db):
    db_path, cfg = migrated_db
    command.upgrade(cfg, "head")
    assert len(_tables(db_path)) > 15

    command.downgrade(cfg, "base")
    # Only Alembic's own bookkeeping table may remain.
    assert _tables(db_path) <= {"alembic_version"}

    # And it can be rebuilt afterwards (the round trip is not one-way).
    command.upgrade(cfg, "head")
    assert "organizations" in _tables(db_path)


def test_upgrade_is_idempotent_after_create_all(tmp_path, monkeypatch):
    """The legacy bootstrap (``create_all`` first) must not break the chain."""
    db_path = tmp_path / "legacy_bootstrap.db"
    url = f"sqlite:///{db_path.as_posix()}"
    monkeypatch.setenv("CRIX_DATABASE_URL", url)
    get_settings.cache_clear()
    try:
        from sqlalchemy import create_engine

        engine = create_engine(url, future=True)
        Base.metadata.create_all(engine)
        engine.dispose()

        # Should be a no-op rather than a duplicate-table error.
        command.upgrade(_alembic_config(db_path), "head")
        assert "organizations" in _tables(db_path)
    finally:
        get_settings.cache_clear()