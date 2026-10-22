"""The Alembic chain must build a schema from scratch, match the ORM, and reverse.

These tests run the real migrations against a throwaway SQLite file. They exist
because the original chain could NOT build from an empty database (the first
revision was empty, so ``upgrade head`` failed with ``NoSuchTableError``); see the
docstring of ``migrations/versions/17855d545687_initial_schema.py``.
"""
from __future__ import annotations

import json
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


def _seed_legacy_correlation(db_path: Path, *, rule_id: str, finding_ids: list[str]) -> None:
    """Insert one correlation the way the pre-Phase-3 code stored it."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.executescript(
            """
            INSERT INTO users (id, email, password_hash, is_active, email_verified,
                               totp_enabled, created_at)
            VALUES ('user-1', 'legacy@example.com', 'x', 1, 0, 0, '2026-01-01 00:00:00');
            INSERT INTO organizations (id, name, slug, created_by_user_id, created_at)
            VALUES ('org-1', 'Legacy Co', 'legacy-co', 'user-1', '2026-01-01 00:00:00');
            INSERT INTO memberships (id, org_id, user_id, role, is_active, created_at)
            VALUES ('mem-1', 'org-1', 'user-1', 'ORG_ADMIN', 1, '2026-01-01 00:00:00');
            """
        )
        conn.execute(
            "INSERT INTO correlations (id, user_id, run_id, rule_id, title, severity, "
            "confidence, explanation, contributing_event_ids, created_at) "
            "VALUES (?, 'user-1', 'run-1', ?, 'Legacy', 0.7, 0.8, 'explanation', ?, "
            "'2026-01-01 00:00:00')",
            (f"row_{rule_id}", rule_id, json.dumps(finding_ids)),
        )
        conn.commit()
    finally:
        conn.close()


def _build_phase2_correlations_shape(db_path: Path) -> None:
    """Leave ``correlations`` exactly as Phase 2 stored it.

    The initial revision materializes the *current* ORM schema via
    ``create_all``, so upgrading to ``c9d1e2f3a4b5`` from an empty database
    already contains the Phase 3 columns. To exercise the real back-fill path,
    the correlations table is rebuilt in its Phase 2 shape and the revision is
    stamped, so the Phase 3 revision is the one that alters it.
    """
    from sqlalchemy import create_engine

    engine = create_engine(f"sqlite:///{db_path.as_posix()}", future=True)
    Base.metadata.create_all(engine)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            DROP TABLE IF EXISTS correlations;
            CREATE TABLE correlations (
                id VARCHAR(32) NOT NULL PRIMARY KEY,
                user_id VARCHAR(32) NOT NULL,
                run_id VARCHAR(32) NOT NULL,
                rule_id VARCHAR(80) NOT NULL,
                title VARCHAR(200) NOT NULL,
                severity FLOAT NOT NULL,
                confidence FLOAT NOT NULL,
                explanation TEXT NOT NULL,
                contributing_event_ids JSON NOT NULL,
                created_at DATETIME NOT NULL
            );
            CREATE INDEX ix_correlations_user_id ON correlations (user_id);
            CREATE INDEX ix_correlations_run_id ON correlations (run_id);
            CREATE TABLE IF NOT EXISTS alembic_version (
                version_num VARCHAR(32) NOT NULL PRIMARY KEY
            );
            DELETE FROM alembic_version;
            INSERT INTO alembic_version (version_num) VALUES ('c9d1e2f3a4b5');
            """
        )
        conn.commit()
    finally:
        conn.close()
        engine.dispose()


def test_phase3_upgrade_preserves_and_backfills_legacy_rows(tmp_path, monkeypatch):
    """Phase 3 must rename + back-fill without deleting a single correlation."""
    db_path = tmp_path / "legacy_correlations.db"
    monkeypatch.setenv("CRIX_DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    get_settings.cache_clear()
    cfg = _alembic_config(db_path)
    try:
        # 1. Build the database exactly as it stood at the end of Phase 2.
        _build_phase2_correlations_shape(db_path)
        assert "contributing_event_ids" in _columns(db_path, "correlations")
        assert "correlation_id" not in _columns(db_path, "correlations")
        _seed_legacy_correlation(
            db_path, rule_id="elevated_takeover_risk", finding_ids=["evt_b", "evt_a"]
        )

        # 2. Run the Phase 3 revision.
        command.upgrade(cfg, "head")

        assert _columns(db_path, "correlations") >= {
            "correlation_id", "org_id", "rule_version", "correlation_type",
            "uncertainty", "chain", "asset_ids", "evidence", "evaluated_at",
            "finding_ids",
        }
        assert "contributing_event_ids" not in _columns(db_path, "correlations")

        conn = sqlite3.connect(db_path)
        try:
            rows = conn.execute(
                "SELECT id, org_id, rule_id, rule_version, finding_ids, correlation_id "
                "FROM correlations"
            ).fetchall()
        finally:
            conn.close()
        assert len(rows) == 1, "the legacy row must survive the migration"
        row_id, org_id, rule_id, version, finding_ids_raw, correlation_id = rows[0]
        assert org_id == "org-1", "org_id must be back-filled from the writer's membership"
        assert version == "1.0.0", "rule_version must be filled for a known rule"
        assert json.loads(finding_ids_raw) == ["evt_b", "evt_a"], "findings must be kept"
        assert len(correlation_id) == 32, "correlation_id must be deterministic and populated"

        # 3. The unique index exists only AFTER the back-fill ran.
        conn = sqlite3.connect(db_path)
        try:
            index_names = {
                row[1] for row in conn.execute("PRAGMA index_list(correlations)").fetchall()
            }
        finally:
            conn.close()
        assert "uq_correlations_correlation_id" in index_names

        # 4. And the whole thing reverses without data loss on the way back.
        command.downgrade(cfg, "c9d1e2f3a4b5")
        assert "contributing_event_ids" in _columns(db_path, "correlations")
        assert "correlation_id" not in _columns(db_path, "correlations")
        conn = sqlite3.connect(db_path)
        try:
            kept = conn.execute("SELECT COUNT(*) FROM correlations").fetchone()[0]
            ids = conn.execute("SELECT contributing_event_ids FROM correlations").fetchone()[0]
        finally:
            conn.close()
        assert kept == 1, "downgrade must not delete correlations"
        assert json.loads(ids) == ["evt_b", "evt_a"]
    finally:
        get_settings.cache_clear()