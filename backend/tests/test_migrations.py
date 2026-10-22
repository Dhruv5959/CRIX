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


def _build_phase3_risk_results_shape(db_path: Path) -> None:
    """Leave ``risk_results`` exactly as Phase 3 stored it.

    The initial revision materializes the *current* ORM schema via
    ``create_all`` (which already includes the Phase 4 columns), so the table
    is rebuilt in its pre-Phase-4 shape and the revision is stamped — making
    ``f3a1c2d4e5b6`` the revision that actually alters it.
    """
    from sqlalchemy import create_engine

    engine = create_engine(f"sqlite:///{db_path.as_posix()}", future=True)
    Base.metadata.create_all(engine)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            DROP TABLE IF EXISTS risk_results;
            CREATE TABLE risk_results (
                id VARCHAR(32) NOT NULL PRIMARY KEY,
                user_id VARCHAR(32) NOT NULL,
                run_id VARCHAR(32) NOT NULL,
                score FLOAT NOT NULL,
                band VARCHAR(20) NOT NULL,
                confidence VARCHAR(20) NOT NULL,
                range_low FLOAT NOT NULL,
                range_high FLOAT NOT NULL,
                base_risk FLOAT NOT NULL,
                interaction_risk FLOAT NOT NULL,
                mitigation_credit FLOAT NOT NULL,
                components JSON NOT NULL,
                created_at DATETIME NOT NULL
            );
            CREATE INDEX ix_risk_results_user_id ON risk_results (user_id);
            CREATE INDEX ix_risk_results_run_id ON risk_results (run_id);

            INSERT INTO users (id, email, password_hash, is_active, email_verified,
                               totp_enabled, created_at)
            VALUES ('user-1', 'legacy@example.com', 'x', 1, 0, 0, '2026-01-01 00:00:00');
            INSERT INTO organizations (id, name, slug, created_by_user_id, created_at)
            VALUES ('org-1', 'Legacy Co', 'legacy-co', 'user-1', '2026-01-01 00:00:00');
            INSERT INTO memberships (id, org_id, user_id, role, is_active, created_at)
            VALUES ('mem-1', 'org-1', 'user-1', 'ORG_ADMIN', 1, '2026-01-01 00:00:00');

            INSERT INTO risk_results (id, user_id, run_id, score, band, confidence,
                                      range_low, range_high, base_risk, interaction_risk,
                                      mitigation_credit, components, created_at)
            VALUES ('risk-legacy', 'user-1', 'run-legacy', 61.7, 'HIGH', 'high',
                    58.0, 65.0, 48.5, 13.2, 0.0,
                    '{"note": "pre-criticality snapshot"}',
                    '2026-01-01 00:00:00');

            CREATE TABLE IF NOT EXISTS alembic_version (
                version_num VARCHAR(32) NOT NULL PRIMARY KEY
            );
            DELETE FROM alembic_version;
            INSERT INTO alembic_version (version_num) VALUES ('d4e5f6a7b8c9');
            """
        )
        conn.commit()
    finally:
        conn.close()
        engine.dispose()


def test_phase4_upgrade_adds_risk_context_and_preserves_snapshots(tmp_path, monkeypatch):
    """Phase 4 must add + back-fill without re-scoring or deleting a snapshot."""
    db_path = tmp_path / "legacy_risk.db"
    monkeypatch.setenv("CRIX_DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    get_settings.cache_clear()
    cfg = _alembic_config(db_path)
    try:
        # 1. Build the database exactly as it stood at the end of Phase 3.
        _build_phase3_risk_results_shape(db_path)
        assert _columns(db_path, "risk_results") == {
            "id", "user_id", "run_id", "score", "band", "confidence", "range_low",
            "range_high", "base_risk", "interaction_risk", "mitigation_credit",
            "components", "created_at",
        }

        # 2. Run the Phase 4 revision.
        command.upgrade(cfg, "head")

        assert _columns(db_path, "risk_results") >= {
            "org_id", "asset_id", "model_version", "criticality_adjustment",
        }

        conn = sqlite3.connect(db_path)
        try:
            row = conn.execute(
                "SELECT score, band, org_id, asset_id, model_version, "
                "criticality_adjustment, components FROM risk_results "
                "WHERE id = 'risk-legacy'"
            ).fetchone()
            index_names = {
                r[1] for r in conn.execute("PRAGMA index_list(risk_results)").fetchall()
            }
        finally:
            conn.close()
        assert row is not None, "the pre-Phase-4 snapshot must survive the migration"
        score, band, org_id, asset_id, model_version, adjustment, components = row
        # Values are preserved byte-for-byte; only honest back-fills are added.
        assert (score, band) == (61.7, "HIGH")
        assert json.loads(components) == {"note": "pre-criticality snapshot"}
        assert org_id == "org-1", "org_id must be back-filled from the membership"
        assert asset_id is None, "the old rows bound no asset — nothing is invented"
        assert model_version == "risk-1.0", "old rows keep the formula that made them"
        assert adjustment == 0.0, "risk-1.0 had no criticality term"
        assert "ix_risk_results_org_id" in index_names, "org-scoped reads need the index"

        # 3. And it reverses without losing the snapshot.
        command.downgrade(cfg, "d4e5f6a7b8c9")
        assert _columns(db_path, "risk_results").isdisjoint(
            {"org_id", "asset_id", "model_version", "criticality_adjustment"}
        )
        conn = sqlite3.connect(db_path)
        try:
            kept = conn.execute(
                "SELECT score FROM risk_results WHERE id = 'risk-legacy'"
            ).fetchone()
        finally:
            conn.close()
        assert kept == (61.7,), "downgrade must not delete risk snapshots"
    finally:
        get_settings.cache_clear()


# --------------------------------------------------------------------------- #
# Phase 7: remediation tasks gain the task/verification model
# --------------------------------------------------------------------------- #
def _build_phase6_remediation_shape(db_path: Path) -> None:
    """Leave ``remediation_actions`` exactly as Phase 6 stored it.

    The initial revision materializes the *current* ORM schema via
    ``create_all`` (which already includes the Phase 7 columns and the
    history table), so the table is rebuilt in its pre-Phase-7 shape, the
    history table is dropped, and the revision is stamped — making
    ``a2b3c4d5e6f7`` the revision that actually alters them.
    """
    from sqlalchemy import create_engine

    engine = create_engine(f"sqlite:///{db_path.as_posix()}", future=True)
    Base.metadata.create_all(engine)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            DROP TABLE IF EXISTS remediation_task_history;
            DROP TABLE IF EXISTS remediation_actions;
            CREATE TABLE remediation_actions (
                id VARCHAR(32) NOT NULL PRIMARY KEY,
                user_id VARCHAR(32),
                action_key VARCHAR(80) NOT NULL,
                title VARCHAR(200) NOT NULL,
                description TEXT NOT NULL,
                addresses_event_types JSON NOT NULL,
                effort FLOAT NOT NULL,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL
            );
            CREATE INDEX ix_remediation_actions_user_id ON remediation_actions (user_id);
            CREATE INDEX ix_remediation_actions_action_key ON remediation_actions (action_key);

            DROP TABLE IF EXISTS organizations;
            CREATE TABLE organizations (
                id VARCHAR(32) NOT NULL PRIMARY KEY,
                name VARCHAR(200) NOT NULL,
                slug VARCHAR(120) NOT NULL UNIQUE,
                created_by_user_id VARCHAR(32),
                created_at DATETIME NOT NULL
            );

            INSERT INTO users (id, email, password_hash, is_active, email_verified,
                               totp_enabled, created_at)
            VALUES ('user-1', 'legacy@example.com', 'x', 1, 0, 0, '2026-01-01 00:00:00');
            INSERT INTO organizations (id, name, slug, created_by_user_id, created_at)
            VALUES ('org-1', 'Legacy Co', 'legacy-co', 'user-1', '2026-01-01 00:00:00');
            INSERT INTO memberships (id, org_id, user_id, role, is_active, created_at)
            VALUES ('mem-1', 'org-1', 'user-1', 'ORG_ADMIN', 1, '2026-01-01 00:00:00');

            INSERT INTO remediation_actions (id, user_id, action_key, title, description,
                                             addresses_event_types, effort, created_at, updated_at)
            VALUES ('task-legacy', 'user-1', 'strengthen_mfa', 'Strengthen MFA',
                    'legacy user-scoped task', '["no_mfa", "mfa"]', 2.0,
                    '2026-01-01 00:00:00', '2026-01-01 00:00:00');

            CREATE TABLE IF NOT EXISTS alembic_version (
                version_num VARCHAR(32) NOT NULL PRIMARY KEY
            );
            DELETE FROM alembic_version;
            INSERT INTO alembic_version (version_num) VALUES ('f3a1c2d4e5b6');
            """
        )
        conn.commit()
    finally:
        conn.close()
        engine.dispose()


def test_phase7_upgrade_adds_task_model_and_preserves_rows(tmp_path, monkeypatch):
    """Phase 7 must add + back-fill the task model without deleting a row."""
    db_path = tmp_path / "legacy_tasks.db"
    monkeypatch.setenv("CRIX_DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    get_settings.cache_clear()
    cfg = _alembic_config(db_path)
    try:
        # 1. Build the database exactly as it stood at the end of Phase 6.
        _build_phase6_remediation_shape(db_path)
        assert "remediation_task_history" not in _tables(db_path)
        assert _columns(db_path, "remediation_actions") == {
            "id", "user_id", "action_key", "title", "description",
            "addresses_event_types", "effort", "created_at", "updated_at",
        }
        assert "effort_budget" not in _columns(db_path, "organizations")

        # 2. Run the Phase 7 revision.
        command.upgrade(cfg, "head")

        assert _columns(db_path, "remediation_actions") >= {
            "org_id", "target_asset_id", "finding_ids", "prerequisites",
            "dependencies", "required_evidence", "verification_method",
            "status", "assigned_to", "expected_reduction", "completed_at",
        }
        assert "remediation_task_history" in _tables(db_path)
        assert _columns(db_path, "remediation_task_history") >= {
            "id", "action_id", "org_id", "actor_user_id", "from_status",
            "to_status", "method", "result", "model_version", "evidence_refs",
            "detail", "created_at",
        }
        assert "effort_budget" in _columns(db_path, "organizations")

        conn = sqlite3.connect(db_path)
        try:
            row = conn.execute(
                "SELECT user_id, action_key, effort, org_id, status, "
                "verification_method, expected_reduction, completed_at, "
                "finding_ids, prerequisites FROM remediation_actions "
                "WHERE id = 'task-legacy'"
            ).fetchone()
            budget = conn.execute(
                "SELECT effort_budget FROM organizations WHERE id = 'org-1'"
            ).fetchone()
            index_names = {
                r[1] for r in conn.execute("PRAGMA index_list(remediation_actions)").fetchall()
            }
        finally:
            conn.close()
        assert row is not None, "the pre-Phase-7 task must survive the migration"
        user_id, action_key, effort, org_id, status, method, reduction, completed_at, findings, prereqs = row
        assert (user_id, action_key, effort) == ("user-1", "strengthen_mfa", 2.0)
        assert org_id == "org-1", "org_id must be back-filled from the membership"
        assert status == "OPEN", "legacy tasks become OPEN (never claimed, never verified)"
        assert method == "MODELED", "honest default verification path"
        assert reduction is None, "expected_reduction is computed later by the engine, never invented"
        assert completed_at is None, "nothing claims a legacy task was completed"
        assert json.loads(findings) == [] and json.loads(prereqs) == []
        assert budget == (6.0,), "the admin-set default effort budget"
        assert {"ix_remediation_actions_org_id", "ix_remediation_actions_status"} <= index_names

        # 3. And it reverses without losing the task row.
        command.downgrade(cfg, "f3a1c2d4e5b6")
        assert "remediation_task_history" not in _tables(db_path)
        assert _columns(db_path, "remediation_actions").isdisjoint(
            {"org_id", "target_asset_id", "finding_ids", "prerequisites",
             "dependencies", "required_evidence", "verification_method",
             "status", "assigned_to", "expected_reduction", "completed_at"}
        )
        assert "effort_budget" not in _columns(db_path, "organizations")
        conn = sqlite3.connect(db_path)
        try:
            kept = conn.execute(
                "SELECT action_key, effort FROM remediation_actions WHERE id = 'task-legacy'"
            ).fetchone()
        finally:
            conn.close()
        assert kept == ("strengthen_mfa", 2.0), "downgrade must not delete task rows"
    finally:
        get_settings.cache_clear()