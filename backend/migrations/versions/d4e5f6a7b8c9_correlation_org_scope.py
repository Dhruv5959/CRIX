"""Correlation results become explicit, organization-owned records (Phase 3)

``correlations`` gains:

  * correlation_id   stable engine identity (deterministic hash of organization
                     + rule + rule version + contributing finding ids). It is
                     the upsert key: re-running the pipeline on the same
                     findings updates the row instead of appending a duplicate.
  * org_id           organization the correlation belongs to (resolved
                     server-side from the writer's membership)
  * rule_version     the exact rule revision that produced the result
  * correlation_type the rule's correlation category
  * uncertainty      what the confidence figure means and does not mean
  * chain            the reasoning in plain language
  * asset_ids        company asset ids involved (referenced, never copied)
  * evidence         the small set of facts the correlation itself cites
  * evaluated_at     when the engine produced this result

``contributing_event_ids`` is RENAMED to ``finding_ids`` (same data, clearer
name for a record that only ever references findings — it never copies or
mutates them).

Existing rows are preserved and back-filled: ``org_id`` from the writer's
active membership where one exists, and ``correlation_id`` from the row's own
content so a re-run can adopt the row instead of duplicating it. A legacy row
whose content hash would collide with an earlier one (the old schema allowed
one row per run) gets an id derived from its own primary key, so nothing is
deleted to make the uniqueness constraint fit. Rows whose user has no
membership keep the empty ``org_id`` sentinel, which matches no tenant query
(fail-closed).

IDEMPOTENT: every step is guarded by an existence check, because the initial
revision already materialises the current ORM schema with
``Base.metadata.create_all`` on an empty database. ``downgrade`` removes
exactly the columns added here and renames the column back.

Revision ID: d4e5f6a7b8c9
Revises: c9d1e2f3a4b5
Create Date: 2026-10-22
"""
import hashlib
import json
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, None] = 'c9d1e2f3a4b5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Frozen copy of the rule catalog as it stood when versioning was introduced.
# Kept inline on purpose: a data migration must not depend on the application's
# current YAML, which keeps evolving after this file is written.
_KNOWN_RULE_VERSIONS = {
    "credential_stuffing_risk": "1.0.0",
    "targeted_credential_theft": "1.0.0",
    "cascading_recovery_risk": "1.0.0",
    "elevated_takeover_risk": "1.0.0",
    "mfa_ineffective_session_exposure": "1.0.0",
    "identity_reuse_blend": "1.0.0",
    "sim_swap_recovery_exposure": "1.0.0",
    "oversharing_and_phishing": "1.0.0",
}


def _bind():
    return op.get_bind()


def _dialect() -> str:
    return _bind().dialect.name


def _tables() -> set[str]:
    """Current table names.

    Read with raw driver SQL on purpose: SQLAlchemy's reflection cache is not
    invalidated when Alembic's batch mode rebuilds a table inside the same
    migration, which would make the guards below see a stale schema.
    """
    bind = _bind()
    if _dialect() == "sqlite":
        return {
            row[0]
            for row in bind.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    if _dialect() == "postgresql":
        return set(
            bind.execute(
                sa.text(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = current_schema()"
                )
            ).scalars()
        )
    return set(sa.inspect(bind).get_table_names())


def _columns(table: str) -> set[str]:
    if table not in _tables():
        return set()
    bind = _bind()
    if _dialect() == "sqlite":
        return {row[1] for row in bind.exec_driver_sql(f'PRAGMA table_info("{table}")').fetchall()}
    if _dialect() == "postgresql":
        return set(
            bind.execute(
                sa.text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = current_schema() AND table_name = :t"
                ),
                {"t": table},
            ).scalars()
        )
    return {col["name"] for col in sa.inspect(bind).get_columns(table)}


def _indexes(table: str) -> set[str]:
    if table not in _tables():
        return set()
    bind = _bind()
    if _dialect() == "sqlite":
        return {row[1] for row in bind.exec_driver_sql(f'PRAGMA index_list("{table}")').fetchall()}
    if _dialect() == "postgresql":
        return set(
            bind.execute(
                sa.text(
                    "SELECT indexname FROM pg_indexes "
                    "WHERE schemaname = current_schema() AND tablename = :t"
                ),
                {"t": table},
            ).scalars()
        )
    return {ix["name"] for ix in sa.inspect(bind).get_indexes(table)}


def _add_columns(table: str, columns: list[sa.Column]) -> None:
    """Add the columns a table is missing, in one batch.

    ``op.add_column`` with a foreign key makes Alembic emit a separate ALTER
    that SQLite refuses ("No support for ALTER of constraints"), so the columns
    go in through a single ``batch_alter_table`` — a copy-and-move table
    rebuild on SQLite, a plain ALTER on PostgreSQL. Rows are copied, never
    dropped.
    """
    if table not in _tables():
        return
    have = _columns(table)
    missing = [column for column in columns if column.name not in have]
    if not missing:
        return
    with op.batch_alter_table(table) as batch_op:
        for column in missing:
            batch_op.add_column(column)


def _create_index_if_missing(name: str, table: str, column: str) -> None:
    if table in _tables() and column in _columns(table) and name not in _indexes(table):
        op.create_index(name, table, [column])


def _create_unique_index_if_missing(name: str, table: str, column: str) -> None:
    if table in _tables() and column in _columns(table) and name not in _indexes(table):
        op.create_index(name, table, [column], unique=True)


def _backfill_org_id(table: str) -> None:
    """Best-effort: give existing rows the organization of their writer."""
    if table not in _tables() or "memberships" not in _tables():
        return
    op.execute(
        sa.text(
            f"""
            UPDATE {table}
            SET org_id = (
                SELECT m.org_id FROM memberships m
                WHERE m.user_id = {table}.user_id AND m.is_active
                ORDER BY m.created_at, m.id
                LIMIT 1
            )
            WHERE org_id = ''
            """
        )
    )


def _correlation_id(org_id: str, rule_id: str, version: str, finding_ids: list[str]) -> str:
    """Mirror of ``app.engine.correlation._correlation_id`` (kept inline: a data
    migration must not import application code)."""
    key = "|".join([org_id, rule_id, version, *sorted(finding_ids)])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def _parse_finding_ids(raw) -> list[str]:
    if raw is None or raw == "":
        return []
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        return []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _backfill_correlation_ids() -> None:
    """Give every pre-Phase-3 row a deterministic, collision-free identity.

    The clean content hash is preferred (so a post-migration re-run of the same
    findings adopts the row instead of duplicating it); a row whose hash is
    already taken — the old schema inserted one row per run — falls back to an
    id derived from its own primary key. Nothing is deleted.
    """
    table = "correlations"
    if table not in _tables():
        return
    # Read the pre-rename column name.
    source_column = (
        "contributing_event_ids" if "contributing_event_ids" in _columns(table) else "finding_ids"
    )
    if source_column not in _columns(table) or "correlation_id" not in _columns(table):
        return
    bind = _bind()
    rows = bind.execute(
        sa.text(
            f"SELECT id, org_id, rule_id, {source_column} FROM {table} "
            f"WHERE correlation_id = '' OR correlation_id IS NULL"
        )
    ).fetchall()
    used: set[str] = set()
    for row_id, org_id, rule_id, raw_ids in rows:
        org = org_id or ""
        rule = rule_id or ""
        version = _KNOWN_RULE_VERSIONS.get(rule, "unknown")
        candidate = _correlation_id(org, rule, version, _parse_finding_ids(raw_ids))
        if candidate in used:
            candidate = hashlib.sha256(
                f"{org}|{rule}|legacy|{row_id}".encode("utf-8")
            ).hexdigest()[:32]
        used.add(candidate)
        bind.execute(
            sa.text(
                "UPDATE correlations SET correlation_id = :cid, rule_version = :version "
                "WHERE id = :id AND (correlation_id = '' OR correlation_id IS NULL)"
            ),
            {"cid": candidate, "version": version, "id": row_id},
        )


def upgrade() -> None:
    _add_columns(
        "correlations",
        [
            # Stable engine identity. Added without the unique index: the index
            # is created AFTER the backfill below, so existing rows can be
            # given distinct ids first (the old schema allowed duplicates).
            sa.Column("correlation_id", sa.String(32), nullable=False, server_default=""),
            sa.Column(
                "org_id", sa.String(32),
                sa.ForeignKey(
                    "organizations.id", ondelete="CASCADE",
                    name="fk_correlations_org_id",
                ),
                nullable=False, server_default="",
            ),
            sa.Column("rule_version", sa.String(20), nullable=False, server_default=""),
            sa.Column("correlation_type", sa.String(80), nullable=False, server_default=""),
            # What the confidence figure means and does not mean.
            sa.Column("uncertainty", sa.JSON(), nullable=False, server_default="{}"),
            # The reasoning in plain language.
            sa.Column("chain", sa.JSON(), nullable=False, server_default="[]"),
            # Referenced ids only: a correlation never copies the findings.
            sa.Column("asset_ids", sa.JSON(), nullable=False, server_default="[]"),
            # The small set of facts the correlation itself cites.
            sa.Column("evidence", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=True),
        ],
    )
    _create_index_if_missing("ix_correlations_org_id", "correlations", "org_id")

    _backfill_org_id("correlations")
    _backfill_correlation_ids()

    # Rename now that every row carries a distinct correlation_id. A direct
    # RENAME COLUMN is used because it is supported verbatim by both SQLite
    # (3.25+) and PostgreSQL, whereas Alembic's batch ``alter_column(new_name)``
    # does not rename on SQLite. Guarded by existence checks so it is idempotent.
    if (
        "correlations" in _tables()
        and "contributing_event_ids" in _columns("correlations")
        and "finding_ids" not in _columns("correlations")
    ):
        op.execute(
            sa.text(
                "ALTER TABLE correlations RENAME COLUMN contributing_event_ids TO finding_ids"
            )
        )

    # Only after the backfill: the hash must be unique across existing rows.
    _create_unique_index_if_missing(
        "uq_correlations_correlation_id", "correlations", "correlation_id"
    )


def _drop_index_if_exists(name: str, table: str) -> None:
    # Indexes on the columns being dropped must go first: the batch rebuild
    # re-creates every index it reflects, including ones we are removing.
    if table in _tables() and name in _indexes(table):
        op.drop_index(name, table_name=table)


def downgrade() -> None:
    # Two index names can point at ``correlation_id``: the migration's unique
    # index ``uq_...``, and the ORM's ``ix_...`` (from ``index=True``), which the
    # initial revision's ``create_all`` materializes. A batch rebuild re-creates
    # every index it reflects, so BOTH must go before the column drops — the
    # ``ix_`` one would otherwise reference a column that no longer exists.
    _drop_index_if_exists("uq_correlations_correlation_id", "correlations")
    _drop_index_if_exists("ix_correlations_correlation_id", "correlations")
    _drop_index_if_exists("ix_correlations_org_id", "correlations")

    # Restore the old column name, then remove the Phase 3 columns. The rename
    # uses a direct RENAME COLUMN (supported by SQLite 3.25+ and PostgreSQL);
    # the drops use a batch op because SQLite refuses ``ALTER TABLE ... DROP
    # COLUMN`` for a foreign-key column (a rebuild on SQLite, a plain ALTER on
    # PostgreSQL). Rows are copied, never dropped.
    if (
        "correlations" in _tables()
        and "finding_ids" in _columns("correlations")
        and "contributing_event_ids" not in _columns("correlations")
    ):
        op.execute(
            sa.text(
                "ALTER TABLE correlations RENAME COLUMN finding_ids TO contributing_event_ids"
            )
        )

    if "correlations" in _tables():
        present = [
            name
            for name in (
                "evaluated_at",
                "evidence",
                "asset_ids",
                "chain",
                "uncertainty",
                "correlation_type",
                "rule_version",
                "org_id",
                "correlation_id",
            )
            if name in _columns("correlations")
        ]
        if present:
            with op.batch_alter_table("correlations") as batch_op:
                for name in present:
                    batch_op.drop_column(name)
