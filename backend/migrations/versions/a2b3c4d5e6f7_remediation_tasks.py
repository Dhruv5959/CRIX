"""Remediation tasks become org-scoped planning + verification records (Phase 7)

``remediation_actions`` gains the task-model fields the planner and the
verification workflow need:

  * org_id                  organization the task belongs to (resolved
                            server-side from the creator's membership — never
                            from the request body). Legacy user-scoped rows are
                            back-filled from the writer's active membership
                            where one exists; the rest keep NULL (fail-closed).
  * target_asset_id         the company asset the task is about
  * finding_ids             the findings this task addresses
  * prerequisites           action keys that must be planned before this one
  * dependencies            free-form declared dependencies (human context)
  * required_evidence       what the verifier will look for
  * verification_method     MODELED | OBSERVED (the declared preferred path)
  * status                  OPEN | DONE | VERIFIED_MODELED | VERIFIED_OBSERVED
  * assigned_to             the user the task is assigned to
  * expected_reduction      modeled reduction COMPUTED by the real risk model
                            (NULL until computed; never invented)
  * completed_at            when the task was claimed done

New table ``remediation_task_history``: an append-only transition and
verification log (method, evidence refs, result, model version, timestamp).
Rows are never updated or deleted, so reopening and re-verification always
keep the full trail.

``organizations`` gains ``effort_budget``: the admin-set default budget the
planner packs under (documented relative units, not wall-clock time).

IDEMPOTENT: every step is guarded by an existence check, because the initial
revision already materialises the current ORM schema with
``Base.metadata.create_all`` on an empty database. ``downgrade`` removes
exactly the columns, indexes and table added here, never a row.

Revision ID: a2b3c4d5e6f7
Revises: f3a1c2d4e5b6
Create Date: 2026-10-23
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a2b3c4d5e6f7'
down_revision: Union[str, None] = 'f3a1c2d4e5b6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


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


def _drop_index_if_exists(name: str, table: str) -> None:
    # An index on a column being dropped must go first: the batch rebuild
    # re-creates every index it reflects, including ones we are removing.
    if table in _tables() and name in _indexes(table):
        op.drop_index(name, table_name=table)


def _create_task_history_table() -> None:
    if "remediation_task_history" in _tables():
        return
    op.create_table(
        "remediation_task_history",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column(
            "action_id", sa.String(32),
            sa.ForeignKey("remediation_actions.id", ondelete="CASCADE",
                          name="fk_remediation_task_history_action_id"),
            nullable=False,
        ),
        sa.Column(
            "org_id", sa.String(32),
            sa.ForeignKey("organizations.id", ondelete="CASCADE",
                          name="fk_remediation_task_history_org_id"),
            nullable=True,
        ),
        sa.Column(
            "actor_user_id", sa.String(32),
            sa.ForeignKey("users.id", ondelete="SET NULL",
                          name="fk_remediation_task_history_actor_user_id"),
            nullable=True,
        ),
        sa.Column("from_status", sa.String(30), nullable=True),
        sa.Column("to_status", sa.String(30), nullable=False),
        sa.Column("method", sa.String(40), nullable=False),
        sa.Column("result", sa.String(20), nullable=False, server_default="OK"),
        sa.Column("model_version", sa.String(20), nullable=True),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("detail", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_remediation_task_history_action_id", "remediation_task_history", ["action_id"]
    )
    op.create_index(
        "ix_remediation_task_history_org_id", "remediation_task_history", ["org_id"]
    )


def _backfill_task_org_id() -> None:
    """Best-effort: give existing tasks the organization of their writer."""
    table = "remediation_actions"
    if table not in _tables() or "org_id" not in _columns(table) or "memberships" not in _tables():
        return
    op.execute(
        sa.text(
            """
            UPDATE remediation_actions
            SET org_id = (
                SELECT m.org_id FROM memberships m
                WHERE m.user_id = remediation_actions.user_id AND m.is_active
                ORDER BY m.created_at, m.id
                LIMIT 1
            )
            WHERE org_id IS NULL
            """
        )
    )


def upgrade() -> None:
    _add_columns(
        "organizations",
        [
            # Admin-set default effort budget for the planner (§9).
            sa.Column(
                "effort_budget", sa.Float(),
                nullable=False, server_default="6.0",
            ),
        ],
    )
    _add_columns(
        "remediation_actions",
        [
            sa.Column(
                "org_id", sa.String(32),
                sa.ForeignKey(
                    "organizations.id", ondelete="CASCADE",
                    name="fk_remediation_actions_org_id",
                ),
                nullable=True,
            ),
            sa.Column("target_asset_id", sa.String(64), nullable=True),
            sa.Column("finding_ids", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("prerequisites", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("dependencies", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("required_evidence", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column(
                "verification_method", sa.String(30),
                nullable=False, server_default="MODELED",
            ),
            sa.Column(
                "status", sa.String(30),
                nullable=False, server_default="OPEN",
            ),
            sa.Column(
                "assigned_to", sa.String(32),
                sa.ForeignKey(
                    "users.id", ondelete="SET NULL",
                    name="fk_remediation_actions_assigned_to",
                ),
                nullable=True,
            ),
            # Computed by the real risk model; NULL until a run computes it.
            sa.Column("expected_reduction", sa.Float(), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        ],
    )
    _create_index_if_missing("ix_remediation_actions_org_id", "remediation_actions", "org_id")
    _create_index_if_missing("ix_remediation_actions_status", "remediation_actions", "status")
    _backfill_task_org_id()
    _create_task_history_table()


def downgrade() -> None:
    if "remediation_task_history" in _tables():
        op.drop_table("remediation_task_history")

    _drop_index_if_exists("ix_remediation_actions_status", "remediation_actions")
    _drop_index_if_exists("ix_remediation_actions_org_id", "remediation_actions")

    if "remediation_actions" in _tables():
        present = [
            name
            for name in (
                "completed_at", "expected_reduction", "assigned_to", "status",
                "verification_method", "required_evidence", "dependencies",
                "prerequisites", "finding_ids", "target_asset_id", "org_id",
            )
            if name in _columns("remediation_actions")
        ]
        if present:
            # Batch op: a rebuild on SQLite (which cannot DROP COLUMN a
            # foreign-key column), a plain ALTER on PostgreSQL. Rows are
            # copied, never dropped.
            with op.batch_alter_table("remediation_actions") as batch_op:
                for name in present:
                    batch_op.drop_column(name)

    if "effort_budget" in _columns("organizations"):
        with op.batch_alter_table("organizations") as batch_op:
            batch_op.drop_column("effort_budget")
