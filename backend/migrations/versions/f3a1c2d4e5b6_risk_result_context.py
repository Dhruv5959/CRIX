"""Risk snapshots gain context: organization, asset, model version (Phase 4)

``risk_results`` gains:

  * org_id                   organization the run belonged to (resolved
                             server-side from the writer's membership) — makes
                             stored snapshots queryable inside one tenant only.
  * asset_id                 the most important registered asset affected by
                             the findings (NULL when nothing was bound).
  * model_version            which formula produced the row. Existing rows are
                             stamped ``risk-1.0`` (they pre-date the asset
                             criticality term); new rows are written as
                             ``risk-2.0`` by the application. A snapshot is
                             never re-scored when the model changes.
  * criticality_adjustment    the additive criticality term of the score
                             (0.0 for every ``risk-1.0`` row, which is correct:
                             that formula had no criticality term).

Existing rows are preserved and only back-filled (org from the writer's active
membership where one exists; everything else keeps NULL/0.0). Rows whose user
has no membership keep ``org_id = NULL``, which matches no tenant query
(fail-closed).

IDEMPOTENT: every step is guarded by an existence check, because the initial
revision already materialises the current ORM schema with
``Base.metadata.create_all`` on an empty database. ``downgrade`` removes exactly
the columns and index added here, never a row.

Revision ID: f3a1c2d4e5b6
Revises: d4e5f6a7b8c9
Create Date: 2026-10-22
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f3a1c2d4e5b6'
down_revision: Union[str, None] = 'd4e5f6a7b8c9'
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


def _backfill_org_id() -> None:
    """Best-effort: give existing snapshots the organization of their writer."""
    table = "risk_results"
    if table not in _tables() or "org_id" not in _columns(table) or "memberships" not in _tables():
        return
    op.execute(
        sa.text(
            """
            UPDATE risk_results
            SET org_id = (
                SELECT m.org_id FROM memberships m
                WHERE m.user_id = risk_results.user_id AND m.is_active
                ORDER BY m.created_at, m.id
                LIMIT 1
            )
            WHERE org_id IS NULL
            """
        )
    )


def upgrade() -> None:
    _add_columns(
        "risk_results",
        [
            sa.Column(
                "org_id", sa.String(32),
                sa.ForeignKey(
                    "organizations.id", ondelete="CASCADE",
                    name="fk_risk_results_org_id",
                ),
                nullable=True,
            ),
            # The most important registered asset the findings touched.
            sa.Column("asset_id", sa.String(64), nullable=True),
            # Which formula produced the row (existing rows pre-date Phase 4).
            sa.Column(
                "model_version", sa.String(20),
                nullable=False, server_default="risk-1.0",
            ),
            # 0.0 for risk-1.0 rows: that formula had no criticality term.
            sa.Column(
                "criticality_adjustment", sa.Float(),
                nullable=False, server_default="0.0",
            ),
        ],
    )
    _create_index_if_missing("ix_risk_results_org_id", "risk_results", "org_id")
    _backfill_org_id()


def _drop_index_if_exists(name: str, table: str) -> None:
    # An index on a column being dropped must go first: the batch rebuild
    # re-creates every index it reflects, including ones we are removing.
    if table in _tables() and name in _indexes(table):
        op.drop_index(name, table_name=table)


def downgrade() -> None:
    # The ORM's own ``ix_`` index (from ``index=True``) materializes through
    # the initial revision's create_all too — both names must go before the
    # column drop, or the rebuild would reference a missing column.
    _drop_index_if_exists("ix_risk_results_org_id", "risk_results")

    if "risk_results" in _tables():
        present = [
            name
            for name in ("criticality_adjustment", "model_version", "asset_id", "org_id")
            if name in _columns("risk_results")
        ]
        if present:
            # Batch op: a rebuild on SQLite (which cannot DROP COLUMN a
            # foreign-key column), a plain ALTER on PostgreSQL. Rows are
            # copied, never dropped.
            with op.batch_alter_table("risk_results") as batch_op:
                for name in present:
                    batch_op.drop_column(name)
