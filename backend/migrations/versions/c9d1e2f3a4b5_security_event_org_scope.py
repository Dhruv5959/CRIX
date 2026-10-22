"""Security finding organization scope + evidence (Phase 2)

``security_events`` (the normalized findings) gains:

  * org_id        organization that owns the finding (resolved server-side)
  * asset_id      stable ``org_assets.asset_id`` of the affected COMPANY asset
                  when it is known; NULL means "not mapped", never a guess
  * first_seen    observation window start (source-supplied, else CRIX's first
                  recorded observation of that finding)
  * last_seen     observation window end
  * evidence      minimal, sanitized facts that explain the finding
  * updated_at    when the row last changed

``connected_signals`` (user-declared company-relevant accounts) gains a best
effort ``org_id`` label so account reads can be tenant-scoped later.

Existing rows are preserved: every new column has a constant default, and
``org_id`` is back-filled from the writer's active membership where one exists.
A row whose user has no membership keeps the empty sentinel, which matches no
tenant query (fail-closed) — no data is deleted.

IDEMPOTENT: every step is guarded by an existence check, because the initial
revision already materialises the current ORM schema with
``Base.metadata.create_all`` on an empty database. ``upgrade head`` is therefore
safe on an empty database, on an already-``create_all``-ed one, and on a database
migrated by this chain. ``downgrade`` removes exactly the columns added here.

Revision ID: c9d1e2f3a4b5
Revises: b1a7c3d9e2f4
Create Date: 2026-10-22
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c9d1e2f3a4b5'
down_revision: Union[str, None] = 'b1a7c3d9e2f4'
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

    ``op.add_column`` with a foreign key makes Alembic emit a separate ALTER that
    SQLite refuses ("No support for ALTER of constraints"), so the columns go in
    through a single ``batch_alter_table`` — a copy-and-move table rebuild on
    SQLite, a plain ALTER on PostgreSQL. Rows are copied, never dropped.
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


def upgrade() -> None:
    # Findings: organization scope, affected asset, observation window,
    # sanitized evidence, and updated_at. One batch per table so the foreign key
    # can be carried (a plain ALTER with an FK is refused by SQLite).
    _add_columns(
        "security_events",
        [
            sa.Column(
                "org_id", sa.String(32),
                sa.ForeignKey(
                    "organizations.id", ondelete="CASCADE",
                    name="fk_security_events_org_id",
                ),
                nullable=False, server_default="",
            ),
            # Stable company-asset id; NULL means "not mapped to a company asset"
            # — an explicit unknown, never a guessed identifier.
            sa.Column("asset_id", sa.String(64), nullable=True),
            # Observation window. Nothing is back-filled with a guessed value.
            sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
            # Minimal, sanitized explanation facts (app.schemas.sanitize_evidence).
            sa.Column("evidence", sa.JSON(), nullable=False, server_default="{}"),
            # Nullable only because SQLite cannot ALTER a column to NOT NULL
            # without a rebuild; existing rows are filled from their own
            # created_at below and the ORM writes it on every insert/update.
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        ],
    )
    _create_index_if_missing("ix_security_events_org_id", "security_events", "org_id")
    _create_index_if_missing("ix_security_events_asset_id", "security_events", "asset_id")
    if "security_events" in _tables() and "updated_at" in _columns("security_events"):
        op.execute(
            sa.text(
                "UPDATE security_events SET updated_at = created_at "
                "WHERE updated_at IS NULL"
            )
        )

    # Account rows carry their organization when one can be derived (best
    # effort: a user without a membership keeps NULL, which matches no tenant).
    _add_columns(
        "connected_signals",
        [
            sa.Column(
                "org_id", sa.String(32),
                sa.ForeignKey(
                    "organizations.id", ondelete="CASCADE",
                    name="fk_connected_signals_org_id",
                ),
                nullable=True,
            ),
        ],
    )
    _create_index_if_missing("ix_connected_signals_org_id", "connected_signals", "org_id")

    _backfill_org_id("security_events")
    _backfill_org_id("connected_signals")


def _drop_index_if_exists(name: str, table: str) -> None:
    # Indexes on the columns being dropped must go first: the batch rebuild
    # re-creates every index it reflects, including ones we are removing.
    if table in _tables() and name in _indexes(table):
        op.drop_index(name, table_name=table)


def downgrade() -> None:
    # SQLite refuses ``ALTER TABLE ... DROP COLUMN`` for a column that is part of
    # a foreign key, so a batch op (a table rebuild on SQLite, a plain ALTER on
    # PostgreSQL) is used. Rows are copied, never dropped.
    _drop_index_if_exists("ix_connected_signals_org_id", "connected_signals")
    _drop_index_if_exists("ix_security_events_org_id", "security_events")
    _drop_index_if_exists("ix_security_events_asset_id", "security_events")

    for table, names in (
        ("connected_signals", ("org_id",)),
        (
            "security_events",
            ("updated_at", "evidence", "last_seen", "first_seen", "asset_id", "org_id"),
        ),
    ):
        if table not in _tables():
            continue
        present = [name for name in names if name in _columns(table)]
        if not present:
            continue
        with op.batch_alter_table(table) as batch_op:
            for name in present:
                batch_op.drop_column(name)
