"""User breach-monitoring columns (Features A + B)

``users`` gains the Feature A / B bookkeeping columns:

  * breach_monitor_consent      affirmative opt-in for automatic breach
                                monitoring of the registered work email
                                (NOT NULL, database default 0 = no consent —
                                consent is never a silent default)
  * breach_monitor_consent_at   when consent was first given
  * last_breach_check_at        honest cache stamp: when the registered email
                                was last checked by any breach auto-refresh
                                (the cache key for the >24h refresh rule)
  * last_password_exposure      login-time Pwned-Passwords outcome metadata
                                (provider/status/count/checked_at). Contains
                                NO password material — never the plaintext,
                                never its hash.

All timestamps are nullable; rows predating the feature keep NULL/CLEARED
state, which the status endpoint reports as "never checked", never as "safe".

IDEMPOTENT: every step is guarded by an existence check, matching the chain
convention (the initial revision already materialises the current ORM schema
with ``Base.metadata.create_all`` on an empty database). ``downgrade`` removes
exactly the columns added here, never a row.

Revision ID: e8f9a0b1c2d3
Revises: a2b3c4d5e6f7
Create Date: 2026-10-24
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e8f9a0b1c2d3'
down_revision: Union[str, None] = 'a2b3c4d5e6f7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _dialect() -> str:
    return op.get_bind().dialect.name


def _columns(table: str) -> set[str]:
    bind = op.get_bind()
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


def upgrade() -> None:
    if "users" not in sa.inspect(op.get_bind()).get_table_names():
        return
    have = _columns("users")
    missing = [c for c in _NEW_COLUMNS if c.name not in have]
    if not missing:
        return
    with op.batch_alter_table("users") as batch_op:
        for column in missing:
            batch_op.add_column(column)


def downgrade() -> None:
    if "users" not in sa.inspect(op.get_bind()).get_table_names():
        return
    present = [name for name in _NEW_COLUMN_NAMES if name in _columns("users")]
    if not present:
        return
    # Batch op: a rebuild on SQLite, a plain ALTER on PostgreSQL. Rows are
    # copied, never dropped; the consent state these columns recorded is
    # intentionally NOT required to survive a downgrade of an optional feature.
    with op.batch_alter_table("users") as batch_op:
        for name in present:
            batch_op.drop_column(name)


_NEW_COLUMNS = [
    sa.Column("breach_monitor_consent", sa.Boolean(), nullable=False, server_default="0"),
    sa.Column("breach_monitor_consent_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("last_breach_check_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("last_password_exposure", sa.JSON(), nullable=True),
]

_NEW_COLUMN_NAMES = [c.name for c in _NEW_COLUMNS]
