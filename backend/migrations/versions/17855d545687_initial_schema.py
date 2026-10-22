"""initial schema

Revision ID: 17855d545687
Revises:
Create Date: 2026-10-08 00:45:10.912265

NOTE (documented deviation, 2026-10-22): this project bootstrapped its schema with
``Base.metadata.create_all`` (see ``app/db.py::init_db``) and only adopted Alembic
for *incremental* changes, so this first revision was originally empty (``pass``).
That made ``alembic upgrade head`` unable to build a database from scratch — it
failed with ``NoSuchTableError: security_events`` because the next revision
reflects a table this one never created.

This revision now materialises the base schema from the current model metadata
with ``checkfirst=True``, and every later revision in the chain is idempotent.
The chain therefore runs both from an EMPTY database and from an already
``create_all``-ed database, and ``downgrade base`` returns to an empty database.

Trade-off: this base revision tracks ``Base.metadata`` rather than a frozen
2026-10-08 snapshot. There are no deployed databases to migrate (the project is a
single-developer prototype), so a frozen snapshot would carry no benefit. Recorded
in ``docs/SMB_MIGRATION_AUDIT.md``.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

import app.models  # noqa: F401  (register every table on Base.metadata)
from app.db import Base


revision: str = '17855d545687'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind(), checkfirst=True)


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind(), checkfirst=True)