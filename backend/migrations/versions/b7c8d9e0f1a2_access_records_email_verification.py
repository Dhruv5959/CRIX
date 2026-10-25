"""Access-record tables + email verification (Feature F / §9.F)

Three new tables, ONE revision:

``asset_access_records``   admin-declared member→asset access statements
                           (POSTURE data, provenance ``ADMIN_DECLARED``);
                           unique per (org, member, asset); removable in place
                           (``status`` flips to REMOVED — history survives).
``asset_access_record_history``
                           append-only lifecycle log for the rows above
                           (CREATED / REVIEWED / REMOVED, actor + redacted
                           detail). Cascade-deletes with its record.
``email_verification_tokens``
                           single-use, expiring, hash-only tokens proving
                           control of a registered address (consent gate for
                           breach monitoring).

All FKs CASCADE on delete so no orphan row can outlive its tenant parent.
Nothing is written into existing tables; no column of any current table
changes semantics. Downgrade drops exactly these three tables.

IDEMPOTENT: every create/drop is guarded by an existence check (the chain
convention — an empty database is materialised by ``Base.metadata.create_all``
directly from the ORM, so a fresh SQLite sees this revision as a no-op).

Revision ID: b7c8d9e0f1a2
Revises: e8f9a0b1c2d3
Create Date: 2026-10-25
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b7c8d9e0f1a2'
down_revision: Union[str, None] = 'e8f9a0b1c2d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _existing() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    have = _existing()
    if "asset_access_records" not in have:
        op.create_table(
            "asset_access_records",
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column(
                "org_id",
                sa.String(32),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "org_asset_id",
                sa.String(32),
                sa.ForeignKey("org_assets.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "membership_id",
                sa.String(32),
                sa.ForeignKey("memberships.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("level", sa.String(12), nullable=False),
            sa.Column("provenance", sa.String(24), nullable=False, server_default="ADMIN_DECLARED"),
            sa.Column("status", sa.String(12), nullable=False, server_default="ACTIVE"),
            sa.Column(
                "granted_at", sa.DateTime(timezone=True), nullable=False,
                server_default=sa.func.now(),
            ),
            sa.Column("last_reviewed_at", sa.DateTime(timezone=True), nullable=True),
            # created_at / updated_at follow the shared TimestampMixin shape.
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("org_id", "membership_id", "org_asset_id", name="uq_access_record"),
        )
        op.create_index("ix_asset_access_records_org_id", "asset_access_records", ["org_id"])
        op.create_index("ix_asset_access_records_org_asset_id", "asset_access_records", ["org_asset_id"])
        op.create_index("ix_asset_access_records_membership_id", "asset_access_records", ["membership_id"])

    have = _existing()
    if "asset_access_record_history" not in have:
        op.create_table(
            "asset_access_record_history",
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column(
                "record_id",
                sa.String(32),
                sa.ForeignKey("asset_access_records.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "org_id",
                sa.String(32),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("actor_user_id", sa.String(32), nullable=False),
            sa.Column("method", sa.String(12), nullable=False),
            sa.Column("detail", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_asset_access_record_history_record_id", "asset_access_record_history", ["record_id"])
        op.create_index("ix_asset_access_record_history_org_id", "asset_access_record_history", ["org_id"])

    have = _existing()
    if "email_verification_tokens" not in have:
        op.create_table(
            "email_verification_tokens",
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column(
                "user_id",
                sa.String(32),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_email_verification_tokens_user_id", "email_verification_tokens", ["user_id"])
        op.create_index(
            "ix_email_verification_tokens_token_hash", "email_verification_tokens", ["token_hash"], unique=True
        )


def downgrade() -> None:
    have = _existing()
    # Reverse dependency order: history before records; tokens are independent.
    if "asset_access_record_history" in have:
        op.drop_table("asset_access_record_history")
    if "asset_access_records" in have:
        op.drop_table("asset_access_records")
    if "email_verification_tokens" in have:
        op.drop_table("email_verification_tokens")
