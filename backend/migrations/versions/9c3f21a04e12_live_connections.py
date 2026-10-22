"""live account connections + compromise propagation

Adds the tables and column backing the live-OAuth scope change:
  * security_events.source_mode  (REAL | USER_PROVIDED | SIMULATED | FIXTURE | UNAVAILABLE)
  * provider_connections          authorized OAuth relationships (tokens encrypted)
  * provider_capabilities         curated "what the API actually exposes" matrix
  * account_relationships         USER_CONFIRMED edges between connected accounts
  * propagation_results           persisted compromise-propagation simulations

Status column is widened to 30 chars to hold UNAVAILABLE_THROUGH_PROVIDER.

Revision ID: 9c3f21a04e12
Revises: 17855d545687
Create Date: 2026-10-08
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '9c3f21a04e12'
down_revision: Union[str, None] = '17855d545687'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. New provenance column on the normalized event schema.
    with op.batch_alter_table("security_events") as batch:
        batch.add_column(
            sa.Column("source_mode", sa.String(20), nullable=False, server_default="USER_PROVIDED")
        )
        # Widen for UNAVAILABLE_THROUGH_PROVIDER (SQLite ignores the length, but
        # keep the declared width correct for PostgreSQL).
        batch.alter_column("status", existing_type=sa.String(20), type_=sa.String(30))

    # 2. Authorized OAuth connections (tokens stored encrypted, never logged).
    op.create_table(
        "provider_connections",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("user_id", sa.String(32), sa.ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False),
        sa.Column("provider", sa.String(30), index=True, nullable=False),
        sa.Column("provider_account_id", sa.String(191), nullable=False),
        sa.Column("identifier", sa.String(320), nullable=True),
        sa.Column("display_name", sa.String(200), nullable=True),
        sa.Column("connection_status", sa.String(30), nullable=False, server_default="CONNECTED"),
        sa.Column("source_mode", sa.String(20), nullable=False, server_default="REAL"),
        sa.Column("access_token_enc", sa.Text(), nullable=True),
        sa.Column("refresh_token_enc", sa.Text(), nullable=True),
        sa.Column("token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scopes", sa.Text(), nullable=False, server_default=""),
        sa.Column("connected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("account_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", "provider", name="uq_conn_user_provider"),
    )

    # 3. Curated capability matrix (what the official API actually exposes).
    op.create_table(
        "provider_capabilities",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("provider", sa.String(30), index=True, nullable=False),
        sa.Column("capability", sa.String(120), nullable=False),
        sa.Column("available", sa.Boolean(), nullable=False),
        sa.Column("source", sa.String(300), nullable=False, server_default=""),
        sa.Column("last_verified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("provider", "capability", name="uq_cap_provider_capability"),
    )

    # 4. USER_CONFIRMED relationships between connected accounts.
    op.create_table(
        "account_relationships",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("user_id", sa.String(32), sa.ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False),
        sa.Column("from_account_id", sa.String(64), index=True, nullable=False),
        sa.Column("to_account_id", sa.String(64), index=True, nullable=False),
        sa.Column("relationship_type", sa.String(40), nullable=False),
        sa.Column("source", sa.String(30), nullable=False, server_default="USER_CONFIRMED"),
        sa.Column("source_mode", sa.String(20), nullable=False, server_default="USER_PROVIDED"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("weight", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "user_id", "from_account_id", "to_account_id", "relationship_type",
            name="uq_rel_user_from_to_type",
        ),
    )

    # 5. Persisted compromise-propagation simulations.
    op.create_table(
        "propagation_results",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("user_id", sa.String(32), sa.ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False),
        sa.Column("run_id", sa.String(32), index=True, nullable=False),
        sa.Column("upstream_account_id", sa.String(64), index=True, nullable=False),
        sa.Column("source_mode", sa.String(20), nullable=False, server_default="SIMULATED"),
        sa.Column("affected_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("highest_exposure", sa.String(20), nullable=False, server_default="LOW"),
        sa.Column("highest_risk_account_id", sa.String(64), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("propagation_results")
    op.drop_table("account_relationships")
    op.drop_table("provider_capabilities")
    op.drop_table("provider_connections")
    with op.batch_alter_table("security_events") as batch:
        batch.drop_column("source_mode")
