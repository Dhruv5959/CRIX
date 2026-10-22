"""live account connections + compromise propagation

Adds the tables and column backing the live-OAuth scope change:
  * security_events.source_mode  (REAL | USER_PROVIDED | SIMULATED | FIXTURE | UNAVAILABLE)
  * provider_connections          authorized OAuth relationships (tokens encrypted)
  * provider_capabilities         curated "what the API actually exposes" matrix
  * account_relationships         USER_CONFIRMED edges between connected accounts
  * propagation_results           persisted compromise-propagation simulations

Status column is widened to 30 chars to hold UNAVAILABLE_THROUGH_PROVIDER.

IDEMPOTENT (2026-10-22): the initial revision materialises the full current
schema, so every step here checks the live schema first and only performs the
change if it is actually missing. That makes ``upgrade head`` safe on both an
empty database and an already-``create_all``-ed database.

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


def _create_table_if_missing(name: str, *args, **kwargs) -> None:
    if name not in set(sa.inspect(op.get_bind()).get_table_names()):
        op.create_table(name, *args, **kwargs)


def _drop_table_if_exists(name: str) -> None:
    if name in set(sa.inspect(op.get_bind()).get_table_names()):
        op.drop_table(name)


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    columns = (
        {c["name"] for c in inspector.get_columns("security_events")}
        if "security_events" in tables
        else set()
    )

    # 1. New provenance column on the normalized event schema.
    add_source_mode = "source_mode" not in columns
    widen_status = "security_events" in tables and any(
        c["name"] == "status" and (getattr(c["type"], "length", None) or 0) < 30
        for c in inspector.get_columns("security_events")
    )
    if add_source_mode or widen_status:
        with op.batch_alter_table("security_events") as batch:
            if add_source_mode:
                batch.add_column(
                    sa.Column(
                        "source_mode", sa.String(20), nullable=False, server_default="USER_PROVIDED"
                    )
                )
            if widen_status:
                # Widen for UNAVAILABLE_THROUGH_PROVIDER (SQLite ignores the
                # length, but keep the declared width correct for PostgreSQL).
                batch.alter_column("status", existing_type=sa.String(20), type_=sa.String(30))

    # 2. Authorized OAuth connections (tokens stored encrypted, never logged).
    _create_table_if_missing(
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
    _create_table_if_missing(
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
    _create_table_if_missing(
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
    _create_table_if_missing(
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
    _drop_table_if_exists("propagation_results")
    _drop_table_if_exists("account_relationships")
    _drop_table_if_exists("provider_capabilities")
    _drop_table_if_exists("provider_connections")
    inspector = sa.inspect(op.get_bind())
    if "security_events" in set(inspector.get_table_names()) and "source_mode" in {
        c["name"] for c in inspector.get_columns("security_events")
    }:
        with op.batch_alter_table("security_events") as batch:
            batch.drop_column("source_mode")