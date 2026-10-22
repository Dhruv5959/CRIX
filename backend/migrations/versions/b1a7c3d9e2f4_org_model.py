"""organization-first data model (Phase 1)

Adds the tenant tables for the CRIX-SMB migration:

  * organizations          company tenant
  * memberships            user role inside one organization
  * invitations            single-use, expiring join tokens (hash stored)
  * org_assets             company-owned assets with admin-set criticality
  * asset_dependencies     ADMIN_DECLARED dependency edges
  * admin_view_audit_log   every admin access to a member's data

Curated reference tables (provider_metadata, graph_relationships,
knowledge_nodes, knowledge_edges, provider_capabilities) stay GLOBAL reference
data and intentionally do not gain an org_id.

The legacy user-scoped event/analysis tables were scheduled here to gain
their org_id in Phase 2; the Phase 2 work delivered that for
``security_events`` (NOT NULL, server-resolved) and ``connected_signals``
(best-effort label), and deferred the remaining analysis tables. The exact,
honest scope is recorded in docs/SMB_MIGRATION_AUDIT.md §11.7.

Revision ID: b1a7c3d9e2f4
Revises: 9c3f21a04e12
Create Date: 2026-10-22

IDEMPOTENT (2026-10-22): the initial revision materialises the full current
schema, so table creation here is guarded by an existence check. ``upgrade head``
is therefore safe on both an empty database and an already-``create_all``-ed
database, and no step ever drops data.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b1a7c3d9e2f4'
down_revision: Union[str, None] = '9c3f21a04e12'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _create_table_if_missing(name: str, *args, **kwargs) -> None:
    if name not in set(sa.inspect(op.get_bind()).get_table_names()):
        op.create_table(name, *args, **kwargs)


def _drop_table_if_exists(name: str) -> None:
    if name in set(sa.inspect(op.get_bind()).get_table_names()):
        op.drop_table(name)


def upgrade() -> None:
    # 1. The organization tenant itself.
    _create_table_if_missing(
        "organizations",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(120), index=True, unique=True, nullable=False),
        sa.Column("created_by_user_id", sa.String(32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 2. A user's role inside one organization.
    _create_table_if_missing(
        "memberships",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column(
            "org_id", sa.String(32),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False,
        ),
        sa.Column(
            "user_id", sa.String(32),
            sa.ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False,
        ),
        sa.Column("role", sa.String(20), nullable=False, server_default="MEMBER"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "user_id", name="uq_membership_org_user"),
    )

    # 3. Single-use, expiring invitations (only the token hash is stored).
    _create_table_if_missing(
        "invitations",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column(
            "org_id", sa.String(32),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False,
        ),
        sa.Column("email", sa.String(320), index=True, nullable=False),
        sa.Column("role", sa.String(20), nullable=False, server_default="MEMBER"),
        sa.Column("token_hash", sa.String(64), index=True, unique=True, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("accepted_by_user_id", sa.String(32), nullable=True),
        sa.Column("invited_by_user_id", sa.String(32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 4. Company-owned assets with admin-set criticality.
    _create_table_if_missing(
        "org_assets",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column(
            "org_id", sa.String(32),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False,
        ),
        sa.Column("asset_id", sa.String(64), nullable=False),
        sa.Column("asset_type", sa.String(40), nullable=False),
        sa.Column("label", sa.String(200), nullable=False),
        sa.Column("service_name", sa.String(120), nullable=True),
        sa.Column("criticality", sa.Integer(), nullable=False, server_default="3"),
        sa.Column(
            "owner_membership_id", sa.String(32),
            sa.ForeignKey("memberships.id", ondelete="SET NULL"), index=True, nullable=True,
        ),
        sa.Column("source_mode", sa.String(20), nullable=False, server_default="USER_PROVIDED"),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "asset_id", name="uq_org_asset_id"),
    )

    # 5. ADMIN_DECLARED dependency edges between company assets.
    _create_table_if_missing(
        "asset_dependencies",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column(
            "org_id", sa.String(32),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False,
        ),
        sa.Column("from_asset_id", sa.String(64), index=True, nullable=False),
        sa.Column("to_asset_id", sa.String(64), index=True, nullable=False),
        sa.Column("relationship_type", sa.String(40), nullable=False),
        sa.Column("edge_source", sa.String(30), nullable=False, server_default="ADMIN_DECLARED"),
        sa.Column("weight", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "org_id", "from_asset_id", "to_asset_id", "relationship_type",
            name="uq_asset_dependency",
        ),
    )

    # 6. Admin access to member-level data, visible to the member.
    _create_table_if_missing(
        "admin_view_audit_log",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column(
            "org_id", sa.String(32),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False,
        ),
        sa.Column("admin_user_id", sa.String(32), index=True, nullable=False),
        sa.Column("admin_membership_id", sa.String(32), nullable=False),
        sa.Column("subject_membership_id", sa.String(32), index=True, nullable=False),
        sa.Column("subject_user_id", sa.String(32), index=True, nullable=False),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("resource", sa.String(120), nullable=False, server_default=""),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    _drop_table_if_exists("admin_view_audit_log")
    _drop_table_if_exists("asset_dependencies")
    _drop_table_if_exists("org_assets")
    _drop_table_if_exists("invitations")
    _drop_table_if_exists("memberships")
    _drop_table_if_exists("organizations")
