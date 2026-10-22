"""SQLAlchemy ORM models.

Two tenancy layers coexist during the CRIX-SMB migration:

* **Organization-scoped tables** (``organizations``, ``memberships``,
  ``invitations``, ``org_assets``, ``asset_dependencies``,
  ``admin_view_audit_log``) carry a non-nullable ``org_id``. Every query
  against them is scoped to the caller's membership organization.
* **Legacy user-scoped tables** (events, correlations, risk results, plans,
  propagation, audit log, connections) still carry a non-nullable ``user_id``.
  They receive ``org_id`` in Phase 2 together with the SecurityEvent work, so
  that every writer is updated atomically. See ``docs/SMB_MIGRATION_AUDIT.md``.

Curated reference tables (``provider_metadata``, ``provider_capabilities``,
``graph_relationships``, ``knowledge_nodes``, ``knowledge_edges``) are GLOBAL
reference data, not tenant data, and deliberately carry no ``org_id``.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class TimestampMixin:
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #
class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # TOTP 2FA (optional nice-to-have; wired but off by default).
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    memberships: Mapped[list["Membership"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class RefreshToken(Base, TimestampMixin):
    """One rotating refresh token. Only a hash of the token is stored."""

    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Rotation chain: when a token is used, it is revoked and a child is issued.
    replaced_by_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    user_agent: Mapped[str | None] = mapped_column(String(400), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)

    user: Mapped[User] = relationship(back_populates="refresh_tokens")

    @property
    def is_active(self) -> bool:
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=dt.timezone.utc)
        return self.revoked_at is None and expires > _now()


class PasswordResetToken(Base):
    """Single-use, short-expiry password reset token (hash stored, not raw)."""

    __tablename__ = "password_reset_tokens"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )


# --------------------------------------------------------------------------- #
# Signals & events
# --------------------------------------------------------------------------- #
class ConnectedSignal(Base, TimestampMixin):
    """A user-declared account/asset that CRIX analyzes.

    ``source`` records provenance: ``hibp`` (real), ``manual`` or ``simulated``
    (user-entered, clearly labeled in the UI), etc.
    """

    __tablename__ = "connected_signals"
    __table_args__ = (
        UniqueConstraint("user_id", "account_id", name="uq_signal_user_account"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    account_id: Mapped[str] = mapped_column(String(64), nullable=False)
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    service_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(60), nullable=True)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    source: Mapped[str] = mapped_column(String(40), default="manual", nullable=False)

    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class SecurityEvent(Base, TimestampMixin):
    """The single normalized schema shared by every signal module (§4)."""

    __tablename__ = "security_events"
    __table_args__ = (
        UniqueConstraint("event_id", name="uq_security_event_id"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    event_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    account_id: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    exposure_type: Mapped[str | None] = mapped_column(String(40), nullable=True)
    severity: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    source: Mapped[str] = mapped_column(String(60), nullable=False)
    source_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="USER_PROVIDED")
    detected_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="NOT_CHECKED")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    provenance: Mapped[str] = mapped_column(Text, nullable=False, default="")


class ProviderMetadata(Base):
    """Curated passkey/MFA/recovery capability table (~20 real services).

    Rows are curated by hand from vendor documentation; ``source`` and
    ``last_verified_at`` record provenance so this is never mistaken for
    auto-discovered data (§3.B, §8).
    """

    __tablename__ = "provider_metadata"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    service_name: Mapped[str] = mapped_column(String(120), unique=True, index=True, nullable=False)
    supports_passkey: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_methods: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    recovery_methods: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    sms_recovery_possible: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    source: Mapped[str] = mapped_column(String(300), nullable=False)
    last_verified_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class GraphRelationship(Base):
    """Curated account dependency edge (§8). Static, not auto-discovered."""

    __tablename__ = "graph_relationships"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    from_service: Mapped[str] = mapped_column(String(120), index=True, nullable=False)
    to_service: Mapped[str] = mapped_column(String(120), index=True, nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(60), nullable=False)
    weight: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    source: Mapped[str] = mapped_column(String(300), nullable=False)
    last_verified_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class KnowledgeNode(Base):
    """Curated security knowledge-graph node for the GraphRAG layer (§11)."""

    __tablename__ = "knowledge_nodes"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    node_id: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    node_type: Mapped[str] = mapped_column(String(40), nullable=False)  # technique|defense|...
    label: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    source: Mapped[str] = mapped_column(String(300), nullable=False)


class KnowledgeEdge(Base):
    """Curated KG edge, e.g. ``passkey --prevents--> push_bombing``."""

    __tablename__ = "knowledge_edges"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    edge_id: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    from_node: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    to_node: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    predicate: Mapped[str] = mapped_column(String(40), nullable=False)  # enables|defeats|prevented_by
    evidence: Mapped[str] = mapped_column(Text, default="", nullable=False)
    source: Mapped[str] = mapped_column(String(300), nullable=False)


# --------------------------------------------------------------------------- #
# Engine outputs
# --------------------------------------------------------------------------- #
class Correlation(Base, TimestampMixin):
    __tablename__ = "correlations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    run_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    rule_id: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    contributing_event_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)


class RiskResult(Base, TimestampMixin):
    __tablename__ = "risk_results"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    run_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    band: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    range_low: Mapped[float] = mapped_column(Float, nullable=False)
    range_high: Mapped[float] = mapped_column(Float, nullable=False)
    base_risk: Mapped[float] = mapped_column(Float, nullable=False)
    interaction_risk: Mapped[float] = mapped_column(Float, nullable=False)
    mitigation_credit: Mapped[float] = mapped_column(Float, nullable=False)
    components: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class AttributionResult(Base, TimestampMixin):
    __tablename__ = "attribution_results"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    run_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    method: Mapped[str] = mapped_column(String(40), nullable=False)  # "exact_shapley"
    total_risk: Mapped[float] = mapped_column(Float, nullable=False)
    contributions: Mapped[dict[str, float]] = mapped_column(JSON, default=dict, nullable=False)
    compute_ms: Mapped[float] = mapped_column(Float, nullable=False)


class RemediationAction(Base, TimestampMixin):
    __tablename__ = "remediation_actions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=True
    )
    action_key: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    addresses_event_types: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    effort: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)


class RemediationPlan(Base, TimestampMixin):
    __tablename__ = "remediation_plans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    run_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    method: Mapped[str] = mapped_column(String(30), nullable=False)  # greedy|exact
    actions: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    total_effort: Mapped[float] = mapped_column(Float, nullable=False)
    risk_after: Mapped[float] = mapped_column(Float, nullable=False)
    risk_reduction: Mapped[float] = mapped_column(Float, nullable=False)
    compute_ms: Mapped[float] = mapped_column(Float, nullable=False)
    is_greedy_trap: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class EvaluationRecord(Base, TimestampMixin):
    """Persisted results of the evaluation harness (§13, Phase 13).

    These rows are written ONLY by code that actually ran a measurement.
    The UI renders "not yet measured" when no row exists.
    """

    __tablename__ = "evaluation_records"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    suite: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    metric_name: Mapped[str] = mapped_column(String(120), nullable=False)
    metric_value: Mapped[float] = mapped_column(Float, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class AuditLog(Base, TimestampMixin):
    """Security-relevant audit trail. Never stores secrets or tokens (§14)."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    action: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


# --------------------------------------------------------------------------- #
# Live account connections (OAuth)  — scope change, §1–§4 of the OAuth spec
# --------------------------------------------------------------------------- #
class ProviderConnection(Base, TimestampMixin):
    """A user-authorized relationship established through official OAuth.

    This proves CRIX has an authorized relationship with the account. It does NOT
    imply CRIX has live security information about it — see
    ``ProviderCapability`` for what each provider API actually exposes.
    """

    __tablename__ = "provider_connections"
    __table_args__ = (
        UniqueConstraint("user_id", "provider", name="uq_conn_user_provider"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    provider: Mapped[str] = mapped_column(String(30), index=True, nullable=False)
    provider_account_id: Mapped[str] = mapped_column(String(191), nullable=False)
    identifier: Mapped[str | None] = mapped_column(String(320), nullable=True)  # email/sub
    display_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    connection_status: Mapped[str] = mapped_column(String(30), nullable=False, default="CONNECTED")
    source_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="REAL")
    # Encrypted blobs; raw tokens never leave the backend and are never logged.
    access_token_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    refresh_token_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scopes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    connected_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_synced_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # CRIX asset id that represents this connection in the dependency graph.
    account_id: Mapped[str | None] = mapped_column(String(64), nullable=True)


class ProviderCapability(Base, TimestampMixin):
    """Curated capability matrix: what each official API actually exposes.

    Source of truth is ``backend/app/data/provider_capabilities.yaml``.
    ``available`` is never inferred from a connection — a connection only proves
    authorization (§12 of the OAuth spec).
    """

    __tablename__ = "provider_capabilities"
    __table_args__ = (
        UniqueConstraint("provider", "capability", name="uq_cap_provider_capability"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    provider: Mapped[str] = mapped_column(String(30), index=True, nullable=False)
    capability: Mapped[str] = mapped_column(String(120), nullable=False)
    available: Mapped[bool] = mapped_column(Boolean, nullable=False)
    source: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    last_verified: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    note: Mapped[str] = mapped_column(Text, default="", nullable=False)


class AccountRelationship(Base, TimestampMixin):
    """USER-CONFIRMED relationship between two connected accounts (§5).

    OAuth authentication does NOT prove a recovery relationship. Every edge here
    is asserted by the CRIX user and labeled ``source = USER_CONFIRMED``.
    """

    __tablename__ = "account_relationships"
    __table_args__ = (
        UniqueConstraint(
            "user_id", "from_account_id", "to_account_id", "relationship_type",
            name="uq_rel_user_from_to_type",
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    from_account_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    to_account_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(40), nullable=False)
    source: Mapped[str] = mapped_column(String(30), nullable=False, default="USER_CONFIRMED")
    source_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="USER_PROVIDED")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    weight: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)


class PropagationResult(Base, TimestampMixin):
    """Persisted output of a compromise-propagation simulation (§6–§9).

    ``downstream_exposure_score`` is a relative prioritization measure, NOT a
    probability of being hacked and NOT a prediction (§18).
    """

    __tablename__ = "propagation_results"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    run_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    upstream_account_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    source_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="SIMULATED")
    affected_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    highest_exposure: Mapped[str] = mapped_column(String(20), nullable=False, default="LOW")
    highest_risk_account_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


# --------------------------------------------------------------------------- #
# Organizations, memberships, invitations  (org-first product; §4)
# --------------------------------------------------------------------------- #
class Organization(Base, TimestampMixin):
    """A company tenant.

    Every organization-scoped row in the database belongs to exactly one
    organization. There is no personal/default organization: registration
    creates a real organization and the registrant becomes its first
    ``ORG_ADMIN`` (§4).
    """

    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), unique=True, index=True, nullable=False)
    created_by_user_id: Mapped[str | None] = mapped_column(String(32), nullable=True)

    memberships: Mapped[list["Membership"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )


class Membership(Base, TimestampMixin):
    """A user's role inside one organization (ORG_ADMIN | MEMBER | VIEWER).

    The role is the authorization authority for every organization-scoped
    endpoint; it is resolved server-side from the database, never trusted from
    a client-sent claim.
    """

    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("org_id", "user_id", name="uq_membership_org_user"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="MEMBER")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    organization: Mapped[Organization] = relationship(back_populates="memberships")
    user: Mapped[User] = relationship(back_populates="memberships")


class Invitation(Base):
    """A single-use, expiring invitation to join an organization (§4).

    Only the SHA-256 hash of the invitation token is stored; the raw token is
    delivered out-of-band and is never logged.
    """

    __tablename__ = "invitations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    email: Mapped[str] = mapped_column(String(320), index=True, nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="MEMBER")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_by_user_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    invited_by_user_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )


class OrgAsset(Base, TimestampMixin):
    """A COMPANY-OWNED asset: work email/workspace identity, code repository,
    cloud storage, CI system, business app, or domain, plus its criticality.

    Personal accounts are explicitly out of scope (§2). The API rejects any
    attempt to register a personal-account/personal-device asset type.
    ``criticality`` (1 = low .. 5 = business-critical) is the importance the
    company assigns, set by an admin, and is what makes "which asset matters
    most" answerable.
    """

    __tablename__ = "org_assets"
    __table_args__ = (
        UniqueConstraint("org_id", "asset_id", name="uq_org_asset_id"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    asset_id: Mapped[str] = mapped_column(String(64), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(40), nullable=False)
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    service_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    # 1 (low) .. 5 (business-critical). Admin-set; never inferred from a client score.
    criticality: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    owner_membership_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("memberships.id", ondelete="SET NULL"), index=True, nullable=True
    )
    source_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="USER_PROVIDED")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class AssetDependency(Base, TimestampMixin):
    """An ADMIN_DECLARED dependency edge between two company assets (§7).

    CRIX never invents relationships. Every row here is declared by an admin
    and is labelled ``ADMIN_DECLARED`` so it is never confused with curated
    reference edges or auto-discovered ones.
    """

    __tablename__ = "asset_dependencies"
    __table_args__ = (
        UniqueConstraint(
            "org_id", "from_asset_id", "to_asset_id", "relationship_type",
            name="uq_asset_dependency",
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    from_asset_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    to_asset_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(40), nullable=False)
    edge_source: Mapped[str] = mapped_column(String(30), nullable=False, default="ADMIN_DECLARED")
    weight: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    note: Mapped[str] = mapped_column(Text, default="", nullable=False)


class AdminViewAuditLog(Base):
    """Records every admin access to a member's data (§2 privacy boundary).

    Each row is written when an ORG_ADMIN reads another member's member-level
    data and is visible to that member through ``GET /api/org/admin-views``.
    """

    __tablename__ = "admin_view_audit_log"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    admin_user_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    admin_membership_id: Mapped[str] = mapped_column(String(32), nullable=False)
    subject_membership_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    subject_user_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    resource: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )