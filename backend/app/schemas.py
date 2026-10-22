"""Pydantic request/response schemas.

Note the SecurityEvent schema (§4) is the single normalized shape every signal
module emits.
"""
from __future__ import annotations

import datetime as dt
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


# --------------------------------------------------------------------------- #
# Enums (mirror the string values stored in the DB)
# --------------------------------------------------------------------------- #
class EventStatus(str, Enum):
    FINDING = "FINDING"
    CHECKED_SAFE = "CHECKED_SAFE"
    NOT_CHECKED = "NOT_CHECKED"
    UNAVAILABLE = "UNAVAILABLE"
    # Live-OAuth scope: the official provider API does not expose this signal.
    # Deliberately distinct from CHECKED_SAFE — never shown as "safe" (§12).
    UNAVAILABLE_THROUGH_PROVIDER = "UNAVAILABLE_THROUGH_PROVIDER"


class ExposureType(str, Enum):
    PASSWORD_ONLY = "PASSWORD_ONLY"
    PASSWORD_AND_SESSION = "PASSWORD_AND_SESSION"
    SESSION_ONLY = "SESSION_ONLY"


class DataProvenance(str, Enum):
    """How a datum came to exist. Surfaced verbatim in the UI (§12)."""

    REAL = "REAL"                       # from a real external source (HIBP)
    USER_REPORTED = "USER_REPORTED"     # manually entered by the user
    SIMULATED = "SIMULATED"             # deliberately constructed scenario
    CURATED = "CURATED"                 # hand-verified static reference data
    MODEL = "MODEL"                     # output of a trained model
    UNAVAILABLE = "UNAVAILABLE"         # could not be obtained


class SourceMode(str, Enum):
    """Provenance for every event and connection (live OAuth scope, §11).

    Distinct from :class:`DataProvenance`: this is the authoritative marker the
    UI shows for account connections and compromise scenarios.
    """

    REAL = "REAL"                       # official provider API actually returned it
    USER_PROVIDED = "USER_PROVIDED"     # typed/confirmed by the CRIX user
    SIMULATED = "SIMULATED"             # scenario state, never touches a real account
    FIXTURE = "FIXTURE"                 # clearly-labeled local demo data (not real)
    UNAVAILABLE = "UNAVAILABLE"         # not obtainable through the provider API


class ConnectionStatus(str, Enum):
    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    ERROR = "ERROR"


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
    # Registration creates the organization; the registrant becomes its first
    # ORG_ADMIN (§4). Optional so an existing client still works.
    org_name: str | None = Field(default=None, max_length=200)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    totp_code: str | None = Field(default=None, max_length=10)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: dt.datetime
    csrf_token: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: EmailStr
    is_active: bool
    email_verified: bool
    totp_enabled: bool
    created_at: dt.datetime


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    new_password: str = Field(min_length=10, max_length=128)


# --------------------------------------------------------------------------- #
# Organizations, membership roles, invitations, company assets (§4)
# --------------------------------------------------------------------------- #
class OrgRole(str, Enum):
    """The three roles of the RBAC matrix (see docs/RBAC.md)."""

    ORG_ADMIN = "ORG_ADMIN"
    MEMBER = "MEMBER"
    VIEWER = "VIEWER"


# Asset types CRIX assesses: COMPANY-OWNED only (§2). Personal accounts and
# personal devices are explicitly out of scope, so they are rejected below.
COMPANY_ASSET_TYPES = (
    "WORK_EMAIL",
    "WORKSPACE_IDENTITY",
    "CODE_REPOSITORY",
    "CLOUD_STORAGE",
    "CI_SYSTEM",
    "BUSINESS_APP",
    "DOMAIN",
    "SAAS_DEPENDENCY",
    "OTHER_COMPANY",
)
PERSONAL_ASSET_TYPES = (
    "PERSONAL_ACCOUNT",
    "PERSONAL_DEVICE",
    "PERSONAL_EMAIL",
    "BYOD",
    "PERSONAL",
)


class OrgUpdateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=200)


class OrgResponse(BaseModel):
    id: str
    name: str
    slug: str
    role: OrgRole
    member_count: int
    asset_count: int
    created_at: dt.datetime


class MemberResponse(BaseModel):
    membership_id: str
    user_id: str
    email: EmailStr
    role: OrgRole
    is_active: bool
    joined_at: dt.datetime
    # Aggregate only: what an admin may see for every member by default.
    assets_owned: int


class MemberDetailResponse(BaseModel):
    """Member-level detail. Reading another member's detail is audit-logged."""

    membership_id: str
    user_id: str
    email: EmailStr
    role: OrgRole
    is_active: bool
    joined_at: dt.datetime
    assets: list[dict[str, Any]] = Field(default_factory=list)


class InvitationCreateRequest(BaseModel):
    email: EmailStr
    role: OrgRole = OrgRole.MEMBER


class InvitationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    role: str
    expires_at: dt.datetime
    used_at: dt.datetime | None
    created_at: dt.datetime


class InvitationCreatedResponse(InvitationResponse):
    """Returned ONLY to the inviting admin so the link can be shared.

    The raw token is never written to logs or to the audit trail.
    """

    invite_link: str


class InvitationAcceptRequest(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    # Required only when the invited email has no account yet.
    password: str | None = Field(default=None, min_length=10, max_length=128)


class OrgAssetCreate(BaseModel):
    asset_id: str = Field(min_length=1, max_length=64)
    asset_type: str
    label: str = Field(min_length=1, max_length=200)
    service_name: str | None = Field(default=None, max_length=120)
    # 1 (low) .. 5 (business-critical). Admin-set importance, not a risk score.
    criticality: int = Field(default=3, ge=1, le=5)
    owner_membership_id: str | None = None

    @field_validator("asset_type")
    @classmethod
    def _company_owned_only(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized in PERSONAL_ASSET_TYPES:
            raise ValueError(
                "Personal accounts and personal/BYOD devices are out of scope for "
                "CRIX. Register only company-owned assets (work email, workspace, "
                "repositories, cloud storage, CI, business apps, domains)."
            )
        if normalized not in COMPANY_ASSET_TYPES:
            raise ValueError(
                f"Unknown asset_type {value!r}. Allowed: {', '.join(COMPANY_ASSET_TYPES)}."
            )
        return normalized


class OrgAssetUpdate(BaseModel):
    label: str | None = Field(default=None, min_length=1, max_length=200)
    service_name: str | None = Field(default=None, max_length=120)
    criticality: int | None = Field(default=None, ge=1, le=5)
    owner_membership_id: str | None = None


class OrgAssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str
    asset_type: str
    label: str
    service_name: str | None
    criticality: int
    owner_membership_id: str | None
    source_mode: str
    created_at: dt.datetime


class AssetDependencyCreate(BaseModel):
    from_asset_id: str = Field(min_length=1, max_length=64)
    to_asset_id: str = Field(min_length=1, max_length=64)
    relationship_type: str = Field(min_length=1, max_length=40)
    weight: float = Field(default=1.0, ge=0.0, le=1.0)
    note: str = Field(default="", max_length=500)


class AssetDependencyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    from_asset_id: str
    to_asset_id: str
    relationship_type: str
    edge_source: str
    weight: float
    note: str
    created_at: dt.datetime


class AdminViewResponse(BaseModel):
    """An admin's access to a member's data, shown to that member."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    admin_email: str | None
    action: str
    resource: str
    detail: dict[str, Any]
    created_at: dt.datetime


# --------------------------------------------------------------------------- #
# Connected signals / accounts
# --------------------------------------------------------------------------- #
class AccountCreate(BaseModel):
    account_id: str = Field(min_length=1, max_length=64)
    label: str = Field(min_length=1, max_length=200)
    service_name: str | None = Field(default=None, max_length=120)
    platform: str | None = Field(default=None, max_length=60)
    email: EmailStr | None = None
    source: DataProvenance = DataProvenance.USER_REPORTED


class AccountResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    account_id: str
    label: str
    service_name: str | None
    platform: str | None
    email: str | None
    source: str
    created_at: dt.datetime


# --------------------------------------------------------------------------- #
# SecurityEvent (§4) — the single normalized schema
# --------------------------------------------------------------------------- #
class SecurityEventSchema(BaseModel):
    """Normalized security event. ``severity``/``confidence`` here are the
    module's *observation* strength; authoritative risk is computed server-side
    by the risk engine and can never be injected by a client (§14)."""

    event_id: str
    user_id: str
    account_id: str
    event_type: str
    exposure_type: ExposureType | None = None
    severity: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    source_mode: SourceMode = SourceMode.USER_PROVIDED
    detected_at: dt.datetime = Field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))
    status: EventStatus = EventStatus.NOT_CHECKED
    metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: str = ""


class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    user_id: str
    account_id: str
    event_type: str
    exposure_type: str | None
    severity: float
    confidence: float
    source: str
    source_mode: str
    detected_at: dt.datetime
    status: str
    metadata: dict[str, Any]
    provenance: str


# --------------------------------------------------------------------------- #
# Signal module input contracts
# --------------------------------------------------------------------------- #
class BreachCheckRequest(BaseModel):
    account_id: str
    email: EmailStr
    # Simulated exposure scenario (§3.A) — never claimed to be real.
    simulated_exposure_type: ExposureType | None = None
    simulated_mfa_bypass_capable: bool = False


class PasswordReuseItem(BaseModel):
    """A client-side reuse result. The plaintext (and even its hash) never
    reaches the server: the browser compares hashes locally and submits only a
    boolean. This is user-reported hygiene data, not authoritative risk."""

    label: str = Field(min_length=1, max_length=120)
    reused: bool


class PasswordHygieneRequest(BaseModel):
    account_id: str
    provider: str | None = None
    mfa_enabled: bool = False
    mfa_method: str | None = Field(default=None, max_length=40)  # passkey|totp|sms|push
    passkey_enabled: bool = False
    sms_otp_recovery: bool = False
    push_bombing_reported: bool = False
    reused_credentials: list[PasswordReuseItem] = Field(default_factory=list)


class PhishingAnalyzeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20000)


class PhishingAnalyzeResponse(BaseModel):
    label: str
    confidence: float
    ai_generated_label: str | None
    ai_generated_confidence: float | None
    model_version: str
    signals: list[dict[str, Any]]
    provenance: str
    note: str


class PermissionEntry(BaseModel):
    app_name: str = Field(min_length=1, max_length=120)
    platform: str = Field(min_length=1, max_length=60)
    permissions: list[str] = Field(default_factory=list, min_length=1)
    granted_at: dt.date | None = None
    last_used_at: dt.date | None = None


class PermissionAuditRequest(BaseModel):
    account_id: str
    entries: list[PermissionEntry] = Field(default_factory=list, min_length=1)


# --------------------------------------------------------------------------- #
# Engine outputs
# --------------------------------------------------------------------------- #
class CorrelationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    rule_id: str
    title: str
    severity: float
    confidence: float
    explanation: str
    contributing_event_ids: list[str]


class RiskResponse(BaseModel):
    score: float
    band: str
    confidence: str
    range_low: float
    range_high: float
    base_risk: float
    interaction_risk: float
    mitigation_credit: float
    components: dict[str, Any]


class AttributionResponse(BaseModel):
    method: str
    total_risk: float
    contributions: dict[str, float]
    compute_ms: float


class AnalysisResult(BaseModel):
    """The full deterministic pipeline output for one run."""

    run_id: str
    events: list[SecurityEventResponse]
    correlations: list[CorrelationResponse]
    risk: RiskResponse
    attribution: AttributionResponse
    generated_at: dt.datetime


class ExplanationResponse(BaseModel):
    summary: str
    citations: list[dict[str, Any]]
    context: dict[str, Any]
    grounded: bool
    unsupported_claims: list[str]


class WhatIfToggle(BaseModel):
    """A candidate mitigation applied to a hypothetical copy of the input."""

    action_key: str
    enabled: bool
    target_account_id: str | None = None


class WhatIfRequest(BaseModel):
    toggles: list[WhatIfToggle] = Field(default_factory=list)


class RemediationPlanResponse(BaseModel):
    method: str
    actions: list[str]
    total_effort: float
    risk_after: float
    risk_reduction: float
    compute_ms: float


class PlannerComparison(BaseModel):
    greedy: RemediationPlanResponse
    exact: RemediationPlanResponse
    optimality_gap: float
    is_greedy_trap: bool


class HealthResponse(BaseModel):
    status: str
    version: str
    env: str
    hibp_configured: bool
    # Which provider will handle the next email breach lookup, resolved from
    # CRIX_BREACH_EMAIL_PROVIDER. Reported so the UI never has to guess.
    breach_email_provider: str
    breach_email_provider_label: str


def validate_event_status(value: str) -> EventStatus:
    try:
        return EventStatus(value)
    except ValueError as exc:  # pragma: no cover - defensive
        raise ValueError(f"Unknown event status: {value}") from exc