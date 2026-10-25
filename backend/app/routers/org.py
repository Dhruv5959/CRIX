"""Organization, members, invitations, and member-facing privacy endpoints (§4).

Authorization model (enforced server-side; see ``docs/RBAC.md``):

* Every route resolves the caller's membership from the database, so the
  ``org_id`` used to scope queries is never client-supplied.
* ``ORG_ADMIN`` manages the organization, assets, dependencies and invites.
* ``MEMBER`` and ``VIEWER`` may read organization-level aggregates.
* Reading another member's member-level detail is ORG_ADMIN-only and writes an
  ``AdminViewAuditLog`` row that the member can see via
  ``GET /api/org/admin-views``.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import re
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit, security
from app.config import Settings, get_settings
from app.db import get_db
from app.deps import get_current_membership, get_current_user_or_none, require_role
from app.models import (
    AdminViewAuditLog,
    Invitation,
    Membership,
    Organization,
    OrgAsset,
    User,
)
from app.rate_limit import client_ip, enforce, invite_accept_limiter
from app.schemas import (
    AdminViewResponse,
    InvitationAcceptRequest,
    InvitationCreateRequest,
    InvitationCreatedResponse,
    InvitationResponse,
    MemberDetailResponse,
    MemberResponse,
    OrgResponse,
    OrgRole,
    OrgUpdateRequest,
)
from app.services.email import EmailDeliveryError, send_email

router = APIRouter(prefix="/api", tags=["organization"])

INVITATION_TTL_DAYS = 7
ADMIN_ROLES = (OrgRole.ORG_ADMIN.value,)


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug[:100] or "org"


def unique_slug(db: Session, name: str) -> str:
    base = slugify(name)
    slug = base
    suffix = 2
    while db.scalar(select(Organization.id).where(Organization.slug == slug)) is not None:
        slug = f"{base}-{suffix}"[:120]
        suffix += 1
    return slug


def create_organization(db: Session, *, name: str, created_by_user_id: str) -> Organization:
    """Create an organization. Commits the row so its id is stable."""
    org = Organization(
        name=name.strip()[:200] or "My Company",
        slug=unique_slug(db, name),
        created_by_user_id=created_by_user_id,
    )
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


# --------------------------------------------------------------------------- #
# Organization
# --------------------------------------------------------------------------- #
@router.get("/org", response_model=OrgResponse)
def get_org(
    membership: Annotated[Membership, Depends(get_current_membership)],
    db: Session = Depends(get_db),
) -> OrgResponse:
    org = db.get(Organization, membership.org_id)
    if org is None:  # pragma: no cover - defensive; FK guarantees existence
        raise HTTPException(status_code=404, detail="Organization not found.")
    member_count = db.scalar(
        select(func.count()).select_from(Membership).where(Membership.org_id == org.id)
    )
    asset_count = db.scalar(
        select(func.count()).select_from(OrgAsset).where(OrgAsset.org_id == org.id)
    )
    return OrgResponse(
        id=org.id,
        name=org.name,
        slug=org.slug,
        role=OrgRole(membership.role),
        member_count=int(member_count or 0),
        asset_count=int(asset_count or 0),
        created_at=org.created_at,
    )


@router.patch("/org", response_model=OrgResponse)
def update_org(
    payload: OrgUpdateRequest,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
) -> OrgResponse:
    org = db.get(Organization, membership.org_id)
    if org is None:  # pragma: no cover - defensive
        raise HTTPException(status_code=404, detail="Organization not found.")
    org.name = payload.name.strip()[:200]
    db.commit()
    audit.record(db, action="org.updated", user_id=membership.user_id, detail={"org_id": org.id})
    return OrgResponse(
        id=org.id,
        name=org.name,
        slug=org.slug,
        role=OrgRole(membership.role),
        member_count=int(
            db.scalar(
                select(func.count()).select_from(Membership).where(Membership.org_id == org.id)
            )
            or 0
        ),
        asset_count=int(
            db.scalar(select(func.count()).select_from(OrgAsset).where(OrgAsset.org_id == org.id))
            or 0
        ),
        created_at=org.created_at,
    )


# --------------------------------------------------------------------------- #
# Members
# --------------------------------------------------------------------------- #
def _assets_owned(db: Session, org_id: str, membership_id: str) -> int:
    return int(
        db.scalar(
            select(func.count())
            .select_from(OrgAsset)
            .where(OrgAsset.org_id == org_id, OrgAsset.owner_membership_id == membership_id)
        )
        or 0
    )


@router.get("/members", response_model=list[MemberResponse])
def list_members(
    membership: Annotated[Membership, Depends(get_current_membership)],
    db: Session = Depends(get_db),
) -> list[MemberResponse]:
    """Member directory with AGGREGATE data only (no member-level findings)."""
    rows = db.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.org_id == membership.org_id)
        .order_by(Membership.created_at.asc())
    ).all()
    return [
        MemberResponse(
            membership_id=m.id,
            user_id=m.user_id,
            email=u.email,
            role=OrgRole(m.role),
            is_active=m.is_active,
            joined_at=m.created_at,
            assets_owned=_assets_owned(db, m.org_id, m.id),
        )
        for m, u in rows
    ]


@router.get("/members/{membership_id}", response_model=MemberDetailResponse)
def get_member(
    membership_id: str,
    membership: Annotated[Membership, Depends(get_current_membership)],
    request: Request,
    db: Session = Depends(get_db),
) -> MemberDetailResponse:
    """Member-level detail.

    * A member reading their OWN detail is always allowed.
    * An ORG_ADMIN reading ANOTHER member's detail is allowed and audit-logged.
    * Everyone else is denied (403); unknown ids return 404 without leaking
      whether the id exists in another organization.
    """
    target = db.scalar(
        select(Membership).where(
            Membership.id == membership_id,
            Membership.org_id == membership.org_id,
        )
    )
    if target is None:
        raise HTTPException(status_code=404, detail="Member not found.")

    is_self = target.id == membership.id
    is_admin = membership.role == OrgRole.ORG_ADMIN.value
    if not is_self and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You may only view your own member detail.",
        )

    if not is_self and is_admin:
        db.add(
            AdminViewAuditLog(
                org_id=membership.org_id,
                admin_user_id=membership.user_id,
                admin_membership_id=membership.id,
                subject_membership_id=target.id,
                subject_user_id=target.user_id,
                action="member_detail.viewed",
                resource=f"membership:{target.id}",
                detail={"ip": client_ip(request)},
            )
        )
        db.commit()

    user = db.get(User, target.user_id)
    assets = db.scalars(
        select(OrgAsset)
        .where(OrgAsset.org_id == membership.org_id, OrgAsset.owner_membership_id == target.id)
        .order_by(OrgAsset.criticality.desc())
    ).all()
    return MemberDetailResponse(
        membership_id=target.id,
        user_id=target.user_id,
        email=user.email if user else "",
        role=OrgRole(target.role),
        is_active=target.is_active,
        joined_at=target.created_at,
        assets=[
            {
                "asset_id": a.asset_id,
                "asset_type": a.asset_type,
                "label": a.label,
                "criticality": a.criticality,
            }
            for a in assets
        ],
    )


@router.get("/org/admin-views", response_model=list[AdminViewResponse])
def my_admin_views(
    membership: Annotated[Membership, Depends(get_current_membership)],
    db: Session = Depends(get_db),
) -> list[AdminViewResponse]:
    """Every admin access to MY member-level data, shown to me (§2)."""
    rows = db.scalars(
        select(AdminViewAuditLog)
        .where(AdminViewAuditLog.subject_membership_id == membership.id)
        .order_by(AdminViewAuditLog.created_at.desc())
    ).all()
    admin_emails: dict[str, str | None] = {}
    out: list[AdminViewResponse] = []
    for row in rows:
        if row.admin_user_id not in admin_emails:
            admin = db.get(User, row.admin_user_id)
            admin_emails[row.admin_user_id] = admin.email if admin else None
        out.append(
            AdminViewResponse(
                id=row.id,
                admin_email=admin_emails[row.admin_user_id],
                action=row.action,
                resource=row.resource,
                detail=row.detail or {},
                created_at=row.created_at,
            )
        )
    return out


# --------------------------------------------------------------------------- #
# Invitations
# --------------------------------------------------------------------------- #
@router.post(
    "/invitations",
    response_model=InvitationCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_invitation(
    payload: InvitationCreateRequest,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    email = payload.email.lower()

    existing_member = db.scalar(
        select(Membership)
        .join(User, User.id == Membership.user_id)
        .where(Membership.org_id == membership.org_id, User.email == email)
    )
    if existing_member is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That person is already a member of this organization.",
        )

    # Re-use a still-valid pending invite instead of stacking duplicates.
    existing = db.scalar(
        select(Invitation).where(
            Invitation.org_id == membership.org_id,
            Invitation.email == email,
            Invitation.used_at.is_(None),
        )
    )
    raw = security.new_opaque_token()
    now = dt.datetime.now(dt.timezone.utc)
    if existing is not None:
        existing.token_hash = _hash_token(raw)
        existing.role = payload.role.value
        existing.expires_at = now + dt.timedelta(days=INVITATION_TTL_DAYS)
        invite = existing
    else:
        invite = Invitation(
            org_id=membership.org_id,
            email=email,
            role=payload.role.value,
            token_hash=_hash_token(raw),
            expires_at=now + dt.timedelta(days=INVITATION_TTL_DAYS),
            invited_by_user_id=membership.user_id,
        )
        db.add(invite)
    db.commit()
    db.refresh(invite)

    link = f"{settings.public_base_url}/invite?token={raw}"
    try:
        send_email(
            to=email,
            subject=f"You have been invited to join {db.get(Organization, membership.org_id).name} on CRIX",
            body=f"Accept your invitation within {INVITATION_TTL_DAYS} days:\n\n{link}\n",
            settings=settings,
        )
    except EmailDeliveryError as exc:
        # The recipient must not be able to use a token that was never delivered.
        invite.used_at = now
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Invitation email could not be delivered. Please try again later.",
        ) from exc
    audit.record(
        db,
        action="invitation.created",
        user_id=membership.user_id,
        detail={"invitation_id": invite.id, "email": email, "role": payload.role.value},
    )
    # The raw token is returned ONLY to the inviting admin (never logged) so the
    # link can be shared out-of-band alongside the email.
    return {
        "id": invite.id,
        "email": invite.email,
        "role": invite.role,
        "expires_at": invite.expires_at,
        "used_at": invite.used_at,
        "created_at": invite.created_at,
        "invite_link": link,
    }


@router.get("/invitations", response_model=list[InvitationResponse])
def list_invitations(
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
) -> list[Invitation]:
    return list(
        db.scalars(
            select(Invitation)
            .where(Invitation.org_id == membership.org_id)
            .order_by(Invitation.created_at.desc())
        ).all()
    )


@router.delete("/invitations/{invitation_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_invitation(
    invitation_id: str,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
) -> None:
    invite = db.scalar(
        select(Invitation).where(
            Invitation.id == invitation_id, Invitation.org_id == membership.org_id
        )
    )
    if invite is None:
        raise HTTPException(status_code=404, detail="Invitation not found.")
    db.delete(invite)
    db.commit()
    audit.record(
        db, action="invitation.revoked", user_id=membership.user_id,
        detail={"invitation_id": invitation_id},
    )


@router.post("/invitations/accept", status_code=status.HTTP_200_OK)
def accept_invitation(
    payload: InvitationAcceptRequest,
    request: Request,
    caller: Annotated[User | None, Depends(get_current_user_or_none)],
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Accept an invitation, creating the account if the email is new.

    The token is single-use and expiring; only its hash is stored.

    Proof-of-control rules (pre-registration takeover defense):

    * Creating a NEW account through the link is fine — the token was emailed
      to that address, so possession demonstrates control of the inbox.
    * An account that ALREADY exists (e.g. pre-registered by someone else) can
      NOT be bound to the invitation by token possession alone: the binding
      requires an authenticated session for that exact account. Otherwise an
      attacker who pre-registered a colleague's address could silently capture
      the membership when the real recipient accepted.
    """
    enforce(
        invite_accept_limiter, request, limit=settings.invite_accept_rate_limit_per_minute
    )
    invite = db.scalar(select(Invitation).where(Invitation.token_hash == _hash_token(payload.token)))
    now = dt.datetime.now(dt.timezone.utc)
    if invite is None or invite.used_at is not None or _as_utc(invite.expires_at) <= now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired invitation.",
        )

    user = db.scalar(select(User).where(User.email == invite.email))
    if user is not None and (caller is None or caller.id != user.id or not caller.is_active):
        # Token possession is NOT proof that the requester controls an
        # already-registered account (an account could have been pre-registered
        # by someone else with a different password). Only the authenticated
        # owner of that account may bind its membership.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "An account already exists for this email. Log in with that "
                "account first, then accept the invitation from your session."
            ),
        )

    if user is None:
        # New account: the emailed token is the proof of inbox control.
        if not payload.password:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="A password is required to create an account for this invitation.",
            )
        try:
            password_hash = security.hash_password(payload.password, settings)
        except security.PasswordPolicyError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            ) from exc
        user = User(email=invite.email, password_hash=password_hash, email_verified=True)
        db.add(user)
        db.flush()

    existing_membership = db.scalar(
        select(Membership).where(
            Membership.org_id == invite.org_id, Membership.user_id == user.id
        )
    )
    if existing_membership is None:
        db.add(
            Membership(org_id=invite.org_id, user_id=user.id, role=invite.role, is_active=True)
        )
        audit.record(
            db, action="invitation.accepted", user_id=user.id,
            ip_address=client_ip(request),
            detail={"org_id": invite.org_id, "role": invite.role},
        )
    else:
        existing_membership.is_active = True

    invite.used_at = now
    invite.accepted_by_user_id = user.id
    db.commit()
    return {
        "detail": "Invitation accepted. You can now log in.",
        "email": user.email,
        "role": invite.role,
        "org_id": invite.org_id,
    }
