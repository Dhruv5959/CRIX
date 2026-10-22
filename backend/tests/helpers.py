"""Helpers to construct normalized security events in tests."""
from __future__ import annotations

from app.schemas import SecurityEventSchema


def seed_org_for_user(db, user_id: str = "user-1", org_name: str = "Test Company") -> str:
    """Give ``user_id`` an organization + active membership, as registration does.

    Findings are organization-owned (§4): every writer resolves the organization
    from the author's membership, so a test that persists findings directly must
    give that user a membership first. Returns the ``org_id``.
    """
    from app.models import Membership, Organization, User
    from app.routers.org import unique_slug
    from sqlalchemy import select

    existing = db.scalar(
        select(Membership).where(Membership.user_id == user_id, Membership.is_active.is_(True))
    )
    if existing is not None:
        return existing.org_id

    if db.get(User, user_id) is None:
        db.add(
            User(
                id=user_id,
                email=f"{user_id}@tests.invalid",
                password_hash="not-a-real-hash",
                email_verified=True,
            )
        )
    org = Organization(name=org_name, slug=unique_slug(db, org_name), created_by_user_id=user_id)
    db.add(org)
    db.flush()
    membership = Membership(org_id=org.id, user_id=user_id, role="ORG_ADMIN", is_active=True)
    db.add(membership)
    db.commit()
    return org.id


def ev(event_type: str, *, severity: float = 0.6, confidence: float = 0.8,
       exposure_type=None, status: str = "FINDING", account_id: str = "acct",
       metadata: dict | None = None, source: str = "test", event_id: str | None = None,
       user_id: str = "user-1", evidence: dict | None = None,
       source_mode=None, org_id: str | None = None):
    event = SecurityEventSchema(
        event_id=event_id or f"evt_{event_type}_{account_id}_{severity}_{exposure_type}",
        user_id=user_id,
        account_id=account_id,
        event_type=event_type,
        exposure_type=exposure_type,
        severity=severity,
        confidence=confidence,
        source=source,
        status=status,
        metadata=metadata or {},
        evidence=evidence or {},
        provenance="test",
    )
    if source_mode is not None:
        event = event.model_copy(update={"source_mode": source_mode})
    if org_id is not None:
        # Simulates a value a client tried to inject: the normalizer must
        # overwrite it with the server-resolved organization.
        event = event.model_copy(update={"org_id": org_id})
    return event