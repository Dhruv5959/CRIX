"""SecurityEvent normalizer (§4, Phase 2).

Turns module outputs (Pydantic ``SecurityEventSchema``) into persisted ORM rows,
enforcing the one-schema contract:

* status is preserved exactly, and a module that could not run stays UNAVAILABLE
  (never silently coerced to CHECKED_SAFE);
* **organization scope is resolved server-side** from the writing user's active
  membership. Any ``org_id`` carried on the incoming schema is overwritten — a
  client-sent value is never trusted;
* the affected company asset is bound by **exact canonical identity inside that
  same organization** (``app.engine.entities``). No match means ``NULL``: an
  unknown asset stays unknown, and a candidate from another tenant can never be
  bound (the lookup is scoped by ``org_id``);
* ``first_seen``/``last_seen`` are a real observation window: whatever the
  detector reported for the source, otherwise the timestamps CRIX itself
  recorded. Nothing is back-filled with a guess.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.engine.entities import resolve_asset
from app.models import ConnectedSignal, Membership, SecurityEvent
from app.schemas import SecurityEventSchema, SourceMode


class OrgScopeError(RuntimeError):
    """A finding was written for a user that has no organization.

    Registration always creates an organization, so this is a programming error,
    not a user error: it fails loudly instead of silently storing an
    organization-less finding.
    """


def resolve_org_id(db: Session, user_id: str) -> str:
    """The organization a finding written by ``user_id`` belongs to.

    Resolved from the database (the active membership), never from a request body.
    """
    membership = db.scalar(
        select(Membership)
        .where(Membership.user_id == user_id, Membership.is_active.is_(True))
        .order_by(Membership.created_at.asc(), Membership.id.asc())
    )
    if membership is None:
        raise OrgScopeError(
            f"user {user_id} has no active organization membership; "
            "an organization-owned finding cannot be stored."
        )
    return membership.org_id


def _account_candidates(db: Session, user_id: str, account_id: str) -> list[str]:
    """Identifiers that may match a registered company asset for this account.

    Only identity-bearing fields are used (the account's email and its stable
    account id). Labels and service names are deliberately excluded: matching on
    them would be the name-similarity merging §3 forbids.
    """
    account = db.scalar(
        select(ConnectedSignal).where(
            ConnectedSignal.user_id == user_id,
            ConnectedSignal.account_id == account_id,
        )
    )
    if account is None:
        return [account_id]
    return [account.email, account.account_id]


def _scope_for(
    db: Session, user_id: str, account_id: str, cache: dict
) -> tuple[str, str | None]:
    key = (user_id, account_id)
    if key in cache:
        return cache[key]
    org_id = resolve_org_id(db, user_id)
    asset = resolve_asset(db, org_id, _account_candidates(db, user_id, account_id))
    value = (org_id, asset.asset_id if asset is not None else None)
    cache[key] = value
    return value


def to_row(
    user_id: str,
    event: SecurityEventSchema,
    *,
    org_id: str,
    asset_id: str | None = None,
    first_seen: dt.datetime | None = None,
) -> SecurityEvent:
    """Map the normalized schema onto the ORM row.

    ``org_id`` is mandatory and supplied by the caller (``persist_events``), which
    always derives it from the database — never from the event.
    """
    detected = event.detected_at
    return SecurityEvent(
        event_id=event.event_id,
        org_id=org_id,
        user_id=user_id,
        account_id=event.account_id,
        asset_id=asset_id,
        event_type=event.event_type,
        exposure_type=event.exposure_type.value if event.exposure_type else None,
        severity=float(event.severity),
        confidence=float(event.confidence),
        source=event.source,
        source_mode=_source_mode(event),
        detected_at=detected,
        # Source window if the detector reported one; otherwise the window CRIX
        # itself recorded (earliest prior observation, else this one).
        first_seen=event.first_seen or first_seen or detected,
        last_seen=event.last_seen or detected,
        status=event.status.value if hasattr(event.status, "value") else str(event.status),
        evidence=dict(event.evidence),
        metadata_json=dict(event.metadata),
        provenance=event.provenance,
    )


def _source_mode(event: SecurityEventSchema) -> str:
    """Resolve the declared source_mode, falling back to a source->mode map."""
    mode = getattr(event, "source_mode", None)
    if mode is not None:
        return mode.value if hasattr(mode, "value") else str(mode)
    src = (event.source or "").lower()
    if src in ("hibp", "xposedornot", "oauth", "google", "linkedin"):
        return "REAL"
    if src in ("simulated", "scenario"):
        return "SIMULATED"
    if src in ("fixture", "demo_fixture"):
        return "FIXTURE"
    return "USER_PROVIDED"


def persist_events(
    db: Session,
    events: list[SecurityEventSchema],
    *,
    prior_first_seen: dict[tuple[str, str], dt.datetime] | None = None,
) -> list[SecurityEvent]:
    """Persist normalized findings, resolving organization and asset per event."""
    cache: dict = {}
    prior = prior_first_seen or {}
    rows: list[SecurityEvent] = []
    for event in events:
        org_id, asset_id = _scope_for(db, event.user_id, event.account_id, cache)
        rows.append(
            to_row(
                event.user_id,
                event,
                org_id=org_id,
                asset_id=asset_id,
                first_seen=prior.get((event.account_id, event.event_type)),
            )
        )
    db.add_all(rows)
    db.commit()
    for row in rows:
        db.refresh(row)
    return rows


def list_events(db: Session, user_id: str) -> list[SecurityEvent]:
    return list(
        db.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.user_id == user_id)
            .order_by(SecurityEvent.detected_at.desc())
        ).all()
    )


def list_org_events(db: Session, org_id: str) -> list[SecurityEvent]:
    """Every finding owned by one organization (tenant-scoped read path)."""
    return list(
        db.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.org_id == org_id)
            .order_by(SecurityEvent.detected_at.desc())
        ).all()
    )


def clear_events_for_account(db: Session, user_id: str, account_id: str) -> int:
    """Replace semantics for a re-run of a module: drop prior events of the same
    account so re-checks don't duplicate. Scoped strictly to the user."""
    result = db.execute(
        delete(SecurityEvent).where(
            SecurityEvent.user_id == user_id, SecurityEvent.account_id == account_id
        )
    )
    db.commit()
    return result.rowcount or 0


def _first_seen_by_account_type(db: Session, user_id: str, account_id: str, event_types: list[str]) -> dict[tuple[str, str], dt.datetime]:
    """Earliest observation already recorded for this account's module events.

    Used so a re-check keeps its original ``first_seen`` instead of resetting it
    to "now" — a real, previously recorded timestamp.
    """
    rows = db.scalars(
        select(SecurityEvent).where(
            SecurityEvent.user_id == user_id,
            SecurityEvent.account_id == account_id,
            SecurityEvent.event_type.in_(event_types),
        )
    ).all()
    prior: dict[tuple[str, str], dt.datetime] = {}
    for row in rows:
        key = (row.account_id, row.event_type)
        seen = row.first_seen or row.detected_at
        current = prior.get(key)
        if current is None or seen < current:
            prior[key] = seen
    return prior


def to_schema(row: SecurityEvent) -> SecurityEventSchema:
    return SecurityEventSchema(
        event_id=row.event_id,
        user_id=row.user_id,
        account_id=row.account_id,
        org_id=row.org_id,
        asset_id=row.asset_id,
        event_type=row.event_type,
        exposure_type=row.exposure_type,
        severity=row.severity,
        confidence=row.confidence,
        source=row.source,
        source_mode=SourceMode(getattr(row, "source_mode", None) or SourceMode.USER_PROVIDED.value),
        detected_at=row.detected_at,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        status=row.status,
        evidence=row.evidence or {},
        metadata=row.metadata_json or {},
        provenance=row.provenance,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def replace_module_events(
    db: Session,
    user_id: str,
    account_id: str,
    event_types: list[str],
    schemas: list[SecurityEventSchema],
) -> list[SecurityEvent]:
    """Replace only the events a given module owns for this account, so re-running
    one module never wipes another module's findings."""
    prior = _first_seen_by_account_type(db, user_id, account_id, event_types)
    db.execute(
        delete(SecurityEvent).where(
            SecurityEvent.user_id == user_id,
            SecurityEvent.account_id == account_id,
            SecurityEvent.event_type.in_(event_types),
        )
    )
    db.commit()
    return persist_events(db, schemas, prior_first_seen=prior)


def schema_to_response(event: SecurityEventSchema) -> dict:
    return {
        "event_id": event.event_id,
        "user_id": event.user_id,
        "account_id": event.account_id,
        "org_id": event.org_id,
        "asset_id": event.asset_id,
        "event_type": event.event_type,
        "exposure_type": event.exposure_type.value if event.exposure_type else None,
        "severity": event.severity,
        "confidence": event.confidence,
        "source": event.source,
        "source_mode": (
            event.source_mode.value if hasattr(event.source_mode, "value") else str(event.source_mode)
        ),
        "detected_at": event.detected_at,
        "first_seen": event.first_seen,
        "last_seen": event.last_seen,
        "status": event.status.value if hasattr(event.status, "value") else str(event.status),
        "evidence": event.evidence,
        "metadata": event.metadata,
        "provenance": event.provenance,
        "created_at": event.created_at,
        "updated_at": event.updated_at,
    }


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)
