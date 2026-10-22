"""SecurityEvent normalizer (§4).

Turns module outputs (Pydantic ``SecurityEventSchema``) into persisted ORM rows,
enforcing the one-schema contract: status is preserved exactly, and a module that
could not run stays UNAVAILABLE (never silently coerced to CHECKED_SAFE).
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models import SecurityEvent
from app.schemas import SecurityEventSchema, SourceMode


def to_row(user_id: str, event: SecurityEventSchema) -> SecurityEvent:
    return SecurityEvent(
        event_id=event.event_id,
        user_id=user_id,
        account_id=event.account_id,
        event_type=event.event_type,
        exposure_type=event.exposure_type.value if event.exposure_type else None,
        severity=float(event.severity),
        confidence=float(event.confidence),
        source=event.source,
        source_mode=_source_mode(event),
        detected_at=event.detected_at,
        status=event.status.value if hasattr(event.status, "value") else str(event.status),
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


def persist_events(db: Session, events: list[SecurityEventSchema]) -> list[SecurityEvent]:
    rows = [to_row(event.user_id, event) for event in events]
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


def to_schema(row: SecurityEvent) -> SecurityEventSchema:
    return SecurityEventSchema(
        event_id=row.event_id,
        user_id=row.user_id,
        account_id=row.account_id,
        event_type=row.event_type,
        exposure_type=row.exposure_type,
        severity=row.severity,
        confidence=row.confidence,
        source=row.source,
        source_mode=SourceMode(getattr(row, "source_mode", None) or SourceMode.USER_PROVIDED.value),
        detected_at=row.detected_at,
        status=row.status,
        metadata=row.metadata_json or {},
        provenance=row.provenance,
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
    db.execute(
        delete(SecurityEvent).where(
            SecurityEvent.user_id == user_id,
            SecurityEvent.account_id == account_id,
            SecurityEvent.event_type.in_(event_types),
        )
    )
    db.commit()
    return persist_events(db, schemas)


def schema_to_response(event: SecurityEventSchema) -> dict:
    return {
        "event_id": event.event_id,
        "user_id": event.user_id,
        "account_id": event.account_id,
        "event_type": event.event_type,
        "exposure_type": event.exposure_type.value if event.exposure_type else None,
        "severity": event.severity,
        "confidence": event.confidence,
        "source": event.source,
        "source_mode": (
            event.source_mode.value if hasattr(event.source_mode, "value") else str(event.source_mode)
        ),
        "detected_at": event.detected_at,
        "status": event.status.value if hasattr(event.status, "value") else str(event.status),
        "metadata": event.metadata,
        "provenance": event.provenance,
    }


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)