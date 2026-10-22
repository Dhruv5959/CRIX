"""USER-CONFIRMED account relationships (live-OAuth scope, §5).

OAuth authentication does NOT prove that one account is a recovery account for
another. Every relationship is asserted by the authenticated CRIX user and
stored with ``source = USER_CONFIRMED``. CRIX never invents a recovery edge.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_user
from app.engine.propagation import PROPAGATION_PARAMS
from app.models import AccountRelationship, ConnectedSignal, User

router = APIRouter(prefix="/api/relationships", tags=["relationships"])

# Allowed user-confirmable relationship types (§5).
RELATIONSHIP_TYPES = {
    "recovery_email": "Recovery email",
    "recovery_phone": "Recovery phone",
    "sso": "Login / SSO dependency",
    "oauth_dependency": "Sign-in dependency (OAuth)",
    "same_email_identity": "Same email identity",
    "other": "Other",
}


class RelationshipCreate(BaseModel):
    from_account_id: str = Field(min_length=1, max_length=64)
    to_account_id: str = Field(min_length=1, max_length=64)
    relationship_type: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class RelationshipResponse(BaseModel):
    id: str
    from_account_id: str
    to_account_id: str
    from_label: str | None
    to_label: str | None
    relationship_type: str
    relationship_label: str
    source: str
    source_mode: str
    confidence: float
    weight: float
    created_at: str


def _label_map(db: Session, user_id: str) -> dict[str, str]:
    rows = db.scalars(
        select(ConnectedSignal).where(ConnectedSignal.user_id == user_id)
    ).all()
    return {row.account_id: row.label for row in rows}


def _owned(db: Session, user_id: str, account_id: str) -> None:
    if db.scalar(
        select(ConnectedSignal).where(
            ConnectedSignal.user_id == user_id, ConnectedSignal.account_id == account_id
        )
    ) is None:
        raise HTTPException(status_code=404, detail="Account not found.")


@router.get("/types")
def relationship_types() -> dict:
    return {
        "types": [
            {"key": key, "label": label}
            for key, label in RELATIONSHIP_TYPES.items()
        ],
        "note": (
            "These are relationships YOU confirm. OAuth login does not by itself "
            "prove a recovery path — CRIX never invents one."
        ),
        "weights": PROPAGATION_PARAMS["relationship_weights"],
    }


@router.get("", response_model=list[RelationshipResponse])
def list_relationships(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> list[RelationshipResponse]:
    rows = db.scalars(
        select(AccountRelationship)
        .where(AccountRelationship.user_id == current_user.id)
        .order_by(AccountRelationship.created_at.desc())
    ).all()
    labels = _label_map(db, current_user.id)
    return [
        RelationshipResponse(
            id=row.id,
            from_account_id=row.from_account_id,
            to_account_id=row.to_account_id,
            from_label=labels.get(row.from_account_id),
            to_label=labels.get(row.to_account_id),
            relationship_type=row.relationship_type,
            relationship_label=RELATIONSHIP_TYPES.get(
                row.relationship_type, row.relationship_type
            ),
            source=row.source,
            source_mode=row.source_mode,
            confidence=row.confidence,
            weight=row.weight,
            created_at=row.created_at.isoformat(),
        )
        for row in rows
    ]


@router.post("", response_model=RelationshipResponse, status_code=status.HTTP_201_CREATED)
def create_relationship(
    payload: RelationshipCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> RelationshipResponse:
    if payload.relationship_type not in RELATIONSHIP_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown relationship type. Allowed: {sorted(RELATIONSHIP_TYPES)}",
        )
    if payload.from_account_id == payload.to_account_id:
        raise HTTPException(status_code=422, detail="A relationship needs two different accounts.")

    _owned(db, current_user.id, payload.from_account_id)
    _owned(db, current_user.id, payload.to_account_id)

    existing = db.scalar(
        select(AccountRelationship).where(
            AccountRelationship.user_id == current_user.id,
            AccountRelationship.from_account_id == payload.from_account_id,
            AccountRelationship.to_account_id == payload.to_account_id,
            AccountRelationship.relationship_type == payload.relationship_type,
        )
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail="Relationship already exists.")

    weight = PROPAGATION_PARAMS["relationship_weights"].get(payload.relationship_type, 0.5)
    row = AccountRelationship(
        user_id=current_user.id,
        from_account_id=payload.from_account_id,
        to_account_id=payload.to_account_id,
        relationship_type=payload.relationship_type,
        source="USER_CONFIRMED",
        source_mode="USER_PROVIDED",
        confidence=payload.confidence,
        weight=float(weight),
        created_at=datetime.now(timezone.utc),
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    labels = _label_map(db, current_user.id)
    return RelationshipResponse(
        id=row.id,
        from_account_id=row.from_account_id,
        to_account_id=row.to_account_id,
        from_label=labels.get(row.from_account_id),
        to_label=labels.get(row.to_account_id),
        relationship_type=row.relationship_type,
        relationship_label=RELATIONSHIP_TYPES.get(row.relationship_type, row.relationship_type),
        source=row.source,
        source_mode=row.source_mode,
        confidence=row.confidence,
        weight=row.weight,
        created_at=row.created_at.isoformat(),
    )


@router.delete("/{relationship_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_relationship(
    relationship_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> None:
    row = db.scalar(
        select(AccountRelationship).where(
            AccountRelationship.user_id == current_user.id,
            AccountRelationship.id == relationship_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Relationship not found.")
    db.delete(row)
    db.commit()
