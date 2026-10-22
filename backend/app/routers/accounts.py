"""Connected-signal (account) CRUD. Strictly scoped to the authenticated user."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.deps import get_current_user
from app.db import get_db
from app.models import ConnectedSignal, User
from app.schemas import AccountCreate, AccountResponse

router = APIRouter(prefix="/api/accounts", tags=["accounts"])


@router.get("", response_model=list[AccountResponse])
def list_accounts(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> list[ConnectedSignal]:
    return list(
        db.scalars(
            select(ConnectedSignal)
            .where(ConnectedSignal.user_id == current_user.id)
            .order_by(ConnectedSignal.created_at.desc())
        ).all()
    )


@router.post("", response_model=AccountResponse, status_code=status.HTTP_201_CREATED)
def create_account(
    payload: AccountCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> ConnectedSignal:
    existing = db.scalar(
        select(ConnectedSignal).where(
            ConnectedSignal.user_id == current_user.id,
            ConnectedSignal.account_id == payload.account_id,
        )
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Account already connected."
        )
    account = ConnectedSignal(
        user_id=current_user.id,
        account_id=payload.account_id,
        label=payload.label,
        service_name=payload.service_name,
        platform=payload.platform,
        email=payload.email,
        source=payload.source.value if hasattr(payload.source, "value") else str(payload.source),
        metadata_json={"service_name": payload.service_name},
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    return account


def _get_owned_account(db: Session, user_id: str, account_id: str) -> ConnectedSignal:
    account = db.scalar(
        select(ConnectedSignal).where(
            ConnectedSignal.user_id == user_id, ConnectedSignal.account_id == account_id
        )
    )
    if account is None:
        # 404 (not 403) so we don't confirm existence of another user's account.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found.")
    return account


@router.get("/{account_id}", response_model=AccountResponse)
def get_account(
    account_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> ConnectedSignal:
    return _get_owned_account(db, current_user.id, account_id)


@router.delete("/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(
    account_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> None:
    account = _get_owned_account(db, current_user.id, account_id)
    db.delete(account)
    db.commit()