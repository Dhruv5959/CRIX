"""Authentication and authorization dependencies.

``get_current_user`` resolves the authenticated user from a bearer token;
``get_current_membership`` resolves that user's role inside their organization;
``require_role`` turns a role into a server-side authorization gate.

Every organization-scoped endpoint depends on the membership so the ``org_id``
used to scope the query comes from the database, never from the client (§4).
"""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import ExpiredSignatureError, InvalidTokenError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import get_db
from app.models import Membership, User
from app.security import decode_access_token

_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> User:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_access_token(credentials.credentials, settings)
    except ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token expired.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = db.get(User, payload["sub"])
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive.",
        )
    return user


def get_current_user_or_none(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> User | None:
    """Same as ``get_current_user`` but returns ``None`` instead of raising.

    Used by endpoints that behave differently for anonymous vs. authenticated
    callers (e.g. invitation acceptance) without leaking *why* auth failed.
    """
    if credentials is None or not credentials.credentials:
        return None
    try:
        payload = decode_access_token(credentials.credentials, settings)
    except (ExpiredSignatureError, InvalidTokenError):
        return None
    user = db.get(User, payload["sub"])
    if user is None or not user.is_active:
        return None
    return user


def get_current_membership(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> Membership:
    """Resolve the caller's active membership in their organization.

    The returned membership is the authorization authority for every
    organization-scoped query, so a client can never spoof an ``org_id`` via a
    header or body field (§4, §14 IDOR).
    """
    membership = db.scalar(
        select(Membership)
        .where(
            Membership.user_id == current_user.id,
            Membership.is_active.is_(True),
        )
        .order_by(Membership.created_at.asc())
    )
    if membership is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not belong to an organization.",
        )
    return membership


def require_role(*roles: str):
    """Build a dependency that gates an endpoint to the given role(s).

    The check is server-side against the stored membership role; a client cannot
    elevate its own role.
    """
    allowed = frozenset(roles)

    def _dependency(
        membership: Annotated[Membership, Depends(get_current_membership)],
    ) -> Membership:
        if membership.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your role does not permit this action.",
            )
        return membership

    return _dependency