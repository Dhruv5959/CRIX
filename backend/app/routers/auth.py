"""Authentication: register, login, refresh rotation, logout, password reset, 2FA.

Security properties enforced here:
- bcrypt (cost >= 12) for CRIX's own credentials (§2).
- Short-lived JWT access tokens + rotating refresh tokens in an httpOnly,
  SameSite cookie; double-submit CSRF token on state-changing auth calls (§2).
- Login rate limiting per IP (§2, §14).
- Password reset tokens are single-use, short-expiry, stored only as hashes,
  and delivered out-of-band (never logged) (§2, §14).
"""
from __future__ import annotations

import datetime as dt
import hashlib
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, security, totp
from app.config import Settings, get_settings
from app.db import get_db
from app.deps import get_current_user
from app.models import PasswordResetToken, RefreshToken, User
from app.rate_limit import client_ip, enforce, login_limiter
from app.schemas import (
    LoginRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.services.email import send_email

router = APIRouter(prefix="/api/auth", tags=["auth"])

REFRESH_COOKIE = "crix_refresh"
REFRESH_COOKIE_PATH = "/api/auth"
CSRF_HEADER = "X-CSRF-Token"
RESET_TOKEN_TTL_MINUTES = 30


def _hash_token(raw: str) -> str:
    # Hash the UTF-8 bytes exactly as stored in the cookie, so verification
    # round-trips for any token string.
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _as_utc(value: dt.datetime) -> dt.datetime:
    """Normalize a possibly-naive datetime (SQLite drops tzinfo) to aware UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value


def _set_refresh_cookie(response: Response, raw: str, settings: Settings) -> None:
    max_age = settings.refresh_token_expire_days * 24 * 3600
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=raw,
        max_age=max_age,
        httponly=True,
        secure=settings.is_production,
        samesite="lax",
        path=REFRESH_COOKIE_PATH,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(key=REFRESH_COOKIE, path=REFRESH_COOKIE_PATH)


def _issue_session(
    db: Session, user: User, request: Request, response: Response, settings: Settings
) -> TokenResponse:
    access, expires_at = security.create_access_token(user_id=user.id, settings=settings)
    raw_refresh = security.new_refresh_token()
    csrf = security.new_csrf_token()
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=_hash_token(raw_refresh),
            expires_at=security.refresh_token_expiry(settings),
            csrf_token=csrf,
            user_agent=(request.headers.get("user-agent") or "")[:400],
            ip_address=client_ip(request),
        )
    )
    db.commit()
    _set_refresh_cookie(response, raw_refresh, settings)
    return TokenResponse(access_token=access, expires_at=expires_at, csrf_token=csrf)


# --------------------------------------------------------------------------- #
# Registration & login
# --------------------------------------------------------------------------- #
@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> User:
    email = payload.email.lower()
    existing = db.scalar(select(User).where(User.email == email))
    if existing is not None:
        # Avoid user enumeration: generic message, but still record the attempt.
        audit.record(db, action="register.duplicate", ip_address=client_ip(request))
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )
    try:
        password_hash = security.hash_password(payload.password, settings)
    except security.PasswordPolicyError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    user = User(email=email, password_hash=password_hash)
    db.add(user)
    db.commit()
    db.refresh(user)
    audit.record(db, action="register.success", user_id=user.id, ip_address=client_ip(request))
    return user


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    enforce(login_limiter, request, limit=settings.login_rate_limit_per_minute)
    email = payload.email.lower()
    user = db.scalar(select(User).where(User.email == email))

    # Always run a hash comparison to reduce timing-based user enumeration.
    dummy_hash = "$2b$12$" + "0" * 53
    ok = security.verify_password(
        payload.password, user.password_hash if user else dummy_hash, settings
    )
    if not user or not ok or not user.is_active:
        audit.record(db, action="login.failure", ip_address=client_ip(request))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if user.totp_enabled:
        if not payload.totp_code or not user.totp_secret or not totp.verify(
            user.totp_secret, payload.totp_code
        ):
            audit.record(db, action="login.2fa_required", user_id=user.id, ip_address=client_ip(request))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="A valid two-factor code is required.",
            )

    audit.record(db, action="login.success", user_id=user.id, ip_address=client_ip(request))
    return _issue_session(db, user, request, response, settings)


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    raw = request.cookies.get(REFRESH_COOKIE)
    if not raw:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No refresh token.")

    row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == _hash_token(raw)))
    if row is None:
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token.")

    # Double-submit CSRF check for this state-changing action.
    if request.headers.get(CSRF_HEADER, "") != row.csrf_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF check failed.")

    # Reuse detection: a revoked token being presented means possible theft.
    if row.revoked_at is not None:
        if row.replaced_by_id:
            audit.record(
                db, action="refresh.reuse_detected", user_id=row.user_id, ip_address=client_ip(request)
            )
            _revoke_all_user_tokens(db, row.user_id)
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token already used.")

    if _as_utc(row.expires_at) <= dt.datetime.now(dt.timezone.utc):
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired.")

    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found.")

    # Rotate: revoke old, issue new, link the chain.
    csrf = security.new_csrf_token()
    raw_refresh = security.new_refresh_token()
    new_row = RefreshToken(
        user_id=user.id,
        token_hash=_hash_token(raw_refresh),
        expires_at=security.refresh_token_expiry(settings),
        csrf_token=csrf,
        user_agent=(request.headers.get("user-agent") or "")[:400],
        ip_address=client_ip(request),
    )
    db.add(new_row)
    db.flush()
    row.revoked_at = dt.datetime.now(dt.timezone.utc)
    row.replaced_by_id = new_row.id
    db.commit()

    access, expires_at = security.create_access_token(user_id=user.id, settings=settings)
    _set_refresh_cookie(response, raw_refresh, settings)
    return TokenResponse(access_token=access, expires_at=expires_at, csrf_token=csrf)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> Response:
    raw = request.cookies.get(REFRESH_COOKIE)
    if raw:
        row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == _hash_token(raw)))
        if row is not None and row.revoked_at is None:
            if request.headers.get(CSRF_HEADER, "") != row.csrf_token:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF check failed.")
            row.revoked_at = dt.datetime.now(dt.timezone.utc)
            db.commit()
            audit.record(db, action="logout", user_id=row.user_id, ip_address=client_ip(request))
    _clear_refresh_cookie(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


def _revoke_all_user_tokens(db: Session, user_id: str) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    rows = db.scalars(select(RefreshToken).where(RefreshToken.user_id == user_id)).all()
    for row in rows:
        if row.revoked_at is None:
            row.revoked_at = now
    db.commit()


@router.get("/me", response_model=UserResponse)
def me(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    return current_user


# --------------------------------------------------------------------------- #
# Password reset
# --------------------------------------------------------------------------- #
@router.post("/password-reset/request", status_code=status.HTTP_202_ACCEPTED)
def password_reset_request(
    payload: PasswordResetRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    # Always return the same response to prevent account enumeration.
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    transport = "none"
    if user is not None:
        raw = security.new_opaque_token()
        db.add(
            PasswordResetToken(
                user_id=user.id,
                token_hash=_hash_token(raw),
                expires_at=dt.datetime.now(dt.timezone.utc)
                + dt.timedelta(minutes=RESET_TOKEN_TTL_MINUTES),
            )
        )
        db.commit()
        link = f"http://localhost:5173/reset-password?token={raw}"
        transport = send_email(
            to=user.email,
            subject="Reset your CRIX password",
            body=f"Use this link within {RESET_TOKEN_TTL_MINUTES} minutes:\n\n{link}\n",
            settings=settings,
        )
        # Audit records the transport only; the token is never logged (§14).
        audit.record(
            db, action="password_reset.requested", user_id=user.id,
            ip_address=client_ip(request), detail={"transport": transport},
        )
    return {"detail": "If that email exists, a reset link has been sent."}


@router.post("/password-reset/confirm", status_code=status.HTTP_200_OK)
def password_reset_confirm(
    payload: PasswordResetConfirm,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    row = db.scalar(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == _hash_token(payload.token))
    )
    now = dt.datetime.now(dt.timezone.utc)
    if row is None or row.used_at is not None or _as_utc(row.expires_at) <= now:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token.")
    user = db.get(User, row.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid reset token.")
    try:
        user.password_hash = security.hash_password(payload.new_password, settings)
    except security.PasswordPolicyError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    row.used_at = now
    db.commit()
    _revoke_all_user_tokens(db, user.id)
    audit.record(db, action="password_reset.completed", user_id=user.id, ip_address=client_ip(request))
    return {"detail": "Password has been reset. Please log in again."}


# --------------------------------------------------------------------------- #
# Optional TOTP 2FA (nice-to-have, §2)
# --------------------------------------------------------------------------- #
@router.post("/2fa/setup")
def setup_2fa(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> dict[str, str]:
    secret = totp.generate_secret()
    current_user.totp_secret = secret
    db.commit()
    return {
        "secret": secret,
        "otpauth_uri": totp.provisioning_uri(secret, current_user.email),
        "detail": "Confirm with a code to enable.",
    }


@router.post("/2fa/enable")
def enable_2fa(
    code: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> dict[str, str]:
    if not current_user.totp_secret or not totp.verify(current_user.totp_secret, code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid 2FA code.")
    current_user.totp_enabled = True
    db.commit()
    return {"detail": "Two-factor authentication enabled."}


@router.post("/2fa/disable")
def disable_2fa(
    code: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> dict[str, str]:
    if not current_user.totp_enabled:
        return {"detail": "Two-factor authentication is not enabled."}
    if not current_user.totp_secret or not totp.verify(current_user.totp_secret, code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid 2FA code.")
    current_user.totp_enabled = False
    current_user.totp_secret = None
    db.commit()
    return {"detail": "Two-factor authentication disabled."}