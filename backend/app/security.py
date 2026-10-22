"""Password hashing and JWT helpers.

This module handles CRIX's OWN login credentials (bcrypt, cost >= 12) and the
issuance/verification of JWT access + refresh tokens. It is deliberately
separate from the password-breach-checking feature (§0.4): CRIX never stores
or transmits a user's third-party passwords, and those never reach the server
in plaintext at all.
"""
from __future__ import annotations

import datetime as dt
import secrets
import uuid
from typing import Any

import bcrypt
import jwt

from app.config import Settings

# bcrypt truncates at 72 bytes; we reject longer to avoid silent truncation.
MAX_PASSWORD_BYTES = 72


class PasswordPolicyError(ValueError):
    """Raised when a password fails the local policy."""


def hash_password(password: str, settings: Settings) -> str:
    """Hash a password with bcrypt at the configured cost factor."""
    _validate_password_policy(password)
    rounds = max(12, int(settings.bcrypt_rounds))
    salt = bcrypt.gensalt(rounds=rounds)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, password_hash: str, settings: Settings) -> bool:
    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _validate_password_policy(password: str) -> None:
    if not isinstance(password, str) or len(password) < 10:
        raise PasswordPolicyError("Password must be at least 10 characters long.")
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise PasswordPolicyError(
            f"Password must be at most {MAX_PASSWORD_BYTES} bytes (bcrypt limit)."
        )
    if password.lower() in _COMMON_PASSWORDS:
        raise PasswordPolicyError("Password is too common.")


_COMMON_PASSWORDS = {
    "password", "password1", "password123", "1234567890", "qwertyuiop",
    "letmein123", "iloveyou123", "admin12345", "welcome1234",
}


# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #
def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def create_access_token(*, user_id: str, settings: Settings) -> tuple[str, dt.datetime]:
    expires_at = _now() + dt.timedelta(minutes=settings.access_token_expire_minutes)
    payload: dict[str, Any] = {
        "sub": user_id,
        "type": "access",
        "iat": int(_now().timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, expires_at


def decode_access_token(token: str, settings: Settings) -> dict[str, Any]:
    """Decode and validate an access token. Raises jwt exceptions on failure."""
    payload = jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
        options={"require": ["exp", "sub", "type"]},
    )
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("Not an access token.")
    return payload


def new_refresh_token() -> str:
    """An opaque, high-entropy refresh token. Only its hash is stored."""
    return secrets.token_urlsafe(48)


def refresh_token_expiry(settings: Settings) -> dt.datetime:
    return _now() + dt.timedelta(days=settings.refresh_token_expire_days)


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def new_opaque_token() -> str:
    """For email verification / password reset links."""
    return secrets.token_urlsafe(32)