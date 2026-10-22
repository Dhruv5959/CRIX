"""Encryption-at-rest for stored OAuth tokens (§14 of the live-OAuth scope).

Raw OAuth tokens must never be logged, never sent to the frontend, and never
stored in plaintext. This module encrypts/decrypts them with Fernet
(AES-128-CBC + HMAC) using a key from ``CRIX_TOKEN_ENCRYPTION_KEY``.

In dev, if no key is configured we derive a stable key from the JWT secret so a
fresh clone works. Production refuses to start without an explicit key
(``Settings.assert_production_safe``).
"""
from __future__ import annotations

import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings

logger = logging.getLogger(__name__)


class TokenDecryptionError(Exception):
    """Raised when a stored token cannot be decrypted (key rotation, corruption)."""


def _fernet() -> Fernet:
    settings = get_settings()
    key = (settings.token_encryption_key or "").strip()
    if key:
        # Accept a raw urlsafe-base64 Fernet key, or derive one from any string.
        try:
            return Fernet(key.encode("utf-8"))
        except (ValueError, TypeError):
            pass
    # Dev fallback: deterministic derivation from the JWT secret.
    digest = hashlib.sha256(
        ("crix:oauth-token:" + settings.jwt_secret).encode("utf-8")
    ).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_token(plaintext: str | None) -> str | None:
    """Encrypt a token for storage. ``None`` stays ``None``."""
    if not plaintext:
        return None
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_token(ciphertext: str | None) -> str | None:
    """Decrypt a stored token. Never logs the value (neither form)."""
    if not ciphertext:
        return None
    try:
        return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        # Log ONLY that decryption failed — never the ciphertext or plaintext.
        logger.warning("oauth token decryption failed: %s", type(exc).__name__)
        raise TokenDecryptionError("Stored token could not be decrypted.") from exc


def redact_token(value: str | None) -> str:
    """Render a token safely for any display/log context."""
    if not value:
        return ""
    return "[REDACTED]"
