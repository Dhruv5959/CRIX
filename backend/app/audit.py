"""Audit logging with secret redaction (§14: secrets/tokens never in logs)."""
from __future__ import annotations

import re

from sqlalchemy.orm import Session

from app.models import AuditLog

# Keys whose values must never be persisted in audit detail.
_REDACT_KEYS = {
    "password", "new_password", "token", "access_token", "refresh_token",
    "authorization", "totp_secret", "totp_code", "secret", "api_key",
    "sha1_suffix", "hash_prefix", "csrf_token",
}
_BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9._\-]{10,}")


def redact(value: object) -> object:
    """Recursively strip anything that looks like a secret."""
    if isinstance(value, dict):
        return {
            key: ("[REDACTED]" if _is_sensitive_key(key) else redact(val))
            for key, val in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _JWT_RE.sub("[REDACTED-JWT]", _BEARER_RE.sub("[REDACTED-TOKEN]", value))
    return value


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in _REDACT_KEYS or any(token in lowered for token in ("password", "secret", "token"))


def record(
    db: Session,
    *,
    action: str,
    user_id: str | None = None,
    ip_address: str | None = None,
    detail: dict | None = None,
) -> AuditLog:
    entry = AuditLog(
        user_id=user_id,
        action=action,
        ip_address=ip_address,
        detail=redact(detail or {}),
    )
    db.add(entry)
    db.commit()
    return entry