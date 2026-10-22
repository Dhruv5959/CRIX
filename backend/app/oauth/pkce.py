"""PKCE + state helpers for the authorization-code flow.

``state`` prevents CSRF and ties the callback to the initiating browser;
``code_verifier`` proves the callback comes from the same client that started
the flow (RFC 7636). Both are stored server-side for the short window between
authorize and callback, then consumed exactly once.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass

# In-flight OAuth attempts. Keyed by state; each entry is single-use. This is
# short-lived request data (not user data), so an in-process table is fine for
# the single-process dev/demo deployment. A multi-process deployment would back
# this with the DB or a shared cache.
_PENDING: dict[str, "PendingAuth"] = {}
_TTL_SECONDS = 600


@dataclass(frozen=True)
class PendingAuth:
    provider: str
    user_id: str
    code_verifier: str
    created_at: float


def new_state() -> str:
    return secrets.token_urlsafe(32)


def new_code_verifier() -> str:
    return secrets.token_urlsafe(64)


def code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def put_pending(state: str, provider: str, user_id: str, code_verifier: str) -> None:
    import time

    _purge()
    _PENDING[state] = PendingAuth(provider, user_id, code_verifier, time.time())


def take_pending(state: str) -> PendingAuth | None:
    """Pop the pending attempt for ``state`` (single use)."""
    import time

    _purge()
    pending = _PENDING.pop(state, None)
    if pending is None:
        return None
    if time.time() - pending.created_at > _TTL_SECONDS:
        return None
    return pending


def _purge() -> None:
    import time

    cutoff = time.time() - _TTL_SECONDS
    for key in [k for k, v in _PENDING.items() if v.created_at <= cutoff]:
        _PENDING.pop(key, None)


def clear() -> None:
    """Test helper."""
    _PENDING.clear()
