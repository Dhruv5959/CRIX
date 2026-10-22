"""Minimal RFC 6238 TOTP implementation (no external dependency).

Used for CRIX's own optional 2FA. Secrets are base32-encoded; codes are
6 digits, 30-second period, SHA-1 (the widely interoperable default).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time

_DIGITS = 6
_PERIOD = 30
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def generate_secret(length: int = 20) -> str:
    raw = secrets.token_bytes(length)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    return base64.b32decode(padded, casefold=True)


def _hotp(secret: bytes, counter: int) -> str:
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** _DIGITS)).zfill(_DIGITS)


def code_at(secret: str, timestamp: float | None = None) -> str:
    ts = timestamp if timestamp is not None else time.time()
    return _hotp(_decode_secret(secret), int(ts // _PERIOD))


def verify(secret: str, code: str, *, window: int = 1, timestamp: float | None = None) -> bool:
    """Verify a code allowing +/- ``window`` periods to tolerate clock skew."""
    if not code or not code.isdigit():
        return False
    ts = timestamp if timestamp is not None else time.time()
    counter = int(ts // _PERIOD)
    secret_bytes = _decode_secret(secret)
    for offset in range(-window, window + 1):
        if hmac.compare_digest(_hotp(secret_bytes, counter + offset), code):
            return True
    return False


def provisioning_uri(secret: str, email: str, issuer: str = "CRIX") -> str:
    from urllib.parse import quote

    label = quote(f"{issuer}:{email}")
    return (
        f"otpauth://totp/{label}?secret={secret}"
        f"&issuer={quote(issuer)}&algorithm=SHA1&digits={_DIGITS}&period={_PERIOD}"
    )