"""Outbound email for password reset / verification.

No SMTP is assumed to be configured for a student project. When SMTP is absent
we write the message to ``backend/artifacts/outbox/`` (a local dev mailbox).
This keeps reset tokens OUT of application logs (§14) while remaining usable
in local development. In production an SMTP transport must be configured.
"""
from __future__ import annotations

import datetime as dt
from email.message import EmailMessage
from pathlib import Path

from app.config import Settings

_OUTBOX = Path(__file__).resolve().parents[2] / "artifacts" / "outbox"


def send_email(*, to: str, subject: str, body: str, settings: Settings) -> str:
    """Deliver an email. Returns a transport label for audit (never the token)."""
    message = EmailMessage()
    message["From"] = "no-reply@crix.local"
    message["To"] = to
    message["Subject"] = subject
    # Use 8bit so the token/URL is not quoted-printable encoded in the dev outbox.
    message.set_content(body, cte="8bit")

    if settings.is_production:
        raise RuntimeError(
            "No SMTP transport configured. Set one before running in production."
        )

    _OUTBOX.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    path = _OUTBOX / f"{stamp}-{to.replace('@', '_at_')}.eml"
    path.write_text(message.as_string(), encoding="utf-8")
    return "dev-outbox"