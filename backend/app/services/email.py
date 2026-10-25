"""Outbound transactional email for password reset / verification.

Two transports, chosen by configuration:

* Development (no SMTP configured): the message is written to
  ``backend/artifacts/outbox/`` — a local dev mailbox. This keeps reset
  tokens OUT of application logs (§14) while remaining usable locally.
* Production can use Resend's HTTPS API (required by the Render Free Blueprint)
  or SMTP on a paid host. Settings validation refuses to start without the
  selected provider's credentials.

Only the transport label is returned to callers/audit — never the token.
"""
from __future__ import annotations

import datetime as dt
import smtplib
from email.message import EmailMessage
from pathlib import Path

import httpx

from app.config import Settings

_OUTBOX = Path(__file__).resolve().parents[2] / "artifacts" / "outbox"
_RESEND_EMAILS_URL = "https://api.resend.com/emails"


class EmailDeliveryError(RuntimeError):
    """A non-sensitive, caller-safe transactional email delivery failure."""


def _build_message(*, to: str, subject: str, body: str, settings: Settings) -> EmailMessage:
    message = EmailMessage()
    message["From"] = settings.email_from
    message["To"] = to
    message["Subject"] = subject
    # Use 8bit so the token/URL is not quoted-printable encoded in the dev outbox.
    message.set_content(body, cte="8bit")
    return message


def send_email(*, to: str, subject: str, body: str, settings: Settings) -> str:
    """Deliver an email. Returns a transport label for audit (never the token)."""
    if settings.email_provider == "resend":
        if not settings.resend_api_key:
            raise EmailDeliveryError("Email delivery is temporarily unavailable.")
        try:
            response = httpx.post(
                _RESEND_EMAILS_URL,
                headers={
                    "Authorization": f"Bearer {settings.resend_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": settings.email_from,
                    "to": [to],
                    "subject": subject,
                    "text": body,
                },
                timeout=15.0,
            )
        except httpx.HTTPError as exc:
            # Do not expose provider exceptions, response bodies, recipient
            # addresses, or the credential through API responses or audit logs.
            raise EmailDeliveryError("Email delivery is temporarily unavailable.") from exc
        if not 200 <= response.status_code < 300:
            raise EmailDeliveryError("Email delivery is temporarily unavailable.")
        return "resend"

    message = _build_message(to=to, subject=subject, body=body, settings=settings)

    if settings.email_provider == "smtp" and settings.smtp_host:
        # Explicitly configured SMTP wins in every environment (dev too), so
        # production behavior can be exercised locally before the real deploy.
        try:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
                if settings.smtp_start_tls:
                    server.starttls()
                if settings.smtp_user:
                    server.login(settings.smtp_user, settings.smtp_password)
                server.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            # Provider error bodies can echo recipients and configuration.
            # Keep them out of API responses and audit details.
            raise EmailDeliveryError("Email delivery is temporarily unavailable.") from exc
        return "smtp"

    if settings.is_production:
        # Defense in depth: assert_production_safe already fails startup
        # without the selected provider, so reaching this line means config was mutated at
        # runtime. Failing loudly beats silently swallowing a reset link.
        raise RuntimeError(
            "Transactional email provider is not configured; cannot send email in production."
        )

    _OUTBOX.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    path = _OUTBOX / f"{stamp}-{to.replace('@', '_at_')}.eml"
    path.write_text(message.as_string(), encoding="utf-8")
    return "dev-outbox"
