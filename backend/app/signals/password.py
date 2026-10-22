"""Password / auth-hygiene signal module (§3.B).

All inputs here are USER-REPORTED and clearly labeled as such. Password reuse is
computed client-side; the server only receives a boolean per credential label.
Passkey/SIM-swap signals combine the curated provider table with self-reports.
"""
from __future__ import annotations

from app import events
from app.schemas import PasswordHygieneRequest, SecurityEventSchema

_REPORT_PROVENANCE = "User-reported auth hygiene (self-attested, not externally verified)."


def build_hygiene_events(
    *,
    user_id: str,
    payload: PasswordHygieneRequest,
    passkey_supported_by_provider: bool,
    provider_source: str | None = None,
) -> list[SecurityEventSchema]:
    out: list[SecurityEventSchema] = []
    account_id = payload.account_id

    reused = [item for item in payload.reused_credentials if item.reused]
    if reused:
        severity = min(0.8, 0.45 + 0.1 * (len(reused) - 1))
        out.append(
            SecurityEventSchema(
                event_id=events.new_event_id(),
                user_id=user_id,
                account_id=account_id,
                event_type=events.PASSWORD_REUSE,
                exposure_type=None,
                severity=severity,
                confidence=0.6,  # self-reported => moderate confidence
                source="user_report",
                status="FINDING",
                evidence={
                    "verified": False,
                    "report_type": "self_reported",
                    "reused_credential_count": len(reused),
                    "reused_labels": [item.label for item in reused][:20],
                },
                metadata={"reused_labels": [item.label for item in reused][:20]},
                provenance=_REPORT_PROVENANCE,
            )
        )

    if not payload.mfa_enabled:
        out.append(
            SecurityEventSchema(
                event_id=events.new_event_id(),
                user_id=user_id,
                account_id=account_id,
                event_type=events.MFA_MISSING,
                exposure_type=None,
                severity=0.6,
                confidence=0.6,
                source="user_report",
                status="FINDING",
                evidence={
                    "verified": False,
                    "report_type": "self_reported",
                    "mfa_enabled": False,
                    # None means "no method reported" — not a guessed method.
                    "mfa_method": None,
                },
                metadata={"mfa_method": None},
                provenance=_REPORT_PROVENANCE,
            )
        )

    if passkey_supported_by_provider and not payload.passkey_enabled:
        out.append(
            SecurityEventSchema(
                event_id=events.new_event_id(),
                user_id=user_id,
                account_id=account_id,
                event_type=events.PASSKEY_READY_NOT_ENABLED,
                exposure_type=None,
                severity=0.35,
                confidence=0.8,
                source="curated_provider_table",
                status="FINDING",
                evidence={
                    "verified": True,
                    "provider": payload.provider,
                    "provider_source": provider_source,
                    "passkey_supported": True,
                    "passkey_enabled": False,
                },
                metadata={
                    "provider": payload.provider,
                    "provider_source": provider_source,
                },
                provenance=(
                    f"Curated provider table indicates passkeys are available for "
                    f"{payload.provider or 'this service'}, but the user reports not enabling them."
                ),
            )
        )

    if payload.sms_otp_recovery:
        out.append(
            SecurityEventSchema(
                event_id=events.new_event_id(),
                user_id=user_id,
                account_id=account_id,
                event_type=events.SIM_SWAP_VULNERABLE,
                exposure_type=None,
                severity=0.5,
                confidence=0.6,
                source="user_report",
                status="FINDING",
                evidence={
                    "verified": False,
                    "report_type": "self_reported",
                    "recovery_method": "sms_otp",
                },
                metadata={"recovery_method": "sms_otp"},
                provenance=(
                    "User reports SMS one-time codes as a recovery method; SMS is "
                    "vulnerable to SIM swapping (see curated knowledge graph)."
                ),
            )
        )

    if payload.push_bombing_reported:
        out.append(
            SecurityEventSchema(
                event_id=events.new_event_id(),
                user_id=user_id,
                account_id=account_id,
                event_type=events.PUSH_BOMBING_REPORTED,
                exposure_type=None,
                severity=0.55,
                confidence=0.5,
                source="user_report",
                status="FINDING",
                evidence={
                    "verified": False,
                    "report_type": "self_reported",
                    "report": "repeated_unexpected_mfa_push_prompts",
                },
                metadata={},
                provenance="User reports repeated unexpected MFA push prompts (push-bombing).",
            )
        )

    return out