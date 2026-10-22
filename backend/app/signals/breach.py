"""Breach / exposure signal module (§3.A).

Real email-breach lookup through one of two live providers, chosen by
``CRIX_BREACH_EMAIL_PROVIDER``:

* ``xposedornot`` — the free XposedOrNot community API. No key and no signup, so
  this is what ``auto`` resolves to out of the box.
* ``hibp`` — the HIBP ``breachedaccount`` API. Richer (it reports which data
  classes leaked), but needs a paid key.

Both providers are normalized into the same events, and the provider that
actually answered is written to every event's ``source`` plus ``metadata``
(``provider``, ``provider_label``, ``checked_at``) so the UI can show it
verbatim rather than guessing.

Honesty rules enforced here:
* A provider failure is UNAVAILABLE — never a clean result, never a synthetic
  substitute, and never a silent fallback to the other provider (§7).
* XposedOrNot does not report which data classes leaked, so its findings carry
  no ``exposure_type`` at all. Claiming ``PASSWORD_ONLY`` would assert that a
  password leaked, which we simply do not know.
* Nothing here sets a risk score. These are observations; the deterministic
  engine in ``app/engine/risk.py`` is the only thing that scores (§8).

Simulated: session-cookie / MFA-bypass exposure scenarios — no real infostealer
database is available to a student project, so these are constructed by the user
and labeled SIMULATED everywhere.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from app import events
from app.config import Settings
from app.schemas import ExposureType, SecurityEventSchema, SourceMode
from app.signals.hibp import HIBPClient, HIBPUnavailable, classify_session_capability
from app.signals.xposedornot import (
    CHECKED_SAFE,
    FINDING,
    PROVIDER_KEY as XON_KEY,
    PROVIDER_LABEL as XON_LABEL,
    UNAVAILABLE,
    XposedOrNotClient,
)

PROVIDER_LABELS: dict[str, str] = {
    XON_KEY: XON_LABEL,
    "hibp": "Have I Been Pwned (breached account API)",
}

# Cap how many breach names we persist/render; the true total is kept separately.
MAX_BREACH_NAMES = 20


@dataclass(frozen=True)
class EmailBreachLookup:
    """One provider's verdict for one address, in a provider-neutral shape."""

    provider: str
    outcome: str  # FINDING | CHECKED_SAFE | UNAVAILABLE
    breach_names: list[str] = field(default_factory=list)
    # HIBP reports DataClasses, so it can say whether a breach plausibly leaked
    # session/auth material. XposedOrNot cannot; False then means "unknown".
    session_capable: bool = False
    data_classes_known: bool = True
    reason: str = ""
    checked_at: dt.datetime = field(
        default_factory=lambda: dt.datetime.now(dt.timezone.utc)
    )


# --------------------------------------------------------------------------- #
# Provider resolution
# --------------------------------------------------------------------------- #
def resolve_email_provider(settings: Settings) -> str:
    """Turn the configured preference into a concrete provider key."""
    preference = str(getattr(settings, "breach_email_provider", "auto") or "auto")
    preference = preference.strip().lower()
    if preference in PROVIDER_LABELS:
        return preference
    return "hibp" if bool(getattr(settings, "hibp_api_key", "")) else XON_KEY


def provider_label(provider: str) -> str:
    return PROVIDER_LABELS.get(provider, provider)


def _default_xon_client(settings: Settings) -> XposedOrNotClient:
    return XposedOrNotClient(
        base_url=settings.xposedornot_base_url,
        timeout=settings.xposedornot_timeout_seconds,
        per_second=settings.xposedornot_requests_per_second,
        per_hour=settings.xposedornot_requests_per_hour,
    )


# --------------------------------------------------------------------------- #
# The two lookups
# --------------------------------------------------------------------------- #
def lookup_email_breaches(
    email: str,
    *,
    settings: Settings,
    provider: str | None = None,
    hibp_client: HIBPClient | None = None,
    xon_client: XposedOrNotClient | None = None,
) -> EmailBreachLookup:
    """Ask exactly ONE provider and return its verdict.

    Passing a client pins that provider (which keeps the pre-existing tests, and
    seed_demo's deliberate offline path, working unchanged).
    """
    if provider is None:
        provider = "hibp" if hibp_client is not None else resolve_email_provider(settings)
    provider = str(provider).strip().lower()

    if provider == "hibp":
        return _lookup_hibp(email, hibp_client or HIBPClient(settings.hibp_api_key))
    if provider == XON_KEY:
        return _lookup_xon(email, xon_client or _default_xon_client(settings))
    return EmailBreachLookup(
        provider=provider,
        outcome=UNAVAILABLE,
        reason=f"Unknown breach provider {provider!r}; nothing was queried.",
    )


def _lookup_hibp(email: str, client: HIBPClient) -> EmailBreachLookup:
    checked_at = dt.datetime.now(dt.timezone.utc)
    try:
        breaches = client.breached_account(email)
    except HIBPUnavailable as exc:
        return EmailBreachLookup(
            "hibp", UNAVAILABLE, reason=str(exc), checked_at=checked_at
        )

    if not breaches:
        return EmailBreachLookup(
            "hibp",
            CHECKED_SAFE,
            reason="HIBP breachedaccount returned 404 (no breach found).",
            checked_at=checked_at,
        )

    names = [
        str(b.get("Name", "unknown")) if isinstance(b, dict) else str(b)
        for b in breaches
    ]
    return EmailBreachLookup(
        "hibp",
        FINDING,
        breach_names=names,
        session_capable=any(classify_session_capability(b) for b in breaches if isinstance(b, dict)),
        data_classes_known=True,
        checked_at=checked_at,
    )


def _lookup_xon(email: str, client: XposedOrNotClient) -> EmailBreachLookup:
    result = client.check_email(email)
    return EmailBreachLookup(
        provider=XON_KEY,
        outcome=result.outcome,
        breach_names=list(result.breaches),
        session_capable=False,
        # XON exposes breach names only — no data classes, no severity detail.
        data_classes_known=False,
        reason=result.reason,
    )


# --------------------------------------------------------------------------- #
# Event construction
# --------------------------------------------------------------------------- #
def check_breach(
    *,
    user_id: str,
    account_id: str,
    email: str,
    settings: Settings,
    simulated_exposure_type: ExposureType | None = None,
    simulated_mfa_bypass_capable: bool = False,
    client: HIBPClient | None = None,
    xon_client: XposedOrNotClient | None = None,
    provider: str | None = None,
) -> list[SecurityEventSchema]:
    """Produce normalized events for one account's breach/exposure check.

    ``client`` keeps its original meaning (an injected HIBP client, which also
    pins the HIBP provider); ``xon_client``/``provider`` were added for the
    XposedOrNot integration.
    """
    lookup = lookup_email_breaches(
        email,
        settings=settings,
        provider=provider,
        hibp_client=client,
        xon_client=xon_client,
    )

    out: list[SecurityEventSchema] = [_breach_event(user_id, account_id, lookup)]
    if lookup.outcome == FINDING:
        out.append(_identity_event(user_id, account_id, lookup))

    # --- simulated session-cookie exposure (§3.A) ---
    if simulated_exposure_type in (ExposureType.SESSION_ONLY, ExposureType.PASSWORD_AND_SESSION):
        severity = 0.9 if simulated_mfa_bypass_capable else 0.6
        out.append(
            SecurityEventSchema(
                event_id=events.new_event_id(),
                user_id=user_id,
                account_id=account_id,
                event_type=events.SESSION_EXPOSURE,
                exposure_type=simulated_exposure_type,
                severity=severity,
                confidence=0.5,
                source="simulated",
                source_mode=SourceMode.SIMULATED,
                status="FINDING",
                metadata={"mfa_bypass_capable": simulated_mfa_bypass_capable},
                provenance=(
                    "SIMULATED exposure scenario entered by the user. No real "
                    "infostealer/session database is consulted."
                ),
            )
        )

    return out


def _base_metadata(lookup: EmailBreachLookup) -> dict:
    """Fields every breach event carries, so the UI can show provider + time."""
    return {
        "provider": lookup.provider,
        "provider_label": provider_label(lookup.provider),
        "checked_at": lookup.checked_at.isoformat(),
    }


def _breach_event(
    user_id: str, account_id: str, lookup: EmailBreachLookup
) -> SecurityEventSchema:
    metadata = _base_metadata(lookup)

    if lookup.outcome == FINDING:
        count = len(lookup.breach_names)
        if not lookup.data_classes_known:
            exposure = None  # unknown, and we refuse to guess a data class
        elif lookup.session_capable:
            exposure = ExposureType.PASSWORD_AND_SESSION
        else:
            exposure = ExposureType.PASSWORD_ONLY
        metadata.update(
            {
                "breach_count": count,
                "breaches": lookup.breach_names[:MAX_BREACH_NAMES],
                "breaches_truncated": count > MAX_BREACH_NAMES,
                "session_capable_breach": lookup.session_capable,
                # Explicit marker: XON cannot say which data classes leaked.
                "exposed_data_classes": (
                    "reported" if lookup.data_classes_known else "UNAVAILABLE_THROUGH_PROVIDER"
                ),
            }
        )
        return SecurityEventSchema(
            event_id=events.new_event_id(),
            user_id=user_id,
            account_id=account_id,
            event_type=events.BREACH_EXPOSURE,
            exposure_type=exposure,
            severity=_breach_severity(count),
            confidence=0.95 if lookup.provider == "hibp" else 0.9,
            source=lookup.provider,
            source_mode=SourceMode.REAL,
            detected_at=lookup.checked_at,
            status="FINDING",
            metadata=metadata,
            provenance=(
                f"{provider_label(lookup.provider)} reported {count} indexed "
                "breach(es) for this address. Provider-reported observation; CRIX's "
                "risk engine decides the score."
            ),
        )

    if lookup.outcome == CHECKED_SAFE:
        metadata.update({"breach_count": 0, "breaches": []})
        return SecurityEventSchema(
            event_id=events.new_event_id(),
            user_id=user_id,
            account_id=account_id,
            event_type=events.BREACH_EXPOSURE,
            exposure_type=None,
            severity=0.0,
            # Slightly lower for XposedOrNot: its not-found body is also what a
            # malformed address gets, so a genuine negative is a little weaker
            # evidence than HIBP's dedicated 404.
            confidence=0.9 if lookup.provider == "hibp" else 0.8,
            source=lookup.provider,
            source_mode=SourceMode.REAL,
            detected_at=lookup.checked_at,
            status=CHECKED_SAFE,
            metadata=metadata,
            provenance=(
                f"{provider_label(lookup.provider)} reported no indexed breach for "
                "this address. Absence of a record is not proof the account is "
                "uncompromised."
            ),
        )

    # UNAVAILABLE — the provider could not be consulted.
    metadata.update(
        {
            "reason": lookup.reason or "Provider unavailable.",
            "breach_count": None,
        }
    )
    return SecurityEventSchema(
        event_id=events.new_event_id(),
        user_id=user_id,
        account_id=account_id,
        event_type=events.BREACH_EXPOSURE,
        exposure_type=None,
        severity=0.0,
        confidence=0.0,
        source=lookup.provider,
        source_mode=SourceMode.UNAVAILABLE,
        detected_at=lookup.checked_at,
        status=UNAVAILABLE,
        metadata=metadata,
        provenance=(
            f"{provider_label(lookup.provider)} could not be consulted "
            f"({lookup.reason or 'unknown reason'}). Recorded as UNAVAILABLE, never "
            "as safe."
        ),
    )


def _identity_event(
    user_id: str, account_id: str, lookup: EmailBreachLookup
) -> SecurityEventSchema:
    metadata = _base_metadata(lookup)
    metadata["breaches"] = lookup.breach_names[:MAX_BREACH_NAMES]
    metadata["breach_count"] = len(lookup.breach_names)
    return SecurityEventSchema(
        event_id=events.new_event_id(),
        user_id=user_id,
        account_id=account_id,
        event_type=events.IDENTITY_EXPOSED,
        exposure_type=None,
        severity=0.4,
        confidence=0.9 if lookup.provider == "hibp" else 0.85,
        source=lookup.provider,
        source_mode=SourceMode.REAL,
        detected_at=lookup.checked_at,
        status="FINDING",
        metadata=metadata,
        provenance=(
            f"Identity (email) appears in {provider_label(lookup.provider)}'s "
            "indexed breach data."
        ),
    )


def _breach_severity(breach_count: int) -> float:
    """More breaches => higher base severity, saturating at 0.85."""
    return min(0.85, 0.45 + 0.1 * max(0, breach_count - 1))