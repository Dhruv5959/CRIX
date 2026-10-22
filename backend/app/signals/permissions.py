"""Permission auditor signal module (§3.D).

Manual entry only (no live OAuth enumeration, per §0.3). Every classification is
EXPLAINED against the curated taxonomy — never a black-box number. Unknown
permissions are reported as UNKNOWN, not guessed.
"""
from __future__ import annotations

import datetime as dt

from app import events
from app.data.loader import permissions_taxonomy
from app.schemas import PermissionAuditRequest, SecurityEventSchema

_SENSITIVITY_SEVERITY = {"low": 0.15, "medium": 0.4, "high": 0.7}


def classify_permission(permission: str) -> dict:
    """Return the taxonomy classification for a permission string."""
    taxonomy = permissions_taxonomy()
    needle = permission.strip().lower()
    # Exact match first, then substring match on the curated `match` tokens.
    for entry in taxonomy["permissions"]:
        if entry["match"].lower() == needle:
            return {
                "permission": permission,
                "matched": True,
                "category": entry["category"],
                "sensitivity": entry["sensitivity"],
                "rationale": entry["rationale"],
            }
    for entry in taxonomy["permissions"]:
        token = entry["match"].lower()
        if token and (token in needle or needle in token):
            return {
                "permission": permission,
                "matched": True,
                "category": entry["category"],
                "sensitivity": entry["sensitivity"],
                "rationale": entry["rationale"],
            }
    default = taxonomy["default"]
    return {
        "permission": permission,
        "matched": False,
        "category": default["category"],
        "sensitivity": default["sensitivity"],
        "rationale": default["rationale"],
    }


def build_permission_events(
    *, user_id: str, payload: PermissionAuditRequest
) -> tuple[list[SecurityEventSchema], list[dict]]:
    """Return (events, classification_report) for a permission audit request."""
    out: list[SecurityEventSchema] = []
    report: list[dict] = []
    taxonomy = permissions_taxonomy()
    stale_after = int(taxonomy["staleness"]["stale_after_days"])
    stale_factor = float(taxonomy["staleness"]["factor"])
    today = dt.date.today()

    for entry in payload.entries:
        classifications = [classify_permission(p) for p in entry.permissions]
        report.append(
            {
                "app_name": entry.app_name,
                "platform": entry.platform,
                "granted_at": entry.granted_at.isoformat() if entry.granted_at else None,
                "last_used_at": entry.last_used_at.isoformat() if entry.last_used_at else None,
                "permissions": classifications,
            }
        )

        high = [c for c in classifications if c["sensitivity"] == "high"]
        medium = [c for c in classifications if c["sensitivity"] == "medium"]
        if high or medium:
            base = max((_SENSITIVITY_SEVERITY[c["sensitivity"]] for c in high + medium), default=0.0)
            # More high-sensitivity permissions raise severity, saturating.
            base = min(0.9, base + 0.05 * max(0, len(high) - 1))
            stale = _is_stale(entry.last_used_at, today, stale_after)
            if stale:
                base = min(0.95, base * stale_factor)
            out.append(
                SecurityEventSchema(
                    event_id=events.new_event_id(),
                    user_id=user_id,
                    account_id=payload.account_id,
                    event_type=events.RISKY_PERMISSION_GRANTED,
                    exposure_type=None,
                    severity=round(base, 4),
                    confidence=0.7,
                    source="manual_entry",
                    status="FINDING",
                    metadata={
                        "app_name": entry.app_name,
                        "platform": entry.platform,
                        "high_sensitivity": [c["permission"] for c in high],
                        "medium_sensitivity": [c["permission"] for c in medium],
                        "rationales": {c["permission"]: c["rationale"] for c in high + medium},
                        "stale": stale,
                    },
                    provenance=(
                        "Manually entered third-party app permissions, classified "
                        "against the curated permission-sensitivity taxonomy."
                    ),
                )
            )
            if stale and high:
                out.append(
                    SecurityEventSchema(
                        event_id=events.new_event_id(),
                        user_id=user_id,
                        account_id=payload.account_id,
                        event_type=events.STALE_PERMISSION_GRANTED,
                        exposure_type=None,
                        severity=round(min(0.8, 0.4 * stale_factor), 4),
                        confidence=0.7,
                        source="manual_entry",
                        status="FINDING",
                        metadata={"app_name": entry.app_name, "last_used_at": entry.last_used_at.isoformat() if entry.last_used_at else None},
                        provenance=(
                            f"High-sensitivity grant with no recorded use for over "
                            f"{stale_after} days (unreviewed standing access)."
                        ),
                    )
                )

    return out, report


def _is_stale(last_used: dt.date | None, today: dt.date, stale_after_days: int) -> bool:
    if last_used is None:
        return True  # never used => treat as stale standing access
    return (today - last_used).days > stale_after_days