"""Access-audit engine (Feature F, §9.F) — review candidates for declared access.

Input: the organization's ACTIVE ``AssetAccessRecord`` rows (admin-declared
member→asset access), joined with their memberships. Output: per-ASSET review
candidates — each is one aggregated ``ACCESS_REVIEW_NEEDED`` finding bound to
that company asset, listed with per-member reason codes:

====================================  ========  ==============================
candidate reason                      code      severity
------------------------------------  --------  ------------------------------
member departed / deactivated         departed  0.70
ADMIN-level declared access           elevated  0.60
never re-confirmed within the         stale     0.45
        review interval (anchored at
        the last review, or at the
        grant when never reviewed;
        settings.access_review_interval_days)
====================================  ========  ==============================

Severity of the asset finding = the MAXIMUM candidate severity (suspicion
wins — the same precedence the phishing checker uses). A record can carry
several reasons at once; all are listed.

Honesty contract:

* These findings describe DECLARED access, not observed access: the data is
  admin-provided bookkeeping (SourceMode.USER_PROVIDED) and the provenance
  string on every event says exactly that.
* A REMOVED record is never a candidate (it was consciously retired; its
  history rows document when and by whom).
* A clean organization persists NOTHING — "no candidates" generates no
  findings, and repeat generation replaces the module's previous events
  (the router does the delete-then-replace) so candidates never stack.
* No numeric score is invented here: events feed the existing deterministic
  engine only (mapped into the ``permissions`` feature pool; see
  docs/RISK_MODEL.md §10).
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from app import events
from app.models import AssetAccessRecord, Membership
from app.schemas import EventStatus, SecurityEventSchema, SourceMode

SOURCE_LABEL = "access_audit"

DEPARTED_SEVERITY = 0.70
ELEVATED_SEVERITY = 0.60
STALE_SEVERITY = 0.45

DEFAULT_REVIEW_INTERVAL_DAYS = 90
# Evidence is capped by the shared sanitizer (4096 chars): bound the member
# list per asset and LABEL the cap, exactly like the repo scanner does.
_CANDIDATES_IN_EVIDENCE = 12

_AWARE = dt.timezone.utc


def _aware(moment: dt.datetime) -> dt.datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=_AWARE)
    return moment


def member_ref(membership: Membership | None) -> str:
    """Stable, non-secret handle for a member inside event evidence.

    Work-email identities are the platform norm for account ids, but a
    review-candidate list may outlive the person: the reference is the
    membership id, which the admin UI resolves. No free-text PII beyond that.
    """
    if membership is None:
        return "unknown-member"
    return f"member:{membership.id[:12]}"


def annotate_record(
    record: AssetAccessRecord,
    *,
    now: dt.datetime,
    interval_days: int,
) -> dict[str, Any] | None:
    """One record → one candidate dict (or None when nothing needs review).

    Precedence is additive: a record contributes its maximum severity and
    EVERY reason that fired (a departed ADMIN is both departed and elevated).
    """
    if (record.status or "ACTIVE") != "ACTIVE":
        return None
    level = (record.level or "VIEW").upper()
    member = record.membership
    reasons: list[dict[str, Any]] = []
    severity = 0.0

    if member is not None and not member.is_active:
        severity = max(severity, DEPARTED_SEVERITY)
        reasons.append({
            "code": "departed",
            "severity": DEPARTED_SEVERITY,
            "days_since_review": _days_since(record.last_reviewed_at, now),
        })
    if level == "ADMIN":
        severity = max(severity, ELEVATED_SEVERITY)
        reasons.append({
            "code": "elevated",
            "severity": ELEVATED_SEVERITY,
            "days_since_review": _days_since(record.last_reviewed_at, now),
        })
    # Stale anchors at the LAST REVIEW, or (when never reviewed) at the
    # GRANT itself: a declaration made today already satisfies its interval
    # requirement; it becomes a review candidate when the interval since
    # that anchor elapses without a re-confirmation.
    reference = record.last_reviewed_at or (
        _aware(record.granted_at) if record.granted_at else None
    )
    stale = _stale_reason(reference, now, interval_days)
    if stale is not None:
        severity = max(severity, STALE_SEVERITY)
        reasons.append({"code": "stale", "severity": STALE_SEVERITY, **stale})

    if not reasons:
        return None
    return {
        "record_id": record.id,
        "membership_ref": member_ref(member),
        "membership_id": record.membership_id,
        "level": level,
        "severity": round(min(max(severity, 0.0), 1.0), 4),
        "reasons": reasons,
        "granted_at": record.granted_at.isoformat() if record.granted_at else None,
        "last_reviewed_at": record.last_reviewed_at.isoformat() if record.last_reviewed_at else None,
    }


def _days_since(moment: dt.datetime | None, now: dt.datetime) -> int | None:
    if moment is None:
        return None
    return max(0, (now - _aware(moment)).days)


def _stale_reason(anchor: dt.datetime | None, now: dt.datetime, interval_days: int) -> dict[str, Any] | None:
    """Stale = the re-confirmation interval has elapsed since ``anchor``.

    ``anchor`` is the record's last review, or its grant when never reviewed
    (the caller passes ``None`` only if the row has no timestamps at all —
    then it can be nothing but honestly unanchored, hence stale).
    """
    if anchor is None:
        return {"age_days": None, "note": f"no review anchor recorded (review interval {interval_days} days)"}
    age = _days_since(anchor, now)
    if age > interval_days:
        return {"age_days": age, "note": f"not re-confirmed for {age} days (review interval {interval_days} days)"}
    return None


# --------------------------------------------------------------------------- #
# Event building (one aggregated finding per asset, module replace semantics)
# --------------------------------------------------------------------------- #

def build_access_events(
    *,
    user_id: str,
    asset_id: str,
    asset_label: str | None,
    criticality: int | None,
    candidates: list[dict[str, Any]],
    interval_days: int,
) -> list[SecurityEventSchema]:
    """Candidates for ONE asset → at most ONE ACCESS_REVIEW_NEEDED finding."""
    if not candidates:
        return []
    severity = max(float(c["severity"]) for c in candidates)
    evidence_candidates = list(candidates[:_CANDIDATES_IN_EVIDENCE])
    reason_codes = sorted({r["code"] for c in candidates for r in c["reasons"]})
    return [
        SecurityEventSchema(
            event_id=events.new_event_id(),
            user_id=user_id,
            account_id=asset_id,
            event_type=events.ACCESS_REVIEW_NEEDED,
            exposure_type=None,
            severity=round(min(max(severity, 0.0), 1.0), 4),
            confidence=0.7,
            source=SOURCE_LABEL,
            source_mode=SourceMode.USER_PROVIDED,
            status=EventStatus.FINDING,
            evidence={
                "target_asset_id": asset_id,
                "asset_label": (asset_label or asset_id)[:120],
                "asset_criticality": criticality,
                "candidate_count": len(candidates),
                "candidates_in_evidence_capped": len(evidence_candidates) < len(candidates),
                "candidates": evidence_candidates,
                "reason_code_legend": {
                    "departed": "member has left the organization or was deactivated",
                    "elevated": "ADMIN-level access to this asset",
                    "stale": "declaration not re-confirmed within the review interval",
                },
                "review_interval_days": interval_days,
                "provenance_note": (
                    "Candidate list reflects ADMIN-DECLARED access bookkeeping; "
                    "CRIX never observed these grants in any identity provider."
                ),
            },
            metadata={
                "target_asset_id": asset_id,
                "reason_codes": reason_codes,
                "candidate_count": len(candidates),
            },
            provenance=(
                "Access-review candidates are derived from administrator-declared "
                "member→asset access records; they are prioritization hints, "
                "neither claims of misuse nor observed grants."
            ),
        )
    ]
