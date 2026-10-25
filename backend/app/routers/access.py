"""Access-review endpoints (Feature F, §9.F).

Authorization model:

* Creating, removing, reviewing and REQUESTING the candidate scan are
  ORG_ADMIN-only. A member's only view is their OWN rows (GET /records) —
  the default role check below.
* Every record is organization-owned; asset resolution goes through
  ``assert_asset_in_org`` so another tenant's asset (or membership) is
  indistinguishable from a missing one (404), never a writable target.
* The candidate scan persists ONE aggregated ``ACCESS_REVIEW_NEEDED`` finding
  per affected asset with module replace semantics (repeat scans never stack
  duplicated findings — §10.6 provenance hygiene), and claims only what the
  data supports: these are ADMIN-DECLARED bookkeeping candidates, never
  observed grants or misuse claims.
"""
from __future__ import annotations

import datetime as dt
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app import audit
from app.config import Settings, get_settings
from app.db import get_db
from app.deps import get_current_membership, require_role
from app.engine import normalizer
from app.engine.entities import assert_asset_in_org, canonical_asset_id
from app.models import (
    AssetAccessRecord,
    AssetAccessRecordHistory,
    Membership,
    OrgAsset,
    SecurityEvent,
)
from app.schemas import AccessRecordCreate, OrgRole, SecurityEventSchema
from app.signals.access_audit import (
    SOURCE_LABEL,
    annotate_record,
    build_access_events,
    member_ref,
)

router = APIRouter(prefix="/api/access", tags=["access"])

ADMIN_ROLES = (OrgRole.ORG_ADMIN.value,)
ACCESS_EVENT_TYPES = ["ACCESS_REVIEW_NEEDED"]


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _replace_org_module_events(
    db: Session,
    org_id: str,
    user_id: str,
    account_id: str,
    event_types: list[str],
    schemas: list[SecurityEventSchema],
) -> list[Any]:
    """Org-scoped delete-then-replace, mirroring ``normalizer.replace_module_events``.

    The normalizer's replace keys deletion on the ACTING user; access-review
    candidates are an ORGANIZATION's bookkeeping, so prior findings for the
    same module+asset are replaced regardless of which admin generated them
    (per §10.6 dedupe). The earliest first_seen survives, like every module.
    Persist scope (org_id/asset_id) is then resolved from ``user_id`` — the
    acting admin's own membership, never a client-sent claim.
    """
    prior_rows = db.scalars(
        select(SecurityEvent).where(
            SecurityEvent.org_id == org_id,
            SecurityEvent.account_id == account_id,
            SecurityEvent.event_type.in_(event_types),
        )
    ).all()
    prior: dict[tuple[str, str], Any] = {}
    for row in prior_rows:
        seen = row.first_seen or row.detected_at
        key = (row.account_id, row.event_type)
        current = prior.get(key)
        if current is None or seen < current:
            prior[key] = seen
    if prior_rows:
        for row in prior_rows:
            db.delete(row)
        db.commit()
    return normalizer.persist_events(db, schemas, prior_first_seen=prior)


def _load_records(db: Session, org_id: str) -> list[AssetAccessRecord]:
    return list(
        db.scalars(
            select(AssetAccessRecord)
            .where(AssetAccessRecord.org_id == org_id)
            .options(
                joinedload(AssetAccessRecord.asset),
                joinedload(AssetAccessRecord.membership).joinedload(Membership.user),
            )
            .order_by(AssetAccessRecord.granted_at.desc())
        ).unique().all()
    )


def _serialize(record: AssetAccessRecord, *, include_member: bool = True) -> dict[str, Any]:
    member: Membership | None = record.membership
    return {
        "id": record.id,
        "membership_id": record.membership_id,
        "member_email": getattr(getattr(member, "user", None), "email", None) if include_member else None,
        "member_role": getattr(member, "role", None),
        "member_active": getattr(member, "is_active", None),
        "asset_id": record.asset.asset_id if record.asset else None,
        "asset_label": record.asset.label if record.asset else None,
        "level": record.level,
        "provenance": record.provenance,
        "status": record.status,
        "granted_at": record.granted_at.isoformat() if record.granted_at else None,
        "last_reviewed_at": record.last_reviewed_at.isoformat() if record.last_reviewed_at else None,
        "created_at": record.created_at.isoformat() if record.created_at else None,
    }


@router.get("/records")
def list_records(
    membership: Annotated[Membership, Depends(get_current_membership)],
    db: Session = Depends(get_db),
) -> dict:
    is_admin = membership.role in ADMIN_ROLES
    records = _load_records(db, membership.org_id)
    if not is_admin:
        records = [r for r in records if r.membership_id == membership.id]
    return {
        "count": len(records),
        "scope": "org" if is_admin else "own",
        "records": [_serialize(r, include_member=is_admin) for r in records],
    }


@router.post("/records", status_code=status.HTTP_201_CREATED)
def create_record(
    payload: AccessRecordCreate,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> dict:
    asset = assert_asset_in_org(db, membership.org_id, payload.asset_id)
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found in this organization.",
        )
    target = db.scalar(
        select(Membership).where(
            Membership.id == payload.membership_id, Membership.org_id == membership.org_id
        )
    )
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="membership_id is not a member of this organization.",
        )
    duplicate = db.scalar(
        select(AssetAccessRecord).where(
            AssetAccessRecord.org_id == membership.org_id,
            AssetAccessRecord.membership_id == payload.membership_id,
            AssetAccessRecord.org_asset_id == asset.id,
            AssetAccessRecord.status == "ACTIVE",
        )
    )
    if duplicate is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This member already has a declared access record for this asset.",
        )

    record = AssetAccessRecord(
        org_id=membership.org_id,
        org_asset_id=asset.id,
        membership_id=payload.membership_id,
        level=payload.level,
        provenance="ADMIN_DECLARED",
        status="ACTIVE",
        granted_at=_utcnow(),
        last_reviewed_at=None,
    )
    db.add(record)
    db.flush()  # need record.id for the history row
    db.add(AssetAccessRecordHistory(
        record_id=record.id,
        org_id=membership.org_id,
        actor_user_id=membership.user_id,
        method="CREATED",
        detail={"asset_id": canonical_asset_id(payload.asset_id), "level": payload.level},
    ))
    db.commit()
    db.refresh(record)
    audit.record(
        db, action="access.record_created", user_id=membership.user_id,
        detail={
            "org_id": membership.org_id,
            "record_id": record.id,
            "asset_id": canonical_asset_id(payload.asset_id),
            "membership_ref": member_ref(target),
            "level": payload.level,
        },
    )
    return _serialize(record)


@router.delete("/records/{record_id}", status_code=status.HTTP_200_OK)
def remove_record(
    record_id: str,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    record = db.scalar(
        select(AssetAccessRecord).where(
            AssetAccessRecord.id == record_id, AssetAccessRecord.org_id == membership.org_id
        )
    )
    if record is None:
        # A record of ANOTHER tenant is indistinguishable from a missing one.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access record not found.")
    if record.status == "REMOVED":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Access record was already removed.")
    record.status = "REMOVED"
    record.updated_at = _utcnow()
    db.add(AssetAccessRecordHistory(
        record_id=record.id,
        org_id=membership.org_id,
        actor_user_id=membership.user_id,
        method="REMOVED",
        detail={"asset_id": record.asset.asset_id if record.asset else None, "level": record.level},
    ))
    db.commit()
    audit.record(
        db, action="access.record_removed", user_id=membership.user_id,
        detail={"org_id": membership.org_id, "record_id": record.id},
    )
    return {"id": record.id, "status": record.status, "removed_at": record.updated_at.isoformat()}


@router.post("/records/{record_id}/review", status_code=status.HTTP_200_OK)
def review_record(
    record_id: str,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    record = db.scalar(
        select(AssetAccessRecord).where(
            AssetAccessRecord.id == record_id, AssetAccessRecord.org_id == membership.org_id
        )
    )
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access record not found.")
    if record.status != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Only an ACTIVE record can be reviewed.",
        )
    stamp = _utcnow()
    record.last_reviewed_at = stamp
    record.updated_at = stamp
    db.add(AssetAccessRecordHistory(
        record_id=record.id,
        org_id=membership.org_id,
        actor_user_id=membership.user_id,
        method="REVIEWED",
        detail={"asset_id": record.asset.asset_id if record.asset else None, "level": record.level},
    ))
    db.commit()
    audit.record(
        db, action="access.record_reviewed", user_id=membership.user_id,
        detail={"org_id": membership.org_id, "record_id": record.id},
    )
    return {
        "id": record.id,
        "status": record.status,
        "last_reviewed_at": stamp.isoformat(),
    }


@router.get("/candidates")
def access_candidates(
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> dict:
    """Scan the org's declared access for review candidates and persist the
    per-asset ACCESS_REVIEW_NEEDED findings (module replace, per asset)."""
    interval_days = settings.access_review_interval_days
    now = _utcnow()
    records = _load_records(db, membership.org_id)

    by_asset: dict[str, list[dict[str, Any]]] = {}
    asset_meta: dict[str, OrgAsset] = {}
    for record in records:
        candidate = annotate_record(record, now=now, interval_days=interval_days)
        if candidate is None:
            continue
        key = record.asset.asset_id if record.asset else record.org_asset_id
        by_asset.setdefault(key, []).append(candidate)
        asset_meta[key] = record.asset

    events_for_replace: dict[str, list[SecurityEventSchema]] = {}
    payload_assets: list[dict[str, Any]] = []
    for asset_id, candidates in sorted(by_asset.items()):
        asset = asset_meta.get(asset_id)
        asset_events = build_access_events(
            user_id=membership.user_id,
            asset_id=asset_id,
            asset_label=getattr(asset, "label", None),
            criticality=getattr(asset, "criticality", None),
            candidates=candidates,
            interval_days=interval_days,
        )
        events_for_replace[asset_id] = asset_events
        payload_assets.append({
            "asset_id": asset_id,
            "asset_label": getattr(asset, "label", None),
            "criticality": getattr(asset, "criticality", None),
            "candidate_count": len(candidates),
            "severity": max((float(c["severity"]) for c in candidates), default=0.0),
            "candidates": candidates,
        })

    stored: list[dict[str, Any]] = []
    for asset_id, asset_events in events_for_replace.items():
        rows = _replace_org_module_events(
            db, membership.org_id, membership.user_id, asset_id, ACCESS_EVENT_TYPES, asset_events
        )
        stored.extend(normalizer.schema_to_response(normalizer.to_schema(row)) for row in rows)

    # Module replace is not only for assets that STILL have candidates: a
    # candidate that was resolved since the last generation (member returned,
    # review stamped, access removed) must clear the stale finding — a
    # persisted ACCESS_REVIEW_NEEDED for an asset that no longer has any
    # candidate would be a dishonest leftover.
    prior_accounts = set(db.scalars(
        select(SecurityEvent.account_id).where(
            SecurityEvent.org_id == membership.org_id,
            SecurityEvent.event_type.in_(ACCESS_EVENT_TYPES),
        ).distinct()
    ).all())
    for resolved in sorted(prior_accounts - set(events_for_replace.keys())):
        _replace_org_module_events(
            db, membership.org_id, membership.user_id, resolved, ACCESS_EVENT_TYPES, []
        )
    db.commit()

    audit.record(
        db, action="access.candidates_generated", user_id=membership.user_id,
        detail={
            "org_id": membership.org_id,
            "source": SOURCE_LABEL,
            "assets_with_candidates": len(payload_assets),
            "event_rows": len(stored),
        },
    )
    return {
        "review_interval_days": interval_days,
        "generated_at": now.isoformat(),
        "assets": payload_assets,
        "events": stored,
        "note": (
            "Candidates come from administrator-declared access records only; "
            "a member with no declaration can still hold real access that CRIX "
            "does not know about."
        ),
    }
