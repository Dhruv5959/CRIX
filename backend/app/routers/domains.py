"""Company domain & email-security posture endpoints (§7.D).

Authorization model:

* Registration, ownership refresh, TXT verification and CHECKS are
  ORG_ADMIN-only. A member cannot make CRIX scan any host: the domain must be
  a registered company asset of *their* organization AND pass the DNS TXT
  ownership challenge before any outbound check runs.
* Every asset lookup uses `assert_asset_in_org` (same-org canonical identity —
  another tenant's domain is indistinguishable from a missing one, 404).
* The outbound-check rate limit is keyed **per organization + domain**, not
  per client IP, so one admin cannot burn a shared budget for everyone.

Provenance: DoH/TLS observations are REAL; the domain asset itself is
USER_PROVIDED (admin entered it). Ownership details (token hash, issue /
verification timestamps) live on `OrgAsset.metadata_json` — no new table for
this feature.
"""
from __future__ import annotations

import datetime as dt
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.config import Settings, get_settings
from app.db import get_db
from app.deps import get_current_membership, require_role
from app.engine import normalizer
from app.engine.entities import assert_asset_in_org, canonical_asset_id
from app.models import Membership, OrgAsset
from app.rate_limit import domain_check_limiter, enforce_key
from app.signals.domain_posture import (
    _probe_https,
    build_domain_events,
    check_dkim,
    check_dmarc,
    check_spf,
    is_well_formed_domain,
    new_ownership_token,
    token_hash,
    verify_ownership_txt,
)
from app.schemas import (
    DomainChecksRequest,
    DomainOwnershipVerifyRequest,
    DomainRegisterRequest,
    OrgRole,
)

router = APIRouter(prefix="/api/domains", tags=["domains"])

ADMIN_ROLES = (OrgRole.ORG_ADMIN.value,)
_DOMAIN_EVENT_TYPES = ["EMAIL_AUTH_WEAKNESS", "TLS_POSTURE_WEAK"]


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(value: dt.datetime | None) -> str | None:
    return value.isoformat() if value else None


def _get_domain_asset(db: Session, org_id: str, asset_id: str) -> OrgAsset:
    asset = assert_asset_in_org(db, org_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Domain asset not found.")
    if (asset.asset_type or "").upper() != "DOMAIN":
        raise HTTPException(status_code=404, detail="Asset is not a registered domain.")
    return asset


def _ownership(meta: dict) -> dict:
    return {
        "challenge_issued": bool(meta.get("ownership_token_hash")),
        "verified": bool(meta.get("ownership_verified_at")),
        "verified_at": meta.get("ownership_verified_at"),
        "challenge_issued_at": meta.get("ownership_issued_at"),
    }


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register_domain(
    payload: DomainRegisterRequest,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
) -> dict:
    domain = payload.domain.strip().lower().rstrip(".")
    if not is_well_formed_domain(domain):
        raise HTTPException(
            status_code=422,
            detail="Enter a valid registrable domain (e.g. example.com; no URLs or paths).",
        )
    canonical = canonical_asset_id(domain)
    if assert_asset_in_org(db, membership.org_id, canonical) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This domain (or its canonical form) is already registered in this organization.",
        )
    verify_value = new_ownership_token()
    asset = OrgAsset(
        org_id=membership.org_id,
        asset_id=canonical,
        asset_type="DOMAIN",
        label=payload.label.strip() or canonical,
        service_name=None,
        criticality=payload.criticality,
        source_mode="USER_PROVIDED",
        metadata_json={
            "ownership_token_hash": token_hash(verify_value),
            "ownership_issued_at": _iso(_utcnow()),
        },
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    audit.record(
        db, action="domain.registered", user_id=membership.user_id,
        detail={"org_id": membership.org_id, "asset_id": asset.asset_id},
    )
    return {
        "asset_id": asset.asset_id,
        "asset_type": asset.asset_type,
        "label": asset.label,
        "criticality": asset.criticality,
        "ownership": _ownership(asset.metadata_json),
        # Shown exactly once; only the SHA-256 hash is stored anywhere.
        "verify_token": verify_value,
        "verify_instructions": (
            f"Create a DNS TXT record on {canonical} with the EXACT value below."
            " Publish it, then verify from this screen."
        ),
    }


@router.get("")
def list_domains(
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
) -> dict:
    """Registered domains of THIS organization with their ownership state."""
    domains = [
        asset
        for asset in db.scalars(
            select(OrgAsset).where(OrgAsset.org_id == membership.org_id)
        ).all()
        if (asset.asset_type or "").upper() == "DOMAIN"
    ]
    return {
        "domains": [
            {
                "asset_id": asset.asset_id,
                "label": asset.label,
                "criticality": asset.criticality,
                "ownership": _ownership(asset.metadata_json or {}),
            }
            for asset in domains
        ],
        "count": len(domains),
    }


@router.post("/{asset_id}/ownership/verify")
def verify_ownership(
    asset_id: str,
    payload: DomainOwnershipVerifyRequest,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> dict:
    asset = _get_domain_asset(db, membership.org_id, asset_id)
    meta = dict(asset.metadata_json or {})
    expect_hash = meta.get("ownership_token_hash")
    if not expect_hash:
        raise HTTPException(status_code=409, detail="No ownership challenge is pending for this domain.")
    issued_at = meta.get("ownership_issued_at")
    ttl = settings.domain_ownership_token_ttl_minutes
    if issued_at:
        try:
            age_minutes = (
                dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(issued_at)
            ).total_seconds() / 60
        except (TypeError, ValueError):
            age_minutes = None
        if age_minutes is not None and age_minutes > ttl:
            raise HTTPException(
                status_code=409,
                detail=(
                    "The ownership challenge expired. Request a new one "
                    "(ownership/refresh) and publish the fresh TXT value."
                ),
            )
    verified, reason = verify_ownership_txt(asset.asset_id, expect_hash, settings)
    if verified is None:
        # The TXT lookup itself failed — never interpreted as ownership pass.
        return {"verified": False, "reason": reason, "retry_allowed": True}
    if verified:
        asset.metadata_json = {
            **meta,
            "ownership_verified_at": _iso(_utcnow()),
        }
        # One-use: the challenge is consumed by a successful verification.
        asset.metadata_json.pop("ownership_token_hash", None)
        asset.metadata_json.pop("ownership_issued_at", None)
        db.commit()
        audit.record(
            db, action="domain.ownership_verified", user_id=membership.user_id,
            detail={"org_id": membership.org_id, "asset_id": asset.asset_id},
        )
    return {"verified": bool(verified), "reason": reason, "ownership": _ownership(asset.metadata_json or {})}


@router.post("/{asset_id}/ownership/refresh")
def refresh_ownership(
    asset_id: str,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
) -> dict:
    """Issue a NEW challenge; the old (possibly leaked/published) value
    becomes useless immediately."""
    asset = _get_domain_asset(db, membership.org_id, asset_id)
    verify_value = new_ownership_token()
    asset.metadata_json = {
        **(asset.metadata_json or {}),
        "ownership_token_hash": token_hash(verify_value),
        "ownership_issued_at": _iso(_utcnow()),
    }
    db.commit()
    audit.record(
        db, action="domain.ownership_challenge_refreshed", user_id=membership.user_id,
        detail={"org_id": membership.org_id, "asset_id": asset.asset_id},
    )
    return {
        "asset_id": asset.asset_id,
        "ownership": _ownership(asset.metadata_json),
        "verify_token": verify_value,
        "verify_instructions": (
            f"Publish the NEW TXT value on {asset.asset_id}; the previous one is now invalid."
        ),
    }


@router.post("/{asset_id}/checks")
def run_domain_checks(
    asset_id: str,
    payload: DomainChecksRequest,
    request: Request,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> dict:
    """Run DNS + HTTPS posture checks for ONE owned, ownership-verified domain.

    Rate-limited per (org, domain); requires the DNS TXT ownership challenge.
    Findings are stored as the module's events (replacing earlier ones for the
    same domain) and returned with per-check status.
    """
    if not settings.domain_checks_enabled:
        raise HTTPException(status_code=503, detail="Domain checks are disabled")
    asset = _get_domain_asset(db, membership.org_id, asset_id)
    meta = dict(asset.metadata_json or {})
    if not meta.get("ownership_verified_at"):
        raise HTTPException(
            status_code=403,
            detail=(
                "Outbound checks are locked until the DNS TXT ownership challenge "
                "for this domain is verified (ownership/verify)."
            ),
        )
    domain = asset.asset_id
    enforce_key(
        domain_check_limiter,
        f"{membership.org_id}:{domain}",
        limit=settings.domain_check_rate_limit_per_minute,
    )

    results: list[dict] = [check_spf(domain, settings), check_dmarc(domain, settings)]
    results.append(check_dkim(domain, payload.dkim_selector, settings))
    results.append(_probe_https(domain, settings))
    hsts = results[-1].get("hsts")
    if isinstance(hsts, dict) and hsts.get("check") == "hsts":
        results.append(hsts)

    for result in results:
        result.setdefault("target", domain)

    events = build_domain_events(user_id=membership.user_id, asset_id=domain, results=results)
    rows = normalizer.replace_module_events(
        db, membership.user_id, domain, _DOMAIN_EVENT_TYPES, events
    )
    audit.record(
        db, action="domain.checks_run", user_id=membership.user_id,
        detail={
            "org_id": membership.org_id,
            "asset_id": domain,
            "defect_events": len(rows),
            "checks": [r["check"] for r in results],
        },
    )
    return {
        "asset_id": domain,
        "ownership": _ownership(meta),
        "checks": results,
        "events": [normalizer.schema_to_response(normalizer.to_schema(row)) for row in rows],
        "note": (
            "Defects are stored as findings; passes and unavailable checks are shown "
            "here only. Unavailable is not a pass: it means the check could not complete."
        ),
    }
