"""Company asset and dependency management (§2, §7).

* Reads are available to every role.
* Writes (create/update/delete asset, declare/remove dependency) are
  ORG_ADMIN-only and are recorded in the audit log.
* Every query is scoped to the caller's ``org_id``; an id from another
  organization is indistinguishable from a missing one (404).
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.deps import get_current_membership, require_role
from app.engine.entities import assert_asset_in_org, canonical_asset_id
from app.engine.org_graph import (
    PROVENANCE_LABELS,
    RELATIONSHIP_SEMANTICS,
    canonical_relationship_type,
    supported_relationship_type_list,
)
from app.models import AssetDependency, Membership, OrgAsset
from app.schemas import (
    AssetDependencyCreate,
    AssetDependencyResponse,
    AssetDependencyUpdate,
    OrgAssetCreate,
    OrgAssetResponse,
    OrgAssetUpdate,
    OrgRole,
)

router = APIRouter(prefix="/api", tags=["assets"])

ADMIN_ROLES = (OrgRole.ORG_ADMIN.value,)


def _get_asset(db: Session, org_id: str, asset_id: str) -> OrgAsset:
    """Resolve an asset by stable id, **within this organization only**.

    The lookup canonicalises both sides (URL/email/domain normalisation), so the
    same repository or work address always maps to the same asset, while an id
    belonging to another tenant is indistinguishable from a missing one (404).
    """
    asset = assert_asset_in_org(db, org_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    return asset


def _get_dependency(db: Session, org_id: str, dependency_id: str) -> AssetDependency:
    """Resolve one declared relationship **within this organization only**.

    A dependency id from another tenant is indistinguishable from a missing
    one (404) — the error never reveals another organization's data.
    """
    edge = db.scalar(
        select(AssetDependency).where(
            AssetDependency.id == dependency_id, AssetDependency.org_id == org_id
        )
    )
    if edge is None:
        raise HTTPException(status_code=404, detail="Dependency not found.")
    return edge


def _validate_owner(db: Session, org_id: str, membership_id: str | None) -> None:
    if membership_id is None:
        return
    owner = db.scalar(
        select(Membership).where(Membership.id == membership_id, Membership.org_id == org_id)
    )
    if owner is None:
        raise HTTPException(
            status_code=422, detail="owner_membership_id is not a member of this organization."
        )


@router.get("/assets", response_model=list[OrgAssetResponse])
def list_assets(
    membership: Annotated[Membership, Depends(get_current_membership)],
    db: Session = Depends(get_db),
) -> list[OrgAsset]:
    return list(
        db.scalars(
            select(OrgAsset)
            .where(OrgAsset.org_id == membership.org_id)
            .order_by(OrgAsset.criticality.desc(), OrgAsset.created_at.asc())
        ).all()
    )


@router.post("/assets", response_model=OrgAssetResponse, status_code=status.HTTP_201_CREATED)
def create_asset(
    payload: OrgAssetCreate,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
) -> OrgAsset:
    _validate_owner(db, membership.org_id, payload.owner_membership_id)
    # Canonical identity (§3): the same repository URL or work address always
    # stores as the same stable id, so findings can bind to it exactly.
    canonical = canonical_asset_id(payload.asset_id)
    if not canonical or len(canonical) > 64:
        raise HTTPException(
            status_code=422,
            detail="asset_id must be a stable identifier of at most 64 characters.",
        )
    existing = assert_asset_in_org(db, membership.org_id, canonical)
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An asset with this asset_id already exists in this organization.",
        )
    asset = OrgAsset(
        org_id=membership.org_id,
        asset_id=canonical,
        asset_type=payload.asset_type,
        label=payload.label,
        service_name=payload.service_name,
        criticality=payload.criticality,
        owner_membership_id=payload.owner_membership_id,
        source_mode="USER_PROVIDED",
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    audit.record(
        db, action="asset.created", user_id=membership.user_id,
        detail={"org_id": membership.org_id, "asset_id": asset.asset_id,
                "asset_type": asset.asset_type, "criticality": asset.criticality},
    )
    return asset


@router.get("/assets/{asset_id}", response_model=OrgAssetResponse)
def get_asset(
    asset_id: str,
    membership: Annotated[Membership, Depends(get_current_membership)],
    db: Session = Depends(get_db),
) -> OrgAsset:
    return _get_asset(db, membership.org_id, asset_id)


@router.patch("/assets/{asset_id}", response_model=OrgAssetResponse)
def update_asset(
    asset_id: str,
    payload: OrgAssetUpdate,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
) -> OrgAsset:
    asset = _get_asset(db, membership.org_id, asset_id)
    if payload.owner_membership_id is not None:
        _validate_owner(db, membership.org_id, payload.owner_membership_id)
        asset.owner_membership_id = payload.owner_membership_id
    if payload.label is not None:
        asset.label = payload.label
    if payload.service_name is not None:
        asset.service_name = payload.service_name
    if payload.criticality is not None:
        asset.criticality = payload.criticality
    db.commit()
    db.refresh(asset)
    audit.record(
        db, action="asset.updated", user_id=membership.user_id,
        detail={"org_id": membership.org_id, "asset_id": asset.asset_id,
                "criticality": asset.criticality},
    )
    return asset


@router.delete("/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: str,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
) -> None:
    asset = _get_asset(db, membership.org_id, asset_id)
    db.delete(asset)
    db.commit()
    audit.record(
        db, action="asset.deleted", user_id=membership.user_id,
        detail={"org_id": membership.org_id, "asset_id": asset_id},
    )


@router.get("/dependencies", response_model=list[AssetDependencyResponse])
def list_dependencies(
    membership: Annotated[Membership, Depends(get_current_membership)],
    db: Session = Depends(get_db),
) -> list[AssetDependency]:
    return list(
        db.scalars(
            select(AssetDependency)
            .where(AssetDependency.org_id == membership.org_id)
            .order_by(AssetDependency.created_at.asc())
        ).all()
    )


@router.post(
    "/dependencies", response_model=AssetDependencyResponse, status_code=status.HTTP_201_CREATED
)
def create_dependency(
    payload: AssetDependencyCreate,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
) -> AssetDependency:
    # Both endpoints must exist in THIS organization — CRIX never invents edges
    # and never links across tenants.
    from_id = canonical_asset_id(payload.from_asset_id)
    to_id = canonical_asset_id(payload.to_asset_id)
    if not from_id or not to_id or from_id == to_id:
        raise HTTPException(
            status_code=422,
            detail="A dependency needs two distinct, stable asset identifiers.",
        )
    _get_asset(db, membership.org_id, from_id)
    _get_asset(db, membership.org_id, to_id)
    # Relationship-type validation happens AFTER authorization and the
    # existence checks above: a cross-tenant or missing endpoint stays a 404
    # and never leaks whether the type would have been accepted. Unsupported
    # types are rejected, never coerced into a supported one (§5.7, §5.13).
    rel_type = canonical_relationship_type(payload.relationship_type)
    if rel_type is None:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Unsupported relationship_type {payload.relationship_type!r}. "
                "Supported types: "
                + ", ".join(supported_relationship_type_list())
                + "."
            ),
        )
    existing = None
    for row in db.scalars(
        select(AssetDependency).where(
            AssetDependency.org_id == membership.org_id,
        )
    ).all():
        # Compare canonical forms so case-variants of one type still conflict.
        if canonical_relationship_type(row.relationship_type) != rel_type:
            continue
        if (
            canonical_asset_id(row.from_asset_id) == from_id
            and canonical_asset_id(row.to_asset_id) == to_id
        ):
            existing = row
            break
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Dependency already exists.")
    edge = AssetDependency(
        org_id=membership.org_id,
        from_asset_id=from_id,
        to_asset_id=to_id,
        relationship_type=rel_type,
        edge_source="ADMIN_DECLARED",
        weight=payload.weight,
        note=payload.note,
    )
    db.add(edge)
    db.commit()
    db.refresh(edge)
    audit.record(
        db, action="dependency.created", user_id=membership.user_id,
        detail={"org_id": membership.org_id, "from": edge.from_asset_id,
                "to": edge.to_asset_id, "type": edge.relationship_type},
    )
    return edge


@router.get("/dependencies/{dependency_id}", response_model=AssetDependencyResponse)
def get_dependency(
    dependency_id: str,
    membership: Annotated[Membership, Depends(get_current_membership)],
    db: Session = Depends(get_db),
) -> AssetDependency:
    """The evidence behind one declared relationship (Phase 6, §5.10).

    Readable by every role; scoped to the caller's organization, so a foreign
    id is indistinguishable from a missing one (404).
    """
    edge = _get_dependency(db, membership.org_id, dependency_id)
    return edge


@router.patch("/dependencies/{dependency_id}", response_model=AssetDependencyResponse)
def update_dependency(
    dependency_id: str,
    payload: AssetDependencyUpdate,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
) -> AssetDependency:
    """Correct a declared relationship's type, weight or note (§5.10).

    Endpoints cannot be rewritten here: moving a relationship to different
    assets means deleting and re-declaring it, which stays explicit and
    auditable. Every update is recorded in the audit log.
    """
    edge = _get_dependency(db, membership.org_id, dependency_id)
    updates: dict[str, str] = {}
    if payload.relationship_type is not None:
        rel_type = canonical_relationship_type(payload.relationship_type)
        if rel_type is None:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Unsupported relationship_type {payload.relationship_type!r}. "
                    "Supported types: "
                    + ", ".join(supported_relationship_type_list())
                    + "."
                ),
            )
        for row in db.scalars(
            select(AssetDependency).where(
                AssetDependency.org_id == membership.org_id,
                AssetDependency.id != edge.id,
            )
        ).all():
            if (
                canonical_relationship_type(row.relationship_type) == rel_type
                and canonical_asset_id(row.from_asset_id)
                == canonical_asset_id(edge.from_asset_id)
                and canonical_asset_id(row.to_asset_id) == canonical_asset_id(edge.to_asset_id)
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Dependency already exists.",
                )
        edge.relationship_type = rel_type
        updates["relationship_type"] = rel_type
    if payload.weight is not None:
        edge.weight = payload.weight
        updates["weight"] = str(payload.weight)
    if payload.note is not None:
        edge.note = payload.note
        updates["note"] = payload.note
    db.commit()
    db.refresh(edge)
    audit.record(
        db, action="dependency.updated", user_id=membership.user_id,
        detail={"org_id": membership.org_id, "dependency_id": dependency_id,
                "updates": updates},
    )
    return edge


@router.delete("/dependencies/{dependency_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_dependency(
    dependency_id: str,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
) -> None:
    edge = _get_dependency(db, membership.org_id, dependency_id)
    db.delete(edge)
    db.commit()
    audit.record(
        db, action="dependency.deleted", user_id=membership.user_id,
        detail={"org_id": membership.org_id, "dependency_id": dependency_id},
    )
