"""Account dependency graph endpoints (§8) and the organization-scoped company
asset dependency graph (Phase 6, §5).

The personal ``/api/graph`` endpoint ranks the user's connected accounts from
the curated ``graph_relationships`` table. The ``/api/org/graph`` family
answers a different, organization-level question: if one company asset were
compromised, which other assets **might** be exposed through relationships an
administrator declared — along which documented paths, and why. It reports
potential exposure only; it never claims an attack or compromise occurred
(§5, §5.8).
"""
from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_membership, get_current_user
from app.engine import graph
from app.engine import org_graph as orggraph
from app.engine.entities import assert_asset_in_org, canonical_asset_id
from app.models import ConnectedSignal, Membership, User

router = APIRouter(prefix="/api", tags=["graph"])


@router.get("/graph")
def dependency_graph(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> dict:
    accounts = db.scalars(
        select(ConnectedSignal).where(ConnectedSignal.user_id == current_user.id)
    ).all()
    services = {a.service_name for a in accounts if a.service_name}
    payload = graph.graph_payload(db, services=services or None)

    # Annotate which services the user actually connects (contextual highlight).
    for node in payload["nodes"]:
        node["connected"] = node["id"] in services
    return payload


# --------------------------------------------------------------------------- #
# Organization asset dependency graph (Phase 6, §5)
# --------------------------------------------------------------------------- #
def _resolve_asset(db: Session, org_id: str, asset_id: str) -> str:
    """Canonical id of an asset of THIS organization, or a generic 404.

    The 404 never distinguishes "belongs to another organization" from "does
    not exist" (§5.5): an error must not reveal another tenant's assets.
    """
    asset = assert_asset_in_org(db, org_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    # Graph nodes are keyed by the canonical id; a stored id is canonical
    # already, but normalising here keeps resolution exact either way.
    return canonical_asset_id(asset.asset_id)


def _build(db: Session, org_id: str):
    try:
        return orggraph.build_org_graph(db, org_id)
    except orggraph.GraphTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc


@router.get("/org/graph")
def org_asset_graph(
    membership: Annotated[Membership, Depends(get_current_membership)],
    db: Session = Depends(get_db),
) -> dict:
    """Operation A: the organization's asset graph with provenance and limits.

    Nodes are the organization's registered company assets; edges are the
    relationships its administrators declared. Nothing is inferred from names.
    """
    try:
        return orggraph.graph_payload(db, membership.org_id)
    except orggraph.GraphTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc


@router.get("/org/graph/neighbors")
def org_asset_neighbors(
    membership: Annotated[Membership, Depends(get_current_membership)],
    db: Session = Depends(get_db),
    asset_id: str = Query(min_length=1, max_length=256),
    direction: Literal["in", "out", "both"] = "both",
) -> dict:
    """Operation B: assets directly connected to one asset, by exposure direction.

    ``out`` = what a compromise of this asset could expose; ``in`` = what could
    expose this asset; ``both`` = both.
    """
    _resolve_asset(db, membership.org_id, asset_id)
    graph_obj, _stats = _build(db, membership.org_id)
    try:
        return orggraph.direct_neighbors(graph_obj, asset_id, direction=direction)
    except LookupError as exc:  # pragma: no cover - resolved above
        raise HTTPException(status_code=404, detail="Asset not found.") from exc


@router.get("/org/graph/paths")
def org_asset_paths(
    membership: Annotated[Membership, Depends(get_current_membership)],
    db: Session = Depends(get_db),
    source: str = Query(min_length=1, max_length=256),
    target: str = Query(min_length=1, max_length=256),
    max_depth: int = Query(
        default=orggraph.GRAPH_LIMITS["default_depth"],
        ge=1,
        le=orggraph.GRAPH_LIMITS["max_depth"],
    ),
    max_paths: int = Query(
        default=orggraph.GRAPH_LIMITS["default_paths"],
        ge=1,
        le=orggraph.GRAPH_LIMITS["max_paths"],
    ),
) -> dict:
    """Operation D: documented exposure paths between two assets, with evidence.

    Paths are simple (no repeated node), depth- and count-bounded, so cyclic
    graphs are never fully enumerated (§5.7).
    """
    _resolve_asset(db, membership.org_id, source)
    _resolve_asset(db, membership.org_id, target)
    graph_obj, _stats = _build(db, membership.org_id)
    return orggraph.paths_between(
        graph_obj, source, target, max_depth=max_depth, max_paths=max_paths
    )


@router.get("/org/graph/blast-radius")
def org_asset_blast_radius(
    membership: Annotated[Membership, Depends(get_current_membership)],
    db: Session = Depends(get_db),
    asset_id: str = Query(min_length=1, max_length=256),
    max_depth: int = Query(
        default=orggraph.GRAPH_LIMITS["default_depth"],
        ge=1,
        le=orggraph.GRAPH_LIMITS["max_depth"],
    ),
) -> dict:
    """Operation E (with F): potential exposure from one asset, critical assets flagged.

    Reports which registered assets **might** be exposed if this asset were
    compromised, along the documented relationships that justify each hop.
    It is not evidence that a compromise occurred.
    """
    _resolve_asset(db, membership.org_id, asset_id)
    graph_obj, _stats = _build(db, membership.org_id)
    return orggraph.blast_radius(graph_obj, asset_id, max_depth=max_depth)


@router.get("/org/graph/critical-exposure")
def org_critical_exposure(
    membership: Annotated[Membership, Depends(get_current_membership)],
    db: Session = Depends(get_db),
    asset_id: str | None = Query(default=None, min_length=1, max_length=256),
    max_depth: int = Query(
        default=orggraph.GRAPH_LIMITS["default_depth"],
        ge=1,
        le=orggraph.GRAPH_LIMITS["max_depth"],
    ),
) -> dict:
    """Operation F: critical assets reachable through documented paths.

    With ``asset_id``: the critical subset of that asset's potential blast
    radius. Without: for every critical asset, which registered assets have a
    documented exposure path toward it.
    """
    if asset_id is not None:
        _resolve_asset(db, membership.org_id, asset_id)
    graph_obj, _stats = _build(db, membership.org_id)
    return orggraph.critical_exposure(graph_obj, asset_id=asset_id, max_depth=max_depth)
