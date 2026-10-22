"""Organization-scoped company asset dependency graph (Phase 6, §5).

Answers the question: **if one company asset is compromised, which other
assets might be exposed through documented relationships, along which paths,
and why?**

Honesty boundaries enforced here:

* Nodes are the organization's registered ``OrgAsset`` rows only — keyed by
  the canonical asset id from :mod:`app.engine.entities`. Similar names never
  merge assets, and an id from another organization can never become a node
  because every query filters on ``org_id``.
* Edges are the organization's ``AssetDependency`` rows only, restricted to
  the documented :data:`SUPPORTED_RELATIONSHIP_TYPES`. CRIX never invents a
  relationship; a missing edge stays missing.
* The graph documents **potential exposure along declared relationships**.
  A reachable asset is never described as breached, hacked or compromised —
  no attack is asserted or implied.
* Provenance labels distinguish what is registered (``REGISTERED_ASSET``),
  what an administrator declared (``ADMIN_DECLARED``), and what CRIX derived
  from those two (``DERIVED_PATH``). ``PROVIDER_DISCOVERED`` and
  ``MODEL_INFERRED`` are *documented as absent*: this system does not produce
  them, so they are never shown.
* Every traversal is bounded (depth, path count, expansion budget) and
  deterministic (sorted iteration, stable tie-breaking). Cyclic graphs are
  never fully enumerated: paths are simple (no repeated node) and capped.
* This module does not import the risk engine or the attribution engine and
  contains no scoring logic of its own (§5.9): the graph explains exposure,
  it never changes the authoritative risk score.
"""
from __future__ import annotations

from typing import Literal

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engine.entities import canonical_asset_id
from app.models import AssetDependency, OrgAsset

# --------------------------------------------------------------------------- #
# Documented relationship semantics (§5.2, §5.7)
# --------------------------------------------------------------------------- #
# Each supported type declares how a DECLARED edge translates into EXPOSURE
# direction — "if the source is compromised, the target may be exposed"
# (forward), "if the target is compromised, the source may be exposed"
# (reverse), or either (bidirectional integration). Types outside this table
# are rejected on write and skipped (with a count) on read: CRIX traverses
# only relationships whose semantics it documents.
RELATIONSHIP_SEMANTICS: dict[str, dict] = {
    "RESETS_PASSWORD": {
        "directed": True,
        "exposure": "forward",
        "description": (
            "The source (e.g. a work email) can reset access to the target "
            "(e.g. a repository): compromise of the source may expose the target."
        ),
    },
    "HAS_ACCESS_TO": {
        "directed": True,
        "exposure": "forward",
        "description": (
            "The source application has access to the target resource: "
            "compromise of the source may expose the target."
        ),
    },
    "DEPLOYS_TO": {
        "directed": True,
        "exposure": "forward",
        "description": (
            "The source (e.g. a CI system) deploys to the target: compromise "
            "of the source may expose the target."
        ),
    },
    "DEPENDS_ON": {
        "directed": True,
        "exposure": "reverse",
        "description": (
            "The source depends on the target (e.g. a repository depends on a "
            "cloud identity): compromise of the target may expose the source."
        ),
    },
    "USES": {
        "directed": True,
        "exposure": "reverse",
        "description": (
            "The source uses the target (e.g. an application uses an identity "
            "provider): compromise of the target may expose the source."
        ),
    },
    "INTEGRATES_WITH": {
        "directed": False,
        "exposure": "both",
        "description": (
            "A mutual integration: compromise of either side may expose the "
            "other."
        ),
    },
}

SUPPORTED_RELATIONSHIP_TYPES = tuple(sorted(RELATIONSHIP_SEMANTICS))

# Provenance vocabulary shown to users. Labels this system cannot honestly
# produce are listed with an explicit "not produced" note, never fabricated.
PROVENANCE_LABELS: dict[str, str] = {
    "REGISTERED_ASSET": "Registered company asset (organization inventory).",
    "ADMIN_DECLARED": "Relationship declared by an organization administrator.",
    "DERIVED_PATH": (
        "Exposure path derived by CRIX from registered assets and declared "
        "relationships."
    ),
    "PROVIDER_DISCOVERED": "Not produced by this system.",
    "MODEL_INFERRED": "Not produced by this system.",
}

# Traversal limits (§5.7). Defaults are what the API exposes; the hard caps
# are what the engine will accept at all.
GRAPH_LIMITS: dict[str, int] = {
    "default_depth": 3,
    "max_depth": 5,
    "default_paths": 10,
    "max_paths": 25,
    "max_nodes": 1000,
    "max_expansions": 20000,
}

CRITICAL_CRITICALITY = 4  # criticality >= 4 counts as a critical asset

DISCLAIMER = (
    "Potential exposure derived from registered assets and administrator-"
    "declared relationships only. It is not evidence that any attack or "
    "compromise has occurred."
)


class GraphTooLargeError(ValueError):
    """The organization's graph exceeds the supported size for traversal."""


def canonical_relationship_type(raw: str | None) -> str | None:
    """Canonical (UPPER_SNAKE) form of a relationship type, or ``None``.

    Case-insensitive: ``"deploys_to"`` and ``"DEPLOYS_TO"`` are the same type.
    Unknown types return ``None`` — an unsupported type is never coerced into
    a supported one.
    """
    if not raw:
        return None
    canonical = raw.strip().upper().replace("-", "_").replace(" ", "_")
    return canonical if canonical in RELATIONSHIP_SEMANTICS else None


def supported_relationship_type_list() -> list[str]:
    return list(SUPPORTED_RELATIONSHIP_TYPES)


# --------------------------------------------------------------------------- #
# A. Graph construction
# --------------------------------------------------------------------------- #
def build_org_graph(db: Session, org_id: str) -> tuple[nx.MultiDiGraph, dict]:
    """Build the organization's asset graph (operation A).

    Returns the directed *exposure* multigraph plus build statistics. The
    graph is built fresh from org-scoped rows on every call, so no cache can
    carry another organization's structure. Edges with an unsupported type or
    a missing endpoint (e.g. the asset was deleted) are skipped and counted —
    they are never silently dropped or guessed around.
    """
    graph = nx.MultiDiGraph()
    stats = {
        "assets": 0,
        "relationships": 0,
        "skipped_unsupported_type": 0,
        "skipped_dangling_endpoint": 0,
        "duplicate_edges_skipped": 0,
    }

    assets = sorted(
        db.scalars(select(OrgAsset).where(OrgAsset.org_id == org_id)).all(),
        key=lambda a: (a.asset_id, a.id),
    )
    if len(assets) > GRAPH_LIMITS["max_nodes"]:
        raise GraphTooLargeError(
            f"Organization graph has {len(assets)} assets; the supported "
            f"maximum is {GRAPH_LIMITS['max_nodes']}."
        )
    for asset in assets:
        node_id = canonical_asset_id(asset.asset_id)
        graph.add_node(
            node_id,
            asset_id=node_id,
            asset_type=asset.asset_type,
            label=asset.label,
            criticality=asset.criticality,
            source_mode=asset.source_mode,
            provenance="REGISTERED_ASSET",
        )
    stats["assets"] = graph.number_of_nodes()

    seen_edges: set[tuple[str, str, str]] = set()
    rows = sorted(
        db.scalars(select(AssetDependency).where(AssetDependency.org_id == org_id)).all(),
        key=lambda r: (r.from_asset_id, r.to_asset_id, r.relationship_type, r.id),
    )
    for row in rows:
        rel_type = canonical_relationship_type(row.relationship_type)
        if rel_type is None:
            stats["skipped_unsupported_type"] += 1
            continue
        source = canonical_asset_id(row.from_asset_id)
        target = canonical_asset_id(row.to_asset_id)
        if source not in graph or target not in graph:
            # The declared endpoint is not a registered asset of this org
            # (e.g. it was deleted). The edge is stale, not traversable.
            stats["skipped_dangling_endpoint"] += 1
            continue
        dedupe_key = (source, target, rel_type)
        if dedupe_key in seen_edges:
            stats["duplicate_edges_skipped"] += 1
            continue
        seen_edges.add(dedupe_key)
        semantics = RELATIONSHIP_SEMANTICS[rel_type]
        edge_data = {
            "relationship_id": row.id,
            "relationship_type": rel_type,
            "declared_from": source,
            "declared_to": target,
            "directed": semantics["directed"],
            "exposure": semantics["exposure"],
            "edge_source": row.edge_source,
            "weight": float(row.weight),
            "note": row.note or "",
            "declared_at": row.created_at.isoformat() if row.created_at else None,
            "provenance": row.edge_source or "ADMIN_DECLARED",
        }
        # Exposure arcs: the direction a compromise could travel.
        if semantics["exposure"] in ("forward", "both"):
            graph.add_edge(source, target, **edge_data)
        if semantics["exposure"] in ("reverse", "both"):
            graph.add_edge(target, source, **edge_data)
    stats["relationships"] = len(seen_edges)
    return graph, stats


def graph_payload(db: Session, org_id: str) -> dict:
    """Serializable org graph for the API/frontend (declared direction)."""
    graph, stats = build_org_graph(db, org_id)
    nodes = sorted(
        (
            {
                "asset_id": data["asset_id"],
                "asset_type": data["asset_type"],
                "label": data["label"],
                "criticality": data["criticality"],
                "source_mode": data["source_mode"],
                "provenance": data["provenance"],
            }
            for _, data in graph.nodes(data=True)
        ),
        key=lambda n: n["asset_id"],
    )
    # One entry per DECLARED relationship (not per exposure arc), so the
    # payload shows exactly what was declared and how it was interpreted.
    edges = sorted(
        (
            {
                "relationship_id": data["relationship_id"],
                "from_asset_id": data["declared_from"],
                "to_asset_id": data["declared_to"],
                "relationship_type": data["relationship_type"],
                "directed": data["directed"],
                "exposure": data["exposure"],
                "edge_source": data["edge_source"],
                "weight": data["weight"],
                "note": data["note"],
                "declared_at": data["declared_at"],
                "provenance": data["provenance"],
            }
            for _, _, data in graph.edges(data=True)
        ),
        key=lambda e: (e["from_asset_id"], e["to_asset_id"], e["relationship_type"]),
    )
    # Bidirectional types produce two arcs; deduplicate the declared view.
    unique_edges = list({e["relationship_id"]: e for e in edges}.values())
    unique_edges.sort(
        key=lambda e: (e["from_asset_id"], e["to_asset_id"], e["relationship_type"])
    )
    return {
        "nodes": nodes,
        "edges": unique_edges,
        "stats": stats,
        "limits": dict(GRAPH_LIMITS),
        "provenance_labels": dict(PROVENANCE_LABELS),
        "supported_relationship_types": list(SUPPORTED_RELATIONSHIP_TYPES),
        "disclaimer": DISCLAIMER,
    }


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _require_asset(graph: nx.MultiDiGraph, asset_id: str) -> str:
    """Canonicalize an asset id and require it to be a node of THIS graph.

    A foreign or unknown id raises ``LookupError``; callers map that to a
    generic 404 that reveals nothing about other organizations.
    """
    canonical = canonical_asset_id(asset_id)
    if canonical not in graph:
        raise LookupError("Asset not found.")
    return canonical


def _exposure_arcs(graph: nx.MultiDiGraph, node_id: str, direction: str):
    """Sorted ``(neighbor, edge_data, arc_direction)`` exposure arcs.

    ``arc_direction`` is relative to ``node_id``: ``"out"`` means a compromise
    of this asset could travel along the arc to the neighbor; ``"in"`` means
    the reverse.
    """
    out = [
        (target, dict(data), "out")
        for _, target, _, data in graph.out_edges(node_id, keys=True, data=True)
    ]
    incoming = [
        (source, dict(data), "in")
        for source, _, _, data in graph.in_edges(node_id, keys=True, data=True)
    ]
    if direction == "out":
        arcs = out
    elif direction == "in":
        arcs = incoming
    else:
        arcs = out + incoming
    arcs.sort(key=lambda item: (item[0], item[1]["relationship_id"], item[2]))
    return arcs


def _step_evidence(data: dict, graph: nx.MultiDiGraph) -> dict:
    """One traversal step's structured explanation (operation G)."""
    uncertainty: list[str] = []
    if not data.get("note"):
        uncertainty.append("NOTE_MISSING")
    return {
        "from_asset_id": data["declared_from"],
        "to_asset_id": data["declared_to"],
        "traversed_from": None,
        "traversed_to": None,
        "relationship_id": data["relationship_id"],
        "relationship_type": data["relationship_type"],
        "directed": data["directed"],
        "exposure": data["exposure"],
        "traversal_condition": (
            "Administrator-declared relationship; exposure is modeled along "
            "the documented direction of this relationship type."
        ),
        "evidence": {
            "edge_source": data["edge_source"],
            "note": data["note"],
            "note_present": bool(data["note"]),
            "declared_at": data["declared_at"],
        },
        "uncertainty": uncertainty,
        "provenance": data["provenance"],
        "criticality_of_target": graph.nodes[data["declared_to"]]["criticality"],
    }


# --------------------------------------------------------------------------- #
# B. Direct neighbors
# --------------------------------------------------------------------------- #
def direct_neighbors(
    graph: nx.MultiDiGraph,
    asset_id: str,
    direction: Literal["in", "out", "both"] = "both",
) -> dict:
    """Assets directly connected to ``asset_id`` (operation B).

    ``direction="out"`` lists what a compromise of this asset could expose;
    ``"in"`` lists what could expose this asset; ``"both"`` lists both.
    """
    node_id = _require_asset(graph, asset_id)
    node = graph.nodes[node_id]
    entries: list[dict] = []
    for neighbor, data, arc_direction in _exposure_arcs(graph, node_id, direction):
        step = _step_evidence(data, graph)
        step["traversed_from"] = node_id
        step["traversed_to"] = neighbor
        entries.append(
            {
                "asset_id": neighbor,
                "label": graph.nodes[neighbor]["label"],
                "asset_type": graph.nodes[neighbor]["asset_type"],
                "criticality": graph.nodes[neighbor]["criticality"],
                "direction": arc_direction,
                "relationship": step,
            }
        )
    return {
        "asset_id": node_id,
        "criticality": node["criticality"],
        "direction": direction,
        "neighbors": entries,
        "count": len(entries),
        "disclaimer": DISCLAIMER,
    }


# --------------------------------------------------------------------------- #
# C. Reachability (bounded BFS)
# --------------------------------------------------------------------------- #
def reachable(
    graph: nx.MultiDiGraph, asset_id: str, max_depth: int | None = None
) -> dict:
    """Assets reachable from ``asset_id`` through exposure arcs (operation C).

    Breadth-first, depth-bounded and expansion-bounded; each asset is visited
    once, so cycles terminate. Ordering is deterministic: breadth by depth,
    then asset id.
    """
    node_id = _require_asset(graph, asset_id)
    depth = GRAPH_LIMITS["default_depth"] if max_depth is None else max_depth
    depth = max(1, min(depth, GRAPH_LIMITS["max_depth"]))
    budget = GRAPH_LIMITS["max_expansions"]

    visited: set[str] = {node_id}
    parents: dict[str, tuple[str, dict]] = {}
    levels: list[list[str]] = []
    expansions = 0
    truncated = False
    frontier = [node_id]
    for _ in range(depth):
        if not frontier:
            break
        next_level: list[str] = []
        for current in sorted(frontier):
            for neighbor, data, _arc in _exposure_arcs(graph, current, "out"):
                expansions += 1
                if expansions > budget:
                    truncated = True
                    break
                if neighbor in visited:
                    continue
                visited.add(neighbor)
                parents[neighbor] = (current, data)
                next_level.append(neighbor)
            if truncated:
                break
        if truncated:
            break
        if next_level:
            levels.append(sorted(next_level))
        frontier = next_level

    # Depth exhausted while unvisited neighbours remain: more assets may be
    # reachable beyond the bound, so say so (§5.7).
    if not truncated and frontier:
        pending = {
            neighbor
            for node in frontier
            for neighbor, _data, _arc in _exposure_arcs(graph, node, "out")
            if neighbor not in visited
        }
        truncated = bool(pending)

    entries = []
    for depth_index, level in enumerate(levels, start=1):
        for asset in level:
            parent, data = parents[asset]
            step = _step_evidence(data, graph)
            step["traversed_from"] = parent
            step["traversed_to"] = asset
            entries.append(
                {
                    "asset_id": asset,
                    "label": graph.nodes[asset]["label"],
                    "asset_type": graph.nodes[asset]["asset_type"],
                    "criticality": graph.nodes[asset]["criticality"],
                    "depth": depth_index,
                    "exposure_path": _path_to(node_id, asset, parents),
                    "via_relationship": step,
                }
            )
    return {
        "asset_id": node_id,
        "max_depth": depth,
        "reachable": entries,
        "count": len(entries),
        "truncated": truncated,
        "disclaimer": DISCLAIMER,
    }


def _path_to(source: str, target: str, parents: dict) -> list[dict]:
    """Deterministic shortest exposure path (steps) from ``source`` to ``target``.

    Each step names the declared relationship that justifies it, so a path is
    always evidence-backed rather than an unexplained hop list.
    """
    chain: list[tuple[str, str, dict]] = []
    current = target
    while current != source:
        parent, data = parents[current]
        chain.append((parent, current, data))
        current = parent
    chain.reverse()
    steps = []
    for frm, to, data in chain:
        steps.append(
            {
                "from_asset_id": data["declared_from"],
                "to_asset_id": data["declared_to"],
                "traversed_from": frm,
                "traversed_to": to,
                "relationship_id": data["relationship_id"],
                "relationship_type": data["relationship_type"],
                "exposure": data["exposure"],
                "provenance": data["provenance"],
            }
        )
    return steps


# --------------------------------------------------------------------------- #
# D. Path retrieval (bounded DFS, simple paths only)
# --------------------------------------------------------------------------- #
def paths_between(
    graph: nx.MultiDiGraph,
    source: str,
    target: str,
    max_depth: int | None = None,
    max_paths: int | None = None,
) -> dict:
    """Simple exposure paths from ``source`` to ``target`` (operation D).

    Depth-bounded, path-count-bounded and expansion-budget-bounded: cyclic
    graphs are never fully enumerated. A path never repeats a node. Results
    are sorted by (length, node sequence), so the same graph and query always
    return the same ordering.
    """
    source_id = _require_asset(graph, source)
    target_id = _require_asset(graph, target)
    depth = GRAPH_LIMITS["default_depth"] if max_depth is None else max_depth
    depth = max(1, min(depth, GRAPH_LIMITS["max_depth"]))
    limit = GRAPH_LIMITS["default_paths"] if max_paths is None else max_paths
    limit = max(1, min(limit, GRAPH_LIMITS["max_paths"]))
    budget = GRAPH_LIMITS["max_expansions"]

    found: list[tuple[list[str], list[dict]]] = []
    expansions = 0
    truncated = False

    stack: list[tuple[str, list[str], list[dict]]] = [(source_id, [source_id], [])]
    while stack:
        current, path_nodes, steps = stack.pop()
        if len(path_nodes) - 1 >= depth:
            continue
        for neighbor, data, _arc in _exposure_arcs(graph, current, "out"):
            expansions += 1
            if expansions > budget:
                truncated = True
                break
            if neighbor in path_nodes:
                continue  # simple paths only: no repeated nodes
            step = _step_evidence(data, graph)
            step["traversed_from"] = current
            step["traversed_to"] = neighbor
            new_nodes = path_nodes + [neighbor]
            new_steps = steps + [step]
            if neighbor == target_id:
                found.append((new_nodes, new_steps))
                if len(found) >= limit:
                    truncated = True
                    break
            else:
                stack.append((neighbor, new_nodes, new_steps))
        if truncated:
            break

    found.sort(key=lambda item: (len(item[0]), item[0]))
    paths = [
        {
            "assets": nodes,
            "length": len(nodes) - 1,
            "steps": steps,
            "provenance": "DERIVED_PATH",
        }
        for nodes, steps in found
    ]
    return {
        "source_asset_id": source_id,
        "target_asset_id": target_id,
        "max_depth": depth,
        "max_paths": limit,
        "paths": paths,
        "count": len(paths),
        "truncated": truncated,
        "disclaimer": DISCLAIMER,
    }


# --------------------------------------------------------------------------- #
# E/F. Potential blast radius and critical-asset exposure
# --------------------------------------------------------------------------- #
def blast_radius(
    graph: nx.MultiDiGraph, asset_id: str, max_depth: int | None = None
) -> dict:
    """Assets potentially exposed if ``asset_id`` were compromised (operation E).

    Reachability plus, for each reachable asset, the deterministic shortest
    documented exposure path and the relationship that justifies each step.
    Critical assets (criticality >= ``CRITICAL_CRITICALITY``) are highlighted
    (operation F). Nothing here asserts that a compromise happened.
    """
    reach = reachable(graph, asset_id, max_depth=max_depth)
    entries = reach["reachable"]
    critical = [e for e in entries if e["criticality"] >= CRITICAL_CRITICALITY]
    return {
        "asset_id": reach["asset_id"],
        "max_depth": reach["max_depth"],
        "potential_exposure": entries,
        "count": reach["count"],
        "critical_assets": critical,
        "critical_count": len(critical),
        "truncated": reach["truncated"],
        "disclaimer": DISCLAIMER,
    }


def critical_exposure(
    graph: nx.MultiDiGraph,
    asset_id: str | None = None,
    max_depth: int | None = None,
) -> dict:
    """Critical assets reachable through documented paths (operation F).

    With a source asset: the critical subset of that asset's potential blast
    radius — the critical assets a compromise of the source could expose.
    Without: for every critical asset, which registered assets have a
    documented exposure path *toward* it (reverse reachability, bounded),
    i.e. where an exposure could come *from*.
    """
    if asset_id is not None:
        radius = blast_radius(graph, asset_id, max_depth=max_depth)
        return {
            "scope": "asset",
            "asset_id": radius["asset_id"],
            "critical_assets": radius["critical_assets"],
            "count": radius["critical_count"],
            "truncated": radius["truncated"],
            "disclaimer": DISCLAIMER,
        }

    critical_nodes = sorted(
        (
            node
            for node, data in graph.nodes(data=True)
            if data["criticality"] >= CRITICAL_CRITICALITY
        )
    )
    budget = GRAPH_LIMITS["max_expansions"]
    entries = []
    truncated = False
    # Walk the reversed graph: from a critical asset back along exposure arcs
    # to the assets whose compromise could reach it. The stored paths are then
    # flipped so every hop reads in the direction exposure would actually
    # travel (exposing asset -> critical asset).
    reversed_graph = graph.reverse(copy=False)
    for node in critical_nodes:
        reach = reachable(reversed_graph, node, max_depth=max_depth)
        if reach["truncated"]:
            truncated = True
        exposed_by = []
        for entry in reach["reachable"]:
            steps = []
            for step in reversed(entry["exposure_path"]):
                flipped = dict(step)
                flipped["traversed_from"] = step["traversed_to"]
                flipped["traversed_to"] = step["traversed_from"]
                steps.append(flipped)
            exposed_by.append(
                {
                    "asset_id": entry["asset_id"],
                    "depth": entry["depth"],
                    "exposure_path": steps,
                }
            )
        entries.append(
            {
                "asset_id": node,
                "label": graph.nodes[node]["label"],
                "asset_type": graph.nodes[node]["asset_type"],
                "criticality": graph.nodes[node]["criticality"],
                "reachable_from_count": len(exposed_by),
                "reachable_from": exposed_by[:20],
            }
        )
        if len(entries) * max(1, len(exposed_by)) > budget:
            truncated = True
            break
    return {
        "scope": "organization",
        "critical_assets": entries,
        "count": len(entries),
        "truncated": truncated,
        "disclaimer": DISCLAIMER,
    }
