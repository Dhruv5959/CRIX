"""Account dependency graph (§8). NetworkX only — no Neo4j.

Edges come from the curated ``graph_relationships`` table (STATIC / hand-verified,
never auto-discovered). We rank accounts by how much cascading damage a
compromise would cause, using weighted PageRank and weighted in-degree.

GraphRAG and the UI must present these relationships as curated/static.
"""
from __future__ import annotations

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import events
from app.models import GraphRelationship, SecurityEvent
from app.schemas import SecurityEventSchema


def build_graph(db: Session, services: set[str] | None = None) -> nx.DiGraph:
    """Build a directed dependency graph. If ``services`` given, restrict to the
    induced subgraph over those services plus their direct neighbours."""
    graph = nx.DiGraph()
    rows = db.scalars(select(GraphRelationship)).all()
    for row in rows:
        graph.add_edge(
            row.from_service,
            row.to_service,
            weight=row.weight,
            relationship_type=row.relationship_type,
            description=row.description,
            source=row.source,
            last_verified_at=row.last_verified_at,
            curated=True,
        )
    if services is not None:
        keep = set(services)
        for node in list(graph.nodes):
            keep.add(node)
        graph = graph.subgraph(keep).copy()
    return graph


def rank_accounts(graph: nx.DiGraph) -> list[dict]:
    """Rank services by cascading-damage potential.

    Uses weighted PageRank (a compromise at a high-centrality node reaches more
    dependents) plus weighted in-degree (how many accounts trust it). Both are
    computed by NetworkX; nothing here is hand-assigned a rank.
    """
    if graph.number_of_nodes() == 0:
        return []
    pagerank = nx.pagerank(graph, weight="weight")
    in_degree = dict(graph.in_degree(weight="weight"))
    ranked = []
    for node in graph.nodes:
        ranked.append(
            {
                "service": node,
                "pagerank": round(pagerank.get(node, 0.0), 6),
                "weighted_in_degree": round(in_degree.get(node, 0.0), 4),
                "dependents": sorted(graph.predecessors(node)),
            }
        )
    ranked.sort(key=lambda item: (item["pagerank"], item["weighted_in_degree"]), reverse=True)
    for index, item in enumerate(ranked, start=1):
        item["rank"] = index
    return ranked


def dependency_events(
    *,
    user_id: str,
    db: Session,
    compromised_services: set[str],
    centrality_threshold: float = 0.0,
) -> list[SecurityEventSchema]:
    """Emit graph events.

    - ACCOUNT_DEPENDENCY: the account acts as a recovery/OAuth route for others
      (severity scales with centrality).
    - COMPROMISED_RECOVERY_ACCOUNT: a high-centrality account is among the
      compromised ones (feeds the cascading-recovery correlation).
    """
    graph = build_graph(db, services=compromised_services or None)
    ranked = rank_accounts(graph)
    if not ranked:
        return []
    top_pr = max(item["pagerank"] for item in ranked) or 1.0

    out: list[SecurityEventSchema] = []
    for item in ranked:
        if not item["dependents"]:
            continue
        normalized = item["pagerank"] / top_pr
        if normalized < centrality_threshold:
            continue
        severity = round(min(0.8, 0.3 + 0.5 * normalized), 4)
        out.append(
            SecurityEventSchema(
                event_id=events.new_event_id(),
                user_id=user_id,
                account_id=item["service"],
                event_type=events.ACCOUNT_DEPENDENCY,
                exposure_type=None,
                severity=severity,
                confidence=0.8,
                source="curated_graph",
                status="FINDING",
                evidence={
                    "source": "curated_graph_relationships",
                    "dependent_count": len(item["dependents"]),
                    "dependents": item["dependents"][:20],
                    "pagerank": item["pagerank"],
                    "normalized_pagerank": normalized,
                    "curated": True,
                },
                metadata={
                    "dependents": item["dependents"][:20],
                    "pagerank": item["pagerank"],
                    "rank": item["rank"],
                    "curated": True,
                },
                provenance=(
                    "Curated account-dependency relationships (static, hand-verified; "
                    "see graph_relationships with source references)."
                ),
            )
        )
        if item["service"] in compromised_services and normalized >= 0.6:
            out.append(
                SecurityEventSchema(
                    event_id=events.new_event_id(),
                    user_id=user_id,
                    account_id=item["service"],
                    event_type=events.COMPROMISED_RECOVERY_ACCOUNT,
                    exposure_type=None,
                    severity=round(min(0.9, 0.5 + 0.4 * normalized), 4),
                    confidence=0.6,
                    source="curated_graph",
                    status="FINDING",
                    evidence={
                        "source": "curated_graph_relationships",
                        "dependent_count": len(item["dependents"]),
                        "dependents": item["dependents"][:20],
                        "central_account": item["service"],
                        "normalized_pagerank": normalized,
                    },
                    metadata={"dependents": item["dependents"][:20], "pagerank": item["pagerank"]},
                    provenance=(
                        "A high-centrality recovery/OAuth account also shows a "
                        "compromise signal; compromise could cascade to its dependents."
                    ),
                )
            )
    return out


def graph_payload(db: Session, services: set[str] | None = None) -> dict:
    """Serializable graph + ranking for the frontend dependency view."""
    graph = build_graph(db, services=services)
    nodes = [
        {
            "id": node,
            "label": node,
            "curated": True,
        }
        for node in graph.nodes
    ]
    edges = []
    for source, target, data in graph.edges(data=True):
        edges.append(
            {
                "source": source,
                "target": target,
                "weight": data.get("weight", 1.0),
                "relationship_type": data.get("relationship_type", ""),
                "description": data.get("description", ""),
                "source_ref": data.get("source", ""),
                "last_verified_at": data.get("last_verified_at").isoformat()
                if data.get("last_verified_at")
                else None,
                "curated": True,
            }
        )
    return {
        "nodes": nodes,
        "edges": edges,
        "ranking": rank_accounts(graph),
        "provenance": "Curated static relationships; not auto-discovered.",
    }