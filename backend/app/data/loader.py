"""Loader + DB seeder for curated reference data (§3, §5, §8, §11).

Curated YAML lives in this package. ``seed_all`` is idempotent so it can be run
on every startup / in test fixtures without duplicating rows.
"""
from __future__ import annotations

import datetime as dt
from functools import lru_cache
from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    GraphRelationship,
    KnowledgeEdge,
    KnowledgeNode,
    ProviderCapability,
    ProviderMetadata,
)

_DATA_DIR = Path(__file__).resolve().parent


def _load_yaml(name: str) -> dict:
    with (_DATA_DIR / name).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@lru_cache
def correlation_rules() -> list[dict]:
    return _load_yaml("correlation_rules.yaml")["rules"]


@lru_cache
def providers_data() -> list[dict]:
    return _load_yaml("providers.yaml")["services"]


@lru_cache
def graph_relationships_data() -> list[dict]:
    return _load_yaml("graph_relationships.yaml")["relationships"]


@lru_cache
def knowledge_graph_data() -> dict:
    return _load_yaml("knowledge_graph.yaml")


@lru_cache
def permissions_taxonomy() -> dict:
    return _load_yaml("permissions_taxonomy.yaml")


@lru_cache
def provider_capabilities() -> list[dict]:
    return _load_yaml("provider_capabilities.yaml")["capabilities"]


def _parse_date(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value).replace(tzinfo=dt.timezone.utc)


def seed_all(db: Session) -> dict[str, int]:
    """Idempotently insert curated reference data. Returns row counts added."""
    counts = {
        "providers": 0,
        "graph_relationships": 0,
        "knowledge_nodes": 0,
        "knowledge_edges": 0,
        "provider_capabilities": 0,
    }

    for item in providers_data():
        existing = db.scalar(
            select(ProviderMetadata).where(ProviderMetadata.service_name == item["service_name"])
        )
        if existing is None:
            db.add(
                ProviderMetadata(
                    service_name=item["service_name"],
                    supports_passkey=bool(item["supports_passkey"]),
                    mfa_methods=list(item["mfa_methods"]),
                    recovery_methods=list(item["recovery_methods"]),
                    sms_recovery_possible=bool(item["sms_recovery_possible"]),
                    notes=item.get("notes", ""),
                    source=item["source"],
                    last_verified_at=_parse_date(item["last_verified"]),
                )
            )
            counts["providers"] += 1

    for item in graph_relationships_data():
        existing = db.scalar(
            select(GraphRelationship).where(
                GraphRelationship.from_service == item["from_service"],
                GraphRelationship.to_service == item["to_service"],
                GraphRelationship.relationship_type == item["relationship_type"],
            )
        )
        if existing is None:
            db.add(
                GraphRelationship(
                    from_service=item["from_service"],
                    to_service=item["to_service"],
                    relationship_type=item["relationship_type"],
                    weight=float(item["weight"]),
                    description=item.get("description", ""),
                    source=item["source"],
                    last_verified_at=_parse_date(item["last_verified"]),
                )
            )
            counts["graph_relationships"] += 1

    kg = knowledge_graph_data()
    for item in kg["nodes"]:
        existing = db.scalar(select(KnowledgeNode).where(KnowledgeNode.node_id == item["node_id"]))
        if existing is None:
            db.add(
                KnowledgeNode(
                    node_id=item["node_id"],
                    node_type=item["node_type"],
                    label=item["label"],
                    description=item.get("description", ""),
                    source=item["source"],
                )
            )
            counts["knowledge_nodes"] += 1

    for item in kg["edges"]:
        existing = db.scalar(select(KnowledgeEdge).where(KnowledgeEdge.edge_id == item["edge_id"]))
        if existing is None:
            db.add(
                KnowledgeEdge(
                    edge_id=item["edge_id"],
                    from_node=item["from_node"],
                    to_node=item["to_node"],
                    predicate=item["predicate"],
                    evidence=item.get("evidence", ""),
                    source=item["source"],
                )
            )
            counts["knowledge_edges"] += 1

    # Curated "does the official API expose this?" capability matrix (§12).
    for item in provider_capabilities():
        existing = db.scalar(
            select(ProviderCapability).where(
                ProviderCapability.provider == item["provider"],
                ProviderCapability.capability == item["capability"],
            )
        )
        if existing is None:
            db.add(
                ProviderCapability(
                    provider=item["provider"],
                    capability=item["capability"],
                    available=bool(item["available"]),
                    source=item.get("source", ""),
                    last_verified=(
                        _parse_date(item["last_verified"]) if item.get("last_verified") else None
                    ),
                    note=item.get("note", ""),
                )
            )
            counts["provider_capabilities"] += 1

    db.commit()
    return counts