"""Knowledge endpoints: correlation rule catalog, KG, evaluation metrics (§5, §11, §13)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.engine.correlation import describe_rules
from app.models import EvaluationRecord, KnowledgeEdge, KnowledgeNode

router = APIRouter(prefix="/api", tags=["knowledge"])


@router.get("/correlation-rules")
def correlation_rules() -> dict:
    return {
        "rules": describe_rules(),
        "engine": "declarative YAML (app/data/correlation_rules.yaml)",
    }


@router.get("/knowledge-graph")
def knowledge_graph(db: Session = Depends(get_db)) -> dict:
    nodes = db.scalars(select(KnowledgeNode)).all()
    edges = db.scalars(select(KnowledgeEdge)).all()
    return {
        "provenance": "Curated security knowledge graph; each edge carries a source.",
        "nodes": [
            {
                "id": n.node_id,
                "type": n.node_type,
                "label": n.label,
                "description": n.description,
                "source": n.source,
            }
            for n in nodes
        ],
        "edges": [
            {
                "id": e.edge_id,
                "from": e.from_node,
                "to": e.to_node,
                "predicate": e.predicate,
                "evidence": e.evidence,
                "source": e.source,
            }
            for e in edges
        ],
    }


@router.get("/evaluation")
def evaluation(db: Session = Depends(get_db)) -> dict:
    """Return ONLY real, measured metrics. If a suite has not been run, the
    metric is reported as not-yet-measured rather than invented (§0.1, §13)."""
    rows = db.scalars(
        select(EvaluationRecord).order_by(EvaluationRecord.suite, EvaluationRecord.metric_name)
    ).all()
    suites: dict[str, dict] = {}
    for row in rows:
        suite = suites.setdefault(row.suite, {"metrics": {}, "details": {}})
        suite["metrics"][row.metric_name] = row.metric_value
        if row.details:
            suite["details"][row.metric_name] = row.details
    for suite_name, suite in suites.items():
        suite["measured"] = True
    return {
        "measured": bool(rows),
        "note": (
            "Numbers shown here were produced by actually running the evaluation "
            "harness. Empty suites mean 'not yet measured'."
        ),
        "suites": suites,
    }