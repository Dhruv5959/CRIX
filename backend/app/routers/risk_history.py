"""Risk history: read-only view of the organization's risk snapshots (§5).

Every analysis run INSERTs a ``RiskResult`` row (never rewritten), so this is a
straight tenant-scoped read of what the pipeline recorded — no recomputation.
Rows whose writer had no active membership (``org_id`` NULL) match no tenant
query by design, and another organization's snapshots never appear here.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_membership
from app.models import Membership, RiskResult

router = APIRouter(prefix="/api", tags=["risk"])

# The page renders a timeline; cap the read so a long run history cannot turn
# into an unbounded response.
HISTORY_LIMIT = 50


@router.get("/risk-history")
def risk_history(
    membership: Annotated[Membership, Depends(get_current_membership)],
    db: Session = Depends(get_db),
) -> dict:
    rows = db.scalars(
        select(RiskResult)
        .where(RiskResult.org_id == membership.org_id)
        .order_by(RiskResult.created_at.desc(), RiskResult.id.desc())
        .limit(HISTORY_LIMIT)
    ).all()
    return {
        "count": len(rows),
        "entries": [
            {
                "id": row.id,
                "score": row.score,
                "band": row.band,
                "model_version": row.model_version,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ],
    }
