"""Remediation planner endpoints (§9). Compares greedy vs. exact only."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_user
from app.engine import pipeline, planner
from app.models import User

router = APIRouter(prefix="/api/planner", tags=["planner"])


@router.get("/actions")
def list_actions() -> dict:
    return {
        "actions": [
            {
                "key": a.key,
                "title": a.title,
                "description": a.description,
                "effort": a.effort,
                "addresses": list(a.addresses),
            }
            for a in planner.ACTIONS.values()
        ],
        "note": "Effort costs are documented relative units, not wall-clock time.",
    }


@router.get("/plan")
def plan(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
    budget: float = 6.0,
) -> dict:
    result = pipeline.run_analysis(db, current_user.id, persist=False)
    comparison = planner.compare(result["features"], budget=budget)
    return {
        "budget": budget,
        "comparison": comparison,
        "note": (
            "Greedy is a baseline, not claimed to be optimal. The optimality gap "
            "is measured on this scenario's real feature vector."
        ),
    }