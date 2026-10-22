"""Account dependency graph endpoints (§8)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_user
from app.engine import graph
from app.models import ConnectedSignal, User

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