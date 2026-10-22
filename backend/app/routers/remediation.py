"""Remediation tasks: planning under budget + verified completion (Phase 7, §9).

* Reads are available to every role (and audit-logged — task state drives
  decisions, so who read it matters).
* Writes are role-gated server-side: create/update/assign/verify/reopen and
  the budget setting are ORG_ADMIN; completing a task is ORG_ADMIN or MEMBER;
  planning is ORG_ADMIN or MEMBER.
* Every query is scoped to the caller's ``org_id``; an id from another
  organization is indistinguishable from a missing one (404).

Task states — exactly four, never merged:

  OPEN               created, not claimed
  DONE               claimed done by a human (an attestation, NOT a
                     verification: clicking Done never verifies)
  VERIFIED_MODELED   pipeline re-run on the user-attested state; the modeled
                     reduction was confirmed by the real risk engine
  VERIFIED_OBSERVED  a LIVE (REAL-source) provider recheck confirmed it;
                     rejected for SYNTHETIC/FIXTURE data by construction

Every transition and every verification attempt (pass OR fail) is appended to
``remediation_task_history`` with method, evidence refs, timestamp, result and
model version; rows are never rewritten, so reopening preserves the trail.
"""
from __future__ import annotations

import datetime as dt
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.deps import get_current_membership, require_role
from app.engine import pipeline, planner, risk
from app.engine.entities import assert_asset_in_org
from app.models import (
    Membership,
    Organization,
    RemediationAction,
    RemediationTaskHistory,
    SecurityEvent,
)
from app.schemas import (
    OrgRole,
    RemediationSettingsRequest,
    RemediationSettingsResponse,
    RemediationTaskCreate,
    RemediationTaskDetailResponse,
    RemediationTaskHistoryResponse,
    RemediationTaskReopenRequest,
    RemediationTaskResponse,
    RemediationTaskUpdate,
    RemediationTaskVerifyRequest,
)

router = APIRouter(prefix="/api/remediation", tags=["remediation"])

ADMIN_ROLES = (OrgRole.ORG_ADMIN.value,)
CONTRIBUTOR_ROLES = (OrgRole.ORG_ADMIN.value, OrgRole.MEMBER.value)

TASK_STATES = ("OPEN", "DONE", "VERIFIED_MODELED", "VERIFIED_OBSERVED")
VERIFIED_STATES = ("VERIFIED_MODELED", "VERIFIED_OBSERVED")
# A task DECLARES which path will verify it (``verification_method``:
# MODELED/OBSERVED); a verification attempt names the resulting state
# (``method``: VERIFIED_MODELED/VERIFIED_OBSERVED). The two verified states
# are never merged, so the verify vocabulary is the state names.
TASK_VERIFICATION_METHODS = ("MODELED", "OBSERVED")
VERIFICATION_METHODS = ("VERIFIED_MODELED", "VERIFIED_OBSERVED")
VERIFICATION_STATE_FOR_METHOD = {
    "MODELED": "VERIFIED_MODELED",
    "OBSERVED": "VERIFIED_OBSERVED",
}
VERIFICATION_METHOD_LABELS = {
    "VERIFIED_MODELED": "pipeline re-run on the user-attested state",
    "VERIFIED_OBSERVED": "live provider recheck (REAL source only)",
}


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(value: dt.datetime | None) -> str | None:
    return value.isoformat() if value else None


def _get_task(db: Session, org_id: str, task_id: str) -> RemediationAction:
    task = db.get(RemediationAction, task_id)
    # Tenant isolation: a task from another org is indistinguishable from a
    # missing one.
    if task is None or task.org_id != org_id:
        raise HTTPException(status_code=404, detail="Remediation task not found.")
    return task


def _require_catalog_key(action_key: str) -> planner.Action:
    action = planner.ACTIONS.get(action_key)
    if action is None:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Unknown action key {action_key!r}. The documented catalog "
                "(GET /api/planner/actions) is the authority for what an "
                "action does."
            ),
        )
    return action


def _validate_finding_ids(db: Session, org_id: str, finding_ids: list[str]) -> None:
    """Every referenced finding must exist inside THIS organization."""
    if not finding_ids:
        return
    rows = db.scalars(
        select(SecurityEvent.event_id).where(
            SecurityEvent.org_id == org_id,
            SecurityEvent.event_id.in_(finding_ids),
        )
    ).all()
    missing = sorted(set(finding_ids) - set(rows))
    if missing:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "unknown_finding_ids",
                "message": (
                    "These finding ids do not exist in this organization. "
                    "Findings from another tenant are indistinguishable from "
                    "missing ones."
                ),
                "unknown": missing,
            },
        )


def _validate_prerequisite_keys(prerequisites: list[str]) -> None:
    unknown = sorted(k for k in prerequisites if k not in planner.ACTIONS)
    if unknown:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "unknown_prerequisite_action",
                "message": "Prerequisites must name documented catalog actions.",
                "unknown": unknown,
            },
        )


def _validate_assignee(db: Session, org_id: str, user_id: str) -> None:
    member = db.scalar(
        select(Membership).where(
            Membership.org_id == org_id,
            Membership.user_id == user_id,
            Membership.is_active.is_(True),
        )
    )
    if member is None:
        raise HTTPException(
            status_code=422,
            detail=(
                "The assignee must be an active member of this organization."
            ),
        )


def _task_out(task: RemediationAction) -> RemediationTaskResponse:
    return RemediationTaskResponse(
        id=task.id,
        org_id=task.org_id,
        action_key=task.action_key,
        title=task.title,
        description=task.description,
        addresses=list(task.addresses_event_types or []),
        effort=task.effort,
        target_asset_id=task.target_asset_id,
        finding_ids=list(task.finding_ids or []),
        prerequisites=list(task.prerequisites or []),
        dependencies=list(task.dependencies or []),
        required_evidence=list(task.required_evidence or []),
        verification_method=task.verification_method,
        status=task.status,
        assigned_to=task.assigned_to,
        expected_reduction=task.expected_reduction,
        completed_at=_iso(task.completed_at),
        created_at=_iso(task.created_at),
    )


def _task_detail_out(
    task: RemediationAction, history: list[RemediationTaskHistory]
) -> RemediationTaskDetailResponse:
    return RemediationTaskDetailResponse(
        **_task_out(task).model_dump(),
        history=[
            RemediationTaskHistoryResponse(
                id=row.id,
                from_status=row.from_status,
                to_status=row.to_status,
                method=row.method,
                result=row.result,
                model_version=row.model_version,
                evidence_refs=list(row.evidence_refs or []),
                detail=dict(row.detail or {}),
                created_at=_iso(row.created_at) or "",
            )
            for row in history
        ],
    )


def _history_rows(db: Session, task: RemediationAction) -> list[RemediationTaskHistory]:
    return list(
        db.scalars(
            select(RemediationTaskHistory)
            .where(RemediationTaskHistory.action_id == task.id)
            .order_by(
                RemediationTaskHistory.created_at.asc(),
                RemediationTaskHistory.id.asc(),
            )
        ).all()
    )


def _append_history(
    db: Session,
    task: RemediationAction,
    *,
    actor_user_id: str | None,
    from_status: str | None,
    to_status: str,
    method: str,
    result: str = "OK",
    model_version: str | None = None,
    evidence_refs: list[str] | None = None,
    detail: dict | None = None,
) -> RemediationTaskHistory:
    row = RemediationTaskHistory(
        action_id=task.id,
        org_id=task.org_id,
        actor_user_id=actor_user_id,
        from_status=from_status,
        to_status=to_status,
        method=method,
        result=result,
        model_version=model_version,
        evidence_refs=list(evidence_refs or []),
        detail=dict(detail or {}),
    )
    db.add(row)
    return row


def _org_features(
    db: Session, user_id: str
) -> tuple[dict[str, float], int | None, float]:
    """Run the real pipeline (no persistence) and return features/score."""
    result = pipeline.run_analysis(db, user_id, persist=False)
    return result["features"], result["criticality"], result["risk"].score


# --------------------------------------------------------------------------- #
# Settings: the admin-set effort budget
# --------------------------------------------------------------------------- #
@router.get("/settings", response_model=RemediationSettingsResponse)
def get_settings(
    membership: Annotated[Membership, Depends(get_current_membership)],
    db: Session = Depends(get_db),
) -> RemediationSettingsResponse:
    org = db.get(Organization, membership.org_id)
    if org is None:  # pragma: no cover - defensive
        raise HTTPException(status_code=404, detail="Organization not found.")
    return RemediationSettingsResponse(
        org_id=org.id,
        effort_budget=org.effort_budget,
        note=(
            "Effort is a documented relative unit, never wall-clock time. "
            "This budget is the default the planner packs under."
        ),
    )


@router.patch("/settings", response_model=RemediationSettingsResponse)
def update_settings(
    payload: RemediationSettingsRequest,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
) -> RemediationSettingsResponse:
    org = db.get(Organization, membership.org_id)
    if org is None:  # pragma: no cover - defensive
        raise HTTPException(status_code=404, detail="Organization not found.")
    org.effort_budget = payload.effort_budget
    db.commit()
    audit.record(
        db,
        action="remediation.settings_updated",
        user_id=membership.user_id,
        detail={
            "org_id": org.id,
            "effort_budget": org.effort_budget,
        },
    )
    return RemediationSettingsResponse(
        org_id=org.id,
        effort_budget=org.effort_budget,
        note=(
            "Effort is a documented relative unit, never wall-clock time. "
            "This budget is the default the planner packs under."
        ),
    )


# --------------------------------------------------------------------------- #
# Tasks
# --------------------------------------------------------------------------- #
@router.get("/tasks")
def list_tasks(
    membership: Annotated[Membership, Depends(get_current_membership)],
    db: Session = Depends(get_db),
) -> dict:
    tasks = list(
        db.scalars(
            select(RemediationAction)
            .where(RemediationAction.org_id == membership.org_id)
            .order_by(RemediationAction.created_at.asc(), RemediationAction.id.asc())
        ).all()
    )
    audit.record(
        db,
        action="remediation.tasks_read",
        user_id=membership.user_id,
        detail={"org_id": membership.org_id, "count": len(tasks)},
    )
    return {"tasks": [_task_out(t) for t in tasks], "count": len(tasks)}


@router.post("/tasks", response_model=RemediationTaskResponse, status_code=status.HTTP_201_CREATED)
def create_task(
    payload: RemediationTaskCreate,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
) -> RemediationTaskResponse:
    action = _require_catalog_key(payload.action_key)
    if payload.verification_method not in TASK_VERIFICATION_METHODS:
        raise HTTPException(
            status_code=422,
            detail=(
                f"verification_method must be one of {TASK_VERIFICATION_METHODS}, "
                f"got {payload.verification_method!r}."
            ),
        )
    _validate_prerequisite_keys(payload.prerequisites)
    _validate_finding_ids(db, membership.org_id, payload.finding_ids)
    if payload.target_asset_id is not None:
        # Resolves to None when the asset is unknown or belongs to another
        # tenant — indistinguishable, and both are a 404 (never a guess).
        if assert_asset_in_org(db, membership.org_id, payload.target_asset_id) is None:
            raise HTTPException(status_code=404, detail="Asset not found.")
    if payload.effort is not None and not payload.effort > 0:
        raise HTTPException(status_code=422, detail="effort must be > 0.")

    # The expected reduction is COMPUTED by the real risk engine from this
    # organization's own feature vector — never invented, never a constant.
    features, criticality, _score = _org_features(db, membership.user_id)
    expected = planner.expected_reduction(
        features, payload.action_key, criticality=criticality
    )

    task = RemediationAction(
        user_id=membership.user_id,
        org_id=membership.org_id,
        action_key=action.key,
        title=action.title,
        description=action.description,
        addresses_event_types=list(action.addresses),
        effort=float(payload.effort) if payload.effort is not None else action.effort,
        target_asset_id=payload.target_asset_id,
        finding_ids=list(payload.finding_ids),
        prerequisites=list(payload.prerequisites),
        dependencies=list(payload.dependencies),
        required_evidence=list(payload.required_evidence),
        verification_method=payload.verification_method,
        status="OPEN",
        expected_reduction=expected,
    )
    db.add(task)
    db.flush()
    _append_history(
        db,
        task,
        actor_user_id=membership.user_id,
        from_status=None,
        to_status="OPEN",
        method="CREATED",
        model_version=risk.RISK_MODEL_VERSION,
        detail={
            "action_key": task.action_key,
            "expected_reduction": expected,
            "note": (
                "expected_reduction computed by the real risk model from this "
                "organization's current feature vector."
            ),
        },
    )
    db.commit()
    audit.record(
        db,
        action="remediation.task_created",
        user_id=membership.user_id,
        detail={
            "task_id": task.id,
            "org_id": task.org_id,
            "action_key": task.action_key,
            "target_asset_id": task.target_asset_id,
            "expected_reduction": expected,
            "verification_method": task.verification_method,
        },
    )
    return _task_out(task)


@router.get("/tasks/{task_id}", response_model=RemediationTaskDetailResponse)
def get_task(
    task_id: str,
    membership: Annotated[Membership, Depends(get_current_membership)],
    db: Session = Depends(get_db),
) -> RemediationTaskDetailResponse:
    task = _get_task(db, membership.org_id, task_id)
    audit.record(
        db,
        action="remediation.task_read",
        user_id=membership.user_id,
        detail={"task_id": task.id, "org_id": task.org_id},
    )
    return _task_detail_out(task, _history_rows(db, task))


@router.patch("/tasks/{task_id}", response_model=RemediationTaskResponse)
def update_task(
    task_id: str,
    payload: RemediationTaskUpdate,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
) -> RemediationTaskResponse:
    task = _get_task(db, membership.org_id, task_id)

    changed: dict[str, dict] = {}
    if payload.assigned_to is not None and payload.assigned_to != task.assigned_to:
        _validate_assignee(db, membership.org_id, payload.assigned_to)
        changed["assigned_to"] = {"from": task.assigned_to, "to": payload.assigned_to}
        task.assigned_to = payload.assigned_to
    if payload.effort is not None:
        if not payload.effort > 0:
            raise HTTPException(status_code=422, detail="effort must be > 0.")
        if payload.effort != task.effort:
            changed["effort"] = {"from": task.effort, "to": payload.effort}
            task.effort = float(payload.effort)
    if payload.prerequisites is not None:
        _validate_prerequisite_keys(payload.prerequisites)
        if list(payload.prerequisites) != list(task.prerequisites or []):
            changed["prerequisites"] = {
                "from": list(task.prerequisites or []),
                "to": list(payload.prerequisites),
            }
            task.prerequisites = list(payload.prerequisites)
    if payload.dependencies is not None:
        if list(payload.dependencies) != list(task.dependencies or []):
            changed["dependencies"] = {
                "from": list(task.dependencies or []),
                "to": list(payload.dependencies),
            }
            task.dependencies = list(payload.dependencies)
    if payload.required_evidence is not None:
        if list(payload.required_evidence) != list(task.required_evidence or []):
            changed["required_evidence"] = {
                "from": list(task.required_evidence or []),
                "to": list(payload.required_evidence),
            }
            task.required_evidence = list(payload.required_evidence)

    if not changed:
        return _task_out(task)  # nothing to do, nothing to record

    assignment_only = set(changed) == {"assigned_to"}
    _append_history(
        db,
        task,
        actor_user_id=membership.user_id,
        from_status=task.status,
        to_status=task.status,
        method="ASSIGNED" if assignment_only else "UPDATED",
        detail={"changed": changed},
    )
    db.commit()
    audit.record(
        db,
        action="remediation.task_updated",
        user_id=membership.user_id,
        detail={"task_id": task.id, "org_id": task.org_id, "changed": sorted(changed)},
    )
    return _task_out(task)


@router.post("/tasks/{task_id}/complete", response_model=RemediationTaskResponse)
def complete_task(
    task_id: str,
    membership: Annotated[Membership, Depends(require_role(*CONTRIBUTOR_ROLES))],
    db: Session = Depends(get_db),
) -> RemediationTaskResponse:
    """Claim a task done. This is an ATTESTATION, never a verification."""
    task = _get_task(db, membership.org_id, task_id)
    if task.status == "DONE":
        raise HTTPException(
            status_code=409,
            detail="Task is already claimed done. Verify it or reopen it.",
        )
    if task.status in VERIFIED_STATES:
        raise HTTPException(
            status_code=409,
            detail="Task is already verified. Reopen it before changing it.",
        )
    previous = task.status  # OPEN
    task.status = "DONE"
    task.completed_at = _utcnow()
    _append_history(
        db,
        task,
        actor_user_id=membership.user_id,
        from_status=previous,
        to_status="DONE",
        method="COMPLETED",
        detail={
            "note": (
                "Claimed done by a human. This is an attestation, not a "
                "verification: Done never verifies."
            ),
        },
    )
    db.commit()
    audit.record(
        db,
        action="remediation.task_completed",
        user_id=membership.user_id,
        detail={"task_id": task.id, "org_id": task.org_id, "from_status": previous},
    )
    return _task_out(task)


def _verify_modeled(
    db: Session,
    task: RemediationAction,
    membership: Membership,
    payload: RemediationTaskVerifyRequest,
) -> tuple[bool, dict, list[str]]:
    """Modeled verification: pipeline re-run on the user-attested state."""
    if not payload.attested:
        raise HTTPException(
            status_code=422,
            detail=(
                "Modeled verification requires an explicit user attestation "
                "(attested=true) that the action was performed. The engine "
                "re-runs on that attested state; it never guesses."
            ),
        )
    features, criticality, score = _org_features(db, membership.user_id)
    before = score
    after, _ = risk.risk_from_features(
        planner.apply_action(features, task.action_key),
        criticality=criticality,
    )
    reduction = round(before - after, 4)
    passed = reduction > 1e-9
    detail = {
        "verification_method": "VERIFIED_MODELED",
        "modeled_before": round(before, 4),
        "modeled_after": round(after, 4),
        "modeled_reduction": reduction,
        "attested": True,
        "required_evidence": list(task.required_evidence or []),
        "note": VERIFICATION_METHOD_LABELS["VERIFIED_MODELED"],
    }
    if not passed:
        detail["failure_reason"] = (
            "The re-run shows no modeled reduction for this action on the "
            "current feature vector (the weakness is already absent, or the "
            "action addresses nothing that is present). The claim is not "
            "confirmed by the model."
        )
    return passed, detail, []


def _verify_observed(
    db: Session,
    task: RemediationAction,
    membership: Membership,
    payload: RemediationTaskVerifyRequest,
) -> tuple[bool, dict, list[str]]:
    """Observed verification: LIVE provider recheck, REAL sources only."""
    refs = [ref for ref in payload.evidence_refs if ref]
    if not refs:
        raise HTTPException(
            status_code=422,
            detail=(
                "Observed verification requires evidence references to LIVE "
                "provider recheck results (REAL-source findings). SYNTHETIC, "
                "FIXTURE or user-typed data can never verify an observation."
            ),
        )
    events = list(
        db.scalars(
            select(SecurityEvent).where(
                SecurityEvent.org_id == membership.org_id,
                SecurityEvent.event_id.in_(refs),
            )
        ).all()
    )
    found_ids = {e.event_id for e in events}
    unknown = sorted(set(refs) - found_ids)
    if unknown:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "unknown_evidence_refs",
                "message": (
                    "These evidence references do not exist in this "
                    "organization."
                ),
                "unknown": unknown,
            },
        )
    real = [e for e in events if e.source_mode == "REAL"]
    if not real:
        modes = sorted({e.source_mode for e in events})
        raise HTTPException(
            status_code=422,
            detail={
                "error": "evidence_not_live",
                "message": (
                    "VERIFIED_OBSERVED is rejected for SYNTHETIC/FIXTURE "
                    "data: none of the referenced findings came from a LIVE "
                    "(REAL) provider. Observed verification needs a real "
                    "recheck."
                ),
                "source_modes_seen": modes,
            },
        )
    addressed = set(planner.ACTIONS[task.action_key].addresses)
    still_observed = [
        e.event_id
        for e in real
        if e.status == "FINDING"
        and risk.EVENT_TO_FEATURE.get(e.event_type) in addressed
    ]
    passed = not still_observed
    detail = {
        "verification_method": "VERIFIED_OBSERVED",
        "evidence_source_modes": sorted({e.source_mode for e in events}),
        "live_refs": [e.event_id for e in real],
        "addressed_features": sorted(addressed),
        "required_evidence": list(task.required_evidence or []),
        "note": VERIFICATION_METHOD_LABELS["VERIFIED_OBSERVED"],
    }
    if not passed:
        detail["failure_reason"] = (
            "The live recheck still reports the addressed weakness as a "
            "FINDING."
        )
        detail["still_observed"] = still_observed
    return passed, detail, refs


@router.post("/tasks/{task_id}/verify", response_model=RemediationTaskDetailResponse)
def verify_task(
    task_id: str,
    payload: RemediationTaskVerifyRequest,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
) -> RemediationTaskDetailResponse:
    task = _get_task(db, membership.org_id, task_id)
    if payload.method not in VERIFICATION_METHODS:
        raise HTTPException(
            status_code=422,
            detail=(
                f"method must be one of {VERIFICATION_METHODS}, "
                f"got {payload.method!r}. The two verified states are never "
                "merged."
            ),
        )
    if task.status == "OPEN":
        raise HTTPException(
            status_code=409,
            detail="Task must be claimed done (DONE) before verification.",
        )
    if task.status in VERIFIED_STATES:
        raise HTTPException(
            status_code=409,
            detail=(
                "Task is already verified. Reopen it before verifying again; "
                "the two verified states are never merged or overwritten."
            ),
        )
    # task.status == "DONE"
    if payload.method == "VERIFIED_MODELED":
        passed, detail, evidence_refs = _verify_modeled(db, task, membership, payload)
        model_version = risk.RISK_MODEL_VERSION
    else:
        passed, detail, evidence_refs = _verify_observed(db, task, membership, payload)
        # An observation is not a model: no model version applies.
        model_version = None

    previous = task.status  # DONE
    if passed:
        task.status = payload.method  # VERIFIED_MODELED | VERIFIED_OBSERVED
    _append_history(
        db,
        task,
        actor_user_id=membership.user_id,
        from_status=previous,
        to_status=task.status,
        method="VERIFICATION_ATTEMPTED",
        result="OK" if passed else "FAIL",
        model_version=model_version,
        evidence_refs=evidence_refs,
        detail=detail,
    )
    db.commit()
    audit.record(
        db,
        action="remediation.task_verified" if passed else "remediation.task_verification_failed",
        user_id=membership.user_id,
        detail={
            "task_id": task.id,
            "org_id": task.org_id,
            "verification_method": payload.method,
            "result": "OK" if passed else "FAIL",
            "model_version": model_version,
            "status_after": task.status,
        },
    )
    return _task_detail_out(task, _history_rows(db, task))


@router.post("/tasks/{task_id}/reopen", response_model=RemediationTaskResponse)
def reopen_task(
    task_id: str,
    payload: RemediationTaskReopenRequest,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    db: Session = Depends(get_db),
) -> RemediationTaskResponse:
    task = _get_task(db, membership.org_id, task_id)
    if task.status == "OPEN":
        raise HTTPException(status_code=409, detail="Task is already open.")
    previous = task.status
    task.status = "OPEN"
    task.completed_at = None
    _append_history(
        db,
        task,
        actor_user_id=membership.user_id,
        from_status=previous,
        to_status="OPEN",
        method="REOPENED",
        detail={
            "reason": payload.reason,
            "note": "Full history is preserved; reopening never rewrites it.",
        },
    )
    db.commit()
    audit.record(
        db,
        action="remediation.task_reopened",
        user_id=membership.user_id,
        detail={"task_id": task.id, "org_id": task.org_id, "from_status": previous},
    )
    return _task_out(task)


# --------------------------------------------------------------------------- #
# Planning: greedy baseline + exact branch-and-bound under the org budget
# --------------------------------------------------------------------------- #
@router.post("/plan")
def plan_tasks(
    membership: Annotated[Membership, Depends(require_role(*CONTRIBUTOR_ROLES))],
    db: Session = Depends(get_db),
    budget: Annotated[float | None, Query(gt=0, le=1000)] = None,
) -> dict:
    """Plan the organization's OPEN tasks under an effort budget.

    Candidates are this organization's OPEN tasks (deduplicated by action
    key, deterministically). Prerequisites and admin-adjusted efforts come
    from the task rows. The initial risk equals the current run's score — the
    planner re-runs the SAME feature vector the risk engine just scored. The
    plan is computed live and never persisted.
    """
    org = db.get(Organization, membership.org_id)
    if org is None:  # pragma: no cover - defensive
        raise HTTPException(status_code=404, detail="Organization not found.")

    open_tasks = list(
        db.scalars(
            select(RemediationAction)
            .where(
                RemediationAction.org_id == membership.org_id,
                RemediationAction.status == "OPEN",
            )
            .order_by(RemediationAction.created_at.asc(), RemediationAction.id.asc())
        ).all()
    )
    # Deterministic dedupe by action key: the first task (created_at, id)
    # represents the key; every task sharing it is listed in task_map.
    representatives: dict[str, RemediationAction] = {}
    task_map: dict[str, list[str]] = {}
    unplannable: list[dict] = []
    for task in open_tasks:
        if task.action_key not in planner.ACTIONS:
            unplannable.append(
                {
                    "task_id": task.id,
                    "action_key": task.action_key,
                    "reason": (
                        "action_key is not in the documented catalog; the "
                        "engine is the authority for what an action does."
                    ),
                }
            )
            continue
        task_map.setdefault(task.action_key, []).append(task.id)
        representatives.setdefault(task.action_key, task)

    candidate_keys = sorted(representatives)
    prerequisites = {
        key: list(task.prerequisites or []) for key, task in representatives.items()
    }
    efforts = {key: float(task.effort) for key, task in representatives.items()}

    chosen_budget = float(budget) if budget is not None else float(org.effort_budget)
    features, criticality, run_score = _org_features(db, membership.user_id)
    comparison = planner.compare(
        features,
        budget=chosen_budget,
        candidate_actions=candidate_keys,
        criticality=criticality,
        prerequisites=prerequisites,
        efforts=efforts,
    )

    def _plan_view(plan: dict) -> dict:
        return {
            "method": plan["method"],
            "actions": list(plan["actions"]),
            "task_ids": [tid for key in plan["actions"] for tid in task_map.get(key, [])],
            "total_effort": plan["total_effort"],
            "risk_after": plan["risk_after"],
            "risk_reduction": plan.get(
                "risk_reduction", round(comparison["initial_risk"] - plan["risk_after"], 4)
            ),
            "unspent_budget": plan.get("unspent_budget"),
            "infeasible": plan.get("infeasible", []),
            "labels": plan.get("labels", {}),
            "compute_ms": plan.get("compute_ms"),
        }

    audit.record(
        db,
        action="remediation.plan_computed",
        user_id=membership.user_id,
        detail={
            "org_id": membership.org_id,
            "budget": chosen_budget,
            "budget_source": "request" if budget is not None else "organization_setting",
            "candidate_count": len(candidate_keys),
            "optimality_gap": comparison["optimality_gap"],
            "is_greedy_trap": comparison["is_greedy_trap"],
        },
    )
    return {
        "org_id": membership.org_id,
        "budget": chosen_budget,
        "budget_source": "request" if budget is not None else "organization_setting",
        "initial_risk": comparison["initial_risk"],
        "run_score": round(run_score, 4),
        "criticality": criticality,
        "candidate_action_keys": candidate_keys,
        "task_map": task_map,
        "unplannable_tasks": unplannable,
        "greedy": _plan_view(comparison["greedy"]),
        "exact": _plan_view(comparison["exact"]),
        "optimality_gap": comparison["optimality_gap"],
        "is_greedy_trap": comparison["is_greedy_trap"],
        "labels": comparison["labels"],
        "note": (
            "Computed live from this organization's OPEN tasks; never "
            "persisted. Greedy is an approximate baseline; exact is proven "
            "optimal over these candidates under this budget only."
        ),
    }
