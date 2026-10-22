"""Remediation planner (§9).

Exactly TWO methods are compared:
  1. greedy baseline  — repeatedly pick the action with the best
     risk-reduction-per-unit-effort that still fits the budget.
  2. exact branch-and-bound — optimal over the bounded action set.

Greedy is NEVER described as optimal. The optimality gap is measured on our own
scenarios inside this repo, and the scenario set includes a deliberately
constructed "greedy trap" where greedy provably does worse than exact.

Actions operate on the SAME feature vector the risk engine uses, so the planner
re-runs the real risk function — nothing here is a separate toy model.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.engine.risk import (
    ALL_FEATURES,
    MITIGATION_FEATURES,
    RISK_FEATURES,
    risk_from_features,
)


@dataclass(frozen=True)
class Action:
    key: str
    title: str
    description: str
    effort: float
    addresses: tuple[str, ...]


# Documented action catalog with effort costs (higher = more effort/disruption).
ACTIONS: dict[str, Action] = {
    "change_reused_password": Action(
        key="change_reused_password",
        title="Change reused password",
        description="Replace a reused password with a unique one on this account.",
        effort=1.0,
        addresses=("reuse",),
    ),
    "revoke_session": Action(
        key="revoke_session",
        title="Revoke active sessions",
        description="Invalidate stolen/exposed session cookies, forcing re-login.",
        effort=1.0,
        addresses=("session",),
    ),
    "strengthen_mfa": Action(
        key="strengthen_mfa",
        title="Strengthen MFA",
        description="Turn on a real second factor (TOTP or security key).",
        effort=2.0,
        addresses=("no_mfa", "mfa"),
    ),
    "enable_passkey": Action(
        key="enable_passkey",
        title="Enable passkey",
        description="Register a phishing-resistant passkey for this account.",
        effort=3.0,
        addresses=("passkey", "no_mfa"),
    ),
    "replace_sms_recovery": Action(
        key="replace_sms_recovery",
        title="Replace SMS recovery",
        description="Move recovery away from SMS to an app/security key.",
        effort=2.0,
        addresses=("sim_swap",),
    ),
    "revoke_risky_permission": Action(
        key="revoke_risky_permission",
        title="Revoke risky app permission",
        description="Remove a high-sensitivity third-party app grant.",
        effort=2.0,
        addresses=("permissions",),
    ),
}


def apply_action(features: dict[str, float], action_key: str) -> dict[str, float]:
    """Return a NEW feature vector with the action applied (pure function)."""
    updated = dict(features)
    action = ACTIONS[action_key]
    if action_key == "change_reused_password":
        updated["reuse"] = 0.0
    elif action_key == "revoke_session":
        updated["session"] = 0.0
    elif action_key == "strengthen_mfa":
        updated["no_mfa"] = 0.0
        updated["mfa"] = 1.0
    elif action_key == "enable_passkey":
        updated["no_mfa"] = 0.0
        updated["passkey"] = 1.0
        # A passkey removes the SMS-recovery weakness on this account as well.
        updated["sim_swap"] = 0.0
    elif action_key == "replace_sms_recovery":
        updated["sim_swap"] = 0.0
    elif action_key == "revoke_risky_permission":
        updated["permissions"] = 0.0
    for name in ALL_FEATURES:
        if name not in updated:
            updated[name] = 0.0
    return updated


def apply_actions(features: dict[str, float], keys: list[str]) -> dict[str, float]:
    updated = dict(features)
    for key in keys:
        updated = apply_action(updated, key)
    return updated


def _risk(features: dict[str, float], criticality: int | None = None) -> float:
    score, _ = risk_from_features(features, criticality=criticality)
    return score


def greedy_plan(
    features: dict[str, float],
    *,
    budget: float,
    candidate_actions: list[str] | None = None,
    criticality: int | None = None,
) -> dict:
    """Greedy baseline: best reduction-per-effort that fits the remaining budget."""
    candidates = list(candidate_actions or ACTIONS.keys())
    remaining_budget = budget
    chosen: list[str] = []
    current = dict(features)
    current_risk = _risk(current, criticality)

    while True:
        best_choice = None
        best_ratio = 0.0
        for key in candidates:
            if key in chosen:
                continue
            effort = ACTIONS[key].effort
            if effort > remaining_budget + 1e-9:
                continue
            trial = apply_action(current, key)
            reduction = current_risk - _risk(trial, criticality)
            if reduction <= 1e-9:
                continue
            ratio = reduction / effort
            if ratio > best_ratio + 1e-12:
                best_ratio = ratio
                best_choice = key
        if best_choice is None:
            break
        chosen.append(best_choice)
        remaining_budget -= ACTIONS[best_choice].effort
        current = apply_action(current, best_choice)
        current_risk = _risk(current, criticality)

    return {
        "method": "greedy",
        "actions": chosen,
        "total_effort": round(budget - remaining_budget, 4),
        "risk_after": round(current_risk, 4),
    }


def exact_plan(
    features: dict[str, float],
    *,
    budget: float,
    candidate_actions: list[str] | None = None,
    criticality: int | None = None,
) -> dict:
    """Exact branch-and-bound over the bounded action set.

    With <= ~15 candidate actions this is trivially exact (2^n subsets). The
    bound prunes any branch whose optimistic optimum (apply all remaining
    actions ON TOP OF THE CURRENT STATE — the lowest risk reachable, ignoring
    budget) cannot beat the incumbent.
    """
    candidates = list(candidate_actions or ACTIONS.keys())
    # Order by effort ascending to reach feasible incumbents early.
    candidates.sort(key=lambda k: ACTIONS[k].effort)

    initial_risk = _risk(features, criticality)
    best = {"risk_after": initial_risk, "actions": [], "effort": 0.0}

    def optimistic(current: dict[str, float], remaining: list[str]) -> float:
        # Valid lower bound on achievable risk: applying every remaining action
        # yields the minimum of the monotone risk function over the full action
        # set; dropping budget feasibility can only raise the true optimum.
        return _risk(apply_actions(current, remaining), criticality)

    def dfs(index: int, chosen: list[str], effort: float, current: dict[str, float]):
        current_risk = _risk(current, criticality)
        if current_risk < best["risk_after"] - 1e-9 or (
            abs(current_risk - best["risk_after"]) <= 1e-9 and effort < best["effort"] - 1e-9
        ):
            best["risk_after"] = current_risk
            best["actions"] = list(chosen)
            best["effort"] = effort
        if index >= len(candidates):
            return
        # Prune: even applying all remaining actions (from the CURRENT state)
        # cannot beat the incumbent.
        if optimistic(current, candidates[index:]) >= best["risk_after"] - 1e-9:
            return
        for i in range(index, len(candidates)):
            key = candidates[i]
            if key in chosen:
                continue
            cost = ACTIONS[key].effort
            if effort + cost > budget + 1e-9:
                continue
            dfs(i + 1, chosen + [key], effort + cost, apply_action(current, key))

    dfs(0, [], 0.0, dict(features))
    return {
        "method": "exact",
        "actions": best["actions"],
        "total_effort": round(best["effort"], 4),
        "risk_after": round(best["risk_after"], 4),
    }


def compare(
    features: dict[str, float],
    *,
    budget: float,
    candidate_actions: list[str] | None = None,
    criticality: int | None = None,
) -> dict:
    """Run both methods and compute the measured optimality gap.

    Gap is relative to the best achievable improvement:
        gap = (greedy_reduction - exact_reduction) / exact_reduction   (if >0 else 0)
    Greedy may have the SAME risk_after as exact (gap 0); it is still never
    labelled optimal.

    ``criticality`` is the SAME asset-criticality context the risk engine used
    for this run: the planner re-evaluates the real (importance-adjusted)
    function, so ``initial_risk`` equals the run's score and risk_after values
    are comparable with it.
    """
    import time

    initial_risk = _risk(features, criticality)

    start = time.perf_counter()
    greedy = greedy_plan(
        features, budget=budget, candidate_actions=candidate_actions, criticality=criticality
    )
    greedy_ms = (time.perf_counter() - start) * 1000.0

    start = time.perf_counter()
    exact = exact_plan(
        features, budget=budget, candidate_actions=candidate_actions, criticality=criticality
    )
    exact_ms = (time.perf_counter() - start) * 1000.0

    greedy_reduction = initial_risk - greedy["risk_after"]
    exact_reduction = initial_risk - exact["risk_after"]
    # Relative shortfall of greedy vs. the best achievable improvement. Positive
    # when greedy is worse than exact. Zero when they tie (greedy is still never
    # labelled optimal).
    if exact_reduction > 1e-9:
        gap = max(0.0, (exact_reduction - greedy_reduction) / exact_reduction)
    else:
        gap = 0.0

    is_trap = greedy["risk_after"] > exact["risk_after"] + 1e-6

    return {
        "initial_risk": round(initial_risk, 4),
        "greedy": {**greedy, "risk_reduction": round(greedy_reduction, 4), "compute_ms": round(greedy_ms, 4)},
        "exact": {**exact, "risk_reduction": round(exact_reduction, 4), "compute_ms": round(exact_ms, 4)},
        "optimality_gap": round(gap, 6),
        "is_greedy_trap": is_trap,
    }