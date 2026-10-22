"""Remediation planner (§9, Phase 7).

Exactly TWO methods are compared:
  1. greedy baseline  — repeatedly pick the action with the best
     risk-reduction-per-unit-effort that still fits the budget.
  2. exact branch-and-bound — optimal over the bounded action set.

Greedy is NEVER described as optimal. The optimality gap is measured on our own
scenarios inside this repo, and the scenario set includes a deliberately
constructed "greedy trap" where greedy provably does worse than exact.

Actions operate on the SAME feature vector the risk engine uses, so the planner
re-runs the real risk function — nothing here is a separate toy model.

Phase 7 extensions (all additive; the earlier contracts still hold):
  * prerequisites — an action is only selectable once its prerequisite actions
    are chosen; candidates whose prerequisites can never hold are reported as
    INFEASIBLE with a reason, never silently dropped;
  * deterministic tie-breaks — equal ratios resolve on lower effort, then the
    lexicographic key, independent of dict insertion order;
  * partial-budget results — every plan reports what it could not spend;
  * ``pack_budget`` — the shared greedy-by-score/effort packer that the API
    planner (Phase 7) and the evaluation baselines (Phase 12) both call, so a
    baseline can never drift from what the product shows.
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


# --------------------------------------------------------------------------- #
# Prerequisites (Phase 7): an action is selectable only after its prerequisites
# --------------------------------------------------------------------------- #
def normalize_prerequisites(
    candidates: list[str],
    prerequisites: dict[str, list[str]] | None,
) -> tuple[dict[str, tuple[str, ...]], list[dict]]:
    """Validate prerequisites against the candidate set (pure, deterministic).

    Returns ``(usable, infeasible)`` where ``usable`` maps every candidate with
    valid prerequisites to a canonical tuple, and ``infeasible`` lists actions
    whose prerequisites reference actions outside the candidate set — reported
    with a reason, never silently dropped. Cycles are reported separately by
    :func:`topological_order`.
    """
    prerequisites = prerequisites or {}
    candidate_set = set(candidates)
    usable: dict[str, tuple[str, ...]] = {}
    infeasible: list[dict] = []
    for key in sorted(candidate_set):
        raw = prerequisites.get(key, ())
        ordered = tuple(sorted({str(p) for p in raw}))
        unknown = [p for p in ordered if p not in candidate_set]
        if unknown:
            infeasible.append(
                {
                    "action": key,
                    "reason": "prerequisite_not_a_candidate",
                    "detail": sorted(unknown),
                }
            )
            continue
        usable[key] = ordered
    return usable, infeasible


def topological_order(
    candidates: list[str],
    prereqs: dict[str, tuple[str, ...]],
) -> tuple[list[str], list[dict]]:
    """Deterministic prerequisite-before-dependent order (Kahn, lexicographic).

    Returns ``(order, infeasible)``. Candidates caught in a prerequisite cycle
    can never all be selected, so they are excluded and reported with
    ``reason="prerequisite_cycle"`` — the plan is still produced for the rest.
    """
    remaining = {key: set(prereqs.get(key, ())) for key in sorted(set(candidates))}
    infeasible: list[dict] = []
    order: list[str] = []
    while remaining:
        ready = sorted(key for key, deps in remaining.items() if not deps)
        if not ready:
            for key in sorted(remaining):
                infeasible.append(
                    {"action": key, "reason": "prerequisite_cycle", "detail": sorted(remaining[key])}
                )
            break
        for key in ready:
            order.append(key)
            remaining.pop(key)
            for deps in remaining.values():
                deps.discard(key)
    return order, infeasible


def _normalize_efforts(efforts: dict[str, float] | None) -> dict[str, float]:
    """Validate a per-task effort override (Phase 7): positive numbers only.

    An organization may adjust an action's effort (its MFA rollout really is
    harder here). The override is an input like any other — validated, never
    silently accepted — and the catalog effort stays the default.
    """
    if not efforts:
        return {}
    cleaned: dict[str, float] = {}
    for key, value in efforts.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"effort override for {key!r} must be a number, got {value!r}")
        effort = float(value)
        if not effort > 0:
            raise ValueError(f"effort override for {key!r} must be > 0, got {value!r}")
        cleaned[str(key)] = effort
    return cleaned


def _effort_of(key: str, efforts: dict[str, float]) -> float:
    """The effort of one action: the org override if given, else the catalog."""
    return efforts.get(key, ACTIONS[key].effort)


def expected_reduction(
    features: dict[str, float],
    action_key: str,
    *,
    criticality: int | None = None,
) -> float:
    """The modeled risk reduction of one action, computed by the real engine.

    This is the ONLY source of a task's expected reduction: the same
    ``risk_from_features`` the score used, re-evaluated with the action
    applied. It is a modeled reduction (never a promise, never invented).
    """
    if action_key not in ACTIONS:
        raise KeyError(action_key)
    before = _risk(features, criticality)
    after = _risk(apply_action(features, action_key), criticality)
    return round(before - after, 4)


def _select_better(
    ratio: float, effort: float, key: str,
    best_ratio: float, best_effort: float, best_key: str | None,
) -> bool:
    """Deterministic incumbent comparison.

    Strictly better ratio wins; on a tie (within 1e-12) the cheaper action
    wins; on another tie the lexicographically smaller key wins. Tie-breaks
    never depend on dict insertion order.
    """
    if best_key is None:
        return ratio > 1e-12
    if ratio > best_ratio + 1e-12:
        return True
    if abs(ratio - best_ratio) <= 1e-12:
        if effort < best_effort - 1e-9:
            return True
        if abs(effort - best_effort) <= 1e-9 and key < best_key:
            return True
    return False


def greedy_plan(
    features: dict[str, float],
    *,
    budget: float,
    candidate_actions: list[str] | None = None,
    criticality: int | None = None,
    prerequisites: dict[str, list[str]] | None = None,
    efforts: dict[str, float] | None = None,
) -> dict:
    """Greedy baseline: best reduction-per-effort that fits the remaining budget.

    ``prerequisites`` (optional) maps an action key to the action keys that
    must be chosen before it. Actions whose prerequisites can never hold are
    listed under ``infeasible`` with a reason; the result is ALWAYS partial-
    budget honest (``unspent_budget``) and labelled ``approximate`` — greedy
    is a baseline and is never called optimal. ``efforts`` (optional) overrides
    catalog efforts per action (validated, positive).
    """
    overrides = _normalize_efforts(efforts)
    # An explicit empty list means "no candidates" (e.g. no OPEN tasks); only
    # None falls back to the full catalog.
    candidates = list(ACTIONS.keys() if candidate_actions is None else candidate_actions)
    usable_prereqs, infeasible = normalize_prerequisites(candidates, prerequisites)
    order, cycle_infeasible = topological_order(candidates, usable_prereqs)
    infeasible = infeasible + cycle_infeasible
    excluded = {entry["action"] for entry in infeasible}

    remaining_budget = budget
    chosen: list[str] = []
    chosen_set: set[str] = set()
    current = dict(features)
    current_risk = _risk(current, criticality)

    while True:
        best_choice = None
        best_ratio = 0.0
        best_effort = 0.0
        for key in order:
            if key in chosen_set or key in excluded:
                continue
            if not set(usable_prereqs.get(key, ())) <= chosen_set:
                continue  # prerequisites not chosen (yet): not selectable
            effort = _effort_of(key, overrides)
            if effort > remaining_budget + 1e-9:
                continue
            trial = apply_action(current, key)
            reduction = current_risk - _risk(trial, criticality)
            if reduction <= 1e-9:
                continue
            ratio = reduction / effort
            if _select_better(ratio, effort, key, best_ratio, best_effort, best_choice):
                best_ratio, best_effort, best_choice = ratio, effort, key
        if best_choice is None:
            break
        chosen.append(best_choice)
        chosen_set.add(best_choice)
        remaining_budget -= _effort_of(best_choice, overrides)
        current = apply_action(current, best_choice)
        current_risk = _risk(current, criticality)

    return {
        "method": "greedy",
        "actions": chosen,
        "total_effort": round(budget - remaining_budget, 4),
        "risk_after": round(current_risk, 4),
        "unspent_budget": round(remaining_budget, 4),
        "infeasible": infeasible,
        "approximate": True,  # a baseline; never claimed optimal
    }


def exact_plan(
    features: dict[str, float],
    *,
    budget: float,
    candidate_actions: list[str] | None = None,
    criticality: int | None = None,
    prerequisites: dict[str, list[str]] | None = None,
    efforts: dict[str, float] | None = None,
) -> dict:
    """Exact branch-and-bound over the bounded action set.

    With <= ~15 candidate actions this is trivially exact (2^n subsets). The
    bound prunes any branch whose optimistic optimum (apply all remaining
    actions ON TOP OF THE CURRENT STATE — the lowest risk reachable, ignoring
    budget AND prerequisites) cannot beat the incumbent. Dropping constraints
    can only lower the bound, so it stays admissible.

    Prerequisites are respected exactly: candidates are explored in
    prerequisite-before-dependent order (deterministic; cheaper action first,
    then lexicographic, among ready actions), so every feasible subset is
    generated once. The incumbent is seeded with the (feasible) greedy plan,
    which can only improve pruning — never the optimum. Actions in
    prerequisite cycles are reported infeasible.
    """
    candidates = list(ACTIONS.keys() if candidate_actions is None else candidate_actions)
    overrides = _normalize_efforts(efforts)
    usable_prereqs, infeasible = normalize_prerequisites(candidates, prerequisites)
    order, cycle_infeasible = topological_order(candidates, usable_prereqs)
    infeasible = infeasible + cycle_infeasible
    excluded = {entry["action"] for entry in infeasible}
    # Only feasible candidates are searched; infeasible ones are reported with
    # their reason and never silently become plan members.
    order = [key for key in order if key not in excluded]
    # Topological first (prerequisites before dependents), then effort
    # ascending so feasible incumbents appear early; ties on the key.
    order = _effort_topo_order(order, usable_prereqs, overrides)

    # Seed the incumbent with the feasible greedy plan (same prerequisites), so
    # the search starts from a real plan instead of the empty one. The seed can
    # only improve pruning — the DFS still explores every feasible subset.
    seeded = greedy_plan(
        features,
        budget=budget,
        candidate_actions=candidates,
        criticality=criticality,
        prerequisites=prerequisites,
        efforts=overrides or None,
    )
    seeded_risk = _risk(apply_actions(features, seeded["actions"]), criticality)
    best = {
        "risk_after": seeded_risk,
        "actions": list(seeded["actions"]),
        "effort": seeded["total_effort"],
    }

    def optimistic(current: dict[str, float], remaining: list[str]) -> float:
        # Valid lower bound on achievable risk: applying every remaining action
        # yields the minimum of the monotone risk function over the full action
        # set; dropping budget/prerequisite feasibility can only raise the true
        # optimum, so the bound stays admissible.
        return _risk(apply_actions(current, remaining), criticality)

    def dfs(index: int, chosen: list[str], effort: float, current: dict[str, float]):
        current_risk = _risk(current, criticality)
        if current_risk < best["risk_after"] - 1e-9 or (
            abs(current_risk - best["risk_after"]) <= 1e-9 and effort < best["effort"] - 1e-9
        ):
            best["risk_after"] = current_risk
            best["actions"] = list(chosen)
            best["effort"] = effort
        if index >= len(order):
            return
        # Prune: even applying all remaining actions (from the CURRENT state)
        # cannot beat the incumbent.
        if optimistic(current, order[index:]) >= best["risk_after"] - 1e-9:
            return
        for i in range(index, len(order)):
            key = order[i]
            if key in chosen:
                continue
            if not set(usable_prereqs.get(key, ())) <= set(chosen):
                continue  # prerequisite skipped earlier: this subset is infeasible
            cost = _effort_of(key, overrides)
            if effort + cost > budget + 1e-9:
                continue
            dfs(i + 1, chosen + [key], effort + cost, apply_action(current, key))

    dfs(0, [], 0.0, dict(features))
    return {
        "method": "exact",
        "actions": best["actions"],
        "total_effort": round(best["effort"], 4),
        "risk_after": round(best["risk_after"], 4),
        "unspent_budget": round(budget - best["effort"], 4),
        "infeasible": infeasible,
        # "Proven" means: optimal over THESE candidates under THIS budget,
        # verified against exhaustive enumeration in tests. It is not a claim
        # about actions outside the candidate set.
        "proven_optimal_over_candidates": True,
    }


def _effort_topo_order(
    order: list[str],
    prereqs: dict[str, tuple[str, ...]],
    efforts: dict[str, float],
) -> list[str]:
    """Kahn's algorithm with (effort, key) priority — topological and cheap-first.

    Being topological (prerequisites first) makes the exact search enumerate
    every feasible subset exactly once; effort-first priority reaches good
    incumbents early, which is what the bound needs. Efforts honor the org
    override when one is given.
    """
    remaining = {key: set(prereqs.get(key, ())) for key in order}
    result: list[str] = []
    while remaining:
        ready = sorted(
            (key for key, deps in remaining.items() if not deps),
            key=lambda k: (_effort_of(k, efforts), k),
        )
        if not ready:  # cycles were already excluded by topological_order
            result.extend(sorted(remaining))
            break
        for key in ready:
            result.append(key)
            remaining.pop(key)
            for deps in remaining.values():
                deps.discard(key)
    return result


def pack_budget(
    features: dict[str, float],
    *,
    budget: float,
    candidate_actions: list[str] | None = None,
    criticality: int | None = None,
    prerequisites: dict[str, list[str]] | None = None,
    efforts: dict[str, float] | None = None,
) -> dict:
    """The shared budget packer: greedy by risk-reduction per unit effort.

    Phase 7's task planner and Phase 12's evaluation baselines both call THIS
    function, so a baseline can never drift from what the product shows. It is
    labelled ``approximate`` by construction: greedy is a baseline and is never
    described as optimal.
    """
    plan = greedy_plan(
        features,
        budget=budget,
        candidate_actions=candidate_actions,
        criticality=criticality,
        prerequisites=prerequisites,
        efforts=efforts,
    )
    return {
        **plan,
        "packer": "greedy_by_score_per_effort",
        "note": (
            "Shared budget packer (greedy by risk-reduction per unit effort). "
            "Approximate by construction; compare against exact_plan for the "
            "measured gap on bounded instances."
        ),
    }


def compare(
    features: dict[str, float],
    *,
    budget: float,
    candidate_actions: list[str] | None = None,
    criticality: int | None = None,
    prerequisites: dict[str, list[str]] | None = None,
    efforts: dict[str, float] | None = None,
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
        features, budget=budget, candidate_actions=candidate_actions,
        criticality=criticality, prerequisites=prerequisites, efforts=efforts,
    )
    greedy_ms = (time.perf_counter() - start) * 1000.0

    start = time.perf_counter()
    exact = exact_plan(
        features, budget=budget, candidate_actions=candidate_actions,
        criticality=criticality, prerequisites=prerequisites, efforts=efforts,
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
        "budget": budget,
        "greedy": {**greedy, "risk_reduction": round(greedy_reduction, 4), "compute_ms": round(greedy_ms, 4)},
        "exact": {**exact, "risk_reduction": round(exact_reduction, 4), "compute_ms": round(exact_ms, 4)},
        "optimality_gap": round(gap, 6),
        "is_greedy_trap": is_trap,
        "labels": {
            "greedy": "approximate baseline — never claimed optimal",
            "exact": (
                "proven optimal over these candidates under this budget "
                "(verified against exhaustive enumeration in tests)"
            ),
        },
    }