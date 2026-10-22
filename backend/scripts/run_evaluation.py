"""Evaluation harness (Phase 13).

Runs every measurable claim in this repo ON REAL CODE and persists the results to
``evaluation_records``. The dashboard reads ONLY these persisted rows, so nothing
in the UI can show an unmeasured number.

Sections:
  1. Phishing + AI-detector metrics on the synthetic disjoint-template test split.
  2. Remediation planner greedy-vs-exact optimality gap over a scenario suite
     (including a deliberately constructed greedy trap).
  3. Shapley efficiency + timing benchmark.
  4. Correlation engine scenario coverage.

Usage (from repo root):
    .venv\\Scripts\\python.exe backend\\scripts\\run_evaluation.py
"""
from __future__ import annotations

import statistics
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.db import SessionLocal, init_db  # noqa: E402
from app.engine import planner, risk, shapley  # noqa: E402
from app.ml.trainer import evaluate, train_all  # noqa: E402
from app.models import EvaluationRecord  # noqa: E402


def _clear_previous(db, suites: list[str]) -> None:
    from sqlalchemy import delete

    db.execute(delete(EvaluationRecord).where(EvaluationRecord.suite.in_(suites)))
    db.commit()


def _record(db, suite: str, metric: str, value: float, details: dict | None = None) -> None:
    db.add(
        EvaluationRecord(
            suite=suite, metric_name=metric, metric_value=float(value), details=details or {}
        )
    )


def _scenarios() -> list[dict]:
    """Deterministic scenario suite for the planner benchmark."""
    def feat(**kw):
        base = {name: 0.0 for name in risk.ALL_FEATURES}
        base.update(kw)
        return base

    return [
        {"name": "breach_only", "features": feat(breach=0.8), "budget": 6.0,
         "candidate_actions": list(planner.ACTIONS), "trap": False},
        {"name": "breach_reuse_no_mfa", "features": feat(breach=0.8, reuse=0.8, no_mfa=0.8),
         "budget": 6.0, "candidate_actions": list(planner.ACTIONS), "trap": False},
        {"name": "session_exposure_suite",
         "features": feat(session=0.9, no_mfa=0.7, breach=0.7), "budget": 6.0,
         "candidate_actions": list(planner.ACTIONS), "trap": False},
        {"name": "sim_swap_chain",
         "features": feat(sim_swap=0.7, no_mfa=0.7, reuse=0.6), "budget": 6.0,
         "candidate_actions": list(planner.ACTIONS), "trap": False},
        {"name": "permission_phishing",
         "features": feat(permissions=0.8, phishing=0.8, identity=0.6), "budget": 6.0,
         "candidate_actions": list(planner.ACTIONS), "trap": False},
        # Deliberately constructed greedy trap: cheap high-ratio actions lure greedy
        # away from the pricier combinations that unlock large compounding
        # reductions. Budget is tuned so greedy cannot take everything.
        {"name": "greedy_trap_constructed",
         "features": feat(breach=0.8, reuse=0.8, no_mfa=0.8),
         "budget": 2.0,
         "candidate_actions": ["change_reused_password", "strengthen_mfa"],
         "trap": True},
        {"name": "full_stack",
         "features": feat(breach=0.9, session=0.8, reuse=0.8, no_mfa=0.9, sim_swap=0.7,
                          phishing=0.7, permissions=0.7, identity=0.6, push_bombing=0.6,
                          dependency=0.6),
         "budget": 8.0, "candidate_actions": list(planner.ACTIONS), "trap": False},
    ]


def evaluate_planner(db) -> dict:
    gaps = []
    trap_hits = 0
    rows = []
    for scenario in _scenarios():
        comparison = planner.compare(
            scenario["features"], budget=scenario["budget"], candidate_actions=scenario["candidate_actions"]
        )
        gaps.append(comparison["optimality_gap"])
        if comparison["is_greedy_trap"]:
            trap_hits += 1
        rows.append((scenario, comparison))

    _record(db, "planner", "mean_optimality_gap", statistics.mean(gaps))
    _record(db, "planner", "max_optimality_gap", max(gaps))
    _record(db, "planner", "scenario_count", float(len(gaps)))
    _record(db, "planner", "greedy_trap_scenarios_constructed",
            float(sum(1 for s in _scenarios() if s["trap"])))
    _record(db, "planner", "greedy_trap_observed", float(trap_hits))

    details = [
        {
            "scenario": name,
            "greedy_risk_after": comparison["greedy"]["risk_after"],
            "exact_risk_after": comparison["exact"]["risk_after"],
            "gap": comparison["optimality_gap"],
            "is_trap": comparison["is_greedy_trap"],
        }
        for name, comparison in [(s["name"], c) for s, c in rows]
    ]
    _record(db, "planner", "per_scenario", statistics.mean(gaps), {"scenarios": details})
    return {"gaps": gaps, "trap_hits": trap_hits}


def evaluate_shapley(db) -> dict:
    import random

    rng = random.Random(99)
    errors = []
    times = []
    for _ in range(50):
        features = {name: rng.random() for name in risk.ALL_FEATURES}
        result = shapley.attribute(features)
        errors.append(result["efficiency_error"])
        times.append(result["compute_ms"])
    _record(db, "shapley", "max_efficiency_error", max(errors))
    _record(db, "shapley", "mean_compute_ms", statistics.mean(times))
    _record(db, "shapley", "max_compute_ms", max(times))
    _record(db, "shapley", "n_features", float(len(risk.ALL_FEATURES)))
    _record(db, "shapley", "samples", float(len(errors)))
    return {"max_error": max(errors), "mean_ms": statistics.mean(times)}


def evaluate_ml(db) -> dict:
    if not (BACKEND / "artifacts" / "phishing_model.joblib").exists():
        train_all()
    metrics = evaluate()
    phish = metrics["phishing"]
    ai = metrics["ai_generated"]
    for name, value in phish.items():
        if isinstance(value, (int, float)):
            _record(db, "phishing_classifier", name, float(value))
    _record(db, "phishing_classifier", "total_evaluated",
            float(sum(sum(row) for row in phish["confusion_matrix"])),
            {"matrix": phish["confusion_matrix"], "labels": ["legit", "phishing"]})
    for name, value in ai.items():
        if isinstance(value, (int, float)):
            _record(db, "ai_text_detector", name, float(value))
    _record(db, "ai_text_detector", "total_evaluated",
            float(sum(sum(row) for row in ai["confusion_matrix"])),
            {"matrix": ai["confusion_matrix"], "labels": ["human", "ai"]})
    return {"phishing": phish, "ai": ai, "dataset": metrics["dataset"]}


def evaluate_correlations(db) -> dict:
    from app.data.loader import correlation_rules
    from app.engine.correlation import evaluate as corr_eval
    from app.schemas import ExposureType, SecurityEventSchema

    def ev(etype, **meta):
        return SecurityEventSchema(
            event_id=f"eval_{etype}_{len(meta)}", user_id="u", account_id="a",
            event_type=etype, severity=0.6, confidence=0.8, source="eval",
            status="FINDING", metadata=meta or {},
        )

    scenario_map = {
        "credential_stuffing_risk": [ev("BREACH_EXPOSURE"), ev("PASSWORD_REUSE")],
        "targeted_credential_theft": [ev("PHISHING_MESSAGE_DETECTED"), ev("IDENTITY_EXPOSED")],
        "cascading_recovery_risk": [ev("COMPROMISED_RECOVERY_ACCOUNT"), ev("ACCOUNT_DEPENDENCY")],
        "elevated_takeover_risk": [ev("BREACH_EXPOSURE"), ev("MFA_MISSING")],
        "mfa_ineffective_session_exposure": [
            SecurityEventSchema(
                event_id="eval_session", user_id="u", account_id="a",
                event_type="SESSION_EXPOSURE", exposure_type=ExposureType.SESSION_ONLY,
                severity=0.9, confidence=0.5, source="eval", status="FINDING",
                metadata={"mfa_bypass_capable": True},
            )
        ],
        "identity_reuse_blend": [ev("BREACH_EXPOSURE"), ev("PASSWORD_REUSE"), ev("MFA_MISSING")],
        "sim_swap_recovery_exposure": [ev("SIM_SWAP_VULNERABLE"), ev("MFA_MISSING")],
        "oversharing_and_phishing": [ev("RISKY_PERMISSION_GRANTED"), ev("PHISHING_MESSAGE_DETECTED")],
    }
    total_rules = len(correlation_rules())
    fired = 0
    for rule_id, events in scenario_map.items():
        ids = {c.rule_id for c in corr_eval(events)}
        if rule_id in ids:
            fired += 1
    _record(db, "correlation", "rules_defined", float(total_rules))
    _record(db, "correlation", "rules_exercised_by_scenario_suite", float(fired))
    _record(db, "correlation", "scenario_pass_rate", fired / max(1, len(scenario_map)))
    return {"rules": total_rules, "fired": fired}


def main() -> None:
    init_db()
    db = SessionLocal()
    suites = ["phishing_classifier", "ai_text_detector", "planner", "shapley", "correlation"]
    try:
        _clear_previous(db, suites)
        print("Evaluating ML models...")
        ml = evaluate_ml(db)
        print(f"  phishing  F1={ml['phishing']['f1']:.3f} on {ml['phishing']['n_samples']} samples")
        print(f"  ai-detect F1={ml['ai']['f1']:.3f} on {ml['ai']['n_samples']} samples")
        print("Evaluating planner...")
        pl = evaluate_planner(db)
        print(f"  mean optimality gap={statistics.mean(pl['gaps']):.4f}, traps observed={pl['trap_hits']}")
        print("Evaluating Shapley...")
        sh = evaluate_shapley(db)
        print(f"  max efficiency error={sh['max_error']:.2e}, mean {sh['mean_ms']:.1f} ms")
        print("Evaluating correlations...")
        co = evaluate_correlations(db)
        print(f"  {co['fired']}/{co['rules']} rules exercised")
        db.commit()
        print("Persisted evaluation records. View via GET /api/evaluation.")
    finally:
        db.close()


if __name__ == "__main__":
    main()