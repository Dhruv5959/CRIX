"""Planner gap report (Phase 7): measured greedy-vs-exact, honestly labelled.

Runs the planner comparison on this repo's own scenarios and prints the
MEASURED gap — never a claimed one. Includes:

  * the deterministic suite (shared with ``run_evaluation.py`` so the two
    reports can never drift);
  * a deliberately constructed GREEDY TRAP (greedy is provably worse than
    exact there);
  * prerequisite-constrained scenarios (Phase 7);
  * a seeded random feature family (the seed is printed; re-running with the
    same seed reproduces every number).

No database needed. Usage (from repo root):
    .venv\\Scripts\\python.exe backend\\scripts\\report_planner_gap.py
"""
from __future__ import annotations

import random
import statistics
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.engine import planner, risk  # noqa: E402

# The seed for the random family. Printed on every run; re-running with this
# seed reproduces the exact same scenarios and numbers.
RANDOM_SEED = 20261023
RANDOM_FAMILY_SIZE = 40


def _feat(**kw) -> dict[str, float]:
    base = {name: 0.0 for name in risk.ALL_FEATURES}
    base.update(kw)
    return base


def _deterministic_suite() -> list[dict]:
    """run_evaluation's 7 deterministic scenarios + 2 prerequisite cases.

    The first seven entries are IMPORTED from ``run_evaluation._scenarios``
    (shared vectors, budgets, candidates) so the two reports can never drift;
    the two ``prereq_*`` cases are Phase 7 additions that exercise
    prerequisite ordering and infeasible-candidate reporting.
    """
    from scripts.run_evaluation import _scenarios as evaluation_scenarios

    shared = [
        {**scenario, "prerequisites": None}
        for scenario in evaluation_scenarios()
    ]

    def feat(**kw):
        base = {name: 0.0 for name in risk.ALL_FEATURES}
        base.update(kw)
        return base

    return shared + [
        # Phase 7: prerequisite-constrained scenarios. The passkey route must
        # come after strengthening MFA; the planner must respect the order and
        # report infeasible actions (here: none — both are candidates).
        {"name": "prereq_passkey_after_mfa",
         "features": feat(breach=0.7, reuse=0.7, no_mfa=0.8, sim_swap=0.6),
         "budget": 6.0,
         "candidate_actions": ["strengthen_mfa", "enable_passkey", "change_reused_password"],
         "prerequisites": {"enable_passkey": ["strengthen_mfa"]},
         "trap": False},
        # A prerequisite that can never hold (the prerequisite action is not a
        # candidate): the dependent must be reported infeasible with a reason,
        # never silently dropped and never planned.
        {"name": "prereq_infeasible_chain",
         "features": feat(breach=0.7, reuse=0.7, no_mfa=0.8),
         "budget": 6.0,
         "candidate_actions": ["enable_passkey", "change_reused_password"],
         "prerequisites": {"enable_passkey": ["strengthen_mfa"]},
         "trap": False},
    ]


def _random_family() -> list[dict]:
    """A seeded random family: reproducible feature vectors and budgets."""
    rng = random.Random(RANDOM_SEED)
    scenarios = []
    for i in range(RANDOM_FAMILY_SIZE):
        features = {name: round(rng.random(), 3) for name in risk.ALL_FEATURES}
        budget = rng.choice([1.0, 2.0, 3.0, 4.0, 6.0, 8.0])
        scenarios.append(
            {
                "name": f"random_{i:03d}",
                "features": features,
                "budget": budget,
                "candidate_actions": list(planner.ACTIONS),
                "prerequisites": None,
                "trap": False,
            }
        )
    return scenarios


def _prereq_random_family() -> list[dict]:
    """Seeded random features WITH a fixed prerequisite constraint."""
    rng = random.Random(RANDOM_SEED + 1)
    scenarios = []
    for i in range(10):
        features = {name: round(rng.random(), 3) for name in risk.ALL_FEATURES}
        scenarios.append(
            {
                "name": f"random_prereq_{i:03d}",
                "features": features,
                "budget": rng.choice([3.0, 5.0, 6.0, 8.0]),
                "candidate_actions": ["strengthen_mfa", "enable_passkey", "revoke_session"],
                "prerequisites": {"enable_passkey": ["strengthen_mfa"]},
                "trap": False,
            }
        )
    return scenarios


def main() -> int:
    suites = [
        ("deterministic", _deterministic_suite()),
        (f"random(seed={RANDOM_SEED})", _random_family()),
        (f"random_prereq(seed={RANDOM_SEED + 1})", _prereq_random_family()),
    ]

    all_gaps: list[float] = []
    traps_observed = 0
    traps_constructed = 0
    total = 0

    header = (
        f"{'scenario':<28} {'budget':>6} {'greedy':>8} {'exact':>8} "
        f"{'gap':>9} {'trap':>5} {'infeas':>6}"
    )
    print("=" * len(header))
    print("PLANNER GAP REPORT — measured greedy vs. exact (never claimed)")
    print("=" * len(header))
    for suite_name, scenarios in suites:
        print(f"\n--- suite: {suite_name} ({len(scenarios)} scenarios) ---")
        print(header)
        for scenario in scenarios:
            comparison = planner.compare(
                scenario["features"],
                budget=scenario["budget"],
                candidate_actions=scenario["candidate_actions"],
                prerequisites=scenario["prerequisites"],
            )
            gap = comparison["optimality_gap"]
            all_gaps.append(gap)
            total += 1
            if scenario["trap"]:
                traps_constructed += 1
            if comparison["is_greedy_trap"]:
                traps_observed += 1
            infeasible_count = len(comparison["greedy"].get("infeasible", []))
            print(
                f"{scenario['name']:<28} {scenario['budget']:>6.1f} "
                f"{comparison['greedy']['risk_after']:>8.3f} "
                f"{comparison['exact']['risk_after']:>8.3f} "
                f"{gap:>9.6f} "
                f"{'YES' if comparison['is_greedy_trap'] else '-':>5} "
                f"{infeasible_count:>6}"
            )

    print("\n" + "=" * len(header))
    print("SUMMARY")
    print("=" * len(header))
    print(f"scenarios evaluated      : {total}")
    print(f"seeds                    : deterministic suite has none (fixed "
          f"vectors); random family seed = {RANDOM_SEED}; "
          f"prereq random family seed = {RANDOM_SEED + 1}")
    print(f"mean optimality gap      : {statistics.mean(all_gaps):.6f}")
    print(f"max optimality gap       : {max(all_gaps):.6f}")
    print(f"scenarios with gap > 0   : {sum(1 for g in all_gaps if g > 1e-9)}")
    print(f"greedy traps constructed : {traps_constructed}")
    print(f"greedy traps observed    : {traps_observed}")
    print(
        "\nLabels: greedy is an APPROXIMATE baseline (never optimal, never "
        "labelled optimal); exact is proven optimal over the given candidates "
        "and budget only. A gap of 0 means the two agreed on this scenario — "
        "not that greedy is optimal."
    )
    if traps_constructed and not traps_observed:
        print(
            "\nWARNING: a constructed greedy trap did NOT manifest — the "
            "engine changed behavior. Investigate before reporting any gap."
        )
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
