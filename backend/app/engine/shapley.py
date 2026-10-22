"""Exact cooperative-game Shapley attribution over the CRIX risk function (§7).

We treat each feature group as a player in a cooperative game whose
characteristic function is ``v(S) = risk_from_features(features restricted to S)``
with base value ``v(empty) = 0``. This is an EXACT computation (no sampling, no
approximation) because the number of features is small (2^n subsets, n = 12).

Two properties fall out and are tested:
- Efficiency: sum_i phi_i == v(full) - v(empty) == the total risk score.
- Symmetry / null player: a feature that never changes the score gets phi_i = 0.

This explains the REAL deterministic CRIX function — it does not train a model on
CRIX's own outputs (§0.5).
"""
from __future__ import annotations

import math
import time
from functools import lru_cache

from app.engine.risk import ALL_FEATURES, risk_from_features

N_FEATURES = len(ALL_FEATURES)


def _weight(subset_size: int, n: int) -> float:
    # Shapley weight: |S|!(n-|S|-1)!/n!
    return math.factorial(subset_size) * math.factorial(n - subset_size - 1) / math.factorial(n)


def shapley_values(features: dict[str, float]) -> tuple[dict[str, float], float]:
    """Return (contributions_by_feature, total_risk). Exact enumeration."""
    n = N_FEATURES
    order = list(ALL_FEATURES)
    values = [float(features.get(name, 0.0)) for name in order]

    @lru_cache(maxsize=None)
    def v(mask: int) -> float:
        if mask == 0:
            return 0.0
        subset = {order[i]: values[i] for i in range(n) if mask & (1 << i)}
        score, _ = risk_from_features(subset)
        return score

    full_mask = (1 << n) - 1
    total = v(full_mask)

    contributions: dict[str, float] = {}
    for i in range(n):
        bit = 1 << i
        phi = 0.0
        # Enumerate subsets S that do NOT contain i.
        for mask in range(1 << n):
            if mask & bit:
                continue
            size = bin(mask).count("1")
            phi += _weight(size, n) * (v(mask | bit) - v(mask))
        contributions[order[i]] = round(phi, 9)

    return contributions, round(total, 9)


def attribute(events_features: dict[str, float]) -> dict:
    """Attribution wrapper adding timing and an explicit efficiency check."""
    start = time.perf_counter()
    contributions, total = shapley_values(events_features)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    summed = sum(contributions.values())
    return {
        "method": "exact_shapley",
        "total_risk": total,
        "contributions": contributions,
        "sum_of_contributions": round(summed, 9),
        "efficiency_error": abs(summed - total),
        "compute_ms": round(elapsed_ms, 4),
    }