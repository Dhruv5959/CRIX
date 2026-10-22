"""Cooperative-game Shapley attribution over the CRIX risk function (§7, Phase 5).

THE GAME (documented precisely; the code must match this or a test fails):

* **Players** — the 12 feature groups of the risk function (10 risk features +
  2 mitigation features), i.e. ``risk.ALL_FEATURES``. Each player is one entry
  of the feature vector.
* **Value function** — ``v(S) = risk_from_features(features restricted to S,
  criticality=criticality)``: the REAL deterministic Phase 4 risk function, run
  on only the features in coalition ``S`` (every feature NOT in ``S`` is set to
  its *absent* value). Nothing else may define ``v``; attribution only ever
  *explains* a score, it never overrides or re-derives it.
* **Baseline** — ``v(∅) = 0``. The empty coalition holds every feature at its
  absent value, and the documented risk function scores that as exactly 0. This
  baseline is asserted by a test, not assumed.
* **Absent factor** — a feature not in a coalition (or an input of exactly 0.0)
  contributes value 0 to that coalition. Absent is an explicit, documented
  state — it is NOT "safe", it simply means "not part of this coalition".
* **Clipping** — the value function clips its output to ``[0, 100]`` (Phase 4).
  Clipping is part of ``v``, so the Shapley values describe the *clipped* score
  honestly; they are not the values of the un-clipped inner expression.
* **Residual / efficiency** — by construction ``Σᵢ φᵢ == v(full) − v(∅)``. The
  returned ``residual`` is that difference minus the summed contributions (the
  efficiency error). A residual within ``1e-6`` is the exact guarantee; the
  tests assert it, and the API surfaces it rather than hiding it.
* **Criticality is CONTEXT, not a player** — the asset criticality is held fixed
  across every coalition, so the game explains the score *as computed for that
  asset* and efficiency stays exact. Whether criticality later becomes a player
  is a documented decision (see ``docs/ATTRIBUTION.md``); it is not changed
  here.

TWO WAYS TO COMPUTE (never conflated):

1. ``method="exact_shapley"`` (the default and the reference) — exact
   enumeration over all ``2^n`` coalitions with memoization. This is the
   authoritative attribution and the only one the deterministic pipeline uses.
2. ``method="seeded_approximate_shapley"`` — a seeded permutation-sampling
   approximation. It exists ONLY to demonstrate, and be tested against, the
   exact answer: it is never the authority. Its seed and sample count are
   recorded so it is reproducible, and its error vs the exact values is
   measured and reported — the exact-vs-approx distinction is part of the
   output contract, not hidden.

This explains the REAL deterministic CRIX function — it does not train a model
on CRIX's own outputs (§0.5), and it never assigns causation: a contribution is
how much that factor moved THIS score, nothing more.
"""
from __future__ import annotations

import math
import random
import time
from functools import lru_cache

from app.engine.risk import ALL_FEATURES, risk_from_features

N_FEATURES = len(ALL_FEATURES)

# The residual (efficiency error) below which an attribution is called exact.
EXACT_TOLERANCE = 1e-6

# Documented defaults for the seeded approximation (asserted by tests).
APPROX_DEFAULT_SAMPLES = 256
APPROX_DEFAULT_SEED = 99

# Plain-language contract: what each sign means. Deliberately avoids causation
# ("caused"), probability ("probability of compromise"), and never frames a
# negative contribution as "safe" — a mitigation that lowers risk is still only
# one measured factor, not an all-clear.
_PLAIN_LANGUAGE = {
    "positive": (
        "Positive contributions raised this score: they are the factors pushing "
        "risk up right now."
    ),
    "negative": (
        "Negative contributions lowered this score (typically MFA or a passkey). "
        "Lowering risk is not the same as being safe — other factors may still "
        "be firing."
    ),
    "residual": (
        "These contributions sum to the total score (efficiency). They explain "
        "how the score is composed, not the likelihood of any event, and not an "
        "account of what happened."
    ),
}


def _weight(subset_size: int, n: int) -> float:
    # Shapley weight: |S|!(n-|S|-1)!/n!
    return math.factorial(subset_size) * math.factorial(n - subset_size - 1) / math.factorial(n)


def _make_value(features: dict[str, float], criticality: int | None):
    """Build the memoized value function ``v(mask)`` for this game.

    ``v`` is the real, clipped, criticality-aware Phase 4 risk function run on a
    coalition. ``v(0) == 0`` is the documented baseline (absent-factor state).
    """
    n = N_FEATURES
    order = list(ALL_FEATURES)
    values = [float(features.get(name, 0.0)) for name in order]

    @lru_cache(maxsize=None)
    def v(mask: int) -> float:
        if mask == 0:
            return 0.0
        subset = {order[i]: values[i] for i in range(n) if mask & (1 << i)}
        score, _ = risk_from_features(subset, criticality=criticality)
        return score

    return v


def shapley_values(
    features: dict[str, float], *, criticality: int | None = None
) -> tuple[dict[str, float], float]:
    """Exact Shapley values. Return (contributions_by_feature, total_risk).

    Exact enumeration over all ``2^n`` coalitions — no sampling. ``total_risk``
    is ``v(full)`` and equals the displayed score for this criticality.
    """
    n = N_FEATURES
    order = list(ALL_FEATURES)
    v = _make_value(features, criticality)

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


def approximate_shapley_values(
    features: dict[str, float],
    *,
    criticality: int | None = None,
    samples: int = APPROX_DEFAULT_SAMPLES,
    seed: int = APPROX_DEFAULT_SEED,
) -> tuple[dict[str, float], float]:
    """Seeded permutation-sampling approximation. NOT the authority.

    For each of ``samples`` random player orderings (drawn from a seeded RNG, so
    the result is reproducible), a player's marginal contribution is measured
    against the players ordered before it; the average over orderings estimates
    its Shapley value. This is the standard sampling estimator and is provided
    ONLY to be compared against the exact answer — the deterministic pipeline
    never uses it.

    ``samples`` must be >= 1 and ``seed`` is recorded for reproducibility.
    """
    if samples < 1:
        raise ValueError(f"samples must be >= 1, got {samples!r}")
    n = N_FEATURES
    order = list(ALL_FEATURES)
    v = _make_value(features, criticality)
    rng = random.Random(seed)

    accum = {name: 0.0 for name in order}
    for _ in range(samples):
        permutation = list(range(n))
        rng.shuffle(permutation)
        # Marginal contribution of each player given the prefix before it.
        mask = 0
        for idx in permutation:
            without = v(mask)
            with_player = v(mask | (1 << idx))
            accum[order[idx]] += with_player - without
            mask |= (1 << idx)

    contributions = {name: round(val / samples, 9) for name, val in accum.items()}
    total = v((1 << n) - 1)
    return contributions, round(total, 9)


def _residual(contributions: dict[str, float], total: float) -> float:
    """Efficiency residual: ``v(full) - v(∅) - Σ contributions``.

    For the exact method this is numerical noise (~1e-9). For the seeded
    approximation it is the real sampling error, which the contract surfaces
    honestly instead of hiding.
    """
    return round(total - sum(contributions.values()), 9)


def _signed_breakdown(contributions: dict[str, float]) -> dict:
    """Split contributions into raising / lowering / neutral for the UI."""
    raising = {k: v for k, v in contributions.items() if v > 1e-9}
    lowering = {k: v for k, v in contributions.items() if v < -1e-9}
    neutral = [k for k, v in contributions.items() if abs(v) <= 1e-9]
    return {
        "raising": dict(sorted(raising.items(), key=lambda kv: -kv[1])),
        "lowering": dict(sorted(lowering.items(), key=lambda kv: kv[1])),
        "neutral": sorted(neutral),
    }


def attribute(
    events_features: dict[str, float],
    *,
    criticality: int | None = None,
    method: str = "exact_shapley",
    samples: int = APPROX_DEFAULT_SAMPLES,
    seed: int = APPROX_DEFAULT_SEED,
) -> dict:
    """Attribution wrapper: the output contract for one run's explanation.

    The default and authoritative ``method`` is ``exact_shapley``. Passing
    ``method="seeded_approximate_shapley"`` returns the seeded approximation
    and is clearly labelled as such (``is_exact`` false) with its seed/samples
    recorded — it never silently stands in for the exact answer.

    The payload explains a score; it never re-computes, overrides, or assigns
    causation to it.
    """
    start = time.perf_counter()
    if method == "exact_shapley":
        contributions, total = shapley_values(events_features, criticality=criticality)
    elif method == "seeded_approximate_shapley":
        contributions, total = approximate_shapley_values(
            events_features, criticality=criticality, samples=samples, seed=seed
        )
    else:
        raise ValueError(
            f"unknown attribution method {method!r}; "
            "expected 'exact_shapley' or 'seeded_approximate_shapley'"
        )
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    summed = sum(contributions.values())
    residual = _residual(contributions, total)
    # `is_exact` tracks the METHOD, not the residual: the seeded approximation
    # happens to preserve v(full) exactly (it always evaluates the full
    # coalition) but its per-factor values are sampled — so a near-zero residual
    # there must NOT be reported as an exact attribution.
    is_exact = method == "exact_shapley"
    result = {
        "method": method,
        "is_exact": is_exact,
        "total_risk": total,
        "contributions": contributions,
        "sum_of_contributions": round(summed, 9),
        "efficiency_error": abs(summed - total),
        "residual": residual,
        "compute_ms": round(elapsed_ms, 4),
        "criticality_context": criticality,
        "baseline": {"v_empty": 0.0, "note": "empty coalition scores 0 by the documented function"},
        "absent_factor_note": (
            "A factor held absent (value 0) from a coalition contributes 0 to it; "
            "absent is not the same as safe."
        ),
        "clipping_note": (
            "The value function clips to [0, 100], so these contributions explain "
            "the clipped score as displayed."
        ),
        "breakdown": _signed_breakdown(contributions),
        "plain_language": dict(_PLAIN_LANGUAGE),
    }
    if method == "seeded_approximate_shapley":
        # Reproducibility metadata for the approximation only — the exact
        # authority carries no sampling parameters.
        result["samples"] = samples
        result["seed"] = seed
    return result


def compare_exact_vs_approximate(
    features: dict[str, float],
    *,
    criticality: int | None = None,
    samples: int = APPROX_DEFAULT_SAMPLES,
    seed: int = APPROX_DEFAULT_SEED,
) -> dict:
    """Measure the seeded approximation against the exact answer.

    Exact is the reference. The returned per-factor absolute errors and the
    total error are real measured values (deterministic for a fixed seed) — the
    exact-vs-approx distinction the tests and the docs require.
    """
    exact, total_exact = shapley_values(features, criticality=criticality)
    approx, total_approx = approximate_shapley_values(
        features, criticality=criticality, samples=samples, seed=seed
    )
    per_factor = {name: abs(exact[name] - approx[name]) for name in exact}
    return {
        "reference": "exact_shapley",
        "approximate_method": "seeded_approximate_shapley",
        "seed": seed,
        "samples": samples,
        "exact_contributions": exact,
        "approximate_contributions": approx,
        "per_factor_abs_error": per_factor,
        "max_factor_abs_error": round(max(per_factor.values()), 9),
        "mean_factor_abs_error": round(sum(per_factor.values()) / len(per_factor), 9),
        "total_abs_error": abs(total_exact - total_approx),
        "total_risk_exact": total_exact,
        "total_risk_approximate": total_approx,
    }
