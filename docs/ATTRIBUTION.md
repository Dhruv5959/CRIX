# CRIX-SMB Attribution Model Specification (Shapley, Phase 5)

**Status:** implemented, tested (35 dedicated tests + full suite), verified on
the real dev database. **This document is the authoritative description of the
cooperative game; the code must match it or a test fails.**

*Attribution explains a score. It never overrides, re-derives, or re-computes
the score, and it never assigns causation — a contribution is how much one
factor moved THIS score, nothing more.*

---

## 1. The game, stated precisely

Attribution is a cooperative game over the Phase 4 deterministic risk function.

| Element | Definition |
|---|---|
| **Players** | The 12 feature groups of the risk function (10 risk features + 2 mitigation features), i.e. `risk.ALL_FEATURES`. |
| **Value function** | `v(S) = risk_from_features(features restricted to S, criticality=criticality)` — the REAL Phase 4 function, run on only the features in coalition `S`. Every feature NOT in `S` is set to its *absent* value (0.0). Nothing else may define `v`. |
| **Baseline** | `v(∅) = 0`. The empty coalition holds every feature absent, and the documented function scores that as exactly 0. Asserted by a test, not assumed. |
| **Absent factor** | A feature not in a coalition (or an input of exactly 0.0) contributes 0 to that coalition. **Absent is an explicit state — it is NOT "safe"**, it means "not part of this coalition". |
| **Clipping** | The value function clips its output to `[0, 100]` (Phase 4). Clipping is part of `v`, so the Shapley values describe the *clipped* score honestly; they are not the values of the un-clipped inner expression. |
| **Residual / efficiency** | By construction `Σᵢ φᵢ == v(full) − v(∅)`. The returned `residual` is that difference minus the summed contributions (the efficiency error). A residual within `1e-6` is the exact guarantee. |
| **Criticality is CONTEXT, not a player** | The org-scoped asset criticality is held fixed across every coalition, so the game explains the score *as computed for that asset* and efficiency stays exact. It is not a player; promoting it to one is a documented future decision, not done here. |

**Why criticality is context, not a player.** Promoting it to a player would
mean treating "how much the company cares about this asset" as a factor that
could be switched on and off alongside the evidence. But the score's criticality
term is a *multiplier* on the evidence, not independent evidence: it cannot
create risk on its own (Phase 4 proves `score == 0` with zero findings at every
criticality). Holding it fixed keeps efficiency exact and keeps the attribution
explaining the *actual* displayed score. This is a deliberate, documented
choice.

---

## 2. Two ways to compute — never conflated

1. **`method="exact_shapley"`** (the default and the reference) — exact
   enumeration over all `2^n` coalitions with memoization. This is the
   authoritative attribution and the only one the deterministic pipeline uses.
2. **`method="seeded_approximate_shapley"`** — a seeded permutation-sampling
   approximation. It exists ONLY to demonstrate, and be tested against, the
   exact answer. Its seed and sample count are recorded so it is reproducible,
   and its error vs the exact values is measured and reported.

**The exact-vs-approx distinction is part of the output contract, not hidden.**
The approximation's `is_exact` is `False` and its sampling `seed`/`samples` are
surfaced. (A correctness detail: the approximation always evaluates the full
coalition, so it happens to preserve `v(full)` exactly — its residual can be
near zero while its per-factor values are still sampled. Therefore `is_exact`
tracks the *method*, not the residual, so a near-zero residual on an
approximation is never mislabelled as exact.)

### 2.1 Exactness guarantee and cost

`2^n` subsets with `n = 12` → 4096 coalitions, memoized. Deterministic, no
sampling, no model trained on CRIX's own outputs (§0.5). Efficiency holds to
numerical noise (~1e-9).

### 2.2 Seeded approximation

For each of `samples` random player orderings (drawn from a seeded RNG), a
player's marginal contribution is measured against the players ordered before
it; the average over orderings estimates its Shapley value. Standard sampling
estimator. `samples >= 1` (0 is rejected). Reproducible for a fixed seed.

### 2.3 Limits (honest, actionable status)

| Limit | Status |
|---|---|
| Approximation error | Real, measured, surfaced: `per_factor_abs_error`, `max_factor_abs_error`, `mean_factor_abs_error`, `total_abs_error` from `compare_exact_vs_approximate`. |
| Approximation is never authority | The pipeline never uses it; `is_exact=False` and it is labelled in method and UI. |
| Exact cost | `2^12` = 4096 coalitions, memoized, benchmarked < 2 s (measured ~69 ms). Cheap enough that the approximation is a demonstration, not a necessity. |
| Attribution ≠ causation | A contribution is how much a factor moved this score. It is not the likelihood of any event and not an account of what happened. Stated in `plain_language`. |
| Negative ≠ safe | A negative contribution (a mitigation lowering risk) is still one measured factor, not an all-clear. Stated in `plain_language`. |

---

## 3. Output contract

Every attribution payload carries:

| Key | Content |
|---|---|
| `method` | `"exact_shapley"` or `"seeded_approximate_shapley"`. |
| `is_exact` | `True` only for the exact reference. |
| `total_risk` | `v(full)` — equals the displayed score for this criticality. |
| `contributions` | Per-feature Shapley values. |
| `sum_of_contributions`, `efficiency_error`, `residual` | The efficiency evidence, surfaced not hidden. |
| `compute_ms` | Real benchmark. |
| `criticality_context` | The org-scoped criticality the game used (or `None`). |
| `baseline` | `{"v_empty": 0.0, "note": ...}` — the documented baseline. |
| `absent_factor_note` | Absent is not safe. |
| `clipping_note` | Contributions explain the clipped score. |
| `breakdown` | `raising` / `lowering` / `neutral` split for the UI. |
| `plain_language` | Honest wording that never claims causation, probability of compromise, or safety. |
| `samples`, `seed` | Present only on the approximation. |

---

## 4. Worked demo (real, reproducible)

Seed demo: findings bound to `demo@example.com`, criticality **4**. The
attribution total equals the score **67.87**, efficiency error **0.0**, and the
waterfall explains each feature's exact contribution — summing exactly to the
total. (`docs/PROGRESS.md` records the seed run.)

---

## 5. Honest limitations

* Shapley values explain the *function*, not the world: they say how the score
  is composed, not what is likely to happen.
* The value function is the clipped, criticality-scaled Phase 4 function, so
  contributions are bounded by it and can never exceed the score.
* Criticality is context (§1), so its own effect is folded into every
  contribution rather than shown as a separate player.
* The seeded approximation is a demonstration of the exact-vs-approx gap, not a
  production path.
* Attribution is per-run and org-scoped; cross-tenant factors are never
  aggregated (tested).
