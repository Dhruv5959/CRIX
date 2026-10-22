# CRIX-SMB Risk Model Specification (`risk-2.0`)

**Status:** implemented, tested (35 dedicated tests + full suite), verified on the
real dev database. **This document is the authoritative description of the
formula; the code must match it or a test fails.**

*Score = a deterministic, reproducible prioritization measure. It orders what to
fix first. It is not a probability, not a likelihood of any event, and not a
claim that anything was or was not compromised.*

---

## 1. The formula

```
risk = clip( m(c) × (base_risk + interaction_risk) − mitigation_credit , 0, 100 )
```

where the **asset-criticality multiplier** is

```
m(c) = 1 + step × (c − neutral)      step = 0.10, neutral = 3
c ∈ {1, 2, 3, 4, 5}   →   m ∈ {0.80, 0.90, 1.00, 1.10, 1.20}
c = None (no registered asset bound) → m = 1.00  (explicitly unadjusted)
```

and the additive identity used by the UI (exact, before clipping) is

```
risk = base_risk + interaction_risk + criticality_adjustment − mitigation_credit
criticality_adjustment = (m(c) − 1) × (base_risk + interaction_risk)
```

### 1.1 Terms

| Term | Definition |
|---|---|
| **base_risk** | `100 × Σ_g base_weight[g] × f[g]` over the 10 risk feature groups. Weights sum to exactly 1.00. |
| **interaction_risk** | `100 × Σ_(a,b) coefficient(a,b) × f[a] × f[b]` over the 8 documented pairs. This is CRIX's thesis made explicit: problems compound. Computed **from the findings themselves** — never from grouped-link (correlation) results, which cannot add points. |
| **m(c)** | The single documented way asset importance enters the score. There is no second, hidden importance bonus anywhere in `risk.py`. |
| **mitigation_credit** | `100 × (0.20·passkey + 0.12·mfa) × discount`, `discount = 1 − 0.70×session`, capped at `0.45 × (the scaled exposure)`. Mitigations offset; they never erase the evidence. |
| **clip(·, 0, 100)** | Final bounds. `LOW < 25 ≤ MODERATE < 50 ≤ HIGH < 75 ≤ CRITICAL`. |

### 1.2 Parameters (verbatim from `RISK_PARAMS`, pinned by tests)

```python
base_weights = {breach .15, session .16, identity .05, reuse .10, no_mfa .12,
                sim_swap .08, push_bombing .08, phishing .10, permissions .08,
                dependency .08}                     # Σ = 1.00
interactions = {(breach,reuse) .10, (breach,no_mfa) .10, (session,no_mfa) .08,
                (phishing,identity) .06, (dependency,session) .08,
                (reuse,no_mfa) .06, (permissions,phishing) .05,
                (sim_swap,no_mfa) .05}
mitigation_weights = {passkey .20, mfa .12}
session_mitigation_discount = 0.70
max_mitigation_credit = 0.45        # of the scaled exposure
criticality = {min 1, max 5, neutral 3, step_per_level 0.10}
SENSITIVITY_DELTA = 0.05            # ±5% perturbation for the range
```

Severity is the feature intensity: a finding's severity **is** `f[g]` — severity
is already normalized to `[0, 1]` by the schema (`ge=0, le=1`), and the engine
additionally **rejects** (raises `ValueError`) any intensity outside `[0, 1]`,
NaN, or non-numeric rather than silently clipping it.

## 2. Asset criticality — the input and how it is resolved

`c` is resolved **server-side, organization-scoped**, in
`pipeline.resolve_org_criticality`:

1. Candidates = findings (`status == FINDING`) that are **bound to an asset**
   (`asset_id`) and whose row's `org_id` equals the run's organization.
2. Each candidate is looked up through `entities.assert_asset_in_org`
   (filters on `org_id`): an asset id registered in another tenant resolves to
   nothing — the reference is **rejected as an input (fail-closed)** and listed
   in `components.unresolved_assets` with an explicit reason
   (`finding_not_in_this_organization` /
   `not_a_registered_asset_in_this_organization`).
3. `c = max(criticality of resolved assets)` — the most important affected
   asset drives prioritization; ties break on the sorted asset id.
4. Status recorded: `REGISTERED` (≥1 resolved) | `UNBOUND` (no bound findings) |
   `UNRESOLVED` (candidates existed, none resolved) | `NO_ORGANIZATION`.

**Properties (each pinned by a test):**

* Criticality **alone never creates risk**: `score == 0` with zero findings at
  every `c`, including 5. Importance scales evidence; it is not evidence.
* Missing (`None`) criticality is recorded as an **unknown input**, with an
  uncertainty note stating the score "was not adjusted for asset importance…
  not evidence that the asset does not matter." It is never presented as safe.
* A client-supplied criticality/score/org in the request body is **ignored** —
  the endpoint takes no such parameter and the server resolves its own.
* `c` out of range (`0`, `6`, `3.5`, `"3"`, `True`, …) raises `ValueError`
  (defense in depth behind the API's `Field(ge=1, le=5)`).

## 3. What the score does NOT consume

* **Grouped-link (correlation) results.** `risk.py` never references them
  (a test reads the module source and asserts the substring never appears).
  A firing correlation changes nothing in the score; a test proves a declared
  dependency edge changes the correlation set but not the score. Each score
  records `components.correlations_consumed = {"ids": [], "note": …}` so the
  boundary is visible in the payload, not just in the code.
* **Client input.** Server-side computation only.
* **GraphRAG output.** Explanations read the score; they never write it.
* **Anything not in §1.** No new points, no per-asset feature re-scoping
  (documented limitation: interaction pairs are evaluated on the run's feature
  vector, not per account — preserved deliberately from the original model).

## 4. Missing, unavailable, conflicting, duplicated inputs

| Case | Behavior |
|---|---|
| `UNAVAILABLE` / `UNAVAILABLE_THROUGH_PROVIDER` / `NOT_CHECKED` events | Contribute **nothing** (score 0 if they are all you have) **and** are listed in `components.unavailable_inputs` with an uncertainty note: *"unavailable is not the same as safe"*. |
| No criticality | `m = 1.0`, recorded as unknown (§2.4). |
| Duplicated findings (same issue, two event ids) | Feature intensity = **max** severity in the group → identical score; `finding_ids` still lists every id consumed. |
| Conflicting evidence (a finding + a checked-safe for the same control) | Both enter the documented terms: the finding sets the risk intensity, the checked-safe sets the mitigation credit — resolved by the formula, not by ad-hoc rules. |
| Severity out of `[0,1]` | Rejected by the schema and by `_validate_features` (`ValueError`). |

## 5. Determinism and traceability

Identical inputs produce byte-identical scores **and traces**, regardless of
event order (`finding_ids` and `unavailable_inputs` are sorted; interactions
follow the fixed parameter order). Every score carries, in `components`:

| Key | Content |
|---|---|
| `features` | The exact feature vector used |
| `model_version` | `"risk-2.0"` |
| `criticality`, `criticality_multiplier` | The input and the multiplier applied |
| `criticality_status`, `asset_ids`, `asset_criticalities`, `primary_asset_id`, `unresolved_assets` | Full resolution context |
| `finding_ids` | Every event id the calculation consumed |
| `interaction_terms` | Fired terms with coefficient and value (trace rows only — their sum equals `interaction_risk`, they add nothing) |
| `mitigation` inputs | via `features` (`passkey`, `mfa`, `session`) + `mitigation_credit` |
| `unavailable_inputs`, `uncertainty` | What is unknown, stated next to the score |
| `org_id`, `correlations_consumed` | Provenance of the run and the explicit "nothing else was consumed" |

Persisted snapshots (`risk_results`) additionally store `org_id` (indexed),
`asset_id` (the primary/most-important affected asset), `model_version`, and
`criticality_adjustment` as first-class columns.

## 6. Versioning and snapshots

* `RISK_MODEL_VERSION = "risk-2.0"` — the contextual formula specified here.
* `"risk-1.0"` — the pre-Phase-4 formula (no criticality term). Rows that
  existed before the migration are stamped `risk-1.0` with
  `criticality_adjustment = 0.0` by the migration's back-fill, because that is
  the formula that actually produced them.
* A snapshot is **inserted per run, never rewritten.** Changing the formula
  changes future rows only; historical rows keep their own model version (test:
  a `risk-1.0` row survives a new run byte-for-byte).

## 7. Consumers must use the same context

Attribution (`shapley.attribute`), the planner (`planner.compare`), what-if,
propagation simulation, and the sensitivity range all receive the **same**
`criticality` as the risk call, so:

* Shapley efficiency holds against the displayed score
  (`Σ contributions == score`, error < 1e-6);
* `planner.comparison.initial_risk == score`;
* the sensitivity range always brackets the point estimate;
* a what-if toggle changes controls, never which asset the run is about.

(Criticality is value-function *context* — held fixed across coalitions so
efficiency stays exact. Phase 5 deliberately kept it as context rather than a
Shapley *player*; that decision is documented in `docs/ATTRIBUTION.md` §1.)

## 8. Worked demo example (real, reproducible)

Seed demo: findings bound to `demo@example.com`, criticality **4** → `m = 1.1`.

```
base 48.5 + interaction 13.2 = 61.7          (pre-criticality exposure)
× 1.1  →  67.87;  adjustment = +6.17
mitigation = 0.0
score = 67.87 → displayed 67.9 (HIGH); range 62–76; Shapley sum = 67.8700
```

Pre-Phase-4 demos scored 61.7 (`risk-1.0`, no term). The change is the whole
point of Phase 4 and is stated in `docs/PROGRESS.md`.

## 9. Honest limitations

* Weights are expert-set parameters for **relative** prioritization — they are
  not fitted to breach data and not a probability of anything.
* The sensitivity range is a bounded ±5% input perturbation (criticality held
  fixed), **not** a statistical confidence interval.
* The criticality multiplier bounds importance between 0.8× and 1.2× — it can
  re-rank close cases but can never dominate the evidence itself.
* Interactions are evaluated on the run-level feature vector (not per account);
  preserved from the original defensible model rather than re-scoped here.
* One score per analysis run; per-asset score roll-ups are future work.
