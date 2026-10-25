# CRIX-SMB Risk Model Specification (`risk-2.1`)

**Status:** implemented, tested (35 Phase 4 + 23 Phase 6b dedicated tests + full
suite), verified on the real dev database. **This document is the authoritative
description of the formula; the code must match it or a test fails.**

*Score = a deterministic, reproducible prioritization measure. It orders what to
fix first. It is not a probability, not a likelihood of any event, and not a
claim that anything was or was not compromised.*

---

## 1. The formula

```
risk = clip( m(c) × (base_risk + interaction_risk) + dependency_exposure
             − mitigation_credit , 0, 100 )
```

where the **asset-criticality multiplier** is

```
m(c) = 1 + step × (c − neutral)      step = 0.10, neutral = 3
c ∈ {1, 2, 3, 4, 5}   →   m ∈ {0.80, 0.90, 1.00, 1.10, 1.20}
c = None (no registered asset bound) → m = 1.00  (explicitly unadjusted)
```

and the additive identity used by the UI (exact, before clipping) is

```
risk = base_risk + interaction_risk + criticality_adjustment
       + dependency_exposure − mitigation_credit
criticality_adjustment = (m(c) − 1) × (base_risk + interaction_risk)
```

`dependency_exposure` (Phase 6b) is the organization dependency graph's
documented contribution: `100 × weight × d` with `d ∈ [0, 1)` derived from the
bounded blast-radius query (§1.3). It sits **outside** `m(c)` — the multiplier's
documented scope (the affected asset's importance) is unchanged from Phase 4,
and the graph term carries its own criticality weighting of the *reachable*
assets. Without a graph input the term is exactly 0 and the score equals the
Phase 4 (`risk-2.0`) formula bit-for-bit (pinned by test).

### 1.1 Terms

| Term | Definition |
|---|---|
| **base_risk** | `100 × Σ_g base_weight[g] × f[g]` over the 10 risk feature groups. Weights sum to exactly 1.00. |
| **interaction_risk** | `100 × Σ_(a,b) coefficient(a,b) × f[a] × f[b]` over the 8 documented pairs. This is CRIX's thesis made explicit: problems compound. Computed **from the findings themselves** — never from grouped-link (correlation) results, which cannot add points. |
| **m(c)** | The single documented way asset importance enters the score. There is no second, hidden importance bonus anywhere in `risk.py`. |
| **dependency_exposure** | `100 × 0.08 × d`, the Phase 6b graph term (§1.3). Bounded by 8 points — below a top-weighted finding group at full intensity (session, 16) — so findings lead and the graph re-ranks close cases. |
| **mitigation_credit** | `100 × (0.20·passkey + 0.12·mfa) × discount`, `discount = 1 − 0.70×session`, capped at `0.45 × (the pre-mitigation total = criticality-scaled exposure + dependency_exposure)`. Mitigations offset; they never erase the evidence, graph-derived or otherwise. |
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
max_mitigation_credit = 0.45        # of the scaled exposure (incl. dependency_exposure)
criticality = {min 1, max 5, neutral 3, step_per_level 0.10}
dependency_exposure = {weight 0.08, saturation 4.0}   # Phase 6b graph term
SENSITIVITY_DELTA = 0.05            # ±5% perturbation for the range
```

Severity is the feature intensity: a finding's severity **is** `f[g]` — severity
is already normalized to `[0, 1]` by the schema (`ge=0, le=1`), and the engine
additionally **rejects** (raises `ValueError`) any intensity outside `[0, 1]`,
NaN, or non-numeric rather than silently clipping it.

### 1.3 The dependency-exposure term (Phase 6b) — how the org graph enters

The organization dependency graph (Phase 6, `docs/ORG_GRAPH.md`) contributes
**exactly one documented term**, derived server-side, organization-scoped, from
the same bounded blast-radius query the API already exposes:

```
raw = Σ over blast-radius assets   ((criticality − 1) / 4) × (1 / depth)
d   = raw / (raw + saturation)                 # saturation = 4.0, d < 1 always
points = 100 × weight × d                      # weight = 0.08, bounded by 8
```

Resolution rules (all pinned by tests in
`tests/test_dependency_exposure_phase6b.py`):

* **Primary asset only.** The blast radius is computed **from the run's
  primary affected asset** (§2's most-important affected asset). Exposure
  follows each relationship type's documented direction (`docs/ORG_GRAPH.md`
  §2): forward (`RESETS_PASSWORD`, `HAS_ACCESS_TO`, `DEPLOYS_TO`), reverse
  (`USES`, `DEPENDS_ON`), either (`INTEGRATES_WITH`).
* **Bounded.** Traversal depth is the graph API's documented default (3 hops,
  `GRAPH_LIMITS["default_depth"]`); truncation beyond the bound is recorded
  (`truncated: true`), never silently dropped.
* **Status, always recorded** in `components.dependency_exposure`:

  | Status | Meaning | Intensity |
  |---|---|---|
  | `AVAILABLE` | Graph read, blast radius computed (including an evaluated **zero** when no edges exist) | `d` |
  | `NO_AFFECTED_ASSET` | No registered asset bound to this run's findings — there is nothing to reason *from* | dropped → 0 |
  | `NO_ORGANIZATION` | Run has no org context; the graph cannot be read | dropped → 0 |
  | `UNAVAILABLE` | Graph build failed (e.g. `GraphTooLargeError`) | dropped → 0 |
  | `DISABLED` | `CRIX_RISK_DEPENDENCY_EXPOSURE_ENABLED=false` — excluded **on purpose** (ablation / Phase 12) | dropped → 0 |
  | `NOT_PROVIDED` | `compute_risk` called without a dependency argument (out-of-pipeline use) | dropped → 0 |

* **Fail-closed, never zero-as-unknown:** a non-`AVAILABLE` status drops any
  stray intensity so the recorded status and the math cannot disagree;
  `AVAILABLE` without an intensity (or an unknown status) raises `ValueError`.
  `UNAVAILABLE` and `NO_ORGANIZATION` append an uncertainty note ("unavailable
  is not the same as safe"); an evaluated zero does **not** — it is a measured
  fact, recorded in the note as "absence of a declared relationship is not
  evidence of its absence."
* **Bounded by design.** `d < 1` ⇒ the term never exceeds 8 points — less than
  a top-weighted finding group at full intensity (session, 16). Findings lead;
  the graph re-ranks close cases.
* **Provenance travels with the points:** the context records the source
  (`org_graph.blast_radius`), the formula, the depth used, the reachable-asset
  count, the org graph's asset/edge counts and their provenance
  (`ADMIN_DECLARED`), and the Phase 6 disclaimer, all in the score's own
  `components` — visible in the payload, not just in the code.

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
  A firing correlation changes nothing in the score. Since Phase 6b a declared
  dependency edge *does* move the score — **by exactly the documented
  `dependency_exposure` term of §1.3 and nothing else** (pinned by test), while
  correlations remain consumed by nothing. Each score records
  `components.correlations_consumed = {"ids": [], "note": …}` so the boundary
  is visible in the payload, not just in the code.
* **Raw graph structures.** The graph enters only as the §1.3 term's bounded
  intensity — an edge, a path, or the graph object itself is never a feature, a
  weight, or a Shapley player. `risk.py` still imports nothing from the graph,
  the database, or the network: the intensity is an *input* the pipeline
  resolves, so the engine stays pure and testable (AST-pinned by test).
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
| `features` | The exact feature vector used (13 features: the 12 evidence/control groups + `dependency_exposure`) |
| `model_version` | `"risk-2.1"` |
| `criticality`, `criticality_multiplier` | The input and the multiplier applied |
| `criticality_status`, `asset_ids`, `asset_criticalities`, `primary_asset_id`, `unresolved_assets` | Full resolution context |
| `dependency_exposure` | The §1.3 graph term's full context: status, intensity, points, formula, depth, provenance, disclaimer |
| `finding_ids` | Every event id the calculation consumed |
| `interaction_terms` | Fired terms with coefficient and value (trace rows only — their sum equals `interaction_risk`, they add nothing) |
| `mitigation` inputs | via `features` (`passkey`, `mfa`, `session`) + `mitigation_credit` |
| `unavailable_inputs`, `uncertainty` | What is unknown, stated next to the score |
| `org_id`, `correlations_consumed` | Provenance of the run and the explicit "nothing else was consumed" |

Persisted snapshots (`risk_results`) additionally store `org_id` (indexed),
`asset_id` (the primary/most-important affected asset), `model_version`, and
`criticality_adjustment` as first-class columns.

## 6. Versioning and snapshots

* `RISK_MODEL_VERSION = "risk-2.1"` — the contextual formula specified here
  (Phase 6b: adds the documented `dependency_exposure` term).
* `"risk-2.0"` — the pre-6b contextual formula (criticality term, no graph
  term). With no graph input, `risk-2.1` reproduces it bit-for-bit (pinned by
  test), and a `risk-2.0` row survives a new run byte-for-byte.
* `"risk-1.0"` — the pre-Phase-4 formula (no criticality term). Rows that
  existed before the migration are stamped `risk-1.0` with
  `criticality_adjustment = 0.0` by the migration's back-fill, because that is
  the formula that actually produced them.
* A snapshot is **inserted per run, never rewritten.** Changing the formula
  changes future rows only; historical rows keep their own model version (test:
  a `risk-1.0` row and a `risk-2.0` row both survive a new run byte-for-byte).

## 7. Consumers must use the same context

Attribution (`shapley.attribute`), the planner (`planner.compare`), what-if,
propagation simulation, and the sensitivity range all receive the **same**
`features` vector (including the resolved `dependency_exposure` intensity) and
the same `criticality` as the risk call, so:

* Shapley efficiency holds against the displayed score
  (`Σ contributions == score`, error < 1e-6) with **13 players** — the graph
  term is a normal feature/player, so its contribution is exactly its
  documented points and `v(∅) = 0` still holds by construction (absent graph →
  absent player → 0);
* `planner.comparison.initial_risk == score`;
* the sensitivity range always brackets the point estimate;
* a what-if toggle changes controls, never which asset the run is about;
* propagation simulation's scenario risks inherit the graph term automatically
  (same vector), never a re-derived one.

(Criticality is value-function *context* — held fixed across coalitions so
efficiency stays exact. Phase 5 deliberately kept it as context rather than a
Shapley *player*; that decision is documented in `docs/ATTRIBUTION.md` §1.)

## 8. Worked demo example (real, reproducible)

Seed demo: findings bound to `demo@example.com`, criticality **4** → `m = 1.1`;
one registered critical asset reachable from it (`github.com/acme/api`,
criticality 5, depth 1) → `raw = 1`, `d = 1/5 = 0.2`.

```
base 48.5 + interaction 13.2 = 61.7          (pre-criticality exposure)
× 1.1  →  67.87;  adjustment = +6.17
+ dependency_exposure = 100 × 0.08 × 0.2 = 1.60    (graph term, §1.3)
mitigation = 0.0
score = 69.47 → displayed 69.5 (HIGH); range 63–78; Shapley sum = 69.4700
```

Pre-Phase-4 demos scored 61.7 (`risk-1.0`, no term); Phase 4 raised it to 67.9
(`risk-2.0`, criticality term). The Phase 6b score of 69.5 adds the graph term
on top, each step stated in `docs/PROGRESS.md`.

## 9. Honest limitations

* Weights are expert-set parameters for **relative** prioritization — they are
  not fitted to breach data and not a probability of anything.
* The sensitivity range is a bounded ±5% input perturbation (criticality and
  the graph term held fixed), **not** a statistical confidence interval.
* The criticality multiplier bounds importance between 0.8× and 1.2× — it can
  re-rank close cases but can never dominate the evidence itself.
* The dependency term is bounded at 8 points and depth-limited (3 hops): a
  deeply nested or unregistered exposure cannot move the score much, and
  **absence of declared edges is not absence of exposure** — an evaluated zero
  says only that nothing was declared. Only administrator-declared
  relationships feed it (`ADMIN_DECLARED` provenance), so its honesty ceiling
  is the org's own data quality.
* Interactions are evaluated on the run-level feature vector (not per account);
  preserved from the original defensible model rather than re-scoped here.
* One score per analysis run; per-asset score roll-ups are future work.

---

## 10. Semester-7 addendum: event-type → feature-group mapping (isk-2.1 unchanged)

The **formula, weights, interactions, and model version did not change**; this
addendum documents only which *event types* feed the existing feature pools
(max-severity aggregation) as of the Semester-7 features:

| Event type | Feature group | Introduced by |
|---|---|---|
| PHISHING_URL_DETECTED | phishing | §6.C threat-feed URL checker |
| ACCESS_REVIEW_NEEDED | permissions | §9.F organization access audit |
| EMAIL_AUTH_WEAKNESS | — deliberately unmapped | §7.D domain posture |
| TLS_POSTURE_WEAK | — deliberately unmapped | §7.D domain posture |
| SECRET_PATTERN_MATCHED | — deliberately unmapped | §8.E repository secret scan |

Rationale for the two mapped additions: a threat-feed verdict on a URL is
direct phishing evidence, and an organization-wide access-review candidate is
the org-level sibling of the per-account permission audit — both are already
owned by existing pools, so no new weight or interaction enters the model and
the model version stays isk-2.1.

Rationale for the unmapped ones: domain DNS/TLS posture and repository-borne
secrets are properties of a *company asset* (org-scoped findings), not
account-breach observations; assigning them to an existing per-account feature
pool would be an undocumented model change. They are persisted as findings,
shown in the UI, correlated declaratively (phished_weak_email_auth), and
tracked as remediation-visible evidence — but they do not contribute points to
the account risk score until a future version of this model documents that.
This is pinned by tests (	est_feature_c.py, 	est_feature_d.py keep the
EVENT_TO_FEATURE map regression-checked via the unchanged legacy score).
