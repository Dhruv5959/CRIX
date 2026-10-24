# CRIX-SMB Progress Log

Organization-first CRIX for 10–30 person IT-services/software companies.
Branch `smb-migration`; each phase = one commit + one `phase-N-done` tag, with
tests green before the tag is created. Verification counts are copied from
executed command output, not from intent.

| Phase | Commit | Tag | Backend suite | State |
|---|---|---|---|---|
| 0 baseline | `750f9f2` | `pre-smb-migration` | 181 passed | ✅ |
| 1 org-first data model, RBAC, admin-view audit, OAuth freeze | `8bd6b3a` | — | 225 passed | ✅ |
| 2 common finding format, stable assets, org-owned findings | `6752581` | — | 253 passed | ✅ |
| 3 organization-owned explicit correlation results | `1886aff` | — | 291 passed | ✅ |
| 4 contextual risk scoring (asset criticality) | `3dc923b` | `phase-4-done` | **327 passed** | ✅ |
| 5 Shapley risk attribution (documented game, exact + seeded approx) | (this entry) | `phase-5-done` | **350 passed** | ✅ |
| 6 company asset dependency graph | `749a1ce` | `phase-6-done` | **380 passed** | ✅ |
| 6b dependency exposure wired into the risk score (`risk-2.1`) | (this entry) | `phase-6b-done` | **403 passed** | ✅ |
| 7 remediation planning + verification (tasks, budget, 4-state lifecycle) | (this entry) | `phase-7-done` | **435 passed** | ✅ |

Frontend at every phase: `npx tsc --noEmit` (exit 0), `npx vitest run`
(**21 passed**), `npm run build` (exit 0). PostgreSQL is honestly **not run**
(no Docker/server/`psycopg` in this environment) — claim is "DDL verified for
the PostgreSQL dialect", nothing more.

---

## Pre-Phase-4 baseline re-verification (2026-10-22, this run)

* Git: clean tree on `smb-migration` at `1886aff`; history
  `750f9f2 → 8bd6b3a → 6752581 → 1886aff`; only tag `pre-smb-migration`; no remote.
* Backend: **291 passed, exit 0** · Frontend: tsc 0, **21 passed**, build 0.
* **Secret scan (documented fallback):** no `gitleaks`/`trufflehog` installed, so a
  regex-blob scan script was run over every committed blob in all 4 commits
  (private keys, AWS/GitHub/Slack/Google token shapes, generic key/password
  assignments). Matches: `password-assign` in `backend/scripts/smoke.py`,
  `backend/tests/test_auth.py`, `backend/tests/test_breach_endpoint.py` and a
  `jwt` match (variable named `fake_jwt`) in `backend/tests/test_finding_schema.py`.
  **Triaged by inspection: synthetic test fixtures** (redaction-test data and demo
  test credentials), not real credentials. No private keys, no cloud/OAuth
  provider secrets, `.env` untracked. Values were never printed in the report.

---

## Phase 4 — contextual risk scoring ✅ (`phase-4-done`)

**Change:** the defensible formula was preserved and extended by exactly one
documented term — company asset criticality:

```
risk = clip( m(c) × (base + interaction) − mitigation_credit, 0, 100 )
m(c) = 1 + 0.10 × (c − 3) ∈ [0.8, 1.2]     c = None → 1.0 (unadjusted, recorded as unknown)
```

Full specification, parameters, boundaries, missing-data handling, traceability
contract and versioning: **`docs/RISK_MODEL.md`** (new).

### What was implemented

| Area | Change |
|---|---|
| `app/engine/risk.py` | `RISK_MODEL_VERSION = "risk-2.0"`; `RISK_PARAMS["criticality"]`; `criticality_multiplier()`; strict `_validate_features()` (rejects out-of-range/NaN/non-numeric instead of clipping); `risk_from_features(..., criticality=)`; `compute_risk(..., criticality=)` with full traceability `components` (finding ids, interaction terms, unavailable inputs, uncertainty notes, model version, multiplier); `criticality_adjustment` on the breakdown; sensitivity range takes criticality as a fixed input; module docstring rewritten (source contains no reference to correlations — boundary test still passes). |
| `app/engine/shapley.py` | `shapley_values`/`attribute` accept `criticality` as value-function context (v(∅)=0 ⇒ efficiency exact against the displayed score). |
| `app/engine/planner.py` | `criticality` threaded through `_risk`/`greedy_plan`/`exact_plan`/`compare` — `initial_risk` equals the run's score. |
| `app/engine/pipeline.py` | `resolve_org_criticality` / `resolve_run_criticality`: org-scoped, max-criticality selection, fail-closed cross-org rejection with explicit `unresolved_assets` reasons; run merges asset context + `org_id` + `correlations_consumed: {ids: [], note}` into the score's components; `_persist_run` stores `org_id`, `asset_id` (primary), `model_version`, `criticality_adjustment`. |
| `app/models.py` + migration `f3a1c2d4e5b6` | `risk_results` gains `org_id` (FK, indexed), `asset_id`, `model_version` (server default `risk-1.0`), `criticality_adjustment` (default 0.0); existence-guarded, idempotent, reversible; back-fills `org_id` from the writer's membership (NULL stays NULL = matches no tenant, fail-closed). |
| Routers/schemas | `/api/analysis` risk block adds `model_version`, `criticality`, `criticality_adjustment` (+ components keys); what-if and propagation simulation reuse the run's criticality everywhere (risk, sensitivity, attribution, planner). |
| Frontend | `types.ts` extended; RiskPage shows the criticality term + model version + "grouped-link results are not score inputs"; OverviewPage formula/5th metric; PropagationPage scenario breakdown row. |
| Docs | `docs/RISK_MODEL.md` (new), this log (new), `ARCHITECTURE.md` §6, `IMPLEMENTATION_STATUS.md`, `PRESENTATION.md` demo numbers updated; audit §14 appended. |

### Verification (executed)

| Check | Command | Result |
|---|---|---|
| Full backend suite | `python -m pytest` | **327 passed, exit 0** (291 baseline + 35 new in `tests/test_risk_phase4.py` + 1 migration test) |
| Phase 4 tests | `pytest tests/test_risk_phase4.py tests/test_migrations.py` | 41 passed |
| Frontend | `tsc --noEmit` / `vitest run` / `npm run build` | exit 0 / **21 passed** / exit 0 |
| Migration on existing dev DB (create_all-touched state, version still Phase 3) | `alembic upgrade head` | ran `d4e5f6a7b8c9 → f3a1c2d4e5b6`, guards no-op'd, `ix_risk_results_org_id` created, all NULL `org_id` back-filled from membership |
| Migration from empty | `alembic upgrade head` on fresh file | full chain `17855d…→f3a1c2d4e5b6` exit 0 |
| Demo seed | `python scripts/seed_demo.py` | risk **67.9 (HIGH)** (was 61.7 at `risk-1.0`), base 48.5 + interaction 13.2, adjustment **+6.17** (=0.1×61.7), criticality 4 ×1.1, Shapley sum = total (err 0.0), planner gap 0.00% |
| Persisted snapshot | dev DB query | `model_version=risk-2.0`, `org_id` set, `asset_id=demo@example.com`, components: `criticality 4`, `multiplier 1.1`, `REGISTERED`, 22 finding ids, 4 interaction terms, `correlations_consumed.ids=[]`, 3 uncertainty notes |

### Test coverage (§3.7 → `tests/test_risk_phase4.py`, 35 tests)

Parameters-vs-documentation drift guard · severity linearity · every supported
finding type → its feature group · mitigation-only-as-checked-safe · criticality
scale 1..5 derived values (9.6 … 14.4) · neutral/missing unchanged ·
**criticality-alone-zero** · multiplier rejections (0, 6, 3.5, `"3"`, bool…) ·
exact additive identity · interaction fires once and scales (never
double-counted) · duplicates don't double-count · strongest-severity max ·
conflict resolution by status · 45% mitigation cap under criticality · session
discount preserved under criticality · score bounds 0/100 at every criticality ·
feature intensities rejected when out of range · missing/out-of-range severity
rejected by schema · missing criticality recorded as unknown-not-safe ·
unavailable inputs listed (sorted) and never scored · determinism incl.
order-independent traces · traceability completeness (interaction terms sum ==
`interaction_risk`) · cross-org references rejected fail-closed (both reasons) ·
max-criticality primary-asset selection · unbound/no-org statuses ·
one-context consistency (risk == attribution total == planner initial) ·
declared dependency edge changes correlations but **not** the score ·
snapshots org-scoped + historical `risk-1.0` row never rewritten · API contract
with derived expected score + client-supplied risk inputs ignored · what-if
keeps the same criticality · no raw snapshot route exists · sensitivity
brackets the estimate under criticality · pre-Phase-4 default behavior
reproducible.

### Deviations, findings, limitations

* **Dev-DB anomaly found and remediated honestly:** `backend/crix.db` entered
  this run with the Phase 4 columns already present but `alembic_version` still
  at Phase 3, containing 4 demo-user risk rows stamped `risk-2.0` with no org
  and no adjustment. Cause: rows dated before this session's edits — consistent
  with an earlier discarded attempt that ran `create_all` + seed outside the
  migration path. Handling: (1) the real migration was first executed against
  that exact state — guards no-op'd, index created, `org_id` back-filled,
  version stamped `f3a1c2d4e5b6`; (2) the database file was then backed up to
  `C:\Users\dhruu\AppData\Local\Temp\opencode\crix.db.phase4-backup`,
  deleted, rebuilt from empty via `alembic upgrade head`, and re-seeded.
  Final state verified clean (§table above).
* PostgreSQL suite **not run** (unchanged environment limitation).
* One real bug found & fixed during the phase: `str(EventStatus.X)` yields
  `"EventStatus.X"` — status comparisons in the engine/pipeline now unwrap
  `.value` explicitly.
* Outbox `.eml` files regenerated by test runs were deleted before the commit.
* Nothing else changed: no formula rewrite, no ML, no OAuth change, no paid
  dependency, no GraphRAG behavior change.

---

## Phase 5 — Shapley risk attribution ✅ (`phase-5-done`)

**Change:** the exact Shapley engine was preserved and given a documented
cooperative-game specification, a clearly-labelled seeded approximation with a
measured exact-vs-approx gap, and an honest output contract. No new inputs; the
value function stays the real Phase 4 risk function and the org-scoped asset
criticality stays value-function *context* (held fixed, so efficiency stays
exact). Full specification: **`docs/ATTRIBUTION.md`** (new).

### What was implemented

| Area | Change |
|---|---|
| `app/engine/shapley.py` | Module docstring rewritten to state the game precisely (players = 12 feature groups; value function = real `risk_from_features` restricted to a coalition; baseline `v(∅)=0`; absent factor contributes 0 and is *not* "safe"; clipping is part of `v`; residual/efficiency; criticality is context not a player, with justification). Factored `_make_value` (memoized `v(mask)` shared by both methods). Added `approximate_shapley_values` (seeded permutation sampling, `samples>=1`, reproducible for a fixed seed). `attribute` gained `method`/`samples`/`seed` params and now returns `is_exact`, `residual`, `criticality_context`, `baseline`, `absent_factor_note`, `clipping_note`, `breakdown` (raising/lowering/neutral), `plain_language`, and — only on the approximation — `samples`/`seed`. Added `compare_exact_vs_approximate` measuring per-factor/max/mean/total error. **Correctness fix found during testing:** `is_exact` tracks the *method*, not the residual — the seeded approximation always evaluates the full coalition so its residual can be ~0 while its per-factor values are sampled; deriving `is_exact` from the residual would mislabel it as exact. |
| `app/schemas.py` | `AttributionResponse` gains the new contract fields (`is_exact`, `residual`, `sum_of_contributions`, `efficiency_error`, `criticality_context`, `baseline`, notes, `breakdown`, `plain_language`, optional `samples`/`seed`) — all optional/defaulted so the existing payload shape is preserved. |
| Frontend | `types.ts` `Attribution` extended to mirror the contract; RiskPage shows the exact-vs-approx label and surfaces the server's plain-language `residual` note (replacing a hand-written sentence). |
| Docs | `docs/ATTRIBUTION.md` (new); this log entry; audit §15 appended. |

### Verification (executed)

| Check | Command | Result |
|---|---|---|
| Full backend suite | `python -m pytest` | **350 passed, exit 0** (327 baseline + 23 new in `tests/test_shapley_phase5.py`) |
| Shapley tests | `pytest tests/test_shapley.py tests/test_shapley_phase5.py` | 30 passed (7 pre-existing + 23 new) |
| Frontend | `tsc --noEmit` / `vitest run` / `npm run build` | exit 0 / **21 passed** / exit 0 |
| Demo seed | `python scripts/seed_demo.py` | risk 67.9 (HIGH), Shapley sum = total (err 0.0) — attribution total equals the run score |

### Test coverage (§4.9 → `tests/test_shapley_phase5.py`, 23 tests)

Players are exactly the 12 documented feature groups · value function is the
real risk function (total == `expected_score`, not a surrogate) · **baseline
`v(∅)==0`** · absent factor contributes 0 · clipping bounds the attributed sum
to ≤ 100 · efficiency residual within `1e-6` · efficiency over random inputs at
every criticality · exact method never labelled approximate and carries no
sampling params · compute time benchmarked · output contract exposes every
documented field · breakdown splits raising/lowering/neutral · **plain language
never claims causation, probability of compromise, or "safe"** · unknown method
rejected · approximation labelled `is_exact=False` with seed/samples ·
approximation reproducible for a fixed seed · approximation error measured vs
exact (`compare_exact_vs_approximate`) and reported per-factor · zero samples
rejected · approximation explains the same total as the score · criticality
scales the total but is **not** a player · attribution total == score for the
same criticality · pipeline attribution explains the run score with one
criticality context · API serves the attribution contract · **cross-org
attribution never aggregated** (each tenant explains its own score with its own
criticality).

### Deviations, findings, limitations

* One real bug found & fixed during the phase: `is_exact` was derived from the
  residual, which the seeded approximation can drive to ~0 while its per-factor
  values are still sampled (it always evaluates the full coalition). `is_exact`
  now tracks the method, so an approximation is never mislabelled as exact.
* The plain-language `residual` note originally read "not what caused an
  incident" — the word "caused" tripped the causation scan, so it was reworded
  to avoid any causation verb entirely.
* PostgreSQL suite **not run** (unchanged environment limitation) — Phase 5 is
  additive in Python + optional schema fields; no new migration.
* Criticality remains value-function context, not a promoted player (documented
  decision in `docs/ATTRIBUTION.md` §1).
* Outbox `.eml` files regenerated by test runs were deleted before the commit.
* Nothing else changed: no risk-formula rewrite, no ML, no OAuth change, no
  paid dependency, no GraphRAG behavior change.

## Phase 6 — company asset dependency graph ✅ (`phase-6-done`)

**Change:** a new organization-scoped graph engine answers the
potential-exposure question ("if one asset were compromised, which other
assets might be exposed through documented relationships, along which
paths, and why?") using only existing `OrgAsset` and `AssetDependency`
rows, NetworkX, and honest provenance. The graph never claims a compromise
and never changes the authoritative risk score. Full specification:
**`docs/ORG_GRAPH.md`** (new).

### What was implemented

| Area | Change |
|---|---|
| `app/engine/org_graph.py` | **New.** Builds a `MultiDiGraph` from `OrgAsset` (nodes, canonical ids) + `AssetDependency` (edges, only supported types). `RELATIONSHIP_SEMANTICS` maps each type to forward/reverse/both exposure arcs; `canonical_relationship_type` canonicalizes case/spaces/hyphens and returns `None` for unknowns (never coerces). `GRAPH_LIMITS` bounds depth (default 3/max 5), paths (default 10/max 25), nodes (max 1000 → `GraphTooLargeError`), expansions (max 20000). Provenance labels (`REGISTERED_ASSET`/`ADMIN_DECLARED`/`DERIVED_PATH`; `PROVIDER_DISCOVERED`/`MODEL_INFERRED` documented "Not produced by this system"). Ops A–G: `graph_payload`, `direct_neighbors`, `reachable` (BFS, visited-once, honest `truncated`), `paths_between` (simple paths only, deterministic), `blast_radius`, `critical_exposure` (asset-scoped = critical subset of blast radius; org-scoped = reverse reachability toward each critical asset, paths presented in true exposure direction). Build skips + counts unsupported/dangling/duplicate rows. |
| `app/routers/graph.py` | Rewritten: the personal `/api/graph` is untouched; new org-scoped `GET /api/org/graph`, `/neighbors`, `/paths`, `/blast-radius`, `/critical-exposure` — all `get_current_membership` (any role reads), `_resolve_asset` generic 404 ("Asset not found."), `Query` bounds (422 out of range), `GraphTooLargeError` → 413. Every response carries the potential-exposure disclaimer. |
| `app/routers/assets.py` | Relationship-type validation in `create_dependency` (after auth + asset existence, preserving 403/404 precedence; canonical UPPERCASE stored; duplicate check compares canonical forms). `_get_dependency` helper. New `GET /api/dependencies/{id}` (evidence, all roles) and `PATCH /api/dependencies/{id}` (ORG_ADMIN, audited `dependency.updated`, 409 on type-dup, 422 unsupported, endpoints NOT rewritable). |
| `app/schemas.py` | `AssetDependencyUpdate` (partial: type/weight/note; endpoints excluded by design). |
| Frontend | `types.ts` `OrgGraph*` types; `api.ts` `orgGraph`/`orgGraphNeighbors`/`orgGraphPaths`/`orgGraphBlastRadius`; pure helper `lib/orgGraph.ts` (`toOrgGraphView`, `formatPath`, `pathUncertainty`, `stepNote`); minimal `GraphPage` org section showing declared assets/relationships with the server's disclaimer verbatim. |
| `scripts/seed_demo.py` | Registers 3 more demo assets (repository, CI, backups) + 3 admin-declared relationships and prints a graph summary (assets, relationships, blast radius of the work mailbox, disclaimer). Idempotent. |
| Docs | `docs/ORG_GRAPH.md` (new: model, relationship semantics, provenance, traversal, security boundaries, API contracts); this log entry; audit §16; ARCHITECTURE §8.1. |

### Verification (executed)

| Check | Command | Result |
|---|---|---|
| Full backend suite | `python -m pytest` | **380 passed, exit 0** (350 prior + 30 new in `tests/test_org_graph_phase6.py`) |
| Graph tests | `pytest tests/test_org_graph_phase6.py` | **30 passed, exit 0** (superset of the 25 backend items in §5.12) |
| Frontend | `tsc --noEmit` / `vitest run` / `npm run build` | exit 0 / **31 passed** (21 prior + 10 new) / exit 0 |
| Demo seed | `python scripts/seed_demo.py` | 4 assets, 3 relationships; potential exposure from demo@example.com: 1 asset, 1 critical (github.com/acme/api, depth 1); risk **67.9 (HIGH)** unchanged; Shapley err 0.0; planner gap 0.00% |
| Smoke (dev DB) | TestClient script | 401 unauth on all 5 org endpoints; 201 assets/edges (lowercase canonicalizes); graph 3 nodes/2 edges; neighbors/paths/blast-radius/critical-exposure correct; 422 unsupported type with supported list; 422 max_depth=99 |

### Test coverage (§5.12 → `tests/test_org_graph_phase6.py`, 30 tests; `frontend/src/lib/orgGraph.test.ts`, 10 tests)

Graph construction from registered assets only · directed relationships
traverse in documented exposure direction (forward/reverse/both) ·
direct neighbors by direction · depth-bounded reachability with honest
`truncated` · evidence-backed path retrieval · blast radius framed as
potential exposure (no entry ever labelled breached/hacked/compromised) ·
critical assets reachable org-wide and asset-scoped · cycles and self-loops
terminate with simple paths only · multiple paths discovered and capped ·
disconnected components have empty-but-valid results · stale/dangling
edges skipped and counted (ORM and API) · duplicates deduplicated
(engine) and rejected (DB constraint, API 409 including case variants) ·
unsupported types rejected with actionable 422 and never traversed ·
identity normalization maps URL variants to one node · similar names never
create false relationships · cross-org edge creation rejected (404) ·
cross-org queries return no data · no module-level cache + interleaved
org isolation · deterministic ordering · engine clamps and API rejects
out-of-range limits · evidence and provenance preserved end to end
(`NOTE_MISSING` uncertainty when no note) · API auth 401 + viewer 403 on
writes + audited admin PATCH · schema constraints persist without a Phase 6
migration (unique constraint + org indexes asserted) · **Phase 4 risk
inputs bit-identical after every graph operation** · org_graph imports
neither risk nor shapley · **Phase 5 attribution total == score after
graph operations** and graph is not an attribution player.

### Deviations, findings, limitations

* **The planned `declared_dependency_exposure` correlation did not fire in
  the demo, and that is correct.** The demo's `BREACH_EXPOSURE` event has
  `status=UNAVAILABLE` (offline HIBP fixture — the provider never
  confirmed it); the rule requires a `FINDING`-status breach. Demo
  correlations stay at **2** (0.85, 0.55), matching the already-correct
  `PRESENTATION.md`/`IMPLEMENTATION_STATUS.md` figures — no doc change was
  needed. This is the provider-failure boundary working as designed.
* Three engine honesty fixes found while writing tests: neighbor
  `direction` labels now use the exposure-arc direction (not the declared
  direction); `reachable` reports `truncated` when unexplored nodes remain
  beyond the depth bound; org-wide `critical_exposure` traverses *toward*
  the critical asset (reverse reachability) and presents each path in true
  exposure direction.
* No Phase 6 migration: the Phase 2 schema (`uq_asset_dependency`, org_id
  indexes) is reused as §5.11 allows.
* PostgreSQL suite **not run** (unchanged environment limitation) — no new
  tables or columns; DDL verified for the PostgreSQL dialect only.
* The graph never changes the risk score or attribution (compatibility
  tests assert bit-identical results); it documents relationships, it does
  not prove compromise.
* Outbox `.eml` files regenerated by test runs were deleted before the
  commit.

## Phase 6b — dependency exposure wired into the risk score ✅ (`phase-6b-done`)

**Change:** the organization dependency graph now feeds the contextual score
through **exactly one documented term**, so "graph-based risk prioritization"
is a property of the formula rather than of a slide. The deterministic engine
remains the only risk authority; `risk.py` gained no imports (the intensity is
an *input* the pipeline resolves), and with no graph input the score equals
the Phase 4 (`risk-2.0`) formula **bit-for-bit** (pinned by test). Formula
version bumped to **`risk-2.1`**. Full specification:
**`docs/RISK_MODEL.md`** §1.3 (updated).

```
risk = clip( m(c)·(base + interaction) + dependency_exposure − mitigation_credit, 0, 100 )
dependency_exposure = 100 · w · d,   w = 0.08,   d = raw/(raw + 4.0)
raw = Σ over blast-radius assets from the primary affected asset
      ((criticality − 1)/4) · (1/depth),   depth bound = GRAPH_LIMITS["default_depth"] = 3
```

The term sits **outside** `m(c)` (the multiplier's documented scope is
unchanged) and is the **13th Shapley player** (`dependency_exposure` feature in
`ALL_FEATURES`), so `v(∅) = 0` and efficiency stay exact by construction.

### What was implemented

| Area | Change |
|---|---|
| `app/engine/risk.py` | `RISK_MODEL_VERSION = "risk-2.1"`; `DEPENDENCY_EXPOSURE_FEATURE`; `DEPENDENCY_EXPOSURE_PARAMS = {weight 0.08, saturation 4.0}` in `RISK_PARAMS`; `DEPENDENCY_EXPOSURE_STATUSES` = {AVAILABLE, NO_AFFECTED_ASSET, NO_ORGANIZATION, UNAVAILABLE, DISABLED, NOT_PROVIDED}; `dependency_exposure_points()` (validated, bounded by `100·weight`, monotone); `risk_from_features`/`compute_risk(..., dependency=)` merge the term (AVAILABLE-without-intensity and unknown status raise `ValueError`; non-AVAILABLE drops stray intensity so status and math cannot disagree); mitigation cap base now includes the term; `UNAVAILABLE`/`NO_ORGANIZATION` append uncertainty notes, evaluated zeros do not. Module stays pure (AST-pinned: no org_graph/networkx/models/sqlalchemy imports). |
| `app/config.py` | `CRIX_RISK_DEPENDENCY_EXPOSURE_ENABLED` flag (default true; checked first → status `DISABLED`, term excluded on purpose — the Phase 12 ablation switch). Documented in `.env.example`. |
| `app/engine/pipeline.py` | `resolve_org_dependency_exposure` (org-scoped, primary-asset-scoped: builds the graph, `blast_radius` at the documented depth bound, computes `raw`/`d`, records status/intensity/points/formula/depth/`truncated`/graph asset+edge counts with `ADMIN_DECLARED` provenance and the Phase 6 disclaimer; `GraphTooLargeError` → `UNAVAILABLE` with reason `graph_too_large` — never zero-as-safe); `resolve_run_dependency_exposure` (membership-resolved); `apply_dependency_feature`; `run_analysis` resolves before `compute_risk` and passes `components["features"]` (the single source of truth) to Shapley and the planner. |
| `app/routers/analysis.py` | Risk block now includes the top-level `dependency_exposure` points row (API-contract test pins composition: base + interaction + criticality adjustment + dependency − mitigation = score). |
| `app/routers/propagation.py` | What-if and scenario simulations receive the same resolved dependency context — the graph term inherits through the features vector, never re-derived. |
| Tests | New `tests/test_dependency_exposure_phase6b.py` (**23 tests**: purity, formula bounds/monotonicity/identity/outside-m(c), mitigation cap, all six statuses + fail-closed, uncertainty notes, bit-for-bit `risk-2.0` equivalence, determinism, pipeline wiring incl. 13 players + efficiency + planner consistency, no-findings → `NO_AFFECTED_ASSET` even with edges, evaluated-zero vs unknown, tenant isolation, `GraphTooLargeError` → `UNAVAILABLE`, flag ablation, `risk-2.1` versioning with untouched history, traversal bounds + honest `truncated`, monotonicity, sensitivity bracketing, Shapley baseline/efficiency with the term, propagation helpers, API contract, wording scan). |
| Docs | `RISK_MODEL.md` (risk-2.1: formula, §1.3 term spec, components, versioning, worked demo, limitations); `ATTRIBUTION.md` (13 players, 8192 coalitions, ~100 ms, demo 69.47); `ORG_GRAPH.md` §6 (queries stay read-only; graph *data* feeds the documented term); `ARCHITECTURE.md` (version chain, additive identity); `IMPLEMENTATION_STATUS.md` / `PRESENTATION.md` / `README.md` (re-measured figures); this log entry. |

### Verification (executed)

| Check | Command | Result |
|---|---|---|
| Full backend suite | `python -m pytest` (capture script, **no extra `-q`**) | **403 passed in 90.16s, exit 0** (380 prior + 23 new) |
| Targeted 4-suite run | `pytest tests/test_dependency_exposure_phase6b.py tests/test_risk_phase4.py tests/test_shapley_phase5.py tests/test_org_graph_phase6.py` | **111 passed in 20.08s, exit 0** |
| Frontend | `tsc --noEmit` / `vitest run` / `npm run build` | exit 0 / **31 passed** / exit 0 |
| Demo seed | `python scripts/seed_demo.py` | risk **69.5 (HIGH)** (was 67.9): base 48.5 + interaction 13.2 → 61.7 ×1.1 = 67.87 + dependency 1.6 (`d = 0.2` from `github.com/acme/api`, criticality 5, depth 1); range **63–78**; Shapley err 0.0; planner gap 0.00%; 4 assets / 3 relationships |
| Evaluation harness | `python scripts/run_evaluation.py` | Shapley max efficiency error **2.00e-09**, mean **100.4 ms** (13 features; ~69 ms at 12); planner gap 0.0686, traps 2; ML F1 0.830 / 0.809 |

### Documented intentional test changes (never a weakening)

* `test_shapley_phase5.py`: game pinned at **13** players (was 12) — the
  dependency intensity is a first-class feature/player; nothing removed.
* `test_org_graph_phase6.py` #24: restructured to the sharper property —
  graph *queries* leave score/features/criticality bit-identical (asserted),
  and a **positive control** asserts a new declared relationship moves the
  score by exactly the documented term.
* `test_org_graph_phase6.py` #25: replaced a vacuous `attribution["players"]`
  scan (the payload has no such key) with a real `contributions` check —
  `dependency_exposure` contributes exactly its points; no raw graph structure
  is ever a player.
* `test_risk_phase4.py`: edge test renamed and strengthened to
  `test_a_declared_dependency_edge_moves_the_score_by_exactly_the_documented_term`
  (independent documented formula still reproduces the score; correlations
  still consumed by nothing); `expected_score`/`expected_dependency_points`
  dependency-aware with the engine's 4-decimal rounding; `DOC_MODEL_VERSION`
  → `risk-2.1`; params assertion = weight equals `DOC_BASE_WEIGHTS["dependency"]`
  (0.08) and is below the heavy groups — **not** ≤ min (identity is 0.05).

### Deviations, findings, limitations

* **Exposure direction matters for tests:** `RESETS_PASSWORD`/`HAS_ACCESS_TO`/
  `DEPLOYS_TO` traverse forward, `USES`/`DEPENDS_ON` reverse,
  `INTEGRATES_WITH` both — a reverse-type edge from the primary asset is not
  reachable exposure, so it contributes 0 (correct per §5.2 semantics).
* `build_input_events` mints fresh UUIDs for **derived** graph events per
  call (documented Phase 0 behavior, pre-6b): scores are deterministic; only
  `finding_ids` churns. The determinism test pins components minus that key
  and asserts the stored finding ids are stable.
* No migration, no new dependency (NetworkX already present), OAuth untouched,
  OAuth/secret/wording rules re-verified on the diff.
* PostgreSQL suite **not run** (unchanged environment limitation) — no new
  tables or columns; DDL verified for the PostgreSQL dialect only.
* Outbox `.eml` files regenerated by test runs were deleted before the
  commit.

---

## Phase 7 — remediation planning and verification ✅ (`phase-7-done`)

**Change:** the planner's output now becomes organization-owned work with an
honest lifecycle. A task instantiates a **documented catalog action** against
specific company assets/findings; its `expected_reduction` is **computed by
the real risk model** from this org's own feature vector (never invented);
planning happens under an **admin-set effort budget** with a greedy baseline
and exact branch-and-bound; and a task walks exactly four states:

```
OPEN ──complete (attestation, never verification)──▶ DONE
DONE ──verify MODELED  (pipeline re-run, attested)──▶ VERIFIED_MODELED
DONE ──verify OBSERVED (REAL-source recheck only)───▶ VERIFIED_OBSERVED
DONE | VERIFIED_* ──reopen (admin, history kept)────▶ OPEN
failed verification → stays DONE + FAIL history row (retry keeps both rows)
```

Effort is a documented **relative unit**, never wall-clock time. The two
verified states are never merged; `VERIFIED_OBSERVED` is rejected for
SYNTHETIC/FIXTURE/USER_PROVIDED evidence by construction (REAL sources only).

### What was implemented

| Area | Change |
|---|---|
| `app/engine/planner.py` | `normalize_prerequisites` (unknown prerequisite → infeasible `prerequisite_not_a_candidate` with detail), `topological_order` (Kahn, lexicographic; cycle members → `prerequisite_cycle`, the rest still plans), deterministic `_select_better` tie-break (ratio → lower effort → lexicographic key), validated per-task `efforts` override (`_normalize_efforts` rejects bool/≤0/non-numeric with `ValueError`), public `expected_reduction(features, key, criticality=)` (real `risk_from_features` before/after; `KeyError` on unknown key; honest `0.0` when nothing addressed), `greedy_plan`/`exact_plan`/`compare`/`pack_budget` accept `prerequisites=`/`efforts=`; exact is seeded with the feasible greedy incumbent and labels itself `proven_optimal_over_candidates`; greedy labels itself `approximate`; every plan reports `unspent_budget` + `infeasible`; **falsy-empty fix** — an explicit `candidate_actions=[]` means *no candidates*, only `None` falls back to the full catalog. |
| `app/models.py` | `RemediationAction` extended to the org-scoped action model (`org_id`, `target_asset_id`, `finding_ids`, `prerequisites`, `dependencies`, `required_evidence`, `verification_method`, `status`, `assigned_to`, `expected_reduction`, `completed_at`); new append-only `RemediationTaskHistory` (from/to status, method, result, model_version, evidence_refs, detail, timestamp); `Organization.effort_budget` (default 6.0, now with `server_default` so `create_all` DDL matches the migration). |
| `app/schemas.py` | 10 Phase 7 schemas (create/update/verify/reopen/response/detail/history/settings/planner view) with bounds and enum constraints. |
| `app/routers/remediation.py` (new) | 10 operations: `GET/PATCH /api/remediation/settings` (admin-set budget, gt 0 ≤ 1000), `GET/POST /tasks` (create = ORG_ADMIN, 201), `GET/PATCH /tasks/{id}` (assignment validated to an active member; effort > 0; prerequisite catalog keys), `POST …/complete` (OPEN→DONE only; 409 from DONE/VERIFIED_*; MEMBER may complete), `POST …/verify` (ORG_ADMIN, from DONE only; MODELED requires `attested=true` (422 otherwise) and passes iff the re-run shows reduction > 1e-9 else FAIL stays DONE with `failure_reason` + `model_version=risk-2.1`; OBSERVED requires ≥1 evidence ref — empty/ghost refs 422, no REAL source 422 `evidence_not_live` with `source_modes_seen`, FAIL iff a REAL FINDING maps to an addressed feature, PASS records `model_version=None`), `POST …/reopen` (409 from OPEN; `completed_at` reset; history byte-for-byte preserved), `POST /plan` (candidates = OPEN tasks deduplicated deterministically by action key; prereqs/efforts from rows; budget defaults to the org setting with `budget_source` echo; `initial_risk == run_score`; plan keys mapped back to `task_ids`; `unplannable_tasks` for non-catalog keys; never persisted). RBAC: reads any role but audit-logged, writes admin-gated, complete/plan also MEMBER. |
| `migrations/versions/a2b3c4d5e6f7_remediation_tasks.py` (new) | Guarded/idempotent; revises `f3a1c2d4e5b6`; `batch_alter_table` adds 11 `remediation_actions` columns + org_id/status indexes, creates `remediation_task_history` (+2 indexes), `organizations.effort_budget` with `server_default 6.0`, backfills task org from the writer's membership; downgrade drops exactly what upgrade added. |
| `scripts/report_planner_gap.py` (new) | Measured greedy-vs-exact gap: 9 deterministic scenarios (7 **imported from `run_evaluation._scenarios()`** so the reports cannot drift + 2 prerequisite cases), seeded random family (seed 20261023, 40), seeded prerequisite family (seed 20261024, 10); prints per-scenario gaps, seeds, mean/max, trap counts; exits 3 with a warning if a constructed trap does not manifest. |
| Tests | New `tests/test_remediation_phase7.py` (**31 tests**: packer labels; prerequisite ordering; infeasible-not-a-candidate; cycle exclusion; determinism + order independence; lexicographic tie-breaks; exact vs brute force **with** prerequisites, 12 seeded cases; exact ≤ greedy + honest `unspent_budget`; effort override validated and plan-changing; `expected_reduction` independently recomputed + `KeyError`; explicit-empty plan; settings default/update/RBAC/bounds; create cross-checked against the pipeline + CREATED history with model version; create validation fail-closed (unknown key/method/finding/prereq → 422, asset → 404); RBAC + tenant isolation everywhere; assignment validation + audit rows; complete-is-attestation-never-verifies + 409 conflicts; MEMBER completes/VIEWER cannot; modeled verify attested-gate/PASS/FAIL-stays-DONE; observed rejects SIMULATED/FIXTURE/USER_PROVIDED + empty + ghost refs; observed REAL FAIL then PASS with `model_version=None`; verified states never overwritten; verify-from-OPEN 409 + MEMBER/VIEWER 403; reopen preserves history byte-for-byte + 409 from OPEN + re-complete; FAIL-then-retry keeps both rows; full-lifecycle audit set; plan endpoint budget/task_map/initial-risk/labels/tight-budget/bounds/empty) + `tests/test_migrations.py` gained `test_phase7_upgrade_adds_task_model_and_preserves_rows` (up: new columns/history/budget/backfill/status/defaults/indexes; down: everything dropped, task row kept) → **+32 tests**. |

### Verification (executed)

| Check | Command | Result |
|---|---|---|
| Full backend suite | `python -m pytest` (**no CLI `-q`**) | **435 passed in 111.53s, exit 0** (403 prior + 32 new) |
| Phase 7 targeted run | `pytest tests/test_remediation_phase7.py tests/test_migrations.py tests/test_planner.py tests/test_propagation.py` | **75 passed in 34.97s, exit 0** |
| Frontend | `tsc --noEmit` / `vitest run` / `npm run build` | exit 0 / **31 passed** / exit 0 |
| Planner gap report | `python scripts/report_planner_gap.py` | **59 scenarios**; deterministic 9 (constructed trap gap **0.424968**, `full_stack` 0.055062 also traps, `prereq_infeasible_chain` reports 1 infeasible), random seed **20261023** (40), prereq seed **20261024** (10, all gap 0); mean gap **0.033074**, max **0.436415**, 16 scenarios with gap > 0; traps constructed 1 / observed 16; **exit 0** |
| Diff review + secret scan | working-tree scan script (9 files, 4 untracked) | **CLEAN, exit 0** — no secrets, no unrelated changes |
| OpenAPI registration | import `app.main`, list remediation paths | 7 paths / **10 operations** present |

### Fixes made while getting to green (code, never weakened tests)

* **Router vocabulary bug:** task creation validates `verification_method`
  against the *declaration* vocabulary (`MODELED`/`OBSERVED` — the column's
  documented default) while `/verify` validates the *resulting state*
  (`VERIFIED_MODELED`/`VERIFIED_OBSERVED`); the router initially checked both
  against the state vocabulary. Fixed in the router; tests unchanged.
* **`assert_asset_in_org` returns `None` for unknown/cross-tenant assets — it
  never raises.** The router now raises the 404 explicitly (a silent `None`
  would have accepted a foreign asset id).
* **Migration ↔ ORM DDL drift:** `Organization.effort_budget` had only a
  Python-side default, so `create_all` DDL lacked the SQL default the Alembic
  migration adds (legacy-shape builders hit `NOT NULL` failures). Fixed by
  adding `server_default="6.0"` to the ORM — DDL now matches the migration.
* **Pre-Phase-7 shape builder** rebuilds `organizations` without
  `effort_budget` (as `create_all` now emits it), keeping the Phase 7 up/down
  test an honest before/after.
* **Audit assertion:** one test asserted `remediation.tasks_read` without
  performing a list read — the test now performs the list read it asserts on.

### Deviations, findings, limitations

* **Engine:** an action whose prerequisite is not a candidate, or that sits in
  a prerequisite cycle, is reported `infeasible` **with its reason** and never
  silently dropped; cycles exclude only their members — the rest still plans.
* **Verification semantics as implemented:** exactly 4 statuses;
  `VERIFICATION_ATTEMPTED` is the history `method` for both pass and fail
  (the attempted name lives in `detail.verification_method`); modeled rows
  carry `model_version=risk-2.1`, observed rows `None` (an observation is not
  a model); a failed verification stays `DONE` with a FAIL history row and may
  be retried — both rows persist.
* **Observed verification evidence:** SIMULATED, FIXTURE **and
  USER_PROVIDED** refs are all rejected (`evidence_not_live`) — the prompt
  names SYNTHETIC/FIXTURE; user-typed data is likewise not a live recheck.
* **Plan endpoint** is computed live and never persisted; `budget` may be
  passed by ORG_ADMIN or MEMBER (it changes only this computation), the
  default is the admin-set org budget and `budget_source` says which was used.
* **PostgreSQL suite not run** (unchanged environment limitation): unlike
  6b, this phase **adds a table and columns**; claim is "DDL verified for the
  PostgreSQL dialect" via the migration's batch operations — the full suite on
  PostgreSQL stays a Phase 13 attempt/BLOCKED item.
* No new dependency, no OAuth change, no plaintext secrets; `.env` still
  ignored. Outbox `.eml` files regenerated by test runs were deleted before
  the commit.

---

## Security-hardening pass (2026-10-24, post phase-7 + SMB frontend)

Findings from a full review of `750f9f2..HEAD` were fixed in code. Tests were
only ever strengthened (5 new regression tests); nothing was weakened.

### Fixed

* **Invite pre-registration takeover (HIGH)** — `POST /api/invitations/accept`
  previously bound an invitation to *any* pre-existing account with that email
  by token possession alone. An attacker who pre-registered a colleague's
  address could silently capture the invited membership. Now binding an
  already-existing account requires an authenticated session for that exact
  account (`backend/app/routers/org.py`, `backend/app/deps.py`). New-account
  creation via the emailed token is unchanged (possession = inbox control).
* **Rate limits** on the previously unthrottled anonymous endpoints:
  `/register` (bcrypt-CPU), `/password-reset/request` (email sending +
  enumeration timing), `/invitations/accept` (token brute force).
  (`backend/app/routers/auth.py`, `org.py`, `rate_limit.py`.)
* **`cryptography` added to `backend/requirements.txt`** (was missing → clean
  installs failed at import). All Python deps pinned to the exact versions
  verified in the project venv.
* **SMTP support for production email** (`backend/app/services/email.py`) with
  a fail-fast startup check (`config.assert_production_safe`) that also refuses
  localhost `CRIX_PUBLIC_BASE_URL` in production — reset/invite links are now
  built from `CRIX_PUBLIC_BASE_URL` instead of hardcoded `http://localhost:5173`.
* **Security headers** (nosniff, X-Frame-Options DENY, Referrer-Policy,
  Permissions-Policy; CSP + HSTS in production) and OpenAPI/docs disabled in
  production (`backend/app/main.py`).
* **`CRIX_TRUST_PROXY_HEADERS`** (default False): `X-Forwarded-For` is honored
  only behind a declared trusted proxy, so limits/audit IPs cannot be spoofed.
* **Password-reset tokens**: a new request invalidates earlier unused tokens.
* **2FA enrollment** (`POST /api/auth/2fa/setup`) now requires password
  re-authentication, so a stolen session cannot enroll an attacker
  authenticator (`backend/app/routers/auth.py`).
* **docker-compose**: Postgres binds to loopback only, password overridable
  via `CRIX_PG_PASSWORD`.
* **Frontend (functional bugs from the SMB commit)**: `acceptInvitation`
  pointed at a non-existent `/api/auth/accept-invitation` (now
  `/api/invitations/accept`); a `/invite` acceptance page was missing entirely
  (added, reusing existing design patterns); `remediationPlan` sent its
  `budget` in the body while the backend reads a query parameter — the
  override was silently ignored.
* **Pre-existing `tsc` breakage** from the SMB frontend commit fixed by using
  lucide-react's `LucideIcon` type and removing unused imports — `npm run
  build` works again.

### Honest deployment note (not changed)

The in-process rate limiter and OAuth pending-state table are per-process;
single-worker uvicorn is the supported deployment (startup now prints this).
`psycopg` remains unpinned and the PostgreSQL suite remains never-run here.

### Verification

* Backend: **440 tests passed** (435 before + 5 new hardening regression
  tests, incl. the takeover attack, 3 rate limits, token invalidation).
* Frontend: `tsc --noEmit` **0 errors** (was broken by the SMB commit),
  `vitest` **31/31**, `npm run build` **exit 0**.
* No OAuth/config change, no tenant-scope change, no plaintext secrets; `.env`
  stays untracked.

*(Phase 8+ entries appended when those phases complete.)*
