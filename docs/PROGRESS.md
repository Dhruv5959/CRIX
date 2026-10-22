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

---

*(Phase 7+ entries appended when those phases complete.)*
