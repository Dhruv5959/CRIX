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
| 4 contextual risk scoring (asset criticality) | (this entry) | `phase-4-done` | **327 passed** | ✅ |

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

*(Phase 5 and Phase 6 entries appended below as those phases complete.)*
