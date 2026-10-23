# CRIX-SMB Run Plan v3 — Readback

> Written from the agent's understanding of MASTER_PROMPT_V3.md.
> Branch `smb-migration`, HEAD `b6218c7` (phase-7-done), 435 backend / 31 frontend tests green.

---

## What exists (verified)

| Phase | Tag | Backend tests | Frontend | State |
|---|---|---|---|---|
| 0 baseline | `pre-smb-migration` | 181 | 21 | ✅ |
| 1 org model + RBAC + OAuth freeze | — | 225 | 21 | ✅ |
| 2 common findings + stable assets | — | 253 | 21 | ✅ |
| 3 org-owned correlations | — | 291 | 21 | ✅ |
| 4 contextual risk scoring | `phase-4-done` | 327 | 21 | ✅ |
| 5 Shapley attribution | `phase-5-done` | 350 | 21 | ✅ |
| 6 dependency graph | `phase-6-done` | 380 | 31 | ✅ |
| 6b dependency exposure in score | `phase-6b-done` | 403 | 31 | ✅ |
| 7 remediation planning | `phase-7-done` | 435 | 31 | ✅ |
| 8–13 | — | — | — | NOT STARTED |

### Known frontend gaps (from FRONTEND_REALITY_CHECK.md)
- **FAIL:** Task board UI, risk history chart, audit/"who can see what" page
- **PARTIAL:** Planner budget fixed at 6.0, what-if has 4 hard-coded toggle keys
- **Unverified:** Company-core screens (org setup, invites, overview, assets, findings, members)
- **Cleanup needed:** `/connections` still in nav, `/evaluation` is legacy pre-migration
- **Tests:** 31 utility tests only (password, breach, orgGraph) — no component or journey tests

---

## What to build (phase order)

### Phase 7b — Frontend Catch-Up
**Goal:** Close every frontend gap from phases 1–7 so backend work is no longer ahead of the UI.

| Sub-item | What | Reuse |
|---|---|---|
| 7b-a ORG SCOPING | Ensure analysis, graph, what-if, explanation, history endpoints derive org from membership (not user). Cross-org denial tests. | Existing `get_current_membership` + `require_role()` in `deps.py`. Existing routers already org-scoped per phase 1 migration. Verify, fix the smallest change if not. |
| 7b-b SEED | Idempotent synthetic company with reserved example.com domains, SYNTHETIC labels, reset command. | Existing `seed_demo.py` — extend, do not replace. |
| 7b-c SHARED UI | `ProvenanceBadge`, `StateViews` (loading/empty/error/forbidden/unavailable), `SimulatedBanner`, role-aware nav, typed API client. | Existing `api.ts`, `Layout.tsx`, `auth.tsx`. Factor out patterns already repeated across pages. |
| 7b-d ORG SHELL | Login → org setup → invite accept → overview → asset inventory → findings → members. | Existing pages may partially exist (unverified). Backend routers: `org.py`, `assets.py`, `auth.py` (invite). |
| 7b-e TASK BOARD | 4-state lifecycle (OPEN/DONE/VERIFIED_MODELED/VERIFIED_OBSERVED), assign, evidence, reopen. VERIFIED_OBSERVED rejects SYNTHETIC data. | Backend: `remediation.py` router (10 ops, phase 7). Frontend: no existing UI. |
| 7b-f RISK HISTORY | Chart from `risk_results` snapshots. | Backend: `risk_results` table with `org_id`, `model_version`, `created_at`. Need a history endpoint if none exists. |
| 7b-g AUDIT + RBAC PAGE | ADMIN only: roles, admin visibility, audit log. | Backend: audit events exist in the database. Need a read endpoint. |
| 7b-h PLANNER BUDGET SLIDER | Real planner call with adjustable budget, greedy/exact label. What-if toggles from action catalog. | Backend: `POST /api/remediation/plan`, `GET /api/remediation/settings`. Frontend: `RemediationPage.tsx` exists but budget=6.0 and toggles hard-coded. |
| 7b-i CLEANUP | Remove `/connections` from nav. Label `/evaluation` as legacy. | `Layout.tsx` nav items, `EvaluationPage.tsx`. |

### Phase 8 — What-If Simulation (backend + UI)
Isolated, non-persistent simulation through the real risk engine. Side-by-side candidates. SIMULATED banner. Never mutate state.
**Reuse:** `propagation.py` already has what-if logic. Extend with explicit snapshot isolation and the dependency term.

### Phase 9 — Explanations (backend + UI)
Audit existing retrieval honestly. Tenant-scoped retrieval over org data. Optional LLM adapter (OFF by default). Injection tests. Citations on every claim.
**Reuse:** `knowledge.py` router and `ExplanationPage.tsx` exist. Need to verify whether retrieval is real graph-backed or fixed lookup.
**STOP 1** after this phase.

### Phase 11 — Synthetic Company (4 scenarios)
25 fictional employees. 4 documented scenarios testing different risk profiles. Offline, reproducible, labeled SYNTHETIC.
**Reuse:** `seed_demo.py` pattern. Separate from evaluation corpus.

### Phase 10 — Signature Screens (after phase 11 data exists)
Exposure-path replay, fix-order showdown (3 methods, SIMULATED, demo scenarios only, losses shown honestly), executive brief PDF, screenshot script, journey tests.
**Reuse:** Graph engine `paths_between`/`blast_radius`, planner `compare`, risk engine.
**STOP 2** after this phase.

### Phase 12 — Evaluation
Separate dev/held-out sets. Freeze params before held-out. Metrics plan committed alone (**STOP 3** before running results). 4 methods (severity-only, severity×criticality, CRIX+shared packer, CRIX planner). Independent simulator (no risk engine imports). Known + incomplete graph conditions. Negative results acceptable.
**Reuse:** `run_evaluation.py`, `report_planner_gap.py` (import boundary already partially tested). Legacy `/evaluation` page replaced.

### Phase 13 — Security, Regression, Cleanup
Full RBAC audit, secret validation, injection tests, PostgreSQL suite (BLOCKED if unavailable), Alembic up/down, second phishing model, DATASETS.md, CI, README matches reality.
**Reuse:** Existing security tests (47), propagation tests, migration tests.

---

## Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Company-core screens may not exist at all | Phase 7b scope larger than expected | FRONTEND_REALITY_CHECK_2 audit will reveal true scope before coding starts |
| What-if hard-coded toggles deeply embedded | Breaking change if the planner catalog changes | Toggles will be fetched from the action catalog API |
| Existing evaluation page has pre-migration logic | Cannot simply extend it | Replace entirely in phase 12; label as legacy until then |
| PostgreSQL suite never run | Phase 13 may be BLOCKED | Document honestly; do not claim "Postgres-tested" |
| No Playwright installed | Journey tests blocked | Install as a dev dependency in phase 7b |
| LLM adapter in phase 9 could leak org data | Cross-tenant exposure | Sanitize before external calls; ADMIN consent gate; injection tests |
| Simulator may import risk engine code | Evaluation tainted | AST/import-boundary test blocks this at CI |
| Context compaction may lose prior audit findings | Repeated work | Key findings documented in FRONTEND_REALITY_CHECK.md and PROGRESS.md |

---

## STOP points

1. **Before Phase 7b code:** Write FRONTEND_REALITY_CHECK_2.md → STOP for approval
2. **After Phase 9:** STOP 1 — report and wait
3. **After Phase 10:** STOP 2 — report and wait
4. **After Phase 12 metrics plan commit:** STOP 3 — no results until CONTINUE

---

## Immediate next action

`FRONTEND_REALITY_CHECK_2.md` does not exist → write the company-core audit (Section 4.1) and STOP.

