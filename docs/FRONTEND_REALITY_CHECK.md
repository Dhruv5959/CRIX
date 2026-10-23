# Frontend Reality Check

**Auditor:** Antigravity (read-only)
**Date:** 2026-10-23
**Branch:** `smb-migration` (active)
**Baseline tag:** `pre-smb-migration`
**Phase tags:** `phase-4-done` through `phase-7-done`

---

## 1. Git Evidence

### Branch & Tags

```
* smb-migration            (active, HEAD at b6218c7)
  main
  
Tags: phase-4-done, phase-5-done, phase-6-done, phase-6b-done, phase-7-done, pre-smb-migration
```

### Last 20 Commits Touching `frontend/`

**Only 6 commits have ever touched `frontend/`:**

| Hash | Date | Message |
|------|------|---------|
| `749a1ce` | 2026-10-23 02:21 | phase-6: implement company asset dependency graph |
| `40953fe` | 2026-10-22 23:32 | phase-5: implement Shapley risk attribution |
| `3dc923b` | 2026-10-22 22:49 | phase-4: implement contextual risk scoring |
| `1886aff` | — | Phase 3: organization-owned, explicit correlation results |
| `8bd6b3a` | — | feat(phase1): organization-first data model, RBAC, admin-view audit, OAuth freeze |
| `750f9f2` | 2026-10-22 16:29 | chore(baseline): pre-SMB-migration snapshot |

**Phases 2, 6b, and 7 did NOT touch `frontend/`.** The frontend was last modified in the phase-6 commit.

> [!IMPORTANT]
> There is no phase-8 through phase-13 commit anywhere in the repository. The full commit log contains only 9 total commits, the latest being `b6218c7` (phase-7, backend only).

---

## 2. Feature-by-Feature Frontend Audit

### 2.1 Risk Detail & Score Composition

| Check | Status | Evidence |
|-------|--------|----------|
| Route exists | **PASS** | `/risk` → `RiskPage.tsx` |
| Real API call | **PASS** | `useAnalysis()` → `api.runAnalysis()` → `POST /api/analysis/run` and `api.summary()` |
| In navigation | **PASS** | `Layout.tsx:31` — "Risk & Attribution" |
| Shows real data | **PASS** | Renders `risk.score`, `risk.base_risk`, `risk.interaction_risk`, `risk.criticality_adjustment`, `risk.mitigation_credit`, `risk.model_version`, `risk.range_low`/`range_high` |
| Provenance label | **PASS** | `<ProvenanceBadge provenance="MODEL" />` |

**Verdict: PASS** ✅

### 2.2 Shapley Attribution

| Check | Status | Evidence |
|-------|--------|----------|
| Route exists | **PASS** | Same `/risk` page, right panel |
| Real API call | **PASS** | Data from `result.attribution` via `useAnalysis()` |
| Shows real data | **PASS** | `attribution.contributions` sorted by absolute value, bar chart, efficiency error, compute_ms, method label, sum vs total |
| No mock data | **PASS** | All values from API response |

**Verdict: PASS** ✅

### 2.3 Dependency Graph

| Check | Status | Evidence |
|-------|--------|----------|
| Route exists | **PASS** | `/graph` → `GraphPage.tsx` |
| Real API calls | **PASS** | `api.graph()` → `GET /api/graph` and `api.orgGraph()` → `GET /api/org/graph` |
| In navigation | **PASS** | `Layout.tsx:32` — "Dependency Graph" |
| Shows real data | **PASS** | Force-graph visualization with `react-force-graph-2d`, centrality ranking (PageRank), edge detail panel. Org asset graph panel shows assets, criticalities, relationships |
| Provenance label | **PASS** | `<ProvenanceBadge provenance="CURATED" />` |

**Verdict: PASS** ✅

### 2.4 Remediation Planner (Greedy vs. Exact)

| Check | Status | Evidence |
|-------|--------|----------|
| Route exists | **PASS** | `/remediation` → `RemediationPage.tsx` |
| Real API calls | **PASS** | `result.planner` from `useAnalysis()` + `api.plannerActions()` → `GET /api/planner/actions` |
| In navigation | **PASS** | `Layout.tsx:33` — "Remediation & What-If" |
| Shows real data | **PASS** | Greedy vs. exact plan cards with `risk_after`, `risk_reduction`, `total_effort`, `compute_ms`. Optimality gap, greedy trap detection |
| Budget slider | **FAIL** | No slider/input to change budget. Budget is fixed at pipeline default (6.0). The `api.plannerPlan(budget)` accepts a parameter but the UI does not expose it |

**Verdict: PARTIAL** ⚠️ — planner works but budget is not adjustable

### 2.5 Remediation Tasks (Phase 7)

| Check | Status | Evidence |
|-------|--------|----------|
| Task list UI | **FAIL** | No task list, task status management (OPEN → DONE → VERIFIED), assignment, or verification UI exists in any frontend component |
| Task API calls | **FAIL** | `api.ts` has no calls to any `/api/remediation/tasks` endpoint. The backend `remediation.py` router exists but the frontend doesn't consume it |

**Verdict: FAIL** ❌ — Phase 7 backend tasks have no frontend

### 2.6 What-If Simulator

| Check | Status | Evidence |
|-------|--------|----------|
| Exists | **PASS** | `RemediationPage.tsx:114-166` |
| Real API call | **PASS** | `api.whatIf(payload)` → `POST /api/analysis/what-if` |
| Shows real data | **PASS** | Before/after scores, band, range, delta, applied actions |
| Toggle controls | **PASS** | 4 mitigation toggles (MFA, reused password, revoke session, passkey) |

**Verdict: PASS** ✅ — but only 4 hard-coded toggles (not dynamic from planner actions catalog)

### 2.7 GraphRAG Explanation

| Check | Status | Evidence |
|-------|--------|----------|
| Route exists | **PASS** | `/explanation` → `ExplanationPage.tsx` |
| Real API call | **PASS** | `api.explanation()` → `GET /api/analysis/explanation` |
| In navigation | **PASS** | `Layout.tsx:34` — "GraphRAG Explanation" |
| Shows real data | **PASS** | Summary, grounded status, reasoning statements with citations, retrieved evidence edges with sources, sanitized context |
| Provenance label | **PASS** | `<ProvenanceBadge provenance="CURATED" />` |

**Verdict: PASS** ✅

### 2.8 Risk History

| Check | Status | Evidence |
|-------|--------|----------|
| Route exists | **FAIL** | No `/risk-history` or similar route |
| Historical chart | **FAIL** | No component renders historical risk snapshots over time. `RiskResult` model stores snapshots but no frontend consumes them |

**Verdict: FAIL** ❌ — not built

### 2.9 Admin Audit Log / "Who Can See What"

| Check | Status | Evidence |
|-------|--------|----------|
| Route exists | **FAIL** | No audit log page, no admin panel, no "who can see what" page |
| Backend exists | **PARTIAL** | `AdminViewAuditLog` model exists (line 799 of `models.py`), `AuditLog` model exists. No corresponding frontend |
| Role display | **FAIL** | The UI does not show the user's role, membership, or organization name anywhere visible |

**Verdict: FAIL** ❌ — backend has audit infrastructure, no frontend

### 2.10 Evaluation Metrics

| Check | Status | Evidence |
|-------|--------|----------|
| Route exists | **PASS** | `/evaluation` → `EvaluationPage.tsx` |
| Real API call | **PASS** | `api.evaluation()` → `GET /api/evaluation` |
| In navigation | **PASS** | `Layout.tsx:35` — "Evaluation" |
| Shows real data | **PASS** | Renders suite metrics, confusion matrices, bar charts. Shows "not yet measured" when empty |
| Provenance label | **PASS** | `<ProvenanceBadge provenance="MODEL" />` + "synthetic data" badge |

**Verdict: PASS** ✅

### 2.11 Correlations

| Check | Status | Evidence |
|-------|--------|----------|
| Route exists | **PASS** | `/correlations` → `CorrelationsPage.tsx` |
| Real API call | **PASS** | From `useAnalysis()` |
| In navigation | **PASS** | `Layout.tsx:30` |
| Shows real data | **PASS** | Rule ID, version, severity, confidence, explanation, chain steps, asset IDs, finding IDs, uncertainty notes |

**Verdict: PASS** ✅

### 2.12 Propagation / Compromise Simulation

| Check | Status | Evidence |
|-------|--------|----------|
| Route exists | **PASS** | `/propagation` → `PropagationPage.tsx` (438 lines, most detailed page) |
| Real API calls | **PASS** | `api.propagationAccounts()` and `api.simulateCompromise()` |
| In navigation | **PASS** | `Layout.tsx:29` |
| Shows real data | **PASS** | Downstream exposure, storyline, recomputed risk, Shapley attribution, remediation comparison. Full SIMULATED labeling throughout |

**Verdict: PASS** ✅

---

## 3. Mock Data, Hard-Coded Values, Dead Buttons, Leftovers

### Grep Results

```
grep -r "mock|hardcod|TODO|FIXME|dummy|fake|stub" frontend/src/**/*.tsx
```

**1 hit found:**
- `CorrelationsPage.tsx:17` — "not **hardcoded** conditionals" (a descriptive label, not actual hardcoded data) ✅ clean

### Hard-coded UI Values

| Item | Location | Status |
|------|----------|--------|
| `WHATIF_ACTIONS` array in RemediationPage | `RemediationPage.tsx:19-24` | ⚠️ **4 hard-coded action keys** (`strengthen_mfa`, `change_reused_password`, `revoke_session`, `enable_passkey`). These exist in the backend catalog but the UI doesn't dynamically load the toggle list |
| Service dropdown in SignalsPage | `SignalsPage.tsx:97` | ℹ️ Hard-coded service list ("Google", "GitHub", etc.) — acceptable UX shortcut |

### Dead Buttons

None found. All buttons trigger real API calls.

### Leftover Personal-Security Pages

None. The baseline was a "user-scoped CRIX build" but all routes now serve the SMB-migrated organization-scoped data.

### OAuth UI

| Item | Status |
|------|--------|
| `ConnectionsPage.tsx` exists | **Yes** — fully built (540 lines) |
| Is it reachable? | **Yes** — `/connections` in nav |
| Is OAuth disabled? | **Yes** — `connectorsEnabled` flag correctly detects 404 and shows "Live provider connections are disabled in this build" banner |
| Demo fixture buttons | **Visible** — `connectFixture()` calls `POST /api/oauth/fixtures/{provider}`. When connectors are disabled, the entire provider card section is empty but the banner explains why |
| Security concern? | **No** — gracefully degrades. But the "Demo fixture" button would be visible if connectors were ever enabled |

**Verdict: PARTIAL** ⚠️ — OAuth UI exists and is navigable, correctly shows disabled state, but the "Demo fixture" button scaffold remains.

---

## 4. Demo Seed

| Check | Status | Evidence |
|-------|--------|----------|
| Script exists | **PASS** | `backend/scripts/seed_demo.py` (422 lines) |
| Creates real data | **PASS** | Creates user, org, 3 accounts, breach/hygiene/permission events, relationships, org assets, runs real pipeline |
| No mock data | **PASS** | Uses real engine: `pipeline.run_analysis(db, user.id, persist=True)`. Breach uses offline HIBP client (no real API call) but events are SIMULATED-labeled |
| How to run | **PASS** | `.venv\Scripts\python.exe backend\scripts\seed_demo.py [--email --password --org-name]`, defaults to `demo@example.com` / `demo-password-123` |
| Idempotent | **PASS** | All `_ensure_*` functions check for existing records |
| Prints output | **PASS** | Reports events, correlations, risk score, Shapley, planner gap, org graph stats |

**Verdict: PASS** ✅

---

## 5. Frontend Build, Lint, Tests

### Build (`npm run build`)

```
✓ 3276 modules transformed
✓ built in 17.08s
```

**Verdict: PASS** ✅ — 0 errors, 0 warnings, clean production build

### Lint (`npm run lint` → `tsc --noEmit`)

```
(no output = no errors)
```

**Verdict: PASS** ✅ — 0 type errors

### Tests (`npm test` → `vitest run`)

```
✓ src/lib/orgGraph.test.ts    (10 tests)
✓ src/lib/password.test.ts     (6 tests)
✓ src/lib/breach.test.ts      (15 tests)

Test Files  3 passed (3)
     Tests  31 passed (31)
```

**Verdict: PASS** ✅ — 31/31 tests pass

### What Is NOT Tested

- No component/integration tests (no React Testing Library)
- No end-to-end tests (no Playwright/Cypress)
- Tests cover only utility libraries (`orgGraph`, `password`, `breach`)
- No page-level tests, no API integration tests, no auth flow tests

---

## 6. Phase 12 Metrics Plan Commit Ordering

### Question: Was the metrics plan committed BEFORE the evaluation results?

**Answer: CANNOT DETERMINE — both shipped in the same commit.**

The evaluation endpoint (`GET /api/evaluation`), the `run_evaluation.py` script, and the `EvaluationPage.tsx` all appear in a single commit:

| Hash | Date | Message |
|------|------|---------|
| `750f9f2` | 2026-10-22 16:29:01 +0530 | `chore(baseline): pre-SMB-migration snapshot of the user-scoped CRIX build` |

This baseline commit contains ALL pre-migration code in one snapshot. There is no separate "metrics plan" commit before an "evaluation results" commit. The evaluation harness (`run_evaluation.py`), the endpoint, and the frontend page were all committed together.

**There are no phase 8-13 commits.** The commit history shows phases 1-7 only:

| Phase | Committed | Frontend touched? |
|-------|-----------|-------------------|
| Baseline | 2026-10-22 16:29 | Yes (full snapshot) |
| Phase 1 | — | Yes |
| Phase 2 | — | No |
| Phase 3 | — | Yes |
| Phase 4 | 2026-10-22 22:49 | Yes |
| Phase 5 | 2026-10-22 23:32 | Yes |
| Phase 6 | 2026-10-23 02:21 | Yes |
| Phase 6b | 2026-10-23 03:55 | **No** |
| Phase 7 | 2026-10-23 04:56 | **No** |
| Phase 8-13 | **MISSING** | **N/A** |

**Verdict: BLOCKED** 🚫 — cannot verify ordering because no separate commits exist for phases 8-13

---

## Summary Table

| Feature | Route | Real API | In Nav | Verdict |
|---------|-------|----------|--------|---------|
| Risk detail + composition | `/risk` | ✅ | ✅ | **PASS** |
| Shapley attribution | `/risk` | ✅ | ✅ | **PASS** |
| Dependency graph | `/graph` | ✅ | ✅ | **PASS** |
| Planner (greedy vs exact) | `/remediation` | ✅ | ✅ | **PARTIAL** — no budget slider |
| Remediation tasks (Phase 7) | — | ❌ | ❌ | **FAIL** — backend only |
| What-if simulator | `/remediation` | ✅ | ✅ | **PASS** (hard-coded toggles) |
| GraphRAG explanation | `/explanation` | ✅ | ✅ | **PASS** |
| Risk history | — | ❌ | ❌ | **FAIL** — not built |
| Admin audit log | — | ❌ | ❌ | **FAIL** — not built |
| Evaluation metrics | `/evaluation` | ✅ | ✅ | **PASS** |
| Correlations | `/correlations` | ✅ | ✅ | **PASS** |
| Propagation simulation | `/propagation` | ✅ | ✅ | **PASS** |
| Signals input | `/signals` | ✅ | ✅ | **PASS** |
| Live connections (OAuth) | `/connections` | ✅ | ✅ | **PASS** (disabled correctly) |
| Knowledge graph | `/knowledge` | ✅ | ✅ | **PASS** |
| Demo seed | script | ✅ | N/A | **PASS** |
| Build / lint / tests | — | — | — | **PASS** (31/31) |
| Phase 12 ordering | — | — | — | **BLOCKED** |

### What's Missing for Step B

1. **Budget slider** on the planner page
2. **Exposure-path replay** (step-by-step path visualization)
3. **Fix-order showdown** (3 ranking methods + simulated outcome comparison)
4. **Executive brief PDF** (server-generated)
5. **"Who can see what"** page (roles, admin visibility, audit log)
6. **Remediation task management UI** (OPEN/DONE/VERIFIED lifecycle)
7. **Risk history timeline**
8. **Component/integration/e2e tests** for all pages

### Corrections to Prior Claims

If phases 8-13 were previously claimed as done:

- **Phase 8 (planner UI with budget slider):** PARTIAL — planner exists but no budget control
- **Phase 9 (remediation tasks):** FAIL — backend exists, no frontend
- **Phase 10 (exposure path replay):** FAIL — propagation page shows results but no step-by-step replay
- **Phase 11 (fix-order showdown):** FAIL — not built
- **Phase 12 (evaluation):** PASS for display, BLOCKED for commit ordering verification
- **Phase 13 (executive brief):** FAIL — not built

