# FRONTEND_REALITY_CHECK_2.md — Company-Core & Org-Scoping Audit

> Branch `smb-migration`, HEAD `b6218c7` (phase-7-done).
> Audit date: 2026-10-23. No code was changed.

---

## 1. Company-Core Screens

| Screen | Page file | Route in App.tsx | Nav entry (Layout.tsx) | Calls real API | Verdict |
|---|---|---|---|---|---|
| Org setup (create org flow) | **NONE** | **NONE** | **NONE** | — | **FAIL** |
| Invite accept | **NONE** (only `ResetPasswordPage.tsx` exists as a token-link page) | **NONE** | **NONE** | — | **FAIL** |
| Company overview / dashboard | `OverviewPage.tsx` exists at `/` | ✅ L49 | ✅ L26 "Overview" | Calls `useAnalysis()` → `POST /api/analysis/run` | **PARTIAL** — shows risk + attribution summary but is user-scoped (see §2), not company-scoped; no org name, no member count, no asset inventory summary |
| Asset inventory (CRUD, criticality, dependencies) | **NONE** | **NONE** | **NONE** | — | **FAIL** |
| Findings list (provenance, status, correlations) | **NONE** — `CorrelationsPage.tsx` shows correlation results, `SignalsPage.tsx` lets you *enter* signals, but there is no org-level findings browser | **NONE** | **NONE** | — | **FAIL** |
| Members & roles | **NONE** | **NONE** | **NONE** | — | **FAIL** |

**Evidence:**
- `frontend/src/pages/` contains 13 files; none is named for org/assets/findings/members/invites
- `App.tsx` routes (L36–L103): `/`, `/signals`, `/connections`, `/propagation`, `/correlations`, `/risk`, `/graph`, `/remediation`, `/explanation`, `/evaluation`, `/knowledge` — no `/org`, `/assets`, `/findings`, `/members`, `/invites`
- `api.ts` has **zero** methods for `/api/org/*`, `/api/assets`, `/api/members`, `/api/remediation/tasks`, or `/api/remediation/settings`
- Backend routers exist: `org.py` (GET/PATCH /org, GET /members, POST /invitations), `assets.py` (full CRUD), `remediation.py` (10 operations) — all org-scoped via `get_current_membership`

---

## 2. Org Scoping of Key API Endpoints

| Endpoint | Router file | Auth dependency | Org resolution | Verdict |
|---|---|---|---|---|
| `POST /api/analysis/run` | `analysis.py:84–92` | `get_current_user` (L87) | `pipeline.run_analysis(db, current_user.id)` → internally calls `_resolve_org_or_none(db, user_id)` at L390 which uses `resolve_org_id(db, user_id)` to find membership | **PARTIAL** — org is resolved server-side via user's membership (L42 pipeline.py), but events are loaded by `user_id` not `org_id` (`SecurityEvent.user_id == current_user.id` at L50). No cross-org test at the API level. Findings are user-owned; the org context only affects criticality, dependency, and correlation, not event visibility. |
| `GET /api/analysis/summary` | `analysis.py:95–102` | `get_current_user` (L97) | Same as `/run` | **PARTIAL** — same scoping |
| `GET /api/analysis/events` | `analysis.py:105–115` | `get_current_user` (L107) | `SecurityEvent.user_id == current_user.id` directly (L112) | **FAIL** — pure user-scoped, no org awareness |
| `GET /api/analysis/explanation` | `analysis.py:118–132` | `get_current_user` (L120) | `pipeline.explain_run(db, current_user.id)` — user-scoped | **FAIL** — user-scoped |
| `POST /api/analysis/what-if` | `analysis.py:135–198` | `get_current_user` (L138) | `pipeline.run_analysis(db, current_user.id)` then modifies features locally | **PARTIAL** — org resolved internally, events user-scoped |
| `GET /api/org/graph` | `graph.py:72–83` | `get_current_membership` (L73) | `membership.org_id` (L82) | **PASS** — org-scoped by membership |
| `GET /api/org/graph/neighbors` | `graph.py:88–106` | `get_current_membership` (L89) | `membership.org_id` (L99–100) | **PASS** |
| `GET /api/org/graph/paths` | `graph.py:108+` | `get_current_membership` | `membership.org_id` | **PASS** |
| `GET /api/org/graph/blast-radius` | `graph.py` | `get_current_membership` | `membership.org_id` | **PASS** |
| `POST /api/propagation/simulate` | `propagation.py:72–198` | `get_current_user` (L74) | User-scoped: loads accounts via `_owned_account(db, user_id, ...)` (L33) | **FAIL** — user-scoped, no org |
| `GET /api/knowledge-graph` | `knowledge.py:23–50` | **NONE** | No auth at all — public, loads all `KnowledgeNode`/`KnowledgeEdge` rows from DB | **FAIL** — no auth, no org scoping |
| `GET /api/evaluation` | `knowledge.py:53–75` | **NONE** | No auth — loads all `EvaluationRecord` rows | **FAIL** — no auth, no org scoping |
| `GET /api/correlation-rules` | `knowledge.py:15–20` | **NONE** | Static catalog — no data concern | **PASS** (intentionally public catalog) |
| `GET/PATCH /api/remediation/settings` | `remediation.py:267–316` | `get_current_membership` / `require_role` | `membership.org_id` | **PASS** |
| `GET/POST /api/remediation/tasks` | `remediation.py:318–425` | `get_current_membership` / `require_role` | `membership.org_id` | **PASS** |

**Summary:**
- **Org-scoped (PASS):** org graph (4 endpoints), org.py endpoints, assets.py endpoints, remediation.py (all 10 operations)
- **Hybrid (PARTIAL):** analysis/run, analysis/summary, analysis/what-if — resolve org internally via user, but events are still user-scoped
- **User-scoped (FAIL):** analysis/events, analysis/explanation, propagation/simulate
- **No auth (FAIL):** knowledge-graph, evaluation

---

## 3. Seed Existence

| Check | Evidence | Verdict |
|---|---|---|
| Script exists | `backend/scripts/seed_demo.py` (295+ lines) | **PASS** |
| What it creates | 1 user (demo@example.com), 1 org ("Acme Corp"), 3 connected accounts, 3 user-confirmed relationships, 4 org assets, 3 dependency edges, runs full pipeline | **PASS** |
| Uses example.com | L56–57: "RFC 2606 reserves example.com for documentation", default `--email demo@example.com` | **PASS** |
| SYNTHETIC labels | L160: comment says "SYNTHETIC demo company assets" but no `SYNTHETIC` provenance badge is applied to the created assets — they are plain `OrgAsset` rows with no source_mode field | **PARTIAL** — comment says SYNTHETIC but no programmatic label stored |
| Idempotent | L183: "Idempotent: re-running the seed never duplicates an asset or an edge" — uses `_ensure_*` helpers with existence checks | **PASS** |
| Reset command | **NONE** — no `--reset` flag, no teardown function | **FAIL** |

---

## 4. Legacy Evaluation

| Check | Evidence | Verdict |
|---|---|---|
| `EvaluationPage.tsx` exists | 191 lines, route `/evaluation` in App.tsx L87–93 | **PASS** (exists) |
| Pre-migration build? | Renders data from `GET /api/evaluation` (knowledge.py L53–75). Shows suites: phishing_classifier, ai_text_detector, planner, shapley, correlation. These are from `run_evaluation.py` which imports `app.engine.{planner, risk, shapley}` (see §5). The page is from the pre-org-migration user-scoped build. | **Yes — pre-migration** |
| Labeled as legacy? | **NO** — header says "Evaluation" (L88), subtitle says "Every number here was produced by the evaluation harness" (L90). No legacy/pre-migration label. | **FAIL** |
| Org-scoped data? | No — `GET /api/evaluation` has **no auth** (knowledge.py L53–54), queries all `EvaluationRecord` rows globally | **FAIL** |

---

## 5. Simulator Import Boundary

| Check | Evidence | Verdict |
|---|---|---|
| Script | `backend/scripts/run_evaluation.py` | exists |
| Imports from risk engine | **YES** — L27: `from app.engine import planner, risk, shapley` | **FAIL** |
| Imports from ML | L28: `from app.engine import planner, risk, shapley` and `from app.ml.trainer import evaluate, train_all` | also imports ML |
| Import boundary violated | The evaluation script is NOT an independent simulator — it directly imports and calls the same `risk` and `planner` modules that compute the score. Phase 12 requires the simulator to import nothing from the risk engine. | **FAIL** — this is the evaluation harness, not an independent simulator. The independent simulator has not been written yet. |

---

## 6. /connections Page

| Check | Evidence | Verdict |
|---|---|---|
| Page exists | `ConnectionsPage.tsx`, 540 lines | **PASS** |
| In nav | `Layout.tsx` L28: `{ to: "/connections", label: "Live Connections", icon: Link2 }` | **FAIL** — still in nav despite OAuth being frozen |
| What it shows | Full OAuth provider panel, connect/disconnect buttons, capability matrix, relationship editor. Shows disabled banner when connectors off (L143–151) but banner only appears if the API 404s. | Still operational in nav |
| Should it be there? | **NO** — per master prompt: "Remove /connections from nav and demo path." It currently shows correctly that connectors are disabled, but the 540-line page and nav entry should be removed from the navigation for CRIX-SMB. | **FAIL** |

---

## 7. Additional Findings

### Hard-coded values
| Item | File:Line | Value | Issue |
|---|---|---|---|
| Planner budget | `pipeline.py:413` | `budget=6.0` | Hard-coded, ignores `Organization.effort_budget` (settable via `/api/remediation/settings`) |
| What-if toggle keys | `RemediationPage.tsx:19–24` | `WHATIF_ACTIONS` array with 4 hard-coded keys | Should come from action catalog API (`api.plannerActions()` is called at L34 but only used for the "Available actions" display, not for the toggles) |

### SignalsPage is personal-security
| Item | Evidence |
|---|---|
| `SignalsPage.tsx` | 555 lines of personal account management: "Connected Accounts" (add/delete personal accounts like Gmail, GitHub, PayPal), breach checks on personal email, password hygiene for personal passwords, phishing analysis, personal permission auditing. **This is the pre-migration personal-security page**, not a company-asset page. It creates user-scoped `ConnectedSignal` rows. |
| Impact | The page works and calls real APIs, but it represents the *user-scoped* personal-security model, not the company-asset model. It is the primary data-entry surface for the pipeline, so it cannot simply be deleted — but it needs to be relabeled or adapted for the SMB context. |

### Knowledge endpoints have no auth
| Endpoint | File:Line |
|---|---|
| `GET /api/knowledge-graph` | `knowledge.py:23` — no `Depends(get_current_user)` |
| `GET /api/evaluation` | `knowledge.py:53` — no `Depends(get_current_user)` |
| `GET /api/correlation-rules` | `knowledge.py:15` — no auth (but this is a static catalog, low risk) |

---

## 8. Verdict Summary

| Audit item | Verdict | Fix plan |
|---|---|---|
| **Org setup page** | **FAIL** | Build in 7b-d: login → org setup → invite accept flow |
| **Invite accept page** | **FAIL** | Build in 7b-d: token-link page for invitation acceptance |
| **Company overview** | **PARTIAL** | Exists but user-scoped; needs org name, member count, asset count |
| **Asset inventory page** | **FAIL** | Build in 7b-d: admin CRUD, criticality, dependency edges |
| **Findings page** | **FAIL** | Build in 7b-d: org-level finding browser with provenance |
| **Members page** | **FAIL** | Build in 7b-d: member list, roles, invite management |
| **Analysis org scoping** | **PARTIAL** | 7b-a: events loaded by user_id; org only affects criticality/dependency; need org-scoped event visibility or clear documentation |
| **Propagation org scoping** | **FAIL** | 7b-a: user-scoped; needs org-scoped accounts |
| **Knowledge/eval auth** | **FAIL** | 7b-a: add auth to knowledge-graph and evaluation endpoints |
| **Seed SYNTHETIC labels** | **PARTIAL** | 7b-b: add programmatic provenance labels |
| **Seed reset command** | **FAIL** | 7b-b: add `--reset` flag |
| **Evaluation labeled legacy** | **FAIL** | 7b-i: add "Legacy (pre-migration)" label |
| **Simulator import boundary** | **FAIL** | Phase 12: write independent simulator |
| **/connections in nav** | **FAIL** | 7b-i: remove from nav |
| **Pipeline budget hard-coded** | **FAIL** | 7b-h: use org's `effort_budget` setting |
| **What-if toggles hard-coded** | **FAIL** | 7b-h: populate from action catalog |
| **Task board UI** | **FAIL** | 7b-e: build 4-state lifecycle page |
| **Risk history chart** | **FAIL** | 7b-f: build from risk_results snapshots |
| **Audit / "who can see what"** | **FAIL** | 7b-g: build ADMIN-only page |
| **SignalsPage is personal** | **PARTIAL** | Needs relabeling or adaptation for company context |

### Counts
- **PASS:** 0 items fully pass for company-core
- **PARTIAL:** 3 (overview, analysis scoping, seed labels)
- **FAIL:** 17 items need building or fixing
- **BLOCKED:** 0

---

## 9. Honest Assessment

The backend for phases 1–7 is solid: `org.py`, `assets.py`, and `remediation.py` are fully org-scoped with `get_current_membership` and RBAC. But the frontend has **zero company-core screens** — no page for org setup, assets, findings, members, or tasks. The frontend is still the pre-migration personal-security UI with org-scoped features (graph, remediation planner) bolted on.

Phase 7b is a substantial build: 9 sub-items, most requiring new pages, API client methods, and tests. The backend is ready; the frontend needs to catch up.

