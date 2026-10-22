# CRIX → CRIX-SMB Migration Audit (Step 0)

**Date:** 2026-10-22
**Scope:** audit of the existing repository against the CRIX-SMB master prompt (organization-first product for 10–30 person IT-services/software companies).
**Status:** audit + plan only. **No application code has been written or changed.** Awaiting approval (step 0e).

Method: every verdict below was verified by reading the file or running the command named in
"Evidence" — not by trusting `docs/*.md`, which describe an earlier (user-scoped) design and are
themselves audited in §3.17.

---

## 1. VCS baseline and secret hygiene

The project root was **not** a git repository (only `awesome-design-md/.git`, a vendored
third-party checkout). Step 0b therefore required establishing the safety net first:

| Action | Result |
|---|---|
| `git init -b main` | repo created at project root |
| `.gitignore` extended | added `backend/artifacts/outbox/`, `backend/artifacts/*.eml`, `*.log`, `.opencode/`, `.claude/`, `.playwright/`, `awesome-design-md/` |
| baseline commit | `750f9f2` — 165 files, no secrets |
| tag | **`pre-smb-migration`** (annotated) |
| branch | **`smb-migration`** (current HEAD) |
| `.env` tracked? | **no** — verified with `git ls-files` (secret check preserved) |

**Secret-hygiene finding (fixed before the commit):** `backend/artifacts/outbox/` contained real
dev password-reset messages (`*.eml`, including one generated 2026-10-22) whose bodies embed
single-use reset tokens. `.gitignore` covered only `artifacts/*.joblib` and `artifacts/*.json`, so
those files **would have been committed**. They are now ignored. The `.env`-is-ignored guarantee
is also asserted by an existing test: `tests/test_security.py::test_env_example_present_and_env_gitignored`.

**Note on databases:** the *active* database used by the running API is `backend/crix.db`
(launched with cwd `backend`). The repo-root `crix.db` (last written 2026-10-08) is **stale** and
unused. Both are ignored by `*.db`.

---

## 2. Verified build state (everything below was executed, not assumed)

| Check | Command | Result |
|---|---|---|
| Backend tests | `cd backend; ..\.venv\Scripts\python.exe -m pytest` | **181 passed** (4 warnings) |
| Frontend typecheck | `cd frontend; npx tsc --noEmit` | 0 errors |
| Frontend unit tests | `cd frontend; npx vitest run` | **21 passed** (6 password + 15 breach) |
| Frontend build | `cd frontend; npm run build` | success |
| ML artifacts | `backend/artifacts/` | `phishing_model.joblib`, `ai_detector.joblib` present |
| Evaluation rows | `evaluation_records` in `backend/crix.db` | 26 rows across 5 suites (see Appendix B) |

Tests per file (from `pytest --collect-only`):

```
tests/test_auth.py             14      tests/test_propagation.py   27
tests/test_breach_endpoint.py  11      tests/test_risk.py          11
tests/test_correlation.py      12      tests/test_security.py      20
tests/test_graph_graphrag.py    8      tests/test_shapley.py        7
tests/test_planner.py          10      tests/test_signals.py       26
tests/test_xposedornot.py      35      ────────────────────────────────
                                       181
```

**Deployment reality:** SQLite only. `requirements.txt` has **no PostgreSQL driver**
(no `psycopg`/`asyncpg`), so "PostgreSQL for the full stack" is currently unimplemented
(§3.2, §9 decision D1).

---

## 3. Component audit

Verdicts: **EXISTS+WORKS** (implemented, exercised by passing tests) · **PARTIAL** (real but
incomplete for the SMB requirement) · **MISSING** · **BROKEN** (found defective).

### 3.1 Auth, sessions, secrets

| Item | Verdict | Evidence |
|---|---|---|
| Password hashing (bcrypt ≥ 12) + policy | EXISTS+WORKS | `app/security.py:29-60` (`rounds = max(12, bcrypt_rounds)`, 72-byte guard, common-password list) |
| JWT access + rotating refresh, CSRF, revocation | EXISTS+WORKS | `app/security.py:70-107`, `app/routers/auth.py:58-247`; tests `test_refresh_rotation`, `test_refresh_requires_csrf`, `test_logout_clears_session` |
| Single-use, expiring password reset | EXISTS+WORKS | `app/models.py:90-104`, `app/routers/auth.py:264-330`; `test_password_reset_token_single_use`, `test_password_reset_unknown_email_does_not_enumerate` |
| TOTP 2FA (CRIX's own login) | EXISTS+WORKS (off by default) | `app/totp.py`, `app/routers/auth.py:330-364` |
| Startup secret validation (refuses dev secrets in prod) | EXISTS+WORKS | `app/config.py:126-141`; `test_production_requires_secret` |
| Login / password-check rate limiting | EXISTS+WORKS | `app/rate_limit.py`, `app/routers/auth.py`; `test_login_rate_limited`, `test_password_check_rate_limited` |
| **Organizations, memberships, roles, invitations** | **MISSING** | a repo-wide search for `org_id\|organization\|membership\|invitation\|ORG_ADMIN\|role` across `backend/app/**/*.py` returns **0 matches**. `app/deps.py:21-53` resolves a user and nothing else |
| **RBAC (role × action matrix, enforced server-side)** | **MISSING** | no roles exist; every endpoint is authorised solely by `get_current_user` |
| **Tenant isolation (org_id AND role on every query)** | **MISSING** | isolation today is per-user only: `app/routers/accounts.py:18-93`, `app/routers/analysis.py`, `app/engine/pipeline.py:31-36` all filter `user_id == current_user.id`. Covered by `test_idor_endpoint_matrix` (user-vs-user, not org-vs-org) |
| **Admin access to member data audit-logged + member-visible** | **MISSING** | `app/audit.py` + `AuditLog` exist but are flat and user-scoped (`app/models.py:326-335`); no `admin_view_audit_log` table, no member-facing view |

### 3.2 Data model and tenancy

`app/models.py` (445 lines, 21 tables). Every tenant table carries a **non-nullable `user_id`**
and no `org_id` (`models.py:1-5` states this as the design intent).

Tables present: `users`, `refresh_tokens`, `password_reset_tokens`, `connected_signals`,
`security_events`, `provider_metadata`, `graph_relationships`, `knowledge_nodes`,
`knowledge_edges`, `correlations`, `risk_results`, `attribution_results`, `remediation_actions`,
`remediation_plans`, `evaluation_records`, `audit_logs`, `provider_connections`,
`provider_capabilities`, `account_relationships`, `propagation_results` (+ Alembic tables).

| SMB requirement | Verdict | Evidence |
|---|---|---|
| `users` | EXISTS+WORKS | `models.py:45-59` |
| `organizations`, `memberships`, `invitations` | **MISSING** | absent from `models.py`; confirmed absent in the live DB table list |
| `org_assets` with ownership | **PARTIAL** | the closest concept is `ConnectedSignal` (`models.py:110-133`) — a *user-declared* account/asset. No org ownership, no asset type, no criticality |
| **Asset criticality** (`criticality`) | **MISSING** | no column anywhere; the word does not appear in `backend/app` |
| `asset_dependencies` | **PARTIAL** | two disjoint sources: curated `GraphRelationship` (`models.py:185-197`, 20 rows, service→service, static) and `AccountRelationship` (`models.py:397-423`, user-confirmed, `USER_CONFIRMED`). Neither is an org-declared, admin-owned, `ADMIN_DECLARED` edge |
| `security_events`, `correlations`, `risk_results`, `attribution_results` | EXISTS+WORKS | `models.py:136-277` |
| `remediation_actions` (catalog) / `remediation_plans` | EXISTS+WORKS | `models.py:279-307` (plans persist per run with `method`, `risk_after`, `is_greedy_trap`) |
| **`remediation_items` (OPEN/IN_PROGRESS/DONE/VERIFIED) + claim/verify lifecycle** | **MISSING** | no such table; no task board |
| **`risk_snapshots` + trend** | **PARTIAL** | history data *does* exist (`risk_results` per `run_id`, 19 rows) but there is no snapshot table and no Risk History page |
| `provider_metadata`, `provider_capabilities` | EXISTS+WORKS | `models.py:164-182`, `375-394`; seeded from `datasets/providers.json` (21 rows) |
| `audit_log` | EXISTS+WORKS (flat) | `models.py:326-335`, `app/audit.py` with secret redaction (`test_audit_redaction_removes_secrets`, `test_login_audit_has_no_token`) |
| **`admin_view_audit_log`** | **MISSING** | absent |
| Alembic migrations | EXISTS+WORKS | `backend/migrations/versions/{17855d545687_initial_schema,9c3f21a04e12_live_connections}.py`; plus an additive-column auto-migrator in `app/db.py:52-102` (dev convenience) |

### 3.3 Signal modules

| Module | Verdict | Evidence |
|---|---|---|
| Breach/exposure (XposedOrNot default + optional HIBP) | EXISTS+WORKS | `app/signals/xposedornot.py`, `app/signals/hibp.py`, `app/signals/breach.py`; 35 tests in `tests/test_xposedornot.py` + 11 in `tests/test_breach_endpoint.py`. 429/timeout → `UNAVAILABLE` (§1.10 preserved) |
| Breach consent enforcement | EXISTS+WORKS | `app/routers/breach.py` (consent required); documented in `docs/SECURITY.md` |
| exposure_type + `mfa_bypass_capable` multiplier | EXISTS+WORKS | `app/schemas.py:28-32`, `app/signals/breach.py:241-365`, `app/engine/propagation.py:88-101` |
| Session variants labelled **SIMULATED** | EXISTS+WORKS | `app/schemas.py:45-58` (`SourceMode`), `app/engine/normalizer.py:36-49` |
| Password reuse via client-side fingerprints | EXISTS+WORKS | `frontend/src/lib/password.ts`, `app/signals/password.py`, `app/routers/password_check.py` |
| Compromised-password k-anonymity range check | EXISTS+WORKS | `app/routers/password_check.py:41`; `test_range_endpoint_rejects_full_hash`, `test_range_endpoint_rejects_non_hex`, `test_outgoing_requests_never_contain_plaintext_password` |
| Curated passkey/MFA/recovery table (~20 services) | EXISTS+WORKS | `datasets/providers.json` (**21 rows**), `app/signals/permissions.py`, `app/routers/password_check.py:63-91` |
| `PASSKEY_AVAILABLE_UNUSED`, `SIM_SWAP_EXPOSURE`, `MFA_FATIGUE_INDICATOR` | PARTIAL | `SIM_SWAP_VULNERABLE` exists in `app/signals/password.py` and the risk map (`app/engine/risk.py:42-58`); `PUSH_BOMBING_REPORTED` exists. `PASSKEY_AVAILABLE_UNUSED` and `MFA_FATIGUE_INDICATOR` are **not** distinct event types |
| Phishing/scam classifier (real trained model) | EXISTS+WORKS | `app/signals/phishing.py`, `app/ml/trainer.py`, artifacts present, metrics measured (§Appendix B) |
| AI-generated-vs-human detector | EXISTS+WORKS | `app/ml/dataset.py` (synthetic corpus), `app/ml/trainer.py:81-134` (stylometric features) |
| URL model as a signal source | EXISTS+WORKS | folded into `app/signals/phishing.py:41-103` (`_extract_signals` returns URL/lexical signals) |
| Third-party app / integration auditor | EXISTS+WORKS (user-entered) | `app/signals/permissions.py:18-132` (`classify_permission`, `build_permission_events`), `datasets/permissions_taxonomy.json` (35 entries); events `RISKY_PERMISSION_GRANTED`, `STALE_PERMISSION_GRANTED` |

### 3.4 SecurityEvent contract and entity resolution

| Item | Verdict | Evidence |
|---|---|---|
| Normalized `SecurityEvent` contract with Pydantic validation | EXISTS+WORKS | `app/schemas.py:135-175` (`SecurityEventSchema`), `app/models.py:136-161`, `app/engine/normalizer.py:18-140` |
| Provenance on every datum (REAL / USER_PROVIDED / SIMULATED / FIXTURE / UNAVAILABLE) | EXISTS+WORKS | `app/schemas.py:34-58`; enforced end-to-end (UI badges, `normalizer._source_mode`) |
| Server-authoritative severity/risk (client cannot inject) | EXISTS+WORKS | `test_client_cannot_inject_severity`, `test_risk_is_recomputed_server_side` |
| **Entity resolution layer** | **MISSING** | no resolution module. Identity is handled ad-hoc by string keys: `app/engine/graph.py` and `app/engine/propagation.py:184-195` map accounts by `metadata_json["service_name"]` or `service_name`; `app/engine/pipeline.py:46-49` does the same. This is exactly the "fragile string matching scattered around" the master prompt prohibits |

### 3.5 Correlation and storylines

| Item | Verdict | Evidence |
|---|---|---|
| Declarative, data-driven correlation engine | EXISTS+WORKS | `app/engine/correlation.py` (no hardcoded conditionals), `datasets/correlation_rules.json` = **8 rules**: `credential_stuffing_risk`, `targeted_credential_theft`, `cascading_recovery_risk`, `elevated_takeover_risk`, `mfa_ineffective_session_exposure`, `identity_reuse_blend`, `sim_swap_recovery_exposure`, `oversharing_and_phishing` |
| One test per rule + rule-shape validation | EXISTS+WORKS | `tests/test_correlation.py` (12 tests); non-firing/`FINDING`-only semantics in `correlation.py:26-41` |
| Temporal window field in rules | PARTIAL | rules carry `predicates` + `severity` + `confidence` only; there is **no temporal window** in the schema (`correlation.py` has no time predicate) |
| Storylines (ordered chains + "why it matters") | PARTIAL | `app/routers/propagation.py:_storyline` builds an ordered narrative for one simulation; there is no storyline model, no storyline page, no org-level storyline builder |

### 3.6 Risk engine

| Item | Verdict | Evidence |
|---|---|---|
| Deterministic `base + interaction − mitigation`, parameterized | EXISTS+WORKS | `app/engine/risk.py:61-164` (`RISK_PARAMS`); pure function of a feature vector |
| Confidence band + sensitivity interval (never a probability) | EXISTS+WORKS | `risk.py:187-223` (`SENSITIVITY_DELTA = 0.05`); wording rules honoured in docs/UI |
| Per-account correlation (no cross-account severity borrowing) | EXISTS+WORKS | `correlation.py:79-116` |
| **Asset-criticality weighting** | **MISSING** | `risk_from_features` consumes only per-feature severity (`risk.py:128-153`); criticality is not a parameter and has no data source. This is a *required* SMB change, so it will be added deliberately (not a rewrite of a working algorithm) |
| **Org-level aggregation** | **MISSING** | the pipeline is `run_analysis(db, user_id)` (`pipeline.py:64`); no org roll-up, no "which company asset matters most" |
| Sensitivity analysis artefact | PARTIAL | the engine computes an interval, but there is no standalone sensitivity report script |
| Ordinal-constraint / perturbation-stability tests | PARTIAL | `tests/test_risk.py` (11 tests) covers bands/ranges; the master prompt's ordinal-constraint suite is not present as a named suite |

### 3.7 Shapley

**EXISTS+WORKS.** Exact cooperative-game Shapley over the risk function (`app/engine/shapley.py:26-72`),
efficiency property asserted in `tests/test_shapley.py` (7 tests) and measured
(`max_efficiency_error = 0.0`, Appendix B). No model is trained on CRIX-generated labels anywhere
in the repo — the prohibited circular SHAP approach is absent. Reusable as-is.

### 3.8 Graph and blast radius

| Item | Verdict | Evidence |
|---|---|---|
| NetworkX dependency graph (no Neo4j) | EXISTS+WORKS | `app/engine/graph.py:20-144` |
| Centrality ranking (weighted PageRank + weighted in-degree) | EXISTS+WORKS | `graph.py:44-66` |
| Reachability / dependency events from compromise signals | EXISTS+WORKS | `graph.py:71-143` (`dependency_events`, `ACCOUNT_DEPENDENCY`, `COMPROMISED_RECOVERY_ACCOUNT`) |
| Curated dependency catalog (~15–20) | EXISTS+WORKS | `datasets/graph_relationships.json` = **20 rows** with `source` + `last_verified_at` |
| **`ADMIN_DECLARED` org edges + org-owned assets** | **PARTIAL** | edges are curated or user-confirmed; there is no org/admin declaration concept |
| Blast radius framed for an organisation | PARTIAL | the machinery exists (`graph.py`, `app/engine/propagation.py:293-417`) but is computed per user and framed as "downstream exposure", not org blast radius |

### 3.9 Planner, tasks, history

| Item | Verdict | Evidence |
|---|---|---|
| Exactly two methods: greedy vs exact branch-and-bound | EXISTS+WORKS | `app/engine/planner.py:121-217`; `tests/test_planner.py` (10 tests) |
| Deliberate greedy-trap scenario + measured gap | EXISTS+WORKS | `scripts/run_evaluation.py:47-115` (`greedy_trap_constructed`, budget 2.0); measured mean gap 0.0686, `greedy_trap_observed = 2` |
| Per-action current risk → resulting risk → reduction → effort | EXISTS+WORKS | `planner.py:28-119` (`Action`, `apply_action`), `app/routers/planner.py:17-40` |
| Shared **org** effort budget ("admin has N hours") | PARTIAL | a budget parameter exists (`pipeline.py:75` passes `budget=6.0`) but is not org-configurable or admin-owned |
| Planner output → `remediation_items`; DONE vs VERIFIED by pipeline re-run | **MISSING** | plans persist (`remediation_plans`) but no task items and no verification-by-rerun loop |
| Risk snapshots every run + trend | PARTIAL | `risk_results` rows accumulate (19 rows) but no snapshot table and no UI |

### 3.10 What-if simulator

**EXISTS+WORKS.** `app/routers/analysis.py:109` → re-runs the real pipeline with mitigation
toggles (`app/schemas.py:284-295`); never frontend-computed. Tests: `test_what_if_runs`,
`test_what_if_reduces_risk`, `test_what_if_has_real_attribution`, `test_what_if_rejects_unknown_action`.
Needs to be re-pointed at org mitigation state in the migration.

### 3.11 Compromise propagation (defensive simulation)

**EXISTS+WORKS** (`app/engine/propagation.py`, `app/routers/propagation.py`, 27 tests in
`tests/test_propagation.py`): documented parameters, `weakness_unknown` neutral default, mitigation
credit, path decay, `SIMULATED` provenance, disclaimer forbidding probability language, and real
event rows untouched. **Reusable as the seed of the org-level evaluation simulation (§11).**

### 3.12 GraphRAG

| Item | Verdict | Evidence |
|---|---|---|
| Curated knowledge graph | EXISTS+WORKS | `datasets/knowledge_graph.json`: **15 nodes / 21 edges**, predicates `enables`/`defeats`/`prevents`; includes session_hijacking, push_bombing, aitm_phishing, sim_swapping + mitigations |
| Allowlisted context serializer | EXISTS+WORKS | `app/engine/graphrag.py:58-87`; `test_graphrag_context_whitelist` |
| Citations to retrieved evidence | EXISTS+WORKS | `graphrag.py:119-223` (`_cite`, `_render_summary`) |
| Unsupported-claim detection | EXISTS+WORKS | `graphrag.py:224` (`validate` → `unsupported_claims`) |
| **LLM-generated explanation** | **PARTIAL / effectively MISSING** | by design the generator is **deterministic and template-based** (`graphrag.py` module docstring: "The generator is deliberately deterministic and template-based… There is no free-form invention"); there is **no LLM client and no LLM dependency** in `requirements.txt`. Retrieval + grounding + validation exist; the LLM layer does not |
| Prompt-injection / poisoned-KG robustness tests | PARTIAL | `tests/test_graph_graphrag.py` (8 tests) covers grounding/citations; a poisoned-KG suite is not present |

### 3.13 ML

| Item | Verdict | Evidence |
|---|---|---|
| Real trained classifier with reproducible split/seed | EXISTS+WORKS | `app/ml/trainer.py:44-174` (`seed=1234`), `app/ml/dataset.py`, `datasets/phishing_corpus_*.jsonl` (223 train / 153 test / 4 held-out) |
| Reported precision/recall/F1/confusion matrix from real runs | EXISTS+WORKS | persisted to `evaluation_records` (Appendix B: F1 0.8296, P 1.0, R 0.7089) |
| "One stronger model" beyond the TF-IDF+LR baseline | **MISSING** | no second model exists (`grep 'stronger\|distilbert'` → 0 matches); `docs/IMPLEMENTATION_STATUS.md:209-211` states the DistilBERT comparison "was not attempted" and reports "not yet measured" |
| Robustness check on AI-rewritten phishing | PARTIAL | `app/ml/dataset.py:143-163` generates AI-style variants; no dedicated robustness experiment is recorded |

### 3.14 Evaluation harness

| Item | Verdict | Evidence |
|---|---|---|
| ML / correlation / risk / Shapley / planner suites, persisted with metadata | EXISTS+WORKS | `scripts/run_evaluation.py` (5 suites, 26 rows in `evaluation_records`) |
| UI reads only persisted rows ("not yet measured" otherwise) | EXISTS+WORKS | `app/routers/knowledge.py:53-...`, `frontend/src/pages/EvaluationPage.tsx` |
| **Org-level attack-propagation simulation vs severity-only baselines, N seeded runs with CIs** | **MISSING** | nothing compares fix orderings; `propagation.py` is single-user and single-run |

### 3.15 Frontend

Routes (`frontend/src/App.tsx:34-105`): `/login`, `/reset-password`, `/`, `/signals`,
`/connections`, `/propagation`, `/correlations`, `/risk`, `/graph`, `/remediation`,
`/explanation`, `/evaluation`, `/knowledge`.

| SMB page | Verdict | Evidence |
|---|---|---|
| Login / Register / reset | EXISTS+WORKS | `pages/LoginPage.tsx`, `pages/ResetPasswordPage.tsx` |
| Overview | EXISTS+WORKS (personal framing) | `pages/OverviewPage.tsx` |
| Assets (org assets + criticality) | **MISSING** | nearest is `pages/SignalsPage.tsx` → `AccountManager` (user accounts) |
| Findings | **MISSING** as a page | data served by `app/routers/analysis.py:79` (`/events`) |
| Correlations and Storylines | PARTIAL | `pages/CorrelationsPage.tsx` exists; no storyline page (`pages/PropagationPage.tsx` shows one simulation narrative) |
| Risk + Shapley waterfall | EXISTS+WORKS | `pages/RiskPage.tsx`, `components/ui/risk-gauge.tsx` |
| Dependency graph (interactive) | EXISTS+WORKS | `pages/GraphPage.tsx` (+ force-graph dep) |
| Remediation board / plan + what-if toggles | PARTIAL | `pages/RemediationPage.tsx` shows plans; no task board, no DONE/VERIFIED lifecycle |
| Risk history / trend | **MISSING** | no page |
| GraphRAG explanation with evidence | EXISTS+WORKS | `pages/ExplanationPage.tsx` |
| Evaluation | EXISTS+WORKS | `pages/EvaluationPage.tsx` |
| Audit log | **MISSING** | no page |
| Onboarding wizard (org → assets → criticality → dependencies) | **MISSING** | routes go straight to a dashboard |
| Invite / members / roles UI | **MISSING** | none |
| Provenance badges everywhere | EXISTS+WORKS | `components/ui/badge.tsx`; used across pages |
| Design system (dark-mode, one accent, glass) | EXISTS+WORKS | `components/Layout.tsx`, `components/ui/*`, tailwind config |

### 3.16 Tests

181 backend + 21 frontend tests, all green. The master-prompt security checklist is largely
already covered — `tests/test_security.py` (20) and `tests/test_auth.py` (14) include:
`test_outgoing_requests_never_contain_plaintext_password`,
`test_idor_endpoint_matrix`, `test_client_cannot_inject_severity`,
`test_risk_is_recomputed_server_side`, `test_audit_redaction_removes_secrets`,
`test_login_audit_has_no_token`, `test_graphrag_context_whitelist`,
`test_login_rate_limited`, `test_password_check_rate_limited`,
`test_cors_not_wildcard`, `test_env_example_present_and_env_gitignored`,
`test_production_requires_secret`.

Gaps for the SMB checklist: **cross-org** read denied, MEMBER cannot read others' findings,
VIEWER cannot write, admin-access-to-member-data is audit-logged, offline fixture mode asserted
for the whole demo path (partially: `scripts/seed_demo.py` pins the provider offline and
`tests/conftest.py` forbids live provider calls).

### 3.17 Docs, datasets, packaging

| Item | Verdict | Notes |
|---|---|---|
| `docs/ARCHITECTURE.md`, `SECURITY.md`, `IMPLEMENTATION_STATUS.md`, `PRESENTATION.md` | EXISTS, **stale for SMB** | they document a user-scoped product, personal accounts, and "Q: Why live OAuth to Google/GitHub/Instagram?" (`PRESENTATION.md`). They must be re-scoped, not deleted. `IMPLEMENTATION_STATUS.md` also honestly records "Not a git repository" and the un-measured DistilBERT slot |
| `docs/SMB_MIGRATION_AUDIT.md` | this file | new |
| `datasets/*` | EXISTS+WORKS | 8 correlation rules, 21 providers, 20 graph relationships, 15 KG nodes / 21 edges, 35 permission entries, phishing corpora |
| Dependency policy | clean | `requirements.txt` (21 lines) and frontend deps are minimal; no paid service anywhere. **No PostgreSQL driver**, **no LLM client** |

---

## 4. Conflicts with org-first (what must change)

1. **Tenancy model.** Every table keys `user_id`; there is no `org_id`, no roles, no memberships,
   no invitations. All isolation tests are user-vs-user.
2. **Asset concept.** "Asset" is a *user-declared account* with no owner, type, or criticality.
   "Which company asset matters most" cannot be answered today.
3. **Risk is not criticality-weighted** and cannot aggregate to an organisation.
4. **Remediation has no task lifecycle** (OPEN/IN_PROGRESS/DONE/VERIFIED) and no org budget;
   nothing verifies a fix by re-running the pipeline.
5. **No admin-view audit** (member-level data access is not logged or member-visible).
6. **OAuth is live-by-default** (routers registered in `app/main.py:46-62`, Instagram in
   `app/oauth/providers.py`) — must be frozen behind a flag defaulting **OFF**, and the Instagram
   connector removed (§1.4).
7. **GraphRAG has no LLM** (deterministic renderer), so §8's "LLM explanation" is not met.
8. **ML has a baseline only**; the "stronger model" slot is unimplemented.
9. **No org-level evaluation** (attack-propagation comparison vs baselines).
10. **Frontend is a personal dashboard**; the org pages of §9 and the onboarding wizard are absent.
11. **Employee-privacy boundary** (members own their findings; admins see aggregates unless shared;
    every admin view audit-logged; no surveillance) is entirely absent.
12. **Docs and UI copy** are personal-security framed and must be re-scoped.
13. **No PostgreSQL path** exists (driver absent).
14. **No entity-resolution layer**; identity is ad-hoc string matching.

---

## 5. Reusable as-is (do not rewrite)

- **Auth/security core:** `app/security.py`, `app/routers/auth.py`, `app/rate_limit.py`,
  `app/audit.py`, `app/totp.py`, `app/token_crypto.py`, `app/config.py` (incl. startup validation).
- **Signal modules:** `xposedornot.py`, `hibp.py`, `breach.py`, `password.py`,
  `password_check.py`, `phishing.py`, `permissions.py` — all already emit the `SecurityEvent`
  contract and already honour UNAVAILABLE/consent/labeling rules.
- **Normalizer:** `app/engine/normalizer.py` (contract, provenance, `replace_module_events`).
- **Correlation engine:** `app/engine/correlation.py` + `datasets/correlation_rules.json`.
- **Risk engine:** `app/engine/risk.py` — extended with a criticality term, not replaced.
- **Shapley:** `app/engine/shapley.py` — exact, efficiency-verified.
- **Graph engine:** `app/engine/graph.py` (NetworkX, PageRank/in-degree).
- **Planner:** `app/engine/planner.py` (greedy vs exact, trap suite, gap measurement).
- **Propagation:** `app/engine/propagation.py` — becomes the org-level evaluation simulator.
- **GraphRAG core:** `app/engine/graphrag.py` (sanitizer, retrieval, citations, `validate`).
- **ML stack:** `app/ml/*`, `backend/artifacts/*`, `scripts/train_phishing.py`, `scripts/run_evaluation.py`.
- **Data:** all of `datasets/`, `scripts/seed_demo.py` (offline pinning), `scripts/smoke.py`.
- **Infra:** Alembic setup, `app/db.py` (+ additive column migrator), `.env.example` conventions.
- **Frontend:** design system (`components/ui/*`, `Layout.tsx`, `badge.tsx`), `lib/api.ts`,
  `lib/auth.tsx`, `lib/analysis.tsx`, `lib/password.ts`, `lib/breach.ts` + their tests.

---

## 6. Migrate vs clean database reset

**Recommendation: migrate the schema (real Alembic revision), reset the data.**

Rationale:
- All existing data is synthetic or generated by smoke/probe runs: 38 users, 156 `security_events`,
  19 `risk_results`, 38 `remediation_plans`, 211 `audit_logs` in `backend/crix.db`. There is no
  real user data to preserve, and the master prompt states the data is synthetic.
- Adding `org_id` to user-scoped rows would require inventing an organisation per user, which
  would create fake tenancy — worse than a clean seed, and impossible to test meaningfully.
- A fresh database guarantees every tenant row is created *with* a valid `org_id`, so the
  cross-org isolation tests mean something.
- Keep and extend the Alembic history (so the migration path itself is real and reviewable);
  drop the local `.db` files (root `crix.db` is stale and should be deleted).

What is *not* reset: `datasets/`, `backend/artifacts/*.joblib`, and the evaluation methodology.

---

## 7. Smallest coherent migration plan (proposed)

Mapped to the master prompt's phases. Each phase ends with green tests + a short report; personal
routes are removed only after their org replacement works.

| Phase | Work | Reuses | New |
|---|---|---|---|
| **0** | this audit + git baseline + tag/branch | — | `docs/SMB_MIGRATION_AUDIT.md` |
| **0.5** (small, do with 1) | **Freeze OAuth**: feature flag default OFF, remove Instagram connector + its UI/copy, keep code paths intact behind the flag | `app/oauth/*`, `routers/oauth.py` | flag in `config.py` |
| **1** | Org data model + auth/RBAC: `organizations`, `memberships` (ORG_ADMIN/MEMBER/VIEWER), `invitations`, `org_id` on every tenant table, `org_assets` (with `criticality`, `asset_type`, `owner_member_id`), `asset_dependencies` (`ADMIN_DECLARED`), `admin_view_audit_log`; Alembic revision; role×action matrix in `docs/`; onboarding-capable registration (register creates the org as first admin); invite accept flow; **cross-org isolation + RBAC + admin-view-audit tests**; clean DB reset + updated `seed` | auth core, audit, Alembic | org tables, RBAC deps (`require_role`), invite flow |
| **2** | SecurityEvent org-scoping + entity-resolution layer + adapt signal modules to org assets (`org_id`, `asset_id`) | all signal modules, normalizer | `app/engine/resolution.py`, org-aware event writes |
| **3** | Correlation + storylines at org level: add temporal windows to the rule schema; storyline model + API; new org rules (criticality-aware) | `correlation.py`, rules JSON | temporal predicate support, storyline builder |
| **4** | Risk engine: add documented **criticality weighting** + org aggregation; sensitivity + ordinal-constraint + perturbation-stability suites | `risk.py` structure, `RISK_PARAMS` | criticality params, org roll-up, sensitivity script |
| **5** | Shapley at org level (features now include criticality) + benchmark | `shapley.py` as-is | waterfall page wiring |
| **6** | Graph: org asset graph + `ADMIN_DECLARED` edges + blast radius (centrality × criticality reachability) | `graph.py` | org graph API/payload |
| **7** | Planner → tasks: org effort budget, `remediation_items` lifecycle, DONE vs VERIFIED by pipeline re-run, `risk_snapshots` + trend | `planner.py` | items, snapshots, verify endpoint |
| **8** | What-if re-pointed at org mitigation state (real pipeline re-run) | `analysis.py` what-if | org toggles |
| **9** | GraphRAG: optional LLM adapter **on top of** the existing sanitizer/citations, with NOT_CONFIGURED/UNAVAILABLE fallback (deterministic renderer remains the default so the build never needs a key) | `graphrag.py` core | LLM adapter, poisoned-KG tests |
| **10** | Frontend org pass: Onboarding wizard, Assets, Findings, Storylines, Remediation Board, Risk History, Audit Log, Invite/Members; remove personal routes after replacements land | design system, lib/*, existing pages | new pages |
| **11** | Synthetic 25-person IT company seed + 3 required scenarios + documented ground truth | `seed_demo.py` | new seed |
| **12** | Evaluation harness: add org-level attack-propagation simulation (CRIX vs severity-only vs severity×criticality), N seeded runs, CI, reported as-is | `propagation.py`, `run_evaluation.py` | org eval suite |
| **13** | Security audit + docs (README, ARCHITECTURE, SECURITY, IMPLEMENTATION_STATUS, PRESENTATION re-scoped) + polish | all | docs rewrite |

Deliberate non-rewrites: the deterministic risk *function shape*, exact Shapley, the two-method
planner, the correlation rule interpreter, and the GraphRAG sanitiser stay; they gain inputs
(criticality, org scope) rather than being replaced.

---

## 8. Proposed Phase 1 in detail (the first code phase, pending approval)

1. `app/models.py`: add `Organization`, `Membership` (role enum), `Invitation`, `OrgAsset`
   (`org_id`, `asset_type`, `label`, `criticality` 1–5, `owner_member_id`, `service_name`,
   `source_mode`), `AssetDependency` (`ADMIN_DECLARED`), `AdminViewAuditLog`; add non-null
   `org_id` to `security_events`, `correlations`, `risk_results`, `attribution_results`,
   `remediation_actions`, `remediation_plans`, `evaluation_records`, `audit_logs`,
   `connected_signals` (→ superseded by `org_assets`), `provider_metadata`, etc.
2. New Alembic revision `org_model` (real migration; no data backfill — the DB is reset).
3. `app/deps.py`: add `get_current_membership`, `require_role(...)` returning 403 with no
   information leak (404 on unknown/foreign resources).
4. `app/routers/auth.py`: `register` creates the org + first `ORG_ADMIN`; add
   `POST /api/invitations`, `POST /api/invitations/accept`, `GET /api/org`, `GET /api/members`.
5. `docs/RBAC.md`: role × action matrix.
6. Tests: `tests/test_org_isolation.py` (cross-org read/write denied for every endpoint group),
   `tests/test_rbac.py` (VIEWER cannot write; MEMBER cannot see others' findings),
   `tests/test_admin_view_audit.py` (admin access logged + member-visible), invite single-use/expiry.
7. `scripts/seed_demo.py`: reset + seed a single org with members/assets.

Phase 1 does **not** touch the risk engine, Shapley, planner, or GraphRAG.

---

## 9. Open decisions I need from you before Phase 1

- **D1 — PostgreSQL.** §4 mandates PG for the full stack. No driver is installed. Options:
  (a) add `psycopg[binary]` as a normal dependency and make SQLite the dev/test default
  (recommended: config-only switch, so no server is required to run tests here); or
  (b) stay SQLite-only and document the deviation. This affects `requirements.txt` only.
- **D2 — LLM for GraphRAG (Phase 9).** Which provider/key? Recommended: an optional adapter
  (env-configured) that falls back to the existing deterministic renderer when no key is present,
  so the build and the demo never depend on a paid key (§1.11).
- **D3 — "Stronger model" for phishing (Phase 4/12 scope).** DistilBERT needs large downloads and
  heavy deps. Recommended: a second *classical* model (e.g., linear SVM or gradient boosting) on
  the same documented split, reported honestly, with the package name kept as the "stronger model"
  slot. Confirm, or state that "not yet measured" stays.
- **D4 — The `Propagation` page.** Keep and rename to an org "Attack Path / Blast Radius" view, or
  fold it into the new Dependency Graph + What-If pages? (Recommend: fold in, keep one graph page.)
- **D5 — BYOD boundary.** §2 says company-owned assets only. May a member add a *work-related*
  personal device/mailbox as an asset (labelled `USER_ENTERED`, member-owned), or is that out of scope?
- **D6 — Employee identities.** Should `org_assets` reference a `membership` (so findings can be
  attributed to a work account) while still enforcing "members own their personal findings"? I
  recommend yes: attribute to the *work account asset*, never to a person's private accounts.

---

## 10. Explicitly not done

- No application, frontend, schema, or config code was changed.
- OAuth was **not** touched (still enabled in code — Phase 0.5/1 fixes that).
- The only repo changes are: `.gitignore` hardening (secret-safety), the git baseline
  commit/tag/branch, and this document.
- I did not run a real Google/LinkedIn authorization round-trip (no credentials), and per §1.4 it
  is now frozen anyway, so it is no longer a blocker — but the connectors must be hidden/flagged
  before the SMB demo.

---

## Appendix A — verification commands

```powershell
cd backend; ..\.venv\Scripts\python.exe -m pytest            # 181 passed
cd frontend; npx tsc --noEmit                                 # 0 errors
cd frontend; npx vitest run                                   # 21 passed
cd frontend; npm run build                                    # ok
git log --oneline --decorate                                  # 750f9f2 (tag: pre-smb-migration)
git ls-files | Select-String '^\.env$'                        # empty (not tracked)
{collect-only per file}                                       # counts in §2
```

## Appendix B — measured metrics already persisted (from `evaluation_records`)

| Suite | Metric | Value |
|---|---|---|
| `phishing_classifier` | f1 / precision / recall | **0.82963 / 1.0 / 0.70886** (153 test samples) |
| `ai_text_detector` | f1 / precision / recall | **0.80882 / 0.88710 / 0.74324** |
| `planner` | mean optimality gap | **0.068576** (exact vs greedy) |
| `planner` | greedy traps observed / constructed | 2 / 1 |
| `shapley` | max efficiency error | **0.0** |
| `correlation` | rules defined / exercised | 8 / 8 |

These are synthetic-data measurements on CRIX's own scenarios. They are reported as such and are
not a claim about real-world detection performance.

## 11. Phase 1 completion record (2026-10-22)

Everything in this section was executed, not assumed.

### 11.1 New tenant model

* Tables: `organizations`, `memberships`, `invitations`, `org_assets`, `asset_dependencies`,
  `admin_view_audit_log` (migration `b1a7c3d9e2f4`).
* Registration now creates a real organization and makes the registrant its first `ORG_ADMIN`.
  There is no personal/default tenant.
* Server-side authorization: `get_current_membership` + `require_role` (`app/deps.py`). The
  `org_id` used for every scoped query comes from the database, never from the client.
* API: `GET/PATCH /api/org`, `GET /api/members`, `GET /api/members/{id}` (admin view is
  audit-logged), `GET /api/org/admin-views`, invitations CRUD + accept, assets and
  dependencies CRUD (`app/routers/org.py`, `app/routers/assets.py`).
* Role × action matrix and the privacy boundary: `docs/RBAC.md`.

### 11.2 OAuth freeze + Instagram removal

* `oauth_connectors_enabled` defaults to **False in code** (`app/config.py`); every OAuth route
  (and the callback) returns 404 / `connectors_disabled` when off.
* Instagram removed from the provider registry, provider settings, the connector source map,
  the capability matrix, the UI copy and the demo seed.
* Deliberate boundary: Instagram is **kept** in the curated *reference* catalogues
  (`providers.yaml`, `graph_relationships.yaml`) because those describe real-world services and
  their documented recovery routes, not connectable providers. Recorded here so it is not read
  as an oversight.

### 11.3 Defect found and fixed: the migration chain could not build from scratch

`alembic upgrade head` **failed on an empty database** (`NoSuchTableError: security_events`):
revision `17855d545687` was empty (`pass`) because the project bootstrapped its schema with
`Base.metadata.create_all` and only later adopted Alembic.

Fix: the initial revision now materialises the base schema from `Base.metadata` with
`checkfirst=True`, and every later revision is idempotent (guarded `create_table`/`add_column`/
`drop_table`). The chain now runs from an empty database **and** from an already-`create_all`-ed
database, and `downgrade base` returns to an empty database. `tests/test_migrations.py` (4 tests)
locks this in, including a check that the migrated schema **exactly equals** `Base.metadata`
(no drift between migrations and the ORM).

### 11.4 Verified state

| Check | Command | Result |
|---|---|---|
| Backend suite | `pytest` (backend) | **225 passed** (baseline was 181) |
| New Phase 1 tests | — | org isolation 7, RBAC 5, admin-view audit 4, invitations 8, assets 8, OAuth freeze 5, module independence 2, migrations 4, Postgres-dialect 2 |
| Alembic up/down | `alembic upgrade head` then `downgrade base` | from-empty **works**; `downgrade base` leaves only `alembic_version`; re-upgrade works |
| Fresh DB + seed | `alembic upgrade head`; `scripts/seed_demo.py` | 27 tables, 1 org, 1 membership (ORG_ADMIN), 3 accounts, 2 dependency edges, **0 `provider_connections`** |
| Frontend | `tsc --noEmit`, `vitest run`, `npm run build` | clean, **21 passed**, built in 13.8 s |
| Secret scan | full history (`750f9f2`) + working tree | 6 hits, **all** placeholders/test fixtures (`*.local`, `example.*`, one fake JWT); no keys, no real emails |
| Tracked sensitive files | `git ls-files` | none (`.env`, `*.db`, `*.eml`, `artifacts/` untracked/ignored) |

### 11.5 Measured metrics re-run (this run, `evaluation_records`)

| Suite | Metric | Value |
|---|---|---|
| `phishing_classifier` | f1 / precision / recall / accuracy | 0.829630 / 1.0 / 0.708861 / 0.849673 (153 samples) |
| `ai_text_detector` | f1 / precision / recall / accuracy | 0.808824 / 0.887097 / 0.743243 / 0.830065 (153 samples) |
| `planner` | mean / max optimality gap | 0.0685757 / 0.424968 |
| `planner` | scenarios / traps constructed / traps observed | 7 / 1 / 2 |
| `shapley` | max efficiency error / tolerance | 3.0e-09 / asserted `< 1e-6` |
| `shapley` | features / samples / seed / mean ms | 12 / 50 / 99 / 35.8 ms |
| `correlation` | rules defined / exercised | 8 / 8 |

Synthetic-data measurements on CRIX's own scenarios, reported as such.

### 11.6 Postgres status — honestly NOT run

`psycopg[binary]` was added to `requirements.txt`, `docker-compose.yml` provides PostgreSQL 16,
the test suite honours `CRIX_TEST_DATABASE_URL`, and `tests/test_postgres_dialect.py` compiles
every table for the PostgreSQL dialect. **However the suite was never executed against a real
PostgreSQL server**: Docker is not installed in this environment and no local PostgreSQL exists,
so `psycopg` is not installed either. "Postgres-tested" is therefore **not** claimed; only
"DDL verified for the PostgreSQL dialect".

### 11.7 Known deviations carried forward

* The legacy user-scoped analysis tables were scheduled to **all** gain `org_id` in Phase 2.
  **Delivered in Phase 2 (§12):** `security_events` (NOT NULL, resolved server-side) and
  `connected_signals` (best-effort nullable label). `correlations`, `risk_results`,
  `attribution_results`, `remediation_actions`, `remediation_plans`, `propagation_results`
  and `audit_log` still carry `user_id` only and are deferred to the phases that rework
  them — the delivered scope is recorded honestly in §12.6.
* `app/db.py::init_db()` performs additive `ALTER TABLE ADD COLUMN` as a dev convenience; the
  Alembic chain is now the supported path and is self-sufficient.

---

## 12. Phase 2 completion record (2026-10-22)

Phase 2 delivers the **Common Security Finding Format**: one normalized `SecurityEvent`
schema, stable company-asset identity, and organization ownership of every finding.

### 12.1 What changed

| Area | Change |
|---|---|
| `app/schemas.py` | `SecurityEventSchema` extended with `org_id`, `asset_id`, `first_seen`, `last_seen`, `evidence`, `created_at`, `updated_at`; `EventStatus` still forbids any form of "safe because unknown". Added `sanitize_evidence`: malformed evidence (wrong type or >4096 chars) is **rejected**, credential-like content is **redacted and never stored** (key denylist `password`/`passwd`/`secret`/`token`/`credential`/`otp`/`key`/`session`; value denylist for JWT-, `sk-`/`AKIA`-, private-key- and address-shaped strings). |
| `app/engine/entities.py` (new) | `identity_of` / `canonical_asset_id` / `resolve_asset` / `assert_asset_in_org`. Canonical equality only: emails lowercased+trimmed; scheme, trailing slash and `.git` stripped with the host lowercased and path case kept; a label with spaces is never an identity. No name-similarity merging. |
| `app/engine/normalizer.py` | `org_id` is resolved **server-side** from the author's active membership (`resolve_org_id`, raises `OrgScopeError` for a user with no organization); a client-sent `org_id` is overwritten. Asset binding matches account identity (email / account id) against `org_assets` **inside that same organization**; no match means `NULL` (unknown, never a guess). `first_seen`/`last_seen` prefer the detector's source window and fall back to CRIX's own observation window, which survives re-checks (`replace_module_events`). Added `list_org_events` for tenant-scoped reads. |
| `app/signals/{breach,password,phishing,permissions}.py`, `app/engine/graph.py` | Every emitted `SecurityEventSchema` now carries minimal sanitized `evidence`; breach findings additionally carry `first_seen`/`last_seen` when HIBP reports `BreachDate` (min/max over breaches). XposedOrNot reports no dates, so `evidence.first_breach_date` is `None` and `first_seen` is CRIX's first observation. The phishing path stores extracted indicators only — the submitted message body is never persisted. |
| `app/routers/assets.py` | Asset ids are canonicalized on create and matched canonically on read/dependency, so the same repository or work address always maps to one asset; duplicate-by-another-spelling is a 409; cross-tenant ids stay 404; self-dependency is 422. |
| `app/routers/accounts.py` | Account rows are labeled with the caller's organization, resolved server-side (best effort: a legacy user without a membership keeps `NULL`). |
| `migrations/versions/c9d1e2f3a4b5_security_event_org_scope.py` (new) | Adds the columns above. Idempotent (existence-guarded, raw-driver introspection because SQLAlchemy's reflection cache is not invalidated by an in-migration batch rebuild) and reversible (batch rebuild, rows copied not dropped). Backfills `org_id` from each row's writer membership where one exists; a row with no membership keeps the empty sentinel, which matches no tenant query (fail-closed) — **nothing is deleted**. |
| `scripts/seed_demo.py` | Mirrors the real writers: demo accounts get the org label, one company work-address asset is registered, and the seed prints how many findings are bound to a company asset. |

### 12.2 Verified state (every command executed)

| Check | Command | Result |
|---|---|---|
| Backend suite | `pytest` (backend) | **253 passed** (baseline 225 + 28 new in `tests/test_finding_schema.py`) |
| Migration tests | `pytest tests/test_migrations.py` | 4 passed (empty → head; ORM-first → head no-op; `downgrade base` leaves only `alembic_version`; re-upgrade) |
| Dev DB reset | `alembic downgrade base`, `upgrade head`, `scripts/seed_demo.py` | full cycle from empty works; `alembic_version = c9d1e2f3a4b5`; **0 findings with an empty `org_id`**; 9/9 findings bound to the company asset; 3 accounts org-labeled |
| Risk engine unchanged | seed summary | risk 61.7 (HIGH), Shapley efficiency error 0.0, planner gap 0.00 % — identical to Phase 1 |
| Frontend | `tsc --noEmit`, `vitest run`, `npm run build` | clean, **21 passed**, built in 13.2 s (Phase 2 is additive: the existing `/api/analysis/events` already returns the extended fields, so no UI change was required) |
| Secret scan | persisted `evidence` of every seeded/seeded-by-test finding | no password-, token- or address-shaped values |

New tests cover: schema bounds/enum/blank type, evidence redaction and size, identity
canonicalization and distinctness, label-not-an-identity, asset canonicalization + duplicate
409 + cross-org invisibility, client `org_id` overwritten, findings never binding across
organizations, mail-account-vs-domain distinctness, live `REAL` labeling, `UNAVAILABLE`
provider failure with its own evidence, source dates surfaced when present and **not invented**
when absent, no secrets persisted, re-check without duplicates and with a preserved
`first_seen`, and the API exposing the whole standardized field set.

### 12.3 Postgres status — honestly NOT run (unchanged from §11.6)

The suite was never executed against a real PostgreSQL server (no Docker, no local server,
`psycopg` therefore not installed). Claim: **"DDL verified for the PostgreSQL dialect"**
(`tests/test_postgres_dialect.py`), not "Postgres-tested". The new migration contains
PostgreSQL branches (`information_schema` / `pg_indexes`), which are **not** executed here and
are therefore untested on a real server.

### 12.4 Privacy boundary deliberately kept

There is **no org-wide "all findings" endpoint**. `normalizer.list_org_events` exists and is
tested, but exposing other members' findings through the API would require the Phase 1
admin-view audit path (member-level access, logged and visible to the member). Phase 2 keeps
member findings on the member's own `/api/analysis/events` and stops at the persistence
invariant, which is what the tenant-scoped phases need.

### 12.5 Not done, not claimed

* No risk formula, Shapley, planner or GraphRAG change (the seed's unchanged numbers are the
  evidence); no ML retraining; no frontend redesign; OAuth stays frozen and Instagram stays
  absent. The correlation engine was reworked in **Phase 3 (§13)**, but its severity and
  confidence formulas are unchanged.
* No paid dependency added; no fabricated metric.

### 12.6 Deviations carried forward to Phase 3

* `risk_results`, `attribution_results`, `remediation_actions`, `remediation_plans`,
  `propagation_results`, `audit_log` still carry `user_id` only. Phase 3 adds `org_id` to
  `correlations` (§13); the rest stay user-scoped until their own phase.
* One column-level divergence between the two schema-creation paths: `security_events.org_id`
  is `NOT NULL` in **both** (the migration adds it with `server_default ""`, backfilled to a
  real organization wherever the writer has a membership; a leftover sentinel — impossible
  through registration — matches no tenant query, so the invariant holds fail-closed), but
  **`updated_at`** cannot be added as `NOT NULL` by SQLite `ALTER`, so it is nullable in
  migrated databases while the ORM always writes it. Fresh (ORM-created) databases carry the
  full `NOT NULL` set. `connected_signals.org_id` is nullable by design (best-effort label).

---

## 13. Phase 3 completion record (2026-10-22)

Phase 3 makes correlation **organization-owned and explicit**: rules stay declarative data,
but every result now states exactly which findings it combined, in which organization, under
which rule version, over which company assets, and what its confidence does and does not
mean. It also adds the three high-value asset-aware rules that the Phase 2 identity work made
possible.

### 13.1 What changed

| Area | Change |
|---|---|
| `app/data/correlation_rules.yaml` | Every rule gains `version` (`"1.0.0"`) and an explicit `scope`. Predicates gain `status` (default `FINDING`) and `min_events`. Three new rules added — exactly three, each exercising one Phase 3 capability: `company_asset_compound_exposure` (`scope: same_asset`), `declared_dependency_exposure` (`scope: linked_assets`), `phishing_campaign_window` (`scope: same_account`, `window_hours: 720`, justified: repeated lures in a short window are a campaign, not noise). |
| `app/engine/correlation.py` | Grouping is by `(org_id, account_id)` / `(org_id, asset_id)` / declared `(org_id, from_asset, to_asset)` — never by account alone — so cross-tenant mixing is structurally impossible. A finding with no resolved `org_id` is **excluded (fail-closed)**. `linked_assets` rules may only use edges the pipeline read from `asset_dependencies`; CRIX never infers an edge from name similarity. `correlation_id` is `sha256(org_id\|rule_id\|rule_version\|sorted finding_ids)[:32]`. Results carry `org_id`, `rule_id`+`rule_version`, `finding_ids`, `asset_ids`, a cited `evidence` dict, a rendered `explanation` (template placeholders filled with the real values), a plain-language `chain`, `evaluated_at`, and an explicit `uncertainty` statement. Ordering is `(-severity, rule_id, correlation_id)`. **Severity and confidence formulas are byte-for-byte unchanged.** |
| `app/engine/pipeline.py` | Resolves the run's organization server-side (fail-closed to "no correlations" if the user has none). Stamps derived graph events with that organization *without touching the graph module*. Passes the caller's org-scoped `asset_dependencies` edges to `evaluate`. Persists correlations **upserted by `correlation_id`** (a repeat run refreshes the row, never duplicates it) and removes stale rows whose findings were replaced by a re-check (a correlation is a derived view, never a copy — the findings themselves are never altered). |
| `app/models.py` `Correlation` | Gains `correlation_id` (unique index), `org_id` (FK, NOT NULL, sentinel-backfilled), `rule_version`, `correlation_type`, `uncertainty`/`chain`/`asset_ids`/`evidence` (JSON), `evaluated_at`. Column `contributing_event_ids` **renamed** to `finding_ids` (same data). |
| `migrations/versions/d4e5f6a7b8c9_correlation_org_scope.py` (new) | Idempotent + reversible. Adds the columns, back-fills `org_id` from the writer's membership, gives every legacy row a deterministic `correlation_id` (content hash, with a primary-key-derived fallback for old per-run duplicates so **nothing is deleted** to fit the unique index), then renames `contributing_event_ids`→`finding_ids` via a direct `RENAME COLUMN` (supported by SQLite 3.25+ and PostgreSQL; Alembic's batch `alter_column(new_name)` does not rename on SQLite — found and fixed here). |
| `app/schemas.py` + `app/routers/analysis.py` | `CorrelationResponse` and the `/api/analysis` payload expose the full explicit result: `correlation_id`, `org_id`, `rule_version`, `finding_ids`, `asset_ids`, `evidence`, `uncertainty`, `chain`, `evaluated_at`. |
| `frontend/src/lib/types.ts`, `CorrelationsPage.tsx`, `OverviewPage.tsx`, `KnowledgePage.tsx` | `contributing_event_ids`→`finding_ids`; keys use the stable `correlation_id`; the correlation card renders the plain-language **chain**, the company assets involved, and the uncertainty note; the rule catalog shows version + scope. |

### 13.2 Verified state (every command executed)

| Check | Command | Result |
|---|---|---|
| Backend suite | `pytest` (backend) | **291 passed** (Phase 2's 253 + 34 engine tests in `tests/test_correlation_org.py` + 1 migration test) |
| New correlation tests | `pytest tests/test_correlation_org.py` | 37 passed |
| Migration tests | `pytest tests/test_migrations.py` | 5 passed (incl. a new **data-preservation** test: a Phase 2-shaped `correlations` table with a legacy row is upgraded — `org_id` back-filled, `rule_version` filled, `finding_ids` renamed, 32-char `correlation_id` assigned — then downgraded, keeping the row and its findings) |
| Dev DB rebuild | delete `crix.db`, `alembic upgrade head`, `seed_demo.py` | full cycle works; `alembic_version = d4e5f6a7b8c9`; correlations carry `org_id`, `rule_version 1.0.0`, `finding_ids`, `asset_ids`, `chain`, `evidence`, `uncertainty`, `evaluated_at`; unique index present |
| Upsert, no duplicates | re-run `seed_demo.py` twice | correlation rows stay at **2** (stale rows from replaced findings are cleaned up, fresh ones upserted) |
| Risk engine unchanged | seed summary | risk **61.7 (HIGH)**, Shapley error **0.0**, planner gap **0.00%** — identical to Phases 1 and 2 (a test also asserts `risk.py` never references correlations and that a firing correlation does not move the score) |
| Frontend | `tsc --noEmit`, `vitest run`, `npm run build` | clean, **21 passed**, built in 13.1 s |

New tests cover, per rule: trigger and non-trigger (asset identity required; declared edge
required; window and `min_events` enforced); cross-organization findings sharing an account
id or an asset id never correlate; a finding with no organization is excluded fail-closed;
similar asset names create no relationship; password reuse is never implied without an
explicit reuse finding; an `UNAVAILABLE` finding triggers nothing (it is neither safe nor
compromised); repeat evaluation yields identical ids and ordering; explanations, chains and
evidence cite the real assets/findings with no leftover `{placeholder}`; the uncertainty note
never reads as a probability of compromise; the risk engine source never references
correlations; and persistence upserts rather than duplicates while cleaning stale rows.

### 13.3 Postgres status — honestly NOT run (unchanged from §11.6 / §12.3)

The suite was never executed against a real PostgreSQL server (no Docker, no local server,
`psycopg` therefore not installed). Claim: **"DDL verified for the PostgreSQL dialect"**, not
"Postgres-tested". The Phase 3 migration contains a PostgreSQL `information_schema` /
`pg_indexes` branch that is **not** executed here. The one raw statement added —
`ALTER TABLE ... RENAME COLUMN ... TO ...` — is standard SQL supported by both SQLite 3.25+
and PostgreSQL, but it has **not** been run against a real PostgreSQL server.

### 13.4 Not done, not claimed

* No risk formula, Shapley, planner, graph or GraphRAG change; no ML retraining; OAuth stays
  frozen (flag OFF in code) and Instagram stays absent.
* No new org-wide correlation endpoint: correlations stay on the member's own
  `/api/analysis` payload (the Phase 2 privacy boundary — member-level data is not exposed
  org-wide without the audited admin-view path, which is a later phase).
* No paid dependency added; no fabricated metric. **Phase 4 has not started.**

### 13.5 Deviations carried forward

* `risk_results`, `attribution_results`, `remediation_actions`, `remediation_plans`,
  `propagation_results`, `audit_log` still carry `user_id` only; each gains `org_id` in the
  phase that reworks it.
* `correlations.org_id` mirrors the Phase 2 pattern: `NOT NULL` with a `server_default ""`
  sentinel on the migrated path, back-filled from the writer's membership; a leftover
  sentinel matches no tenant query (fail-closed). Fresh ORM-created databases have the same
  `NOT NULL` constraint.
* A correlation computed over another member's findings is not produced: `run_analysis` loads
  only the calling member's findings (the Phase 2 boundary), so correlations are per-member
  within the organization. Cross-member correlation would require the admin-view audit path.