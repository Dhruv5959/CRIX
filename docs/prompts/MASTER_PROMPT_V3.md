# CRIX-SMB MASTER PROMPT v3: REMAINING PHASES, FRONTEND IN EVERY PHASE

(Supersedes earlier prompts for phases 7b-13. Keep docs/prompts/ copy.)

====================================================================
## 0. TRUTH BASELINE
====================================================================
Git is the source of truth. Reported state: phases 0-7 and 6b have
tags; phases 8-13 have no commits. Known frontend gaps: no task board,
no risk history, no audit/"who can see what" page, planner budget
fixed at 6.0, what-if toggles hard-coded, company-core screens
unverified (org setup, invites, overview, assets, findings, members),
legacy /evaluation from the pre-migration build, /connections still in
nav, frontend tests are 31 utility tests only.
Never claim a phase beyond what tags + passing tests + a visible UI
show. Confirm with `git tag`, `git log`, and test output before work.

====================================================================
## 1. RULE: VERTICAL SLICES
====================================================================
A phase is DONE only if ALL are true:
 (a) backend logic + org-scoped API
 (b) a frontend screen reachable from nav for the right roles
 (c) provenance labels on every datum
 (d) backend tests + component tests + a journey test
 (e) a screenshot saved in docs/screenshots/
 (f) docs/PROGRESS.md updated with real test counts
 (g) one commit + a -done tag, hashes verified
Backend-only = PARTIAL. Report it that way.

====================================================================
## 2. NON-NEGOTIABLES
====================================================================
- The deterministic CRIX risk engine is the only authority for scores.
  ML emits findings only. Explanations never change scores,
  findings, dependencies, evidence or plans.
- No fabricated numbers. Every metric comes from code that ran, with
  seed, config, commit and command stored.
- Label data LIVE / SYNTHETIC / FIXTURE / USER_ENTERED / UNAVAILABLE.
  Errors, timeouts, rate limits, missing keys are never SAFE.
- Backend enforces tenant isolation and RBAC (ADMIN / MEMBER /
  VIEWER). UI hiding is UX only. Never trust client org_id/severity.
- OAuth stays FROZEN and absent from UI. Instagram stays deleted.
- No plaintext passwords, tokens or keys stored or logged. Startup
  rejects empty/default secrets. Breach checks need consent.
  XposedOrNot failures -> UNAVAILABLE. .env ignored and untracked.
- Scope: company-owned assets and work accounts only. No BYOD.
- Forbidden wording: "predicts hacking," "prevents takeover,"
  "probability of compromise," "detected an attack," any compliance
  claim. Allowed: "contextual risk score," "potential exposure path,"
  "simulated," "aligned to." Call the feature "graph-grounded
  explanation" until real graph retrieval is verified and measured.
- Reuse working code. No unrelated changes. Never weaken or delete
  tests to get green. Never report a command or test as passing
  unless you inspected the result.
- If a baseline-history secret is found: STOP, report path, hash and
  category only; do not rewrite history.

====================================================================
## 3. STARTUP
====================================================================
git status/branch/tags/log; run full backend and frontend suites and
report counts; secret scan; read PROGRESS.md; save this prompt in
docs/prompts/; write docs/RUN_PLAN_V3.md as a readback in your own
words (what you will build, reuse, and the risks).

====================================================================
## 4. PHASE 7b: FRONTEND CATCH-UP FOR PHASES 1-7
====================================================================
4.1 If docs/FRONTEND_REALITY_CHECK_2.md does not exist: do the audit
    only (company-core screens, org scoping of /api/analysis/run,
    graph, what-if and explanation endpoints, seed existence, legacy
    evaluation, simulator import boundary, /connections), write it,
    and STOP for my approval.
4.2 After approval, one commit per item, tests each:
 a. ORG SCOPING: analysis, graph, what-if, explanation and history
    endpoints derive org from membership, not user. Cross-org denial
    tests. If user-scoped, make the smallest change. Do not proceed
    until this passes.
 b. SEED: idempotent minimal synthetic company (reserved example
    domains, SYNTHETIC labels, reset command that never touches real
    data).
 c. SHARED UI: ProvenanceBadge, StateViews (loading/empty/error/
    forbidden/unavailable), SimulatedBanner, role-aware nav, typed
    API client.
 d. ORG SHELL: login + org setup + invite accept, company overview,
    asset inventory (admin CRUD, criticality, dependency edges with
    source), findings (provenance, status, correlations), members and
    roles.
 e. TASK BOARD (phase 7 UI): OPEN / DONE / VERIFIED_MODELED /
    VERIFIED_OBSERVED as visibly different states; assign, evidence,
    reopen; VERIFIED_OBSERVED rejected for SYNTHETIC data.
 f. RISK HISTORY chart from risk_results snapshots.
 g. AUDIT + "WHO CAN SEE WHAT" page (ADMIN only): roles, what admins
    can and cannot see about members, admin-access audit log.
 h. PLANNER BUDGET SLIDER calling the real planner, with the
    greedy vs exact label. What-if toggles come from the action
    catalog, not hard-coded keys.
 i. Remove /connections from nav and demo path. Label /evaluation
    "Legacy (pre-migration), not company-level results" until phase 12
    replaces it.
Tag phase-7b-done.

====================================================================
## 5. PHASE 8: WHAT-IF (backend + UI)
====================================================================
Isolated non-persistent simulation of an authorized action through the
real risk engine (including the dependency term). Return baseline,
simulated, difference, affected assets/paths, assumptions, uncertainty,
model version. Never mutate findings, assets, edges, tasks or
snapshots. Compare candidates only on the same snapshot and model
version. UI: org what-if panel with a "SIMULATED" banner, side-by-side
candidates, and a note that a modeled drop is not a real fix.
Tests: recalculation matches phase 4, no persistent change, tenant
isolation, invalid actions, fair comparison, UI journey.

====================================================================
## 6. PHASE 9: EXPLANATIONS (backend + UI)
====================================================================
Audit existing retrieval; document honestly whether it is real graph
retrieval or a fixed lookup. Retrieval over org assets, relationships,
findings, correlations, risk/attribution outputs, plus curated general
knowledge, kept separate and tenant-scoped. Optional LLM adapter: OFF
by default, mock-testable, no paid key, deterministic renderer is the
default and fallback. Before any sanitized context goes to an external
LLM: explicit ADMIN consent plus a UI notice. Citations on every
company-specific claim; validate claims against an evidence allowlist.
Prompt injection: asset names, finding text and submitted messages are
untrusted DATA. Tests: injection in asset names/finding text,
allowlist expansion attempts, cross-org reveal attempts, score/
dependency fabrication attempts, malformed model output, fallback.
UI: explanation panel with citations, uncertainty, and a
"deterministic" or "LLM-backed" indicator.
STOP 1: report and wait for CONTINUE.

====================================================================
## 7. PHASE 11: SYNTHETIC COMPANY (4 scenarios)
====================================================================
Seeded company of about 25 fictional employees. Scenarios: (1) mostly
isolated low-impact findings; (2) interacting weaknesses on connected
assets; (3) high-impact dependency chain; (4) high-severity isolated
finding with no evidence-backed path to critical assets. No hard-coded
exception for scenario 4; report honestly what CRIX does. Offline,
reproducible, labeled, separate from the phase 12 evaluation corpus.
UI: a scenario switcher behind a demo flag, visible ONLY in the
synthetic org. Tests: reproducible seeding, reset, isolation, labels,
all scenarios through real services.

====================================================================
## 8. PHASE 10: SIGNATURE SCREENS (after phase 11 data exists)
====================================================================
 a. Exposure-path replay: step-by-step along documented edges only,
    each step shows relationship type and source. Label: "potential
    exposure path."
 b. Fix-order showdown: severity-only vs severity x criticality vs
    CRIX, with the independent simulator outcome on DEMO scenarios
    only. Label SIMULATED and "demo scenario, not the evaluation
    result." Show losses honestly.
 c. Executive brief PDF: one page for a non-technical owner (top 3
    fixes, why, effort, modeled reduction, data labels, limits).
 d. Screenshot script (Playwright) that saves every screen to
    docs/screenshots/ for the README and viva.
 e. Journey tests as ADMIN, MEMBER and VIEWER, plus cross-org denial.
STOP 2: report, and wait for CONTINUE.

====================================================================
## 9. PHASE 12: EVALUATION
====================================================================
9.1 Separate dev/tuning set and held-out set, both separate from demo
    data. Freeze CRIX parameters before the held-out set is touched.
9.2 Write docs/EVAL_METRICS_PLAN.md (question, methods, metrics and
    direction, simulator assumptions, propagation and fix-effectiveness
    models, budget policy, seeds and run count, uncertainty method,
    exclusion rules, sensitivity design, limitations). Commit it ALONE
    ("phase-12: define evaluation metrics plan"). STOP 3 and wait.
    Run no comparative results before I say CONTINUE.
9.3 Methods, all with the SAME budget packer (greedy by score/effort):
    A severity-only; B severity x criticality; C1 CRIX scores + shared
    packer; C2 full CRIX planner. Optional ablations: no dependency
    term (use the flag); no correlation.
9.4 Independent simulator. Test that it imports nothing from the risk
    engine. Its parameters come from documented distributions
    independent of CRIX weights. Never use CRIX's score as truth.
9.5 Two conditions reported separately: known graph, and incomplete
    graph (hidden edges CRIX cannot see; test they never reach CRIX
    inputs). Record total/visible/hidden edge counts.
9.6 Report primary metric (mean criticality-weighted simulated
    compromised assets after the budget, lower is better under the
    assumptions), variation/CI, relative difference, unused budget,
    runtime, sensitivity. Investigate losses. Negative results are
    acceptable.
9.7 UI: replace the legacy evaluation page with one that renders ONLY
    committed result files, labeled SIMULATED, with config, seeds,
    limitations. Never show held-out numbers elsewhere.
Tag phase-12-done after results exist.

====================================================================
## 10. PHASE 13: SECURITY, REGRESSION, CLEANUP
====================================================================
Isolation and RBAC across every model and endpoint; admin access to
member data audit-logged; startup secret validation; no secrets in
code/logs/history; consent and provider-failure behavior; injection
tests; verified-state integrity; plaintext password never in outgoing
requests; PostgreSQL full-suite run (BLOCKED if unavailable; claim
"Postgres-tested" only if it ran); Alembic upgrade and downgrade
tests; second classical phishing model with real metrics; DATASETS.md
with licenses; CI (tests, gitleaks, dependency audit). README matches
reality: product, architecture, provider limits, formula and
versions, graph semantics, planner and verification states, what-if,
explanations, demo and evaluation commands, screenshots, limitations,
and what is NOT claimed. Remove only obsolete personal-security code.

====================================================================
## 11. FRONTEND TEST STANDARD
====================================================================
Vitest + React Testing Library for each new page (loading, empty,
error, forbidden, unavailable, success, role differences). Playwright
journeys against a seeded backend: login -> overview -> assets ->
findings -> risk + attribution -> graph -> what-if -> explanation ->
task update -> verification states -> audit page (ADMIN only) ->
synthetic org -> cross-org denial. Report build, lint and test counts.

====================================================================
## 12. WORKFLOW AND REPORT
====================================================================
Per phase: review the diff; run tests; check for secrets; update
PROGRESS.md (status, files, tests, gaps, hash, tag); commit; tag; verify.
Never rewrite history. Final report: PASS / FAIL / PARTIAL / BLOCKED per
requirement with file paths, endpoints, commit hashes and test output
as evidence, including what the panel can see in the UI for each phase.
Code existing is not PASS. A passing test you inspected is PASS.

