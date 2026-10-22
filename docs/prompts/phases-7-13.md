CRIX-SMB MASTER PROMPT: PHASES 7-13 (run in segments, with stops)

====================================================================
0. PRODUCT
====================================================================
CRIX is a contextual cybersecurity risk and remediation platform for
small software/IT companies (about 10-30 employees). Company
cybersecurity is the ONLY domain; there is no personal/company mode.
A company registers assets (work email, repos, cloud storage, domains,
business apps). CRIX ingests findings, correlates them, scores
contextual risk, explains it, maps asset dependencies, and recommends
what to fix first under a limited effort budget.

Research question: Can contextual, graph-based risk analysis help small
companies prioritize remediation better than severity-based rankings?
Do NOT assume CRIX wins. Report whatever is measured.

Phases 1-6 are reported complete. Do NOT redo them. Verify them, then
build 7-13.

====================================================================
1. NON-NEGOTIABLE RULES (apply to every phase)
====================================================================
1. The deterministic CRIX risk engine is the ONLY authority for scores
   and priorities. ML models emit findings only. GraphRAG/LLM explains
   only and never calculates, changes or invents scores, findings,
   dependencies, evidence or remediation outcomes.
2. No fabricated numbers. Every metric shown or reported comes from
   code that ran, stored with seed, config, commit hash and command.
3. Label data LIVE / SYNTHETIC / FIXTURE / USER_ENTERED / UNAVAILABLE.
   API errors, timeouts, rate limits and missing keys are never SAFE.
4. Backend enforces tenant isolation and RBAC (ADMIN / MEMBER /
   VIEWER). Never trust a client-supplied org_id or severity.
5. OAuth stays FROZEN: no provider apps, no credentials, connectors
   behind flags that default OFF and absent from UI/demo. Instagram
   connector stays deleted.
6. Never store plaintext passwords, tokens or API keys. Startup
   rejects missing/empty/default JWT and encryption secrets. External
   breach checks need explicit consent. .env stays ignored and
   untracked. No paid dependency is ever required.
7. Scope: company-owned assets and work accounts only. BYOD and
   employees' personal accounts are out of scope. Do not persist raw
   phishing message bodies by default (keep label, confidence,
   redacted excerpt).
8. Wording: "contextual risk score," "risk prioritization," "potential
   exposure path," "simulated." Forbidden: "predicts hacking,"
   "prevents takeover," "probability of compromise," "detected an
   attack," any compliance claim. Call the explanation feature
   "graph-grounded explanation" until real graph retrieval is
   verified and measured; do not call a fixed lookup GraphRAG.
9. Do not rewrite working modules. Reuse and extend. No unrelated
   changes. Never weaken or delete tests to get green.
10. Never claim a command, test, migration or check passed unless you
    inspected its actual result. Unexecutable checks are BLOCKED.

====================================================================
2. STARTUP CHECKS (before any code)
====================================================================
a. git status, branch (smb-migration), tags, log. Confirm
   phase-4-done, phase-5-done, phase-6-done exist and point to the
   expected commits. Skip any phase already tagged and verified;
   report what you skipped. Preserve uncommitted user changes.
b. Run the full backend and frontend suites. Report collected, passed,
   failed, skipped, xfailed, errors, exact commands, exit codes.
c. Scan the baseline commit and history for secrets (never print
   values). If ANY secret is found: STOP. Report only path, commit
   hash, category. Do not edit, commit, rewrite history or rotate.
d. Read docs/PROGRESS.md, the Phase 0 audit, the risk formula doc and
   the graph docs. Save this prompt as docs/prompts/phases-7-13.md.
e. Write docs/RUN_PLAN.md: a readback in YOUR OWN words of what each
   phase builds, what you will reuse, risks, and prerequisite defects
   found. Then continue unless blocked.

====================================================================
3. SEGMENTS AND STOPS
====================================================================
Order: 6b -> 7 -> 8 -> 9 -> STOP 1 -> 11 -> STOP 2 -> 10 -> 12
(metrics plan only) -> STOP 3 -> 12 results -> 13 -> final report.
At each STOP: post a short status report and WAIT for the word
"CONTINUE". Phase 11 runs before Phase 10.

====================================================================
4. PREREQUISITE 6b: WIRE THE GRAPH INTO RISK
====================================================================
The thesis is "graph-based risk," so the dependency graph must
actually affect scoring. Check whether the risk formula consumes a
dependency term.
- If NOT: implement a documented DependencyExposure term from the
  Phase 6 blast-radius query (criticality-weighted reachable assets,
  bounded, documented edges only, provenance/confidence respected,
  UNAVAILABLE when no graph). Bump the formula version. Historical
  snapshots keep their old version. Add a config flag to disable the
  term (needed for ablation). Re-run Phase 4/5 tests; keep Shapley
  efficiency intact with the new factor; document it.
- If it exists: verify with tests and document.
Commit "phase-6b: wire dependency exposure into risk", tag
phase-6b-done.

====================================================================
5. PHASE 7: REMEDIATION PLANNER + VERIFICATION
====================================================================
- Action model: id, org, target asset/findings, effort, expected
  modeled risk reduction (computed by the real risk model, never
  invented), prerequisites, dependencies, required evidence,
  verification method.
- Planner under an admin-set effort budget: greedy baseline + exact
  branch-and-bound on bounded instances. Deterministic tie-breaks,
  prerequisites, infeasible actions, partial-budget results. Expose a
  shared "budget packer" (greedy by score/effort) reusable by Phase 12
  baselines. Label approximate results; never claim global optimality
  unless proven. A script reports the measured greedy-vs-exact gap
  with scenario count and seeds; include a greedy-trap case.
- Task states: OPEN, DONE (claimed), VERIFIED_MODELED (pipeline rerun
  on user-attested state), VERIFIED_OBSERVED (live provider recheck).
  Never merge the two verified states. VERIFIED_OBSERVED must be
  rejected for SYNTHETIC/FIXTURE data. Support failed verification
  and reopening with history preserved. Record method, evidence refs,
  timestamp, result, model version. Clicking Done never verifies.
- RBAC and audit log on create/assign/update/verify/read. Alembic
  upgrade AND downgrade tests for new migrations.
- Tests: budget, prerequisites, determinism, exact vs greedy on small
  cases, infeasible plans, all state transitions, authorization,
  tenant isolation.
Commit "phase-7: implement remediation planning and verification",
tag phase-7-done.

====================================================================
6. PHASE 8: WHAT-IF ANALYSIS
====================================================================
- Service/API: validate an authorized proposed action, apply it to an
  isolated non-persistent state, re-run the REAL risk engine (including
  the dependency term), and return baseline vs simulated score,
  difference, affected assets/findings/paths, attribution change if
  supported, assumptions, uncertainty, model version.
- Never mutate findings, assets, edges, tasks or snapshots. Output is
  labeled "simulated." A modeled drop is not a real fix.
- Compare multiple candidates only on the same baseline snapshot and
  model version.
- Tests: genuine recalculation matches Phase 4, no persistent change,
  tenant isolation, invalid actions, unavailable inputs, fair
  comparison.
Commit "phase-8: implement what-if risk analysis", tag phase-8-done.

====================================================================
7. PHASE 9: GRAPH-GROUNDED EXPLANATIONS
====================================================================
- Audit existing KG, retrieval, sanitiser, renderer, validator.
  Document honestly whether retrieval is real graph retrieval or a
  fixed lookup.
- Retrieval over: org assets/relationships, findings, correlations,
  risk/attribution outputs, curated general knowledge. Keep
  company-specific evidence separate from general knowledge. Strict
  tenant scoping. Return the sources and relationship paths used.
- LLM adapter: provider-agnostic, OFF by default, mock-testable, no
  paid key required. Deterministic renderer is the default and
  fallback. Before any sanitized context goes to an external LLM,
  require explicit org-admin consent plus a UI notice. Send only
  sanitized necessary context: never credentials, tokens, raw private
  messages or other orgs' data.
- Citations on every material company-specific claim. Validate claims
  against an evidence allowlist; reject or qualify unsupported ones.
  Show uncertainty and which method produced the text
  (deterministic / LLM-backed).
- Prompt injection: treat asset names, finding text and submitted
  messages as untrusted DATA. Tests: instructions inside an asset
  name; finding text trying to override rules; content trying to add
  to the allowlist; attempts to reveal another org; attempts to change
  scores or fabricate dependencies. Trusted application code owns the
  allowlist and tenant boundary.
- Tests: retrieval relevance at the implemented level, citations,
  tenant isolation, empty retrieval, malformed model output, LLM
  unavailable, fallback, invented dependency blocked.
Commit "phase-9: implement graph-grounded explanations", tag
phase-9-done.

STOP 1: report status, test counts, and the retrieval honesty note.
Wait for CONTINUE.

====================================================================
8. PHASE 11: SYNTHETIC COMPANY (before Phase 10)
====================================================================
- One seeded, deterministic synthetic company, about 25 fictional
  employees: work email, repos, cloud storage, domains, apps,
  criticality, findings, dependencies, actions. Use reserved example
  domains only; no real people, emails or credentials. Everything
  labeled SYNTHETIC/FIXTURE; never shown as LIVE.
- Four scenarios: (1) mostly isolated low-impact findings;
  (2) interacting weaknesses on connected assets; (3) high-impact
  dependency chain; (4) high-severity but isolated finding with no
  evidence-backed path to critical assets. Do NOT hard-code an
  exception for scenario 4. If CRIX still ranks it first for a
  defensible reason, report that honestly.
- Setup and reset commands that never touch real org data. Works fully
  offline. Demo data is SEPARATE from the Phase 12 evaluation corpus
  and parameters are never tuned on the evaluation set.
- Tests: reproducible seeding, reset, isolation, labels, all scenarios
  exercising real services (scoring, attribution, graph, planner,
  what-if, explanations).
Commit "phase-11: implement synthetic company demonstration", tag
phase-11-done.

STOP 2: report; show the scenario 4 result and the demo reset
commands. Wait for CONTINUE.

====================================================================
9. PHASE 10: FRONTEND
====================================================================
React + TypeScript; reuse existing design system and API conventions.
No personal dashboard, no mode selector. A scenario switcher may exist
ONLY behind a demo flag and ONLY inside the synthetic org.
Screens (all on real backend data): auth + org setup; company overview;
asset inventory; findings (provenance, status, correlations; failures
never shown as SAFE); risk detail + Shapley breakdown (exact vs
approximate shown); dependency graph (documented relationships vs
possible exposure; no invented edges); remediation board (DONE vs
VERIFIED_MODELED vs VERIFIED_OBSERVED shown distinctly); what-if
(labeled simulated); explanations (citations + method indicator);
risk history + audit view; evaluation view (labeled simulated). Fold
the old propagation page into graph/what-if/evaluation views.
No OAuth UI. Loading/empty/error/forbidden states, responsive layout,
keyboard navigation. No dead buttons or hard-coded metrics.
Tests: build, lint, component tests, and journeys: login -> assets ->
findings -> risk/attribution -> graph -> what-if -> explanation ->
task update -> verification states -> synthetic org -> cross-org
denial.
Commit "phase-10: integrate company cybersecurity frontend", tag
phase-10-done.

====================================================================
10. PHASE 12: INDEPENDENT EVALUATION
====================================================================
12.1 CORPORA: a separate tuning/dev set and a held-out evaluation set,
both separate from Phase 11 demo data. Freeze CRIX parameters before
touching the held-out set. Never tune on it. Never pick scenarios
because CRIX does well on them.

12.2 METRICS PLAN FIRST: write docs/EVAL_METRICS_PLAN.md (question,
methods, metrics and direction of improvement, simulator assumptions,
propagation model, fix-effectiveness assumptions, budget policy,
seeds and run count, uncertainty method, tie/failure handling,
invalid-run exclusion rules, sensitivity design, limitations). Commit
it alone as "phase-12: define evaluation metrics plan". Then
STOP 3 and WAIT. Run no comparative results before I say CONTINUE.

12.3 METHODS (same initial scenario, same effort budget, SAME budget
packer for all):
 A. severity-only ranking + shared packer
 B. severity x criticality + shared packer
 C1. CRIX contextual scores + the same shared packer
 C2. full CRIX planner (greedy/exact)
C1 vs A/B isolates the effect of scoring. C2 shows the full system.
Optional ablations (everything else unchanged): CRIX without the
dependency term; CRIX without correlation.

12.4 SIMULATOR: independent module, sampled propagation over a
company graph. Test that the simulator package imports NOTHING from
the risk engine. Its parameters come from documented distributions
independent of CRIX's weights. It never uses CRIX's score as truth.
Labeled "simulated"; never described as real attacks.

12.5 TWO CONDITIONS, reported separately:
 - Known graph: CRIX sees the simulator's edges.
 - Incomplete graph: the simulator has hidden edges CRIX cannot see
   while planning. Test that hidden edges never reach CRIX inputs.
Record total/visible/hidden edge counts.

12.6 REPORT: primary metric, e.g. mean criticality-weighted simulated
compromised assets after the budgeted fixes (lower is better under
the stated assumptions), plus variation/CI, relative difference,
unused budget, planner runtime, sensitivity to propagation, fix
effectiveness, criticality and budget. Investigate losses and
no-difference cases. Machine-readable results plus a written report
with seeds, configs, commands, invalid runs and limitations. Never
fabricate or cherry-pick; negative results are acceptable.

12.7 Tests: seed determinism, demo/eval separation, hidden-edge
isolation, equal budgets, baseline correctness, metric math,
reproducible aggregation, simulator import boundary.
Commit "phase-12: implement independent research evaluation", tag
phase-12-done.

====================================================================
11. PHASE 13: SECURITY, REGRESSION, CLEANUP
====================================================================
Verify and add regression tests for gaps:
- Tenant isolation across models, endpoints, graph, tasks,
  explanations, snapshots, audit; RBAC per role; admin access to
  member-level data is audit-logged; members see what admins can see.
- Secrets: startup rejects bad secrets; no fallback secrets; none in
  code, fixtures, logs, docs, history. .env ignored and untracked.
- Breach providers: consent required; XposedOrNot 429, timeout,
  malformed and network failure -> UNAVAILABLE; fixtures work offline
  and are labeled; provenance accurate; HIBP attribution shown.
- GraphRAG: LLM off by default, works without a key, fallback works,
  injection tests pass, allowlist/tenant boundaries owned by trusted
  code.
- Verification states never conflated; failed verification reopens.
- Plaintext password never appears in outgoing requests (keep test).
- PostgreSQL: run the FULL suite on Postgres once (BLOCKED if
  unavailable; claim "Postgres-tested" only if it ran). Alembic
  upgrade and downgrade tested.
- ML completeness: add a second classical phishing model (LinearSVC or
  gradient boosting), same split and seed; report real metrics even if
  it does not win; no model is "stronger" unless measured.
- docs/DATASETS.md: source, license, size for every dataset.
- Full regression: backend, API, DB/migrations, isolation, risk,
  attribution, graph, planner, what-if, GraphRAG, demo E2E, frontend
  build/lint/tests, evaluation reproducibility.
- README and docs updated to match reality: product, architecture,
  providers and limits, risk formula with versions, attribution,
  graph semantics, planner and verification states, what-if,
  explanations, demo setup, evaluation method and ACTUAL results,
  run commands, security config, known limitations, and what is NOT
  claimed. Remove only obsolete personal-security code. Keep OAuth
  frozen.
- Final repo checks: tags/commits verified, PROGRESS.md accurate, no
  secrets, clean working tree except preserved user changes.
Commit "phase-13: finalize security and project validation", tag
phase-13-done.

====================================================================
12. PER-PHASE WORKFLOW
====================================================================
Review the full diff; run phase tests and relevant regressions; check
for secrets and unrelated changes; update docs/PROGRESS.md (status,
files, decisions, tests with real counts, failures, gaps, commit hash,
tag, next step); commit only relevant files; tag -done ONLY when
acceptance is met; verify hashes. Never rewrite history or force-push.

====================================================================
13. FINAL REPORT (after Phase 13)
====================================================================
Status PASS / FAIL / PARTIAL / BLOCKED per requirement for phases
6b-13; baseline vs final test totals; commands and exit codes;
files added/changed/deleted; commit and tag verification;
verification-state behavior; what-if non-mutation proof; GraphRAG
retrieval honesty note and injection results; four scenario results;
frontend journey results; the committed metrics plan; actual
evaluation results for known and incomplete graph, with ablations;
Postgres result; unresolved defects, blocked checks, limitations; run
commands for backend, frontend, demo and evaluation; remaining work
before a reliable panel demo. Code existing is not PASS. Tests
inspected are PASS.

====================================================================
PHASE 10: FRONTEND AUDIT AND TWEAKS (a frontend already exists)
====================================================================
DO NOT rebuild, restyle, or change framework, routing, design system
or API conventions. Keep what works.

STEP 1: AUDIT FIRST. Write docs/FRONTEND_GAP.md: one row per required
screen below, with columns: exists? / uses real backend data or mock
or hard-coded values? / missing states (loading, empty, error,
forbidden) / provenance labels present? / gaps / planned tweak. Check
for: hard-coded numbers, Math.random, mock arrays, dead buttons,
leftover personal-security navigation, OAuth/connector UI,
frontend-only permission checks. List every file you will touch.
Then proceed with only the listed tweaks.

REQUIRED SCREENS (tweak if present, add only if absent):
auth + org setup; company overview; asset inventory; findings;
risk detail + Shapley breakdown; dependency graph; remediation board;
what-if; explanations; risk history + audit view; evaluation view.

SPECIFIC TWEAKS TO CHECK:
- Provenance badge on every datum: LIVE / SYNTHETIC / FIXTURE /
  USER_ENTERED / UNAVAILABLE. A failed check never renders as SAFE.
- Task board shows DONE, VERIFIED_MODELED and VERIFIED_OBSERVED as
  visibly different states. Nothing else may reuse the word
  "verified."
- Shapley view marks exact vs approximate and shows the baseline.
  Wording says "explains the model's score," never "caused."
- Graph view separates documented relationships from possible
  exposure paths. No edge drawn without a backend relationship ID.
- What-if and evaluation views carry a "SIMULATED" label.
- Explanations show citations and a "deterministic" or "LLM-backed"
  indicator.
- Remove: personal-security nav and pages that conflict with the
  company-first product; any OAuth/connector UI. Fold the old
  propagation page into graph / what-if / evaluation. Delete only
  code that is exclusively used by removed pages.
- A scenario switcher is allowed ONLY behind a demo flag and ONLY in
  the synthetic org.
- Hide controls by role for usability, but the backend remains the
  only enforcement. Add API-level denial tests, not UI-only tests.
- Every screen: loading, empty, error, forbidden, unavailable states;
  keyboard navigation; responsive layout.

TESTS: run existing frontend tests first and report counts. Add tests
only for changed or missing behavior, plus journey tests: login ->
assets -> findings -> risk + attribution -> graph -> what-if ->
explanation -> task update -> verification states -> synthetic org ->
cross-org denial. Build and lint must pass.

Commit "phase-10: tweak frontend for company-first product", tag
phase-10-done. Update PROGRESS.md.
