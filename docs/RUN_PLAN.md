# RUN PLAN — Phases 6b → 13 (readback before any code)

Written in my own words after the §2 startup checks, before touching code.
Master prompt: `docs/prompts/phases-7-13.md` (saved verbatim).

---

## 0. Startup checks — what I ran and what I found

| §2 item | Command / action | Result |
|---|---|---|
| a. git state | `git status --short`, `git log --oneline`, `git rev-parse "<tag>^{commit}"` | Tree **clean**, branch `smb-migration`, 7 commits `750f9f2 → 749a1ce`. Tags resolve: `pre-smb-migration`→`750f9f2`, `phase-4-done`→`3dc923b`, `phase-5-done`→`40953fe`, `phase-6-done`→`749a1ce`. **Phases 4/5/6 skipped (already tagged & verified)**; the plan starts at 6b. No uncommitted user changes to preserve. |
| b. backend suite | `python -m pytest` (via capture script) | **380 passed, 0 failed, 0 skipped, 0 xfailed, 0 errors, exit 0**, `380 passed in 82.68s`; `--collect-only -q` = 380 tests / 25 files. |
| b. frontend suite | `npx tsc --noEmit`, `npx vitest run`, `npm run build` | exit **0** / **31 passed** (3 files) / exit **0**. |
| c. secret scan | custom scan over **all 7 commits × every historical blob** (`git grep -P` per rev + `.env` checks); values never printed | See §"Prerequisite defects" #1 — **triaged CLEAN**, no real secret, `.env` ignored & untracked, `.env.example` all placeholder/empty (`SUSPICIOUS_VALUES=0`). |
| d. reading | `PROGRESS.md`, `IMPLEMENTATION_STATUS.md` (Phase 0 audit), `RISK_MODEL.md`, `ORG_GRAPH.md` | Read in full. Prompt saved to `docs/prompts/phases-7-13.md`. |
| e. this file | — | Written before any code. |

**Honest reporting note:** the pytest summary line is invisible when the CLI adds
`-q` on top of `pytest.ini`'s `addopts = -q` (it becomes `-qq` and drops the
footer). I verified counts by running **without** the extra `-q`, which printed
`380 passed in 82.68s`, plus collect-count 380 and exit 0. This is how every
later phase will report counts (exact line captured, not inferred).

---

## 1. Phase 6b — wire dependency exposure into risk

**What I verified first (§4 precondition):** does scoring consume a graph
term? **No.** `risk.py` imports only `app.schemas`; the `dependency` feature
weight (.08) comes from *finding event types* (`ACCOUNT_DEPENDENCY`,
`COMPROMISED_RECOVERY_ACCOUNT`), not from the Phase 6 graph. `pipeline.py`
never calls `blast_radius`. So 6b = **implement**, not verify.

**What I will build:** a documented `DependencyExposure` term sourced from the
Phase 6 `blast_radius()` query — criticality-weighted reachable assets over
documented, org-scoped edges only, bounded by `GRAPH_LIMITS`, provenance and
confidence respected, recorded `UNAVAILABLE` when the org has no graph (never
0-as-safe). Formula version bumps `risk-2.0 → risk-2.1`; persisted snapshots
keep their own `model_version` (already a tested invariant). A config flag
(`RISK_*_DEPENDENCY_EXPOSURE`, default ON) disables the term for ablation —
Phase 12 will use it.

**What I reuse:** `org_graph.blast_radius` + `build_org_graph` (bounded,
deterministic, org-filtered), `RISK_PARAMS` structure, `components` traceability
block, the existing sensitivity-range and band helpers.

**Shapley:** the term must be *context or player*. Decision: make it a **13th
feature-group player** so efficiency stays exact by construction (v(S) = real
risk restricted to the coalition's features, criticality + dependency exposure
held as context the same way criticality is today, per `docs/ATTRIBUTION.md`
§1). Tests that pin "exactly 12 players" will be **updated to 13 as an
intentional, documented change** — not deleted, not weakened.

**Risks:**
1. Demo score changes (67.9 → new value) ⇒ `RISK_MODEL.md`, `PROGRESS.md`,
   `PRESENTATION.md`, `IMPLEMENTATION_STATUS.md` demo numbers must be updated
   in the same commit, honestly.
2. The Phase 6 compatibility tests (#24/#25) assert graph *queries* leave the
   score bit-identical — that stays true (queries don't mutate). But
   `test_module_independence` may assert `risk`/`pipeline` never import
   `org_graph`; wiring is now intentional, so that assertion must be
   **inverted with a comment explaining why**, which is a legitimate test
   update, not a weakening. I will call it out explicitly in PROGRESS.
3. Consistency: risk, attribution, planner, what-if, sensitivity must all see
   the same dependency input (§7 "consumers use the same context") or
   efficiency breaks.
4. No-edges vs no-graph must be distinguished: empty-but-present graph = term
   value 0 with evidence; missing/unreadable graph = `UNAVAILABLE` (uncertainty
   note, no points either way, never "safe").

---

## 2. Phase 7 — remediation planner + verification

**Build:** org-scoped action model (target asset/findings, effort, expected
reduction **computed by re-running the real model**, prerequisites, dependencies,
required evidence, verification method); admin-set effort budget planner =
greedy baseline + exact branch-and-bound, deterministic tie-breaks,
infeasible/partial-budget handling; a **shared budget packer** (greedy by
score/effort) exposed for Phase 12's four methods; a gap-measurement script with
scenario count, seeds, and a greedy-trap case. Task lifecycle:
`OPEN → DONE (claimed) → VERIFIED_MODELED | VERIFIED_OBSERVED`, plus failed
verification → reopen, full history (method, evidence refs, timestamp, result,
model version). Never merge the two verified states; `VERIFIED_OBSERVED`
rejected for SYNTHETIC/FIXTURE; clicking Done never verifies.

**Reuse:** `engine/planner.py` already has greedy, exact B&B, greedy-trap
scenarios and a gap script (original Phase 8/13) — extend, do not rewrite;
`RemediationAction`/`RemediationPlan` models; audit-log + RBAC patterns from
org/assets routers; Alembic with existence guards (up **and** down tests).

**Risks:** new migration must be reversible on the dev DB; expected-reduction
must go through the real risk model (no invented numbers); task states need a
history table so reopen doesn't erase evidence; RBAC on every verb (create /
assign / update / verify / read) with API-level denial tests.

---

## 3. Phase 8 — what-if analysis

**Build:** endpoint/service that validates an authorized proposed action,
applies it to **isolated, non-persistent state**, re-runs the real engine
(including the new dependency term), and returns baseline vs simulated score,
delta, affected assets/findings/paths, attribution change, assumptions,
uncertainty, model version. Multi-candidate comparison only on one baseline
snapshot + one model version. Everything labeled `simulated`.

**Reuse:** existing `POST /api/analysis/what-if` (mitigation toggles) and
`propagation.simulate` (in-memory scenario re-run) — both already re-run the
real pipeline and don't persist; extend the pattern to proposed *actions*.

**Risks / proofs needed:** a test that hashes org rows (findings, assets,
edges, tasks, snapshots) before and after every what-if call ⇒ byte-identical;
attribution must be recomputed with the same context (efficiency stays ~0);
invalid/unauthorized actions rejected; "modeled drop ≠ real fix" wording.

---

## 4. Phase 9 — graph-grounded explanations

**Build:** first an **honest audit** of the existing KG
(`KnowledgeNode`/`KnowledgeEdge`), retrieval, sanitiser, renderer, validator —
documenting whether retrieval is real graph retrieval or a fixed lookup. Then
retrieval over org assets/relationships (Phase 6 paths as evidence), findings,
correlations, risk/attribution output, curated general knowledge — company
evidence kept separate from general knowledge, strict tenant scoping, sources +
relationship paths returned. LLM adapter provider-agnostic, **OFF by default**,
mock-testable, no paid key; deterministic renderer is default *and* fallback;
org-admin consent + UI notice before any sanitized context leaves; citations on
every material company-specific claim, validated against an allowlist owned by
trusted code. Prompt-injection tests: instruction-in-asset-name, finding text
overriding rules, allowlist tampering, cross-org exfiltration, score/dependency
fabrication.

**Risk:** the honesty note is a deliverable — if the existing implementation is
a fixed lookup, I say exactly that and only rename things to
"graph-grounded explanation" (per Rule §1.8 wording).

---

**→ STOP 1** (status + test counts + retrieval honesty note; wait for CONTINUE).

---

## 5. Phase 11 — synthetic company (runs before Phase 10)

**Build:** one deterministic seeded company ≈25 fictional employees on reserved
example domains, everything `SYNTHETIC`/`FIXTURE`, four scenarios (isolated
low-impact / interacting-on-connected / high-impact dependency chain /
high-severity-but-isolated-with-no-evidence-path). **No special-casing
scenario 4** — whatever the real engine ranks first gets reported as-is.
Offline setup/reset commands that never touch real org data; corpus separate
from Phase 11… correction: separate from the **Phase 12** evaluation corpora.

**Reuse:** `scripts/seed_demo.py` patterns (idempotent seeding, EmailStr-safe
domains, engine summary printing).

**Risks:** reset must be org-scoped (delete only the synthetic org's rows);
seeding must be bit-reproducible; scenario assertions must call real services
(scoring, attribution, graph, planner, what-if, explanations), not fixtures of
their own.

**→ STOP 2** (show scenario 4 result + reset commands; wait for CONTINUE).

---

## 6. Phase 10 — frontend audit and tweaks (NOT a rebuild)

**Process:** write `docs/FRONTEND_GAP.md` first — one row per required screen
(exists / real data vs mock / missing states / provenance labels / gap /
tweak + every file to touch), scanning for hard-coded numbers, `Math.random`,
mock arrays, dead buttons, leftover personal-security nav, OAuth UI, and
frontend-only permission checks. Then touch **only** listed files: provenance
badges, three visibly distinct task states (nothing else may say "verified"),
exact-vs-approximate Shapley with baseline and "explains the model's score",
graph view with no edge lacking a backend relationship id, SIMULATED labels on
what-if/evaluation, explanation citations + method indicator, fold propagation
into graph/what-if/evaluation, scenario switcher only behind a demo flag in the
synthetic org.

**Reuse:** existing design system, routing, API conventions, `lib/orgGraph.ts`
helpers, existing 31 vitest tests (run first, report counts).

**Risks:** touching only listed files; journey test chain is long
(login → … → cross-org denial) so most of it will be API-level with the UI
journey covered by component tests where the harness allows; backend stays the
only enforcement (API denial tests, not UI-only).

---

## 7. Phase 12 — independent evaluation

**Build:** (1) `docs/EVAL_METRICS_PLAN.md` committed **alone** → **STOP 3**, no
comparative runs before CONTINUE; (2) separate tuning/dev vs held-out corpora
(both separate from the Phase 11 demo), parameters frozen before held-out,
never tuned on it; (3) four methods A / B / C1 / C2 on the same scenario, same
budget, **same shared packer**; optional ablations (no dependency term, no
correlation); (4) an **independent simulator** that imports nothing from the
risk engine, uses its own documented distributions, never treats CRIX's score
as truth; (5) two conditions reported separately — known graph vs incomplete
graph (hidden edges never reach CRIX inputs; total/visible/hidden counts
recorded); (6) machine-readable + written report with seeds, configs,
commands, CIs, unused budget, runtimes, sensitivity, invalid-run rules —
negative results included as-is.

**Reuse:** `scripts/run_evaluation.py` + `evaluation_records` table patterns;
Phase 7's shared packer (that is exactly why the prompt demands it).

**Risks:** the import-boundary test (simulator must not import the risk
engine) needs a clean package seam; corpus separation must be provable by test;
STOP 3 discipline — the metrics plan commit must contain no results.

---

## 8. Phase 13 — security, regression, cleanup

**Build/verify:** tenant-isolation sweep across every surface (models,
endpoints, graph, tasks, explanations, snapshots, audit), RBAC per role, admin
member-data access audit-logged; secrets (startup rejects bad secrets, none in
code/fixtures/logs/docs/history — re-run my §2c scanner); breach-provider
failure modes → UNAVAILABLE (429/timeout/malformed/network) with consent and
HIBP attribution; GraphRAG off/fallback/injection; verification states never
conflated; **PostgreSQL full suite once — expected BLOCKED** (no Docker/server/
`psycopg` in this environment; I will attempt it and report BLOCKED with the
exact command if it cannot run); Alembic up **and** down; a second classical
phishing model (LinearSVC or gradient boosting) on the same split/seed with
real metrics even if it loses; `docs/DATASETS.md` (exists — verify
source/license/size for every dataset); full regression; README/docs corrected
to reality; only obsolete personal-security code removed; OAuth stays frozen.

---

## 9. Prerequisite defects / findings so far (before any code)

1. **Secret scan triage (§2c):** 5 `jwt_literal` hits (`fake_jwt` in
   `test_finding_schema.py`), 26 high-entropy-assignment hits (`tests/`
   fixtures: `FakeTokens` for at-rest encryption, the HIBP k-anonymity SHA1
   fixture, `secret_password`, the documented `dev-only-insecure-change-me`
   default, `not-a-real` marker), and `.env.example` (template only, all
   secret keys empty/placeholder, `SUSPICIOUS_VALUES=0`). No AWS/GitHub/
   Google/Slack/Stripe key, no private-key block, `.env` ignored (`check-ignore`
   = yes) and never tracked in history. **Values never printed.** Verdict: no
   real secret ⇒ not a STOP; same triage outcome as the documented
   pre-Phase-4 scan in `PROGRESS.md`.
2. **pytest summary suppression:** `pytest.ini addopts = -q` + a CLI `-q`
   becomes `-qq` and hides the pass-count footer. Worked around; every phase
   will capture the real summary line without the extra `-q`.
3. **Docs that 6b will make stale (must be updated in the same commit):**
   `RISK_MODEL.md` §1/§3/§6 (formula + "does not consume graph"), `ORG_GRAPH.md`
   §6 closing paragraph ("graph never changes the risk score"), and Phase 6
   compatibility-test wording.
4. **Tests that intentionally change in 6b:** "exactly 12 Shapley players" →
   13; module-independence assertion direction (`risk/pipeline → org_graph`
   becomes legal; `org_graph → risk` stays forbidden). Both are documented
   changes with comments, not weakenings.
5. **Not a defect:** the demo's `declared_dependency_exposure` correlation does
   not fire because its breach event is `UNAVAILABLE` — that is the
   provider-failure boundary working as designed (documented in PROGRESS Phase 6).
6. **Environment limit:** PostgreSQL suite cannot run here → Phase 13 reports
   BLOCKED honestly; claim limited to "DDL verified for the PostgreSQL dialect".
7. **Known backlog (untouched):** 15 npm audit advisories needing breaking
   upgrades (deliberately not applied; no paid deps allowed).

---

## 10. Order, stops, and per-phase workflow

Order: **6b → 7 → 8 → 9 → STOP 1 → 11 → STOP 2 → 10 → 12-metrics-plan →
STOP 3 → 12-results → 13 → final report.**

Each phase: implement → run phase tests + relevant regressions (exact counts
captured) → review full diff → secret/unrelated-change check → update
`docs/PROGRESS.md` → commit exactly the relevant files → tag `-done` **only**
when acceptance is met → verify tag == commit, tree clean. Never rewrite
history, never force-push, never weaken a test, never report a pass I did not
inspect. Unexecutable checks are reported BLOCKED.
