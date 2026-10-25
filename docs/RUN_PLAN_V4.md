# RUN PLAN v4 — startup readback

Written at the start of the v4 session, after running the Startup block only.
Nothing in this file is a claim of work done; it is what I verified and what I
understand I am being asked to do. Segment work starts only after `CONTINUE`.

Session date: 2026-10-25 · Operator: single agent (no parallel sub-agents)

---

## 1. Startup evidence (commands actually run this session)

| Item | Command | Result |
|---|---|---|
| Branch | `git branch --show-current` | `main` |
| HEAD | `git log --oneline -1` | `db36428 ui: native select popups read white-on-black on Windows/Chromium` |
| Tags | `git tag -l --sort=creatordate` | `pre-smb-migration`, `phase-4-done`, `phase-5-done`, `phase-6-done`, `phase-6b-done`, `phase-7-done` |
| Uncommitted | `git status --short \| wc -l` | **43** paths (25 modified, 18 untracked) |
| Remote | `git remote -v` | `origin https://github.com/Dhruv5959/CRIX.git` (visibility not verifiable from here) |
| Backend suite | `pytest -q --junitxml=.runlogs/pytest-junit.xml` | **527 tests, 527 passed, 0 failed, 0 errors, 0 skipped**, exit **0**, 241.5 s |
| Frontend unit | `npx vitest run` | **33 passed (3 files)**, exit **0** |
| Typecheck | `npx tsc --noEmit` | exit **0** |
| Production build | `npm run build` | exit **0**, built in 33.4 s |
| Secret scan | regex scan of every patch in all commits (`git log --all -p`) | no real credential found (§2.4 below) |
| Backend routes | `app.openapi()['paths']` | **82** paths |

The suite was run with `--junitxml=.runlogs/pytest-junit.xml`; the exact counts
above were parsed from that XML and the artifact was then deleted so the dirty
tree stays at the pre-session 43 paths + this file (a stray `.xml` is not
covered by the repo's `*.log` ignore rule). Segment 2f will regenerate it
deliberately, together with the decision to commit or ignore it. The console
log remains at `.runlogs/pytest-startup.log` (ignored by `*.log`).

## 2. Corrections to the supplied truth baseline

The baseline is broadly accurate. Four details need correcting, and one is more
serious than the baseline implies.

1. **Tags cover less history than stated.** The prompt says "phases 0-7 and 6b
   tagged". Actual: phase 0 (`pre-smb-migration`), and phases 4, 5, 6, 6b, 7.
   Phases **1, 2 and 3 have no `-done` tag** (`8bd6b3a`, `6752581`, `1886aff`);
   `PROGRESS.md`'s own table lists them with "—". Six tags, not eight.
2. **43 uncommitted paths — confirmed** exactly.
3. **527 collected / exit 0 — now also captured as 527 passed, 0 skipped**
   (previously only the exit code was captured). Vitest 33 confirmed.
4. **Secret scan: no committed secret, no STOP condition.** Hits, values never
   printed: 5 generic `password=…`/`secret=…` assignments that are synthetic test
   fixtures (test files + `scripts/smoke.py` demo password), 2 fake-JWT fixtures
   in `tests/test_finding_schema.py`, and 67 `fernet_key`-shaped matches inside
   `package-lock.json`/`frontend/package-lock.json` that are npm base64 integrity
   hashes (false positives of the loose pattern). `.env` exists locally,
   untracked and git-ignored; only `.env.example` (placeholders) is tracked.
5. **Nothing satisfies §3's definition of DONE today — and this is structural.**
   `docs/screenshots/` **does not exist** and `docs/FEATURES.md` **does not
   exist**. Every phase to date therefore has backend + tests but no screenshot
   and no FEATURES entry, i.e. **PARTIAL** under the v4 vertical-slice rule.
   There are also **no Playwright/browser journey tests** anywhere (no
   `*.spec.ts`, no `frontend/tests`, no `e2e/`), as the baseline said.
   Consequence: no phase may be retro-claimed as DONE; either the gaps get
   filled per segment or the report says PARTIAL.
6. **Minor doc drift:** `PROGRESS.md` says the work is on branch `smb-migration`;
   the repository is on `main`.

### Known defects re-verified this session (not trusted from the prompt)

| Defect | Fresh evidence |
|---|---|
| `GET /api/risk-history` missing | not in the 82 OpenAPI paths; live call returned **404** against a running server earlier this session |
| `dependency_exposure` absent from the UI model | `grep` in `frontend/src/lib/types.ts` → no match (backend does return it) |
| dead `#/connections` link | `SignalsPage.tsx:168`; `App.tsx` does not route `ConnectionsPage` |
| tracked build artifact | `git ls-files frontend/tsconfig.tsbuildinfo` → tracked |
| OAuth frozen, UI clean | `api.ts` still defines oauth client methods, but no page is routed; runtime `/api/oauth/providers` → **404**. Observation: `/api/oauth/connections` answers **401** (auth checked before the freeze gate) while the rest 404 — a probeable inconsistency for Segment 2c. |

## 3. What I will not do (invariants I am holding myself to)

- The deterministic engine in `app/engine/risk.py` is the only scorer. ML and any
  explanation layer emit findings/text and never touch scores, findings,
  dependencies, evidence or plans.
- No number in a report, doc or UI unless a command produced it; record seed,
  config, commit and command with it.
- Every data point keeps an honest label (LIVE / SYNTHETIC / FIXTURE /
  USER_ENTERED / UNAVAILABLE, plus NOT_CHECKED). A timeout, 429, missing key or
  empty response is never rendered as SAFE.
- Tenant isolation and RBAC are enforced server-side; client-supplied `org_id`
  and severity are never trusted; hiding a control in React is UX only.
- OAuth stays frozen: no provider apps, no credentials, flags default OFF in
  code, no OAuth surface in the UI, Instagram removed.
- No plaintext password, token, key or secret in storage, logs or responses.
  Startup rejects default/empty secrets.
- Planner keeps exactly two methods (greedy vs one exact) and four distinct
  task states; `VERIFIED_OBSERVED` is refused for synthetic data. Shapley stays
  exact over the real risk function — no model trained on CRIX's own labels.
- Forbidden wording list applies; the explanation feature is called
  "graph-grounded explanation" until real graph retrieval is actually verified.
  No compliance claims.
- Max 3 retries with backoff on provider errors, then stop and report. A failed
  sub-task is NOT DONE. No history rewrite, no force-push, no test weakening.
- Do not print secret values in any report; if a real secret is found, stop and
  report path + commit + category only.

## 4. Segment readback (my words)

**S1 — Git hygiene.** Split the 43 dirty paths into coherent commits (backend
signal modules, routers/schemas/wiring, migration, tests, frontend, docs),
excluding any secret/`.db`/`.eml`/`.env`/build artefact; `git rm --cached`
`frontend/tsconfig.tsbuildinfo`, ignore it, tag the resulting state, show
`git log --oneline`, and advise a private shared remote (origin already exists;
its visibility needs confirming).

**S2 — Fix pack, no new features.** (a) real org-scoped, role-checked
`GET /api/risk-history` read from `risk_results`, plus the page/chart and
cross-org-denial + empty-state tests; (b) surface the graph-derived
`dependency_exposure` in `RiskResult`, both score-composition views and the
Shapley view, with an explicit UNAVAILABLE when no graph exists; (c) delete the
`#/connections` link and the remaining OAuth UI surface; (d) a demo mode for a
public deployment (invite links shown to the admin instead of emailed, open
registration off, never seed default credentials, DEMO/SYNTHETIC banner) with
production checks unchanged; (e) deployment config — documented
`CRIX_TRUST_PROXY_HEADERS`, a `vercel.json` `/api` rewrite + security headers,
and `docs/DEPLOY.md` for Vercel/Render/Neon; (f) save pytest counts as JUnit,
add an Alembic downgrade test, attempt the PostgreSQL run (or mark BLOCKED), and
add Playwright journeys covering register → org setup → invite → accept → member
login → RBAC denial → cross-org denial → risk history; (g) CI with backend
tests, frontend build/tests, gitleaks, pip-audit, npm audit; (h) a
route-inventory test that fails when a new route is neither intentionally public
nor auth+org guarded.

**S3 — Phase 7b frontend catch-up.** Audit first and skip what already exists;
then org-scoped analysis/graph/what-if/explanation/history, an idempotent
synthetic-company seed, shared provenance/state/simulated/role-aware UI, org
shell (login, org setup, invite, overview, assets CRUD incl. criticality and
edge source, findings, members/roles), a visibly four-state task board, an
ADMIN-only audit/"who can see what" page, a planner budget control that calls
the real planner, what-if toggles from the action catalogue, industry templates
at setup, and the legacy `/evaluation` view explicitly labelled pre-migration.

**S4 — Feature batch 1.** F1 bulk work-email breach check (consent, member
notice, queue/backoff/cache, audited admin run, fixtures, failures
UNAVAILABLE). F2 MFA coverage board (USER_ENTERED, privileged accounts without
MFA). F3 employee client-side password check with admin-only suppressed counts
(<3). F4 phishing report inbox storing label/confidence/redacted excerpt/hash
only. F5 app-access review over the existing permission auditor. F6 offboarding
checklist producing "access not revoked" findings/tasks.

**S5 — Feature batch 2.** F7 SPF/DMARC (DKIM NOT_CHECKED) for admin-registered
domains only, plus a weak-DMARC + phishing impersonation correlation. F8 repo
zip secret scan with strict limits, safe unzip, redacted evidence and a hash
(Meli et al. 2019 cited). F9 deterministic "if this account is hacked" ordered
playbook. Max two declarative rules per feature; then feature freeze.

**S6 — Phases 8/9/11.** Isolated non-persistent what-if over the real engine
(including the dependency term), honest audit of retrieval for explanations,
org-scoped retrieval, deterministic renderer default with an OFF-by-default,
consent-gated, mock-testable LLM adapter, citations on company-specific claims,
allowlist validation, prompt-injection tests; then the ~25-person synthetic
company with four scenarios and a demo-flag-only scenario switcher.

**S7 — Phase 10 screens.** Exposure-path replay over documented edges, a
fix-order showdown on DEMO scenarios only (labelled SIMULATED, losses shown,
never the held-out set), an executive brief PDF, a Playwright screenshot script
and journeys as ADMIN/MEMBER/VIEWER.

**S8 — Phase 12 metrics plan, then stop.** Commit `docs/EVAL_METRICS_PLAN.md`
alone (question, methods A/B/C1/C2, metrics and direction, simulator and
propagation assumptions, budget policy, seeds, run count, uncertainty,
exclusions, sensitivity, limitations) and run **no** comparative results until
told CONTINUE. The simulator must import nothing from the risk engine.

**S9 — Phase 13.** Full isolation/RBAC sweep, admin-view auditing, startup
secret validation, no secrets in code/logs/history, consent and
provider-failure behaviour, injection tests, verification-state integrity,
plaintext-never-sent test, PostgreSQL full suite only if it truly ran, Alembic
up/down, a second classical phishing model with real metrics,
`docs/DATASETS.md` with licences, and a README that matches reality.

Semester-8 backlog (KEV/EPSS/OSV, ATT&CK graph, CIS IG1 mapping, pilots, LLM
adapter measurement, paper) is explicitly **not** built now.

## 5. Known BLOCKED / risk items, up front

- **PostgreSQL suite: BLOCKED in this environment** — no `docker`, no
  `docker compose`, and `psycopg` is not installed (`ModuleNotFoundError`).
  Segment 2f/9 must either install a local Postgres path or be reported BLOCKED,
  never "Postgres-tested".
- **Alembic downgrade is untested** (chain is linear, 9 revisions, single head
  `b7c8d9e0f1a2`). A downgrade test is planned in 2f.
- **gitleaks is not installed**, so the secret scan stays a documented regex
  fallback until CI (2g) runs the real tool.
- **Playwright browsers** are not proven installed (CLI 1.64 alpha present);
  a browser install may be needed before S2f journeys.
- **Render free tier cannot send SMTP**, so the deploy doc must state that
  email-dependent paths are verified locally only.
- **Screenshots/FEATURES.md**: every later segment must produce them, otherwise
  it is PARTIAL by definition.

## 6. Next action (on `CONTINUE`)

Segment 1 only: group the 43 paths into logical commits, untrack
`frontend/tsconfig.tsbuildinfo` and ignore it, tag the hygiene commit, show
`git log --oneline`, and advise on a private shared remote. No fixes and no
features until Segment 2 is separately authorised.
