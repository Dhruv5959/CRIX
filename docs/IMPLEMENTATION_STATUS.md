# CRIX — Implementation Status

> This document began as the **Phase 0 audit** (Rule 0.8: audit before code).
> Section 1 below is preserved as the historical pre-build snapshot. Sections
> 3–8 record the completed build and the measured evidence behind it.
> Last updated: 2026-10-08.

---

## 1. Repository audit (pre-build snapshot — preserved)

| Area | State at Phase 0 | Notes |
|------|------------------|-------|
| Source tree | **Empty** | `C:\sem 7\major project` contained zero files (verified including hidden). |
| Git history | **None** | Not a git repository. No prior commits to inspect or preserve. |
| README | **Missing** | Created during the build. |
| Backend | **Missing** | No FastAPI app, models, migrations, or services. |
| Frontend | **Missing** | No React/Vite/Tailwind app. |
| Tests | **Missing** | No test suite. |
| Docs | **Missing** | Only this file at Phase 0. |
| Curated data | **Missing** | No correlation rules, service catalog, graph relationships, or knowledge graph. |

**Conclusion:** clean greenfield build; nothing to preserve or reconcile.

### Environment (verified)

| Tool | Version | Implication |
|------|---------|-------------|
| Python | 3.13.7 | Avoid unmaintained/wheel-fragile libs. Exact Shapley implemented in-house. |
| Node | 22.19.0 | Modern Vite + React + TS is fine. |
| npm | 11.6.0 | Fine. |
| git | 2.51.0 | Repo can be `git init`-ed. |
| Platform | win32 | Paths/scripts written cross-platform (`pathlib`). |

---

## 2. Deliberate engineering decisions (locked, with rationale)

1. **No `shap` dependency for attribution.** Exact cooperative-game Shapley is
   implemented in-house over the deterministic CRIX risk function. With ≤ ~12
   features exact enumeration is 2^n and fast; this guarantees the efficiency
   property exactly and removes a heavy native dependency.
2. **`bcrypt` used directly, not `passlib`.** `passlib` is unmaintained and emits
   breakage warnings with `bcrypt >= 4.1`. We call `bcrypt` (cost ≥ 12) directly.
3. **`pyjwt`, not `python-jose`.** Simpler, maintained, fewer transitive native
   deps on Python 3.13.
4. **Custom in-house rate limiter** (not `slowapi`) so the limiter is
   unit-testable and deterministic.
5. **Password-breach check is client-side k-anonymity.** The browser computes
   `SHA-1(password)`, sends only the first 5 hex chars to the HIBP range API,
   receives suffixes, and matches locally. Plaintext never transits. A test
   inspects outgoing request bodies to prove this.
6. **Deterministic engine owns authority.** Correlation, risk, attribution,
   graph, and planner are pure functions of stored `SecurityEvent` rows.
   GraphRAG is read-only explanation over a curated KG + the engine's own output.
7. **Status honesty.** `CHECKED_SAFE` (ran, found nothing) ≠ `UNAVAILABLE`
   (couldn't run). Never coerced into "safe."

---

## 3. Build order (phases) — final status

| # | Phase | Status |
|---|-------|--------|
| 0 | Repo audit + this document | ✅ **Done** |
| 1 | DB schema + auth (JWT access + rotating refresh, bcrypt, rate limit, reset, optional TOTP) | ✅ **Done** |
| 2 | Signal modules A–D (breach, password, phishing ML, permissions) | ✅ **Done** |
| 3 | SecurityEvent normalizer | ✅ **Done** |
| 4 | Declarative correlation engine (8 YAML rules) | ✅ **Done** |
| 5 | Contextual risk engine (criticality × (base + interaction) − mitigation) + sensitivity range | ✅ **Done** |
| 6 | Exact Shapley attribution + documented game spec + seeded approximation + efficiency test + timing benchmark | ✅ **Done** |
| 7 | Account dependency graph (NetworkX, curated, centrality) | ✅ **Done** |
| 8 | Remediation planner (greedy vs. exact branch-and-bound, greedy-trap) | ✅ **Done** |
| 9 | What-if simulator (re-runs the real pipeline) | ✅ **Done** |
| 10 | GraphRAG explanation layer + unsupported-claim test | ✅ **Done** |
| 11 | Frontend integration + dark theme pass | ✅ **Done** |
| 12 | Full security test suite (§14 checklist) | ✅ **Done** |
| 13 | Evaluation harness + real measured metrics | ✅ **Done** |
| 14 | Polish, docs, demo scenarios | ✅ **Done** |
| 15 | Live account connections (OAuth 2.0/OIDC + PKCE, encrypted token store, capability matrix) | ✅ **Done** |
| 16 | User-confirmed relationship layer (`USER_CONFIRMED` edges, typed + weighted) | ✅ **Done** |
| 17 | Compromise propagation analysis (documented exposure formula + simulate endpoint) | ✅ **Done** |
| 18 | Connections + Propagation UI, `source_mode` badges, tests, docs | ✅ **Done** |

**Scope change (explicitly requested):** live OAuth with Google, LinkedIn, and
Instagram Professional replaced the original "no live OAuth" constraint. The
honesty rules were *not* relaxed — they were extended: a connection proves an
authorized relationship only, provider capabilities it cannot expose are
`UNAVAILABLE_THROUGH_PROVIDER` (never `SAFE`), relationships are never inferred
from a login, and the propagation score is a relative measure with a
documented formula, never a probability.

---

## 4. Real vs. simulated vs. unavailable (locked data policy)

| Signal | Classification | Mechanism |
|--------|----------------|-----------|
| Email breach exposure | **REAL** | HIBP `breachedaccount` API (requires `CRIX_HIBP_API_KEY`; `UNAVAILABLE` if absent). |
| Password pwned count | **REAL** | HIBP Pwned Passwords range API, k-anonymity, client-side hash. |
| Session-cookie / infostealer exposure | **SIMULATED** | Manually entered; labeled "simulated exposure scenario" in UI. |
| Password reuse | **REAL (user-local)** | Client-side hash comparison only; server never sees plaintext. |
| Passkey/MFA/SIM-swap readiness | **CURATED + SELF-REPORT** | Curated `provider_metadata` (~20 services) + user reports. |
| Push-bombing | **SELF-REPORT** | Single checkbox. |
| Phishing/scam classification | **REAL model** | Trained classifier; metrics measured by an eval script. |
| AI-generated text detection | **REAL model / SYNTHETIC training data** | Trained on self-generated synthetic AI phishing (documented). |
| Permission risk | **MANUAL + CURATED taxonomy** | Explainable per-permission sensitivity. |
| Account dependency edges | **CURATED (static)** | Hand-verified rows with source + `last_verified_at`. |
| GraphRAG techniques/defenses | **CURATED KG** | Never auto-discovered, never invented. |
| OAuth account connection | **REAL** | Official auth-code + PKCE; tokens Fernet-encrypted, never sent to the browser. |
| Connected-account relationship | **USER_CONFIRMED** | Asked of the user; never inferred from an OAuth login. |
| Provider MFA / breach / security-checkup state | **UNAVAILABLE_THROUGH_PROVIDER** | Not exposed by official APIs; never rendered as `SAFE`. |
| Compromise propagation scenario | **SIMULATED** | Defensive what-if; no account is accessed, altered, or attacked. |
| Demo connectors without credentials | **FIXTURE** | Labeled local demo data; disabled in production. |

No number in the UI is hardcoded. The Evaluation page reads from the evaluation
harness output; a metric that has not been measured renders **"not yet
measured."**

---

## 5. Measured results (real, reproduced by the harness)

These are produced by `backend/scripts/run_evaluation.py`, persisted to the
`evaluation_records` table, and rendered on the Evaluation page. They are **not**
hand-entered.

| Metric | Value | Notes |
|--------|-------|-------|
| Phishing classifier F1 | **0.830** (precision 1.00, recall 0.71) | TF-IDF + Logistic Regression, disjoint-template synthetic split (153 samples). Generalization on synthetic data, not a real-world claim. |
| AI-text detector F1 | **0.809** | Trained on self-generated synthetic AI phishing text. |
| Planner mean optimality gap | **0.0686** | Exact branch-and-bound vs. greedy baseline across generated scenarios. |
| Planner greedy traps observed | **2** | Scenarios where greedy is strictly sub-optimal (exact never worse). |
| Shapley max efficiency error | **3.00e-09** | Σ contributions − total, exact enumeration. |
| Shapley mean runtime | **~69 ms** | Per-evaluation timing benchmark. |
| Demo contextual risk score | **67.9 (HIGH)** | Seed demo; base 48.5 + interaction 13.2 + criticality 6.17; Shapley sum = total (err 0.0). |
| Attribution authority | **exact only** | Seeded approximation exists (`is_exact=false`) as a labelled teaching aid; pipeline never uses it. |
| Correlation rules exercised | **8 / 8** | One test per rule. |

---

## 6. Verification (final pass, 2026-10-08)

| Check | Command | Result |
|-------|---------|--------|
| Backend test suite | `cd backend; ..\.venv\Scripts\python.exe -m pytest` | ✅ **123 passed** (92 original + 28 for live connections, propagation, the demo-login guard, and config loading) |
| Frontend unit tests | `cd frontend; npx vitest run` | ✅ **6 passed** |
| Frontend production build | `cd frontend; npm run build` | ✅ **built** |
| Evaluation harness | `..\.venv\Scripts\python.exe scripts\run_evaluation.py` | ✅ metrics persisted |
| End-to-end smoke | `..\.venv\Scripts\python.exe scripts\smoke.py` | ✅ **54 / 54 checks green** (health, auth, signals, pipeline, what-if, graph/planner/explanation, live connections, propagation + scenario remediation, IDOR, logout/refresh) |

The §14 security checklist is covered by automated tests:
plaintext-password-never-in-outgoing-request, IDOR scoping, client cannot
inject/override risk or severity, secrets/tokens never logged, GraphRAG receives
only sanitized context, rate limiting on login + password-check, restrictive CORS
(production refuses a wildcard), and all secrets in env vars with `.env.example`
provided.

The live-connection invariants are covered by `tests/test_propagation.py`
(27 tests): tokens encrypted at rest and never serialized or logged, provider
secrets never exposed, unconfigured providers report `NOT_CONFIGURED`/503 rather
than pretending, connections never flip a capability to available, unavailable
capabilities render `UNAVAILABLE_THROUGH_PROVIDER` and never `SAFE`, relationships
are `USER_CONFIRMED` + weighted (unknown types/self-edges rejected), the exposure
score moves when inputs move (proving it is computed, not hard-coded), mitigation
lowers it, multi-hop paths decay, the disclaimer forbids probability language,
the simulation leaves real event rows untouched, connection lifecycle is audited
without leaking a token, and — because weakness is a *multiplier* — an account
with **no** recorded events is never scored as zero exposure (it is flagged
`weakness_unknown` and given a documented neutral default) while a checked-clean
account scores below it.

`tests/test_auth.py::test_seeded_demo_email_is_accepted_by_the_api` guards the
demo itself: the seed once defaulted to `demo@crix.local`, which Pydantic's
`EmailStr` rejects as an RFC 6761 special-use domain, so the documented demo
login returned **422** while the seed happily created the user. The seed now
defaults to `demo@example.com` (RFC 2606 documentation domain), refuses to
create any account the API's own `RegisterRequest` would reject, and a test
reads the seed's default straight from the script so the two can never drift
apart again.

**Not yet verified end-to-end:** a real Google/LinkedIn/Meta authorization
round-trip. That requires the team to register the three OAuth apps and set
`CRIX_*_CLIENT_ID` / `_SECRET` with the exact redirect URIs — the code path is
real (authorize URL, PKCE, token exchange, encrypted storage, userinfo) and unit
tested with the network boundary stubbed; only the credentials are absent.

---

## 7. Known limitations / open items

- **HIBP key:** email-breach checks return `UNAVAILABLE` without
  `CRIX_HIBP_API_KEY`. The UI surfaces this distinctly from "safe."
- **OAuth apps not yet registered:** Google / LinkedIn / Instagram connectors
  report `NOT_CONFIGURED` until the team creates the three apps and supplies
  `CRIX_*_CLIENT_ID` / `_SECRET` plus the exact redirect URIs
  (`CRIX_OAUTH_REDIRECT_BASE/{provider}/callback`). The flow itself is real and
  tested; only the credentials are missing. A clearly-labeled `FIXTURE`
  connector (dev-only, `source_mode=FIXTURE`) lets the propagation demo run
  without them — it never masquerades as `REAL`.
- **In-flight OAuth `state`/PKCE** lives in an in-process table — correct for a
  single-process dev/demo deployment; a multi-process deployment should move it
  to the DB or a shared cache.
- **Downstream exposure band thresholds** (HIGH ≥ 60, MODERATE ≥ 30) are
  documented, tunable parameters in `PROPAGATION_PARAMS` for relative
  prioritization. They are not calibrated against real compromise data, because
  none exists for this system — and labels are never generated from CRIX's own
  risk formula.
- **Email delivery:** password-reset tokens write to a dev outbox/log locally;
  production requires SMTP configuration. Token values are excluded from logs.
- **DistilBERT comparison** was not attempted; the stronger-model slot reports
  "not yet measured" rather than a fabricated number. TF-IDF + Logistic
  Regression is the guaranteed baseline.
- **Frontend dependencies:** `npm audit fix` (non-breaking) was run and the build
  still passes; **15 advisories remain** (7 moderate, 6 high, 2 critical) and all
  require breaking major upgrades (`react-router-dom` 7, `tailwindcss` 4,
  `vitest` 5) via `npm audit fix --force`, which was intentionally not applied.
  Track via `npm audit` before any public deployment.
- **Trailing spec item:** the original specification was truncated after
  "Strict" in the Database section; the final DB requirement there is unknown.

---

## 8. Definition of done (maps to §16)

Login/refresh/logout tested ✅ · every signal module works with real or clearly
labeled synthetic data ✅ · correlation/risk/Shapley/graph/planner reproduce real
output ✅ · what-if re-runs the real pipeline ✅ · GraphRAG passes the
unsupported-claim test ✅ · full §14 security checklist passes ✅ · dashboard
labels real vs demo vs unavailable everywhere ✅ · README is honest ✅ · live
connections use official OAuth with PKCE + encrypted tokens and never expose
provider secrets ✅ · capability matrix marks unexposed signals
`UNAVAILABLE_THROUGH_PROVIDER`, never `SAFE` ✅ · relationships are
user-confirmed, never inferred ✅ · compromise propagation is a labeled
simulation with a documented formula and no hard-coded score ✅.

---

*Build complete. See `README.md` for setup and architecture, and
`docs/ARCHITECTURE.md` + `docs/SECURITY.md` for the deep dives.*