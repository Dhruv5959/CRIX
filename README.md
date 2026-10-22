# CRIX — Contextual Risk Intelligence

> **CRIX doesn't just tell you what security problems you have — it tells you how
> they connect, which one matters most, why, and what to fix first.**

CRIX is a final-year capstone project: a full-stack system that ingests security
signals (breach exposure, password hygiene, phishing/scam messages, risky app
permissions), correlates them into compound findings, computes a **contextual
risk score**, attributes that score transparently with **exact Shapley values**,
maps **account dependencies**, and plans remediation by comparing a **greedy
baseline against an exact solver**. A **GraphRAG** layer explains the result
using only a curated knowledge graph and CRIX's own output.

---

## Honesty policy (read this first)

This project has an explicit, non-negotiable policy about data and numbers:

- **No fabricated metrics.** Every number shown in the UI comes from code that
  actually ran on real test data. Anything not yet measured renders as
  **"not yet measured."**
- **GraphRAG explains; the risk engine decides.** GraphRAG never computes or
  overrides risk, and never invents a relationship, technique, or citation that
  is not in the curated knowledge graph. An automated test flags unsupported
  claims.
- **Live OAuth connects only what OAuth can actually prove.** CRIX connects to
  Google, LinkedIn, and Instagram through official OAuth 2.0 / OIDC only — it
  never asks for your provider password, never stores provider credentials, and
  never sends an OAuth token to the browser. A connection proves an *authorized
  relationship*, not security posture: those platforms don't expose breach
  status, MFA state, or authorized-app lists to third-party apps, so CRIX marks
  those capabilities `UNAVAILABLE_THROUGH_PROVIDER` — never "safe." Account
  relationships are **user-confirmed**, never inferred from a login.
- **Plaintext passwords never leave the browser.** Password checks use
  client-side SHA-1 hashing and a k-anonymity range query. An automated test
  inspects outgoing requests and fails if a plaintext password ever appears.
- **Shapley explains the real function.** Attribution is exact cooperative-game
  Shapley over CRIX's deterministic risk function — not a model trained on
  CRIX's own labels.

### What is real vs. simulated vs. unavailable

| Signal | Classification | Mechanism |
|---|---|---|
| Email breach exposure | **REAL** | XposedOrNot `check-email` API by default (no key needed); HIBP `breachedaccount` when `CRIX_HIBP_API_KEY` is set. Provider failure → `UNAVAILABLE`, never "safe". |
| Pwned-password count | **REAL** | HIBP Pwned Passwords range API, k-anonymity, client-side hash. |
| Session-cookie / infostealer exposure | **SIMULATED** | User-constructed scenario, labeled "simulated" in the UI. |
| Password reuse | **REAL (client-local)** | Compared in-browser; only a boolean is submitted. |
| Passkey / MFA / SIM-swap readiness | **CURATED + self-report** | Hand-verified provider table + user input. |
| Push-bombing | **SELF-REPORT** | User checkbox. |
| Phishing / scam classification | **REAL model** | Trained classifier; metrics measured by an eval script. |
| AI-vs-human text detection | **REAL model, SYNTHETIC training data** | Trained on a self-generated synthetic corpus (documented). |
| Permission risk | **MANUAL + curated taxonomy** | Explainable per-permission sensitivity. |
| Account dependency edges | **CURATED (static)** | Hand-verified rows with source + `last_verified_at`. |
| GraphRAG techniques/defenses | **CURATED KG** | Never auto-discovered, never invented. |
| OAuth account connections | **REAL (official API)** | Auth-code + PKCE; tokens encrypted at rest, never returned to the browser. |
| Connected-account relationships | **USER_CONFIRMED** | CRIX asks "how are these accounts related?" — it never infers a recovery path. |
| Provider security posture (MFA, checkup, breach) | **UNAVAILABLE_THROUGH_PROVIDER** | Not exposed by the official API; never rendered as "safe." |
| Compromise propagation scenario | **SIMULATED** | Defensive what-if; no account is accessed, altered, or attacked. |
| Demo connectors without credentials | **FIXTURE** | Clearly labeled local demo data; disabled in production. |

**Approved language:** "contextual risk score," "relative risk prioritization,"
"transparent attribution." CRIX does not claim to predict hacking, prevent
account takeover, or estimate a probability of being hacked.

---

## Architecture

```
React (TypeScript) Dashboard
        ↓
FastAPI Backend
        ↓
Signal Modules (Breach, Password, Phishing, Permissions)
        +  Live Account Connections (OAuth 2.0 + PKCE → encrypted token store)
        ↓
SecurityEvent Normalizer (one schema, honest statuses + source_mode)
        ↓
Declarative Correlation Engine (YAML rules)
        ↓
Contextual Risk Aggregation (non-additive)
        ↓
Shapley Attribution (exact)
        ↓
Account Dependency Graph (NetworkX)
        +  USER_CONFIRMED relationship edges + Compromise Propagation (what-if)
        ↓
Remediation Planner (greedy vs. exact branch-and-bound)
        ↓
GraphRAG Explanation Layer (curated KG + engine output)
        ↓
Dashboard (evidence + reasoning, not just a number)
```

A key design choice: the **"couldn't check" ≠ "safe"** distinction is preserved
throughout. Every event carries a status of `FINDING`, `CHECKED_SAFE`,
`NOT_CHECKED`, `UNAVAILABLE`, or `UNAVAILABLE_THROUGH_PROVIDER`, and every
connection/scenario carries a `source_mode` (`REAL` / `USER_PROVIDED` /
`SIMULATED` / `FIXTURE` / `UNAVAILABLE`).

---

## Repository layout

```
backend/
  app/
    config.py            # env-driven settings (secrets never committed)
    security.py          # bcrypt + JWT helpers
    models.py            # SQLAlchemy ORM
    schemas.py           # Pydantic schemas (incl. the one SecurityEvent schema)
    signals/             # breach (HIBP + XposedOrNot), password, permissions, phishing
    oauth/               # PKCE + provider registry + token exchange (official APIs only)
    engine/              # normalizer, correlation, risk, shapley, graph, planner, graphrag, propagation, pipeline
    ml/                  # synthetic dataset + trained models
    data/                # curated YAML: correlation rules, providers, graph, KG, taxonomy, capabilities
    routers/             # FastAPI endpoints (incl. oauth, relationships, propagation)
    token_crypto.py      # Fernet encryption for OAuth tokens at rest
  migrations/            # Alembic
  scripts/               # train_phishing, run_evaluation, seed_demo, smoke, export_datasets
  tests/                 # pytest suite (auth, IDOR, engine, security checklist, connections/propagation)
frontend/
  src/
    lib/                 # api client, auth, analysis context, client-side password hashing
    components/          # shadcn-style UI primitives + layout
    pages/               # Overview, Signals, Connections, Propagation, Correlations, Risk,
                         #   Graph, Remediation, Explanation, Evaluation, Knowledge
    lib/password.test.ts # vitest: plaintext-never-leaves-client invariant
docs/
  IMPLEMENTATION_STATUS.md  # Phase 0 audit + final build status and measured results
  ARCHITECTURE.md           # how each layer works and the contracts it honors
  SECURITY.md               # threat model, controls, and the §14 checklist -> tests
```

---

## Setup

### Prerequisites
- Python 3.11+ (tested on 3.13)
- Node 18+ (tested on 22)
- SQLite is used for local dev; PostgreSQL is supported for production.

### Backend

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt

# Configure environment (copy the example and edit) — create it at the PROJECT ROOT,
# next to .env.example. Both repo-root\.env and backend\.env are read (root wins).
Copy-Item .env.example .env
# Set CRIX_JWT_SECRET to a strong random value. Real email-breach lookups work
# with no key at all (XposedOrNot is the default); set CRIX_HIBP_API_KEY only if
# you want the HIBP lookup instead (it also reports which data classes leaked).
# The API reads these at startup -> restart after editing.

# Apply migrations
cd backend
..\.venv\Scripts\python.exe -m alembic upgrade head

# Train the ML models (writes backend/artifacts/*.joblib)
..\.venv\Scripts\python.exe scripts\train_phishing.py

# Run the evaluation harness (persists real metrics for the Evaluation page)
..\.venv\Scripts\python.exe scripts\run_evaluation.py

# Start the API
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

### Frontend

```powershell
cd frontend
npm install
npm run dev        # http://localhost:5173 (proxies /api to :8000)
```

### Try it

```powershell
# Seed a demo user with a realistic scenario and run the real pipeline
.\.venv\Scripts\python.exe backend\scripts\seed_demo.py
# Log in at http://localhost:5173 with demo@example.com / demo-password-123
```

### Optional: live account connections (OAuth)

CRIX works fully without OAuth. To connect real accounts, register an app with
each provider you want and fill in `.env` **at the project root** (restart the
API afterwards — config is read at startup):

| Provider | Console | Redirect URI to register exactly |
|---|---|---|
| Google | <https://console.cloud.google.com/apis/credentials> | `http://127.0.0.1:8000/api/oauth/google/callback` |
| LinkedIn | <https://www.linkedin.com/developers/apps> | `http://127.0.0.1:8000/api/oauth/linkedin/callback` |
| Instagram (Professional) | <https://developers.facebook.com/apps> | `http://127.0.0.1:8000/api/oauth/instagram/callback` |

```ini
CRIX_GOOGLE_CLIENT_ID=...
CRIX_GOOGLE_CLIENT_SECRET=...
# ...same pattern for LINKEDIN and INSTAGRAM
CRIX_TOKEN_ENCRYPTION_KEY=   # python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Until those are set, each provider reports **`NOT_CONFIGURED`** and the Connect
button is disabled — it never pretends to be connected. The demo propagates
fine without them via the clearly-labeled **FIXTURE** connector
(`source_mode = FIXTURE`, disabled in production).

### Email breach lookups (XposedOrNot / HIBP)

You type an email into **Connected Signals → Breach / Exposure**; the *backend*
performs the lookup and returns normalized events. The browser never calls the
provider directly and you are never redirected to the provider's website.

| `CRIX_BREACH_EMAIL_PROVIDER` | Behaviour |
|---|---|
| `auto` (default) | HIBP when `CRIX_HIBP_API_KEY` is set, otherwise XposedOrNot. |
| `xposedornot` | Always the free XposedOrNot community API. |
| `hibp` | Always HIBP (needs a key; reports which data classes leaked). |

The value is validated at startup (a typo fails loudly), the resolved provider
is reported by `GET /api/health`, and it is stored on every event
(`source`, `metadata.provider`, `metadata.provider_label`, `metadata.checked_at`)
so the UI shows where each result came from.

- **No API key, no paid dependency.** XposedOrNot's `check-email` endpoint is free.
- **Rate limits.** The published free tier is 2 requests/second and 25/hour per IP.
  CRIX gates its own outbound calls on a process-wide throttle at those numbers,
  honours `Retry-After` and backs off after an HTTP 429, and caps inbound calls to
  `POST /api/signals/breach` with `CRIX_BREACH_CHECK_RATE_LIMIT_PER_MINUTE` (10/min).
- **Never a false "safe".** 429, 5xx, timeouts, malformed input, non-JSON, an
  error body arriving with HTTP 200, or an empty breach list all become
  `UNAVAILABLE` (shown as UNKNOWN), never `CHECKED_SAFE`.
- **The provider observes; the engine scores.** Breach events feed the
  deterministic risk engine like any other signal — a provider can never set the
  authoritative score, and no result is fabricated or substituted with synthetic
  data when a live call fails.
- **XposedOrNot reports breach names only**, so its findings deliberately carry no
  `exposure_type` and `exposed_data_classes = UNAVAILABLE_THROUGH_PROVIDER` — CRIX
  will not claim which data classes leaked when the provider does not say.

**Verified live contract (probed against the real endpoint, not just the docs).**
Three behaviours differ from <https://xposedornot.com/api_doc> and are pinned by
regression tests in `backend/tests/test_xposedornot.py`:

1. "No record" arrives as **HTTP 200** `{"Error":"Not found","email":null}` — not
   the HTTP 404 the docs' response table implies (the 404 path is still handled).
2. A **malformed address returns that same body**, so the provider cannot tell
   "invalid input" from "not found". CRIX validates the address itself before
   calling, and only accepts that body as a verified negative for a well-formed
   address.
3. `breaches` is a **list of lists** (`[["Name", "Name", ...]]`); a hit is parsed
   accordingly and capped at 20 names for display while the full count is kept.

The existing **HIBP Pwned Passwords range check is unchanged**: the hash is
computed in your browser, only a 5-character SHA-1 prefix reaches the proxy, and
plaintext passwords are never sent to or stored by the backend.

---

## Tests

```powershell
# Backend: auth, IDOR, engine, and the security checklist
cd backend
..\.venv\Scripts\python.exe -m pytest

# End-to-end HTTP smoke test (server must be running)
..\.venv\Scripts\python.exe scripts\smoke.py

# Frontend:
cd frontend
npx vitest run
npm run build
```

The security checklist (`backend/tests/test_security.py`) has an automated test
for each item in the spec: plaintext-password-leak, IDOR, client-injected risk
rejection, secret redaction in logs, GraphRAG context sanitization, rate
limiting, restrictive CORS, and env-only secrets.

`backend/tests/test_propagation.py` covers the live-connection invariants:
tokens encrypted at rest and never serialized or logged, provider secrets never
exposed, unconfigured providers report `NOT_CONFIGURED` (503) instead of
pretending, connecting never flips a capability to available, unavailable
capabilities render `UNAVAILABLE_THROUGH_PROVIDER` and never `SAFE`,
relationships are `USER_CONFIRMED` + weighted, the propagation score moves when
inputs move (no hard-coded value), and the simulation leaves real events
untouched.

**Current: 123 backend tests, 6 frontend tests, 54/54 smoke checks green.**

---

## Measured results (from `scripts/run_evaluation.py`)

These are produced by the harness on its own test data — not borrowed numbers.

- **Phishing classifier** (TF-IDF + Logistic Regression) is evaluated on a
  **disjoint-template split** of the synthetic corpus. Current measured F1 ≈ 0.83.
- **AI-vs-human detector** (stylometric + Logistic Regression) F1 ≈ 0.81.
- **Remediation planner**: mean optimality gap of greedy vs. exact ≈ 6–7% across
  the scenario suite, with at least one **deliberately constructed greedy trap**
  where greedy is strictly worse than exact.
- **Exact Shapley**: efficiency error within ~2e-9 over the tested feature
  vectors; mean compute time ≈ 100 ms for 13 features on the dev machine.

> The ML corpus is synthetic and clearly labeled. Reported scores measure
> generalization to unseen *templates within a synthetic distribution* — they
> are not claims about real-world phishing detection. Re-run the harness any time;
> the UI reads only persisted measurements.

---

## Security notes

- CRIX's **own** login uses bcrypt (cost ≥ 12), short-lived JWT access tokens,
  rotating refresh tokens in an httpOnly/SameSite cookie with double-submit CSRF,
  per-IP login rate limiting, single-use password-reset tokens, and optional TOTP
  2FA.
- Every data query is scoped to the authenticated `user_id`; an IDOR test proves
  user A cannot read or modify user B's data.
- Secrets live only in environment variables; `.env` is git-ignored and
  `.env.example` is provided. Production refuses to start with the dev JWT
  secret, a CORS wildcard, or a missing `CRIX_TOKEN_ENCRYPTION_KEY`.
- **Live connections** use official OAuth 2.0 with PKCE (S256) and single-use
  state. CRIX never asks for a Google/LinkedIn/Instagram password and never
  stores provider credentials; tokens are Fernet-encrypted at rest and never
  returned to the browser or written to a log.
- A connection proves an **authorized relationship**, not security posture.
  Capabilities the official API won't expose are marked
  `UNAVAILABLE_THROUGH_PROVIDER` — never "safe" — and account relationships
  exist only because the user confirmed them.

## License

Academic capstone project. Provided as-is for portfolio and review purposes.