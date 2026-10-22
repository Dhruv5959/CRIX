# CRIX — Architecture

> Deep-dive companion to `README.md` and `docs/IMPLEMENTATION_STATUS.md`.
> This document describes how the pieces fit together and why, with the exact
> contracts each layer must honor. Last updated: 2026-10-08.

---

## 1. Design principle: deterministic engine decides, GraphRAG explains

CRIX separates **decision** from **explanation**:

- The **deterministic engine** (correlation → risk → Shapley → graph → planner)
  is the single source of truth for every authoritative number. It is a pure
  function of the stored `security_events` rows for a user.
- **GraphRAG** is read-only. It never computes or overrides a score, and every
  statement it makes is traceable to either (a) a curated knowledge-graph edge or
  (b) the engine's own output. A validator flags anything unsupported.

A second invariant runs through every layer: **"couldn't check" is never "safe."**
The `status` field on every event is one of `FINDING`, `CHECKED_SAFE`,
`NOT_CHECKED`, or `UNAVAILABLE`, and only `FINDING` events contribute risk.

---

## 2. Data flow

```
 React (TypeScript) dashboard
        │  REST /api/*  (Bearer access token + refresh cookie + CSRF header)
        ▼
 FastAPI routers
        │
        ▼
 Signal modules ──► SecurityEvent normalizer (one schema, honest statuses)
   • breach (HIBP)          │
   • password (client hash) │
   • phishing (ML)          │
   • permissions (manual)   │
                            ▼
              Declarative correlation engine  (correlation_rules.yaml, 8 rules)
                            │
                            ▼
              Contextual risk engine    risk = m(c)×(base + interaction) − mitigation
                            │
                            ▼
              Exact Shapley attribution        Σ contributions == total (efficiency)
                            │
                            ▼
              Account dependency graph         NetworkX, curated edges, PageRank
                            │
                            ▼
              Remediation planner              greedy baseline vs exact branch-and-bound
                            │
                            ▼
              GraphRAG explanation             curated KG + engine output, cited
                            │
                            ▼
              Dashboard                        evidence + reasoning, not just a number
```

The orchestrator is `backend/app/engine/pipeline.py`:

- `run_analysis(db, user_id)` builds the event set, evaluates correlations,
  computes risk, attributes it, compares planner methods, and (optionally)
  persists a `run_id`'s worth of results. Used by `/api/analysis/summary`.
- `explain_run(db, user_id)` runs the same pipeline without persisting, then
  builds a **sanitized** context and asks GraphRAG to explain it. Used by the
  explanation surface.

### The feature vector is the contract between layers

`risk.extract_features(events)` collapses events into a mapping
`feature_name -> intensity in [0,1]`. This same vector is:

- the input to the risk function,
- the set of **players** in the Shapley cooperative game,
- the state that remediation actions mutate.

Because all three share one vector, the planner and attribution are guaranteed to
explain the *same* deterministic function — there is no separate toy model.

| Feature group | Source event types | Kind |
|---|---|---|
| `breach` | `BREACH_EXPOSURE` | risk |
| `session` | `SESSION_EXPOSURE` | risk |
| `identity` | `IDENTITY_EXPOSED` | risk |
| `reuse` | `PASSWORD_REUSE` | risk |
| `no_mfa` | `MFA_MISSING` | risk |
| `sim_swap` | `SIM_SWAP_VULNERABLE` | risk |
| `push_bombing` | `PUSH_BOMBING_REPORTED` | risk |
| `phishing` | `PHISHING_MESSAGE_DETECTED`, `AI_GENERATED_MESSAGE_DETECTED` | risk |
| `permissions` | `RISKY_PERMISSION_GRANTED`, `STALE_PERMISSION_GRANTED` | risk |
| `dependency` | `ACCOUNT_DEPENDENCY`, `COMPROMISED_RECOVERY_ACCOUNT` | risk |
| `mfa` | `MFA_ENABLED` (status `CHECKED_SAFE`) | mitigation |
| `passkey` | `PASSKEY_ENABLED` (status `CHECKED_SAFE`) | mitigation |

Risk features take the **maximum severity** among `FINDING` events in the group.
Mitigation features are `1.0` when the control is present.

---

## 3. The SecurityEvent schema

One schema (`backend/app/schemas.py`, persisted as `security_events`) is shared by
every module — no per-module ad-hoc shapes.

| Field | Meaning |
|---|---|
| `event_id` | stable id (unique) |
| `user_id` | owner — every query is scoped by this |
| `account_id` | which account/asset |
| `event_type` | semantic type (drives feature mapping + correlations) |
| `exposure_type` | `PASSWORD_ONLY` \| `PASSWORD_AND_SESSION` \| `SESSION_ONLY` (nullable) |
| `severity` | observation strength `[0,1]` |
| `confidence` | `[0,1]` |
| `source` | provenance (`hibp`, `manual`, `simulated`, `curated_graph`, …) |
| `detected_at` | timestamp |
| `status` | `FINDING` \| `CHECKED_SAFE` \| `NOT_CHECKED` \| `UNAVAILABLE` |
| `metadata` | structured extras (never secrets) |
| `provenance` | human-readable origin note |

`SESSION_*` exposures are always labeled in the UI as a **simulated exposure
scenario** — CRIX uses no real infostealer data.

---

## 4. Signal modules (`backend/app/signals/`)

| Module | File | Real? | Notes |
|---|---|---|---|
| HIBP client | `hibp.py` | REAL | `breachedaccount` + Pwned Passwords range API. `UNAVAILABLE` without a key. |
| Breach | `breach.py` | REAL | Emits `BREACH_EXPOSURE` with `exposure_type`. |
| Password hygiene | `password.py` | REAL (client-local) | Client sends only a SHA-1 prefix; server proxies the range. Reuse is compared client-side. |
| Phishing | `phishing.py` | REAL model | TF-IDF + Logistic Regression; AI-vs-human detector on synthetic data. |
| Permissions | `permissions.py` | MANUAL + curated taxonomy | Maps granted permissions to explainable sensitivity. |

The password path is worth spelling out: the browser computes
`SHA-1(password)`, sends **only the first 5 hex chars** to
`GET /api/password/range/{prefix}`, receives the matching suffix list, and
matches locally. Plaintext never leaves the client. The `range` endpoint rejects
full hashes and non-hex input; `test_security.py` additionally inspects outgoing
request bodies.

---

## 5. Declarative correlation engine (`backend/app/engine/correlation.py`)

Rules live in `backend/app/data/correlation_rules.yaml` — **data, not code**. The
engine interprets them; no Python conditional encodes a specific correlation.
Each rule declares:

- `rule_id`, `title`, `correlation_type`
- `predicates` (each matching `event_type`, optional `exposure_type`, `status`,
  `metadata`) with `match: all`
- severity logic: `base`, `per_event` (saturating), `cap`, and optional
  `multiplier_rules` (contextual factors)
- `confidence` aggregation (`min` across contributors)
- a human-readable `explanation` template

Eight rules ship. Each has a dedicated test; the evaluation harness asserts all
eight fire.

---

## 6. Contextual risk engine (`backend/app/engine/risk.py`)

```
risk = clip( m(c) × (base_risk + interaction_risk) − mitigation_credit, 0, 100 )
m(c) = 1 + 0.10 × (c − 3)          # asset criticality c ∈ 1..5 → m ∈ [0.8, 1.2]
```

- **base_risk** = Σ `base_weight[feature] × intensity`, weights sum to 1.00.
- **interaction_risk** = Σ pairwise `coefficient × f[a] × f[b]` — this is CRIX's
  thesis (problems *compound*) made explicit and inspectable. Computed from the
  findings themselves; grouped-link (correlation) results never feed the score.
- **m(c) — asset criticality** (Phase 4) = the single documented way company
  asset importance enters: the criticality (1–5) of the most important
  registered asset affected by the findings scales the evidence-based exposure.
  Neutral level 3 (the registration default) and *missing* criticality both give
  `m = 1.0`; missing is recorded as an unknown input, never as "safe". Criticality
  alone never creates risk — zero findings score 0 at every criticality.
- **mitigation_credit** = credits for MFA/passkey, **discounted** when a session
  is exposed (a stolen session bypasses credential-based controls — mirroring the
  curated KG edge `session_hijacking --defeats--> passkey`) and capped at 45% of
  the (criticality-scaled) exposure.

All parameters live in one `RISK_PARAMS` dict; the full specification — including
the additive UI identity (`base + interaction + criticality_adjustment −
mitigation`), traceability fields, out-of-range/missing-input handling and
model versioning (`risk-1.0` → `risk-2.0`) — is in `docs/RISK_MODEL.md`.
Bands: `LOW <25 ≤ MODERATE <50 ≤ HIGH <75 ≤ CRITICAL`. The reported **range**
is a bounded perturbation sensitivity interval (±5% per feature, criticality
held fixed) — explicitly *not* a statistical confidence interval. A sensitivity
test covers it.

---

## 7. Exact Shapley attribution (`backend/app/engine/shapley.py`)

Each feature group is a player; the characteristic function is
`v(S) = risk_from_features(features restricted to S)` with `v(∅)=0`. Values are
computed by **exact enumeration** over all 2ⁿ subsets (n = 12), with memoization.
No sampling, no approximation, and no model trained on CRIX's labels.

Properties tested:

- **Efficiency:** `Σ φᵢ == v(full) − v(∅)` within tolerance.
- **Null player / symmetry:** a feature that never changes the score gets 0.
- A timing benchmark is recorded.

---

## 8. Account dependency graph (`backend/app/engine/graph.py`)

- **NetworkX only** — no external graph DB.
- Edges come from the curated `graph_relationships` table (static, hand-verified,
  with `source` + `last_verified_at`).
- Ranking uses NetworkX **weighted PageRank** plus **weighted in-degree** —
  nothing is hand-assigned a rank.
- The graph emits two derived event types for compromised/high-centrality
  services: `ACCOUNT_DEPENDENCY` and `COMPROMISED_RECOVERY_ACCOUNT`, feeding the
  cascading-recovery correlation.
- The UI and GraphRAG always present these as *curated / static*.

---

## 9. Remediation planner (`backend/app/engine/planner.py`)

Exactly **two** methods, over a bounded action catalog:

1. **Greedy baseline** — repeatedly take the best risk-reduction-per-effort that
   fits the budget.
2. **Exact branch-and-bound** — optimal over the action set. The bound applies
   *all remaining actions from the current state* to get a valid lower bound on
   reachable risk, and prunes branches that cannot beat the incumbent.

Greedy is **never** labeled optimal. The measured optimality gap is

```
gap = max(0, (exact_reduction − greedy_reduction) / exact_reduction)
```

The scenario suite includes a deliberately constructed **greedy trap** where
greedy is provably worse. A brute-force regression test confirms the exact
solver never loses to greedy.

Actions mutate the same feature vector the risk engine uses, so the planner
re-runs the real risk function.

---

## 10. GraphRAG explanation (`backend/app/engine/graphrag.py`)

Contract:

- Receives **only** `sanitize_context(...)` output — an explicit whitelist of
  event *types*, correlation ids/severities, risk numbers, and graph edge
  endpoints. Raw message text, metadata dicts, passwords, secrets, and tokens are
  dropped (`sanitized: True`).
- Selects relevant curated KG edges for the context and renders template
  statements, each carrying citations (`edge_id` or `engine:*`).
- `validate(...)` returns any statement lacking a citation or citing an unknown
  edge; `grounded = not unsupported_claims`.

The generator is deliberately deterministic and template-based — there is no
free-form invention.

---

## 11. Database (`backend/app/models.py`, Alembic)

| Table | Purpose |
|---|---|
| `users` | accounts, bcrypt hash, TOTP fields |
| `refresh_tokens` | rotating refresh tokens (hashed), CSRF token, rotation chain |
| `password_reset_tokens` | single-use, short-expiry (hashed) |
| `connected_signals` | user-declared accounts/assets |
| `security_events` | the normalized event schema |
| `correlations` | fired rule results per `run_id` |
| `risk_results` | score + breakdown per `run_id` (+ Phase 4 context: `org_id`, `asset_id`, `model_version`, `criticality_adjustment`) |
| `attribution_results` | Shapley contributions per `run_id` |
| `remediation_actions` | action catalog |
| `remediation_plans` | greedy/exact plans per `run_id` |
| `graph_relationships` | curated dependency edges |
| `knowledge_nodes` / `knowledge_edges` | curated GraphRAG KG |
| `provider_metadata` | curated passkey/MFA/recovery table |
| `evaluation_records` | written only by code that actually measured |
| `audit_logs` | security audit trail (never secrets/tokens) |
| `provider_connections` | authorized OAuth relationships; **encrypted** tokens only |
| `provider_capabilities` | curated "what the official API exposes" matrix |
| `account_relationships` | USER_CONFIRMED edges between connected accounts |
| `propagation_results` | persisted compromise-propagation simulations |

Every user-data table carries a non-nullable `user_id` FK with `ON DELETE
CASCADE`, so all queries are strictly scoped and no soft-deleted data leaks.
SQLite for dev, PostgreSQL for production (`CRIX_DATABASE_URL`).

Dev/test startup runs `init_db()`, which calls `create_all` **plus** an additive
column migration: it inspects existing tables and issues `ALTER TABLE ... ADD
COLUMN` for any column a model declares that the database lacks (backfilling a
constant default for `NOT NULL`). It only ever adds — never drops or rewrites —
so it is idempotent. Production uses Alembic
(`migrations/versions/9c3f21a04e12_live_connections.py`).

---

## 11b. Live account connections (`backend/app/oauth/`, `routers/oauth.py`)

Official OAuth 2.0 / OIDC only — no scraping, no unofficial APIs, no provider
password ever requested or stored.

```
GET  /api/oauth/providers            configured? scopes? what it exposes / does not
GET  /api/oauth/capabilities         curated capability matrix (§ below)
GET  /api/oauth/{p}/authorize        → { authorize_url }  (state + PKCE issued)
GET  /api/oauth/{p}/callback         exchange code → store encrypted → redirect
GET  /api/oauth/connections          list (never includes a token)
DELETE /api/oauth/connections/{id}   disconnect
POST /api/oauth/fixtures/{p}         clearly-labeled FIXTURE connector (dev only)
```

**Security invariants** (each is asserted by a test in `tests/test_propagation.py`):

1. **Authorization-code flow with PKCE (S256).** The `code_verifier` never
   leaves the backend; `state` is cryptographically random, single-use, bound to
   the initiating user, and expires after 10 minutes (`oauth/pkce.py`).
2. **Tokens are encrypted at rest.** Fernet via `app/token_crypto.py`, key from
   `CRIX_TOKEN_ENCRYPTION_KEY` (production refuses to start without it). Dev
   falls back to a key derived from `CRIX_JWT_SECRET`.
3. **Tokens never reach the frontend and are never logged.** The connections
   endpoint returns `token_available: boolean`. Decryption failure logs the
   exception *type* only — never either form of the token.
4. **Minimum scopes.** Google asks for `gmail.metadata` (headers/labels), not
   message bodies; `gmail.readonly` is documented as a genuine content need.
5. **Unconfigured ≠ connected.** A blank client id/secret makes the provider
   report `NOT_CONFIGURED` and `authorize` return **503** — it never silently
   pretends to work.

### Capability matrix vs. connection

A connection proves an *authorized relationship*. It does **not** reveal the
provider's security posture, and connecting must not flip a capability to
available (asserted). `data/provider_capabilities.yaml` is the source of truth:

| Provider | Available through official API | Not — marked `UNAVAILABLE_THROUGH_PROVIDER` |
|---|---|---|
| Google | basic profile, Gmail metadata | Security Checkup, 2SV state, breach status, password reuse |
| LinkedIn | basic profile, email | MFA, security checkup, connected apps, breach status |
| Instagram (Professional) | account identity, permitted profile/media | password state, MFA, compromise status, consumer-account data |

Unavailable capabilities are **never** rendered as `SAFE` — the `EventStatus`
value `UNAVAILABLE_THROUGH_PROVIDER` exists specifically so they cannot be
confused with `CHECKED_SAFE`.

---

## 11c. Confirmed relationships (`routers/relationships.py`)

OAuth login does **not** prove that one account is a recovery route for
another. CRIX asks *"How are these accounts related?"* and stores only what the
user confirms: `recovery_email`, `recovery_phone`, `sso`, `oauth_dependency`,
`same_email_identity`, `other` — each with `source = USER_CONFIRMED`,
`source_mode = USER_PROVIDED`, a confidence, and a weight. Unknown types are
rejected (422); self-edges are rejected; both endpoints must be accounts the
caller owns.

---

## 11d. Compromise propagation (`engine/propagation.py`, `routers/propagation.py`)

`POST /api/propagation/simulate { upstream_account_id }` runs a **defensive
what-if**. Nothing is accessed, altered, disabled, or sent — the endpoint only
recomputes. It returns downstream exposure, the storyline, the **recomputed**
contextual risk from the real engine, exact Shapley attribution, and — using the
*same* planner (greedy baseline vs. one exact branch-and-bound) — the
**remediation priority** under the scenario, alongside the no-scenario baseline
so the shift is visible.

```
exposure(d) = clamp0_100(
    100 × ( dependency_strength × account_criticality
            × credential_auth_weakness × path_exposure )
  − 100 × mitigation_credit )
```

- **dependency_strength** — product of edge weights along the best path from the
  upstream account, with per-hop decay (0.75/hop). Edges are *weighted*; a
  recovery edge (1.0) is not an identity edge (0.6).
- **account_criticality** — weighted in-degree centrality mapped into
  `[0.5, 1.0]`.
- **credential_auth_weakness** — sum of this account's `FINDING` events
  (password reuse 0.35, breach exposure 0.30, MFA missing 0.25, …), capped at 1.
  **If the account has no recorded events at all, this is not 0** — an
  un-telemetered account would otherwise render as "zero exposure," an
  unsupported claim of safety. It is scored at `unknown_weakness` (0.5, a
  documented neutral default) and labeled *"no auth telemetry recorded —
  unknown, not safe."* An account that **has** been checked — even all
  `CHECKED_SAFE` — is scored from its evidence, which is why a checked-clean
  account scores below an unchecked one. This is the propagation engine obeying
  CRIX's *couldn't check ≠ safe* rule.
- **path_exposure** — `0.75^(hops−1)`; a 2-hop path transmits less than a
  direct one.
- **mitigation_credit** — passkeys/MFA subtract, capped at 0.35.

Every parameter lives in one `PROPAGATION_PARAMS` dict; every component is
returned so the UI can show *why* a number is what it is. There is **no**
hard-coded propagation score anywhere — a test seeds the same graph with and
without weakness findings and asserts the score moves, and a second test proves
an account with *no* telemetry is never scored as safe.

**Language:** the result is a *relative downstream exposure* under a scenario.
The API ships a disclaimer stating it is **not a probability** and **not a
prediction**, and the UI says "has elevated downstream compromise exposure
*if* X is compromised" — never that an account will be hacked.

**Four things are recalculated, all by the real engines:**

| Output | Engine |
|---|---|
| Downstream exposure + components | `engine/propagation.py` (documented formula) |
| Contextual risk + sensitivity range | `engine/risk.py` (12-feature vector, unchanged) |
| Shapley attribution | `engine/shapley.py` (exact, efficiency error < 1e-6) |
| Remediation priority | `engine/planner.py` (greedy **baseline** vs exact) |

No output is hardcoded; each is recomputed from the scenario's feature vector
on every request.

---

## 11e. `source_mode` provenance

Every event and connection carries `source_mode` (`schemas.SourceMode`):

| Value | Meaning |
|---|---|
| `REAL` | the official provider API actually returned it |
| `USER_PROVIDED` | typed or confirmed by the CRIX user |
| `SIMULATED` | a scenario state; no real account involved |
| `FIXTURE` | clearly-labeled local demo data — **not** real |
| `UNAVAILABLE` | not obtainable |

This is deliberately separate from `DataProvenance` (which describes *how a
datum was produced*, incl. `MODEL` and `CURATED`) — the connection UI must show
these five verbatim, and `FIXTURE` must never blur into `REAL`. The normalizer
carries it both directions (`to_row` / `to_schema`), and the frontend renders
`<SourceModeBadge>` on every connection, relationship, and scenario.

---

## 12. Frontend (`frontend/src/`)

React + TypeScript + Tailwind; dark-mode-first (dark navy/slate, one accent).
Heavy pages are route-level code-split. Pages: Overview, Connected Signals,
**Live Connections**, **Propagation**, Correlations, Risk + Shapley waterfall,
Dependency Graph (force-graph), Remediation + What-If, GraphRAG Explanation,
Learning/Knowledge, Evaluation, Login.

- Charts via **Recharts** (waterfall, evaluation bars); graph via
  `react-force-graph-2d`.
- A REAL / SIMULATED / UNAVAILABLE badge component is used wherever data is shown.
- `<SourceModeBadge>` renders the five `source_mode` values verbatim on every
  connection, relationship, and scenario row (Live Connections + Propagation).
- `/connections` handles the OAuth callback (`?oauth_success=` / `?oauth_error=`),
  shows the capability matrix, and hosts the *"How are these accounts related?"*
  confirmation editor. `/propagation` runs the simulate endpoint and renders the
  storyline, per-component exposure breakdown, recomputed risk, and attribution.
- The Evaluation page reads only persisted `evaluation_records`; when empty it
  renders **"not yet measured."**
- The What-If simulator toggles actions and re-triggers the **real** pipeline
  (risk + Shapley + graph) server-side — historical facts persist, actions change
  mitigation state.
- Client-side password hashing lives in `lib/password.ts`, with a Vitest suite
  asserting plaintext never reaches the network layer.

---

## 13. Honesty & terminology guarantees

- No fabricated metrics anywhere; unmeasured → "not yet measured."
- Approved language only: *contextual risk score*, *relative risk prioritization*,
  *transparent attribution*. CRIX does not claim to predict hacking, prevent
  account takeover, or estimate a probability of being hacked.
- Synthetic ML data is labeled; simulated exposure scenarios are labeled; curated
  tables carry `source`/`last_verified_at`.