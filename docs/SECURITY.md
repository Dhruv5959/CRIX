# CRIX — Security

> Security design and the automated tests that enforce it. Companion to
> `README.md`, `docs/ARCHITECTURE.md`, and `docs/IMPLEMENTATION_STATUS.md`.
> Last updated: 2026-10-08.

CRIX is itself a security product, so its own handling of credentials, sessions,
and data is held to the same honesty and rigor as the analysis it produces.

---

## 1. Threat model (what CRIX defends against)

- **Credential theft / reuse** against CRIX's own login.
- **Session theft / CSRF** against the dashboard.
- **Cross-user data access (IDOR)** — user A reading or mutating user B's data.
- **Secret leakage** — passwords, tokens, or API keys reaching logs, audit rows,
  or the GraphRAG layer.
- **Client-side tampering** — a client trying to inject or override authoritative
  risk/severity values.
- **Abuse / brute force** — repeated login or password-check calls.
- **Third-party password exposure** — the user's *own* passwords accidentally
  reaching the CRIX server.

Out of scope: host/OS compromise, a malicious database operator, and physical
attacks.

---

## 2. CRIX's own authentication

Design lives in `backend/app/security.py`, `routers/auth.py`, `deps.py`, and
`models.py`.

| Control | Implementation |
|---|---|
| Password hashing | **bcrypt** directly, cost `max(12, settings.bcrypt_rounds)`. `passlib` deliberately avoided (unmaintained on `bcrypt ≥ 4.1`). |
| Password policy | ≥ 10 chars, ≤ 72 bytes (bcrypt limit, rejected not silently truncated), common-password blocklist. |
| Access token | JWT (`HS256`) with `sub`, `type=access`, `iat`, `exp` (~15 min), `jti`. |
| Refresh token | Opaque `secrets.token_urlsafe(48)`; **only a hash is stored**. |
| Refresh cookie | `httpOnly`, `SameSite`, `secure` in production (see `_set_refresh_cookie`). |
| Rotation | Each refresh revokes the old token and issues a child, linking `replaced_by_id`. |
| Reuse detection | Presenting an already-revoked token → audit `refresh.reuse_detected` and **revoke all** of the user's tokens. |
| CSRF | Double-submit: the refresh token row stores a `csrf_token`; state-changing refresh/logout require the matching `X-CSRF-Token` header. The token is mirrored in a JS-readable `crix_csrf` cookie (path `/`) because the SPA keeps its copy only in memory — after a reload the client rebuilds the header from that cookie. The header itself remains mandatory. |
| 2FA | Optional TOTP, verified at login when `totp_enabled`. |
| Password reset | Single-use, short-expiry token (hash stored); dev outbox locally, configured email API/SMTP in prod. |
| User enumeration | Login always performs a hash comparison (dummy hash when the user is absent) so timing does not reveal existence, and returns a uniform error. |
| Session fixation | Logout revokes the refresh token and clears the cookie. |

Production guard (`config.assert_production_safe`): the app **refuses to start**
in production if `CRIX_JWT_SECRET` is still the dev placeholder or if CORS
contains a wildcard. The dev default secret triggers an `InsecureKeyLengthWarning`
from PyJWT — intentional signal to set a strong secret.

---

## 3. Authorization & IDOR

- All data-access endpoints depend on `get_current_user` (`deps.py`), which
  resolves the user from the bearer token.
- Every user-data table has a non-nullable `user_id` FK; every query filters by
  `current_user.id`.
- `test_security.py::test_idor_endpoint_matrix` proves user A cannot read or
  modify user B's accounts/events across the endpoint matrix; the end-to-end smoke
  test also asserts "cannot read other's account."

---

## 4. Plaintext passwords never leave the client

The password-breach feature (`frontend/src/lib/password.ts` +
`backend/app/routers/password_check.py`) uses **k-anonymity**:

1. The browser computes `SHA-1(password)`.
2. It sends **only the first 5 hex characters** to `GET /api/password/range/{prefix}`.
3. The server proxies the HIBP Pwned Passwords range and returns matching suffixes.
4. The browser matches locally; reuse is also compared locally.

Safeguards and tests:

- The `range` endpoint **rejects** a full 40-char hash and non-hex input.
- The password-check request schema exposes **no** hash/plaintext fields.
- `test_security.py::test_outgoing_requests_never_contain_plaintext_password`
  inspects outgoing request bodies and fails if plaintext appears.
- `frontend/src/lib/password.test.ts` (Vitest) asserts only the 5-char prefix
  leaves the client's network layer and that plaintext never reaches it.

This is separate from CRIX's own login credential (bcrypt), which never touches
the breach-check path.

---

## 5. Secrets, logs, and the GraphRAG context

- **Env-only secrets.** `config.py` loads everything from `CRIX_*` env vars;
  `.env` is git-ignored and `.env.example` is provided.
- **Audit redaction** (`audit.py`): a recursive redactor drops sensitive keys and
  scrubs bearer tokens and JWT-shaped strings before anything is written to
  `audit_logs`. Tests: `test_audit_redaction_removes_secrets`,
  `test_login_audit_has_no_token`.
- **GraphRAG sanitization** (`engine/graphrag.py::sanitize_context`): the only
  context GraphRAG may receive is an explicit whitelist of event *types*,
  correlation ids/severities, risk numbers, and graph-edge endpoints — raw
  message text, metadata, passwords, secrets, and tokens are dropped. Test:
  `test_graphrag_context_whitelist`; the graph/graphrag test also scans the
  serialized context for `password`, `token`, `secret`, `sha1`, `bearer`.

---

## 6. Client cannot override authoritative values

Correlation severity, risk score, band, attribution, and plans are **recomputed
server-side** in `engine/pipeline.py` from stored events. Tests:

- `test_client_cannot_inject_severity` — a client-supplied severity is ignored.
- `test_risk_is_recomputed_server_side` — the returned score is a function of the
  server's event set.
- `test_what_if_rejects_unknown_action` — the What-If endpoint rejects actions
  outside the known catalog.

---

## 7. Abuse resistance

- In-house **sliding-window rate limiter** (`rate_limit.py`), unit-testable with a
  fake clock and bounded memory.
- Login limited to `CRIX_LOGIN_RATE_LIMIT_PER_MINUTE` (default 5/min/IP);
  password-check limited to `CRIX_PASSWORD_CHECK_RATE_LIMIT_PER_MINUTE`
  (default 30/min). Tests: `test_login_rate_limited`,
  `test_password_check_rate_limited`.
- Client IP comes from the peer address; `X-Forwarded-For` is not trusted unless
  behind a known proxy (documented in `client_ip`).

---

## 8. CORS

Restrictive by default: explicit origins from `CRIX_CORS_ORIGINS`, credentials
allowed, methods/headers enumerated, **never a wildcard**. Tests:
`test_cors_not_wildcard`, `test_cors_allows_configured_origin`, and the production
guard rejecting `*`.

---

## 8b. Live account connections (OAuth)

Code: `backend/app/oauth/`, `backend/app/routers/oauth.py`,
`backend/app/token_crypto.py`. Tests: `backend/tests/test_propagation.py`.

| Invariant | How it is enforced | Test |
|---|---|---|
| No provider password is ever requested or stored | Only the authorization-code flow exists; there is no code path that accepts a provider password | design + `test_unconfigured_authorize_is_unavailable_not_silent` |
| CSRF on the callback | Single-use cryptographically random `state`, bound to the initiating user, 10-min TTL (`oauth/pkce.py`) | `take_pending` pops exactly once |
| Code interception resistant | PKCE S256; `code_verifier` never leaves the backend | `build_authorize_url` derives the challenge server-side |
| Tokens encrypted at rest | Fernet (`token_crypto.encrypt_token`); prod refuses to boot without `CRIX_TOKEN_ENCRYPTION_KEY` | `test_tokens_are_encrypted_at_rest`, `test_token_crypto_roundtrip` |
| Tokens never returned to the frontend | `/api/oauth/connections` exposes `token_available: boolean` only | `test_connections_endpoint_never_returns_tokens` |
| Tokens never logged | Token exchange logs **HTTP status only**, never the body; decrypt failure logs the exception *type* only | `exchange_code`, `token_crypto.decrypt_token` |
| Secrets never serialized to a client | Provider payload carries id, scopes, docs — never a secret | `test_provider_payload_has_no_secrets` |
| Unconfigured ≠ connected | Blank client id/secret → `NOT_CONFIGURED`; `authorize` returns 503 | `test_unconfigured_provider_reports_not_configured` |
| Connection ≠ capability | Capability matrix is curated and independent of connection state | `test_connection_does_not_imply_capability` |
| Nothing rendered as "safe" by absence | `UNAVAILABLE_THROUGH_PROVIDER` status, distinct from `CHECKED_SAFE` | `test_capabilities_mark_unavailable_not_safe` |
| Fixture connector cannot impersonate `REAL` | `source_mode` fixed to `FIXTURE`; disabled when `CRIX_ENV=production` | `test_fixture_connection_is_labeled_fixture` |
| No recovery edge is invented | Relationships must be explicitly `USER_CONFIRMED`; unknown types and self-edges rejected | `test_relationship_source_is_user_confirmed_and_weighted`, `test_relationship_rejects_unknown_type` |
| Simulation touches no real event | Scenario is computed in memory; event rows are unchanged | `test_simulate_does_not_mutate_real_events` |
| Cross-user connection access | All connection/relationship/simulate queries are scoped by `user_id` | `test_simulate_requires_owned_account`, IDOR matrix |

**Authorized-actions boundary.** CRIX performs no exploitation, no
authentication bypass, no session/cookie theft, no credential stuffing, no MFA
bypass, and no account-takeover testing. "Simulate Account Compromise" is a
defensive what-if that alters only in-memory analysis state.

**What OAuth does *not* prove.** A connection establishes an authorized
relationship with an account. It does not reveal MFA state, breach status,
security-checkup status, or connected-app lists — those APIs do not expose them
to third parties, so CRIX marks them `UNAVAILABLE_THROUGH_PROVIDER` and never
`SAFE`. It also does not prove that one account is a recovery route for
another; that edge only exists once the user confirms it.

---

## 9. Security checklist (spec §14) → tests

All items in `backend/tests/test_security.py`, plus the live-connection
invariants in `backend/tests/test_propagation.py`:

| # | Requirement | Test |
|---|---|---|
| 1 | Plaintext password never in an outgoing request | `test_outgoing_requests_never_contain_plaintext_password` |
| 2 | Range endpoint rejects full hash / non-hex | `test_range_endpoint_rejects_full_hash`, `test_range_endpoint_rejects_non_hex` |
| 3 | Password endpoint schema exposes no hash fields | `test_password_endpoint_schema_has_no_hash_fields` |
| 4 | IDOR — cross-user access blocked | `test_idor_endpoint_matrix` |
| 5 | Client cannot inject severity | `test_client_cannot_inject_severity` |
| 6 | Risk recomputed server-side | `test_risk_is_recomputed_server_side` |
| 7 | What-If rejects unknown actions | `test_what_if_rejects_unknown_action` |
| 8 | Secrets redacted from audit | `test_audit_redaction_removes_secrets` |
| 9 | Login audit contains no token | `test_login_audit_has_no_token` |
| 10 | GraphRAG context whitelist | `test_graphrag_context_whitelist` |
| 11 | Login rate limited | `test_login_rate_limited` |
| 12 | Password-check rate limited | `test_password_check_rate_limited` |
| 13 | CORS not wildcard | `test_cors_not_wildcard` |
| 14 | CORS allows configured origin | `test_cors_allows_configured_origin` |
| 15 | `.env` git-ignored, `.env.example` present | `test_env_example_present_and_env_gitignored` |
| 16 | Production requires a real secret | `test_production_requires_secret` |

---

## 10. Data-handling honesty

- Signal provenance is explicit: `REAL`, `SIMULATED`, or `UNAVAILABLE`, surfaced
  with badges in the UI and never conflated.
- Connection/relationship/scenario provenance is explicit via `source_mode`
  (`REAL` / `USER_PROVIDED` / `SIMULATED` / `FIXTURE` / `UNAVAILABLE`),
  rendered verbatim by `<SourceModeBadge>`; `FIXTURE` is never blurred into
  `REAL`.
- `SESSION_*` exposures are labeled **simulated exposure scenarios**; no real
  infostealer data is used.
- Provider capabilities the official API does not expose are shown as
  `UNAVAILABLE_THROUGH_PROVIDER`, never as "safe."
- Propagation obeys the same rule: an account with **no** recorded events is
  never scored as zero exposure. It is flagged `weakness_unknown` and scored at
  a documented neutral default, with the reason surfaced in the UI.
- The downstream exposure score ships a disclaimer: not a probability, not a
  prediction; wording is "elevated exposure *if* compromised."
- Curated tables (`provider_metadata`, `graph_relationships`, `knowledge_*`)
  carry `source` and (where applicable) `last_verified_at`.
- Evaluation metrics are written only by code that actually measured them; when
  absent, the UI shows **"not yet measured."**

---

## 11. Known limitations

- **Refresh tokens are stateless in the access layer:** revocation is enforced on
  the refresh path; a stolen *access* token remains valid until it expires (~15
  min). A production hardening step would maintain an access-token denylist.
- **In-memory rate limiter** is per-process; a multi-worker deployment should
  back it with Redis (documented, not implemented).
- **HIBP** email-breach checks return `UNAVAILABLE` without `CRIX_HIBP_API_KEY`.
- **OAuth providers report `NOT_CONFIGURED`** until the team registers its own
  Google / LinkedIn / Meta apps and supplies `CRIX_*_CLIENT_ID` / `_SECRET` plus
  the exact redirect URIs. The flow, exchange, encryption, and storage code is
  real and tested; only the credentials are absent. A clearly-labeled `FIXTURE`
  connector (dev-only) lets the propagation demo run without them.
- **In-flight OAuth `state`/PKCE is an in-process table** (`oauth/pkce.py`) —
  correct for the single-process dev/demo deployment; a multi-process
  deployment should move it to the DB or a shared cache (documented, not done).
- **Dev token-encryption fallback** derives a key from `CRIX_JWT_SECRET`.
  Production refuses to start without an explicit `CRIX_TOKEN_ENCRYPTION_KEY`.
- **Frontend dependencies** carry 15 advisories that all require breaking major
  upgrades (react-router-dom 7, tailwindcss 4, vitest 5); not applied. Run
  `npm audit` before any public deployment.
- No anti-automation (CAPTCHA) on register/login beyond rate limiting.
