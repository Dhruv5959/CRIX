# FEATURE GAP & IMPLEMENTATION PLAN — Semester 7 (Features C–F + readiness)

Written **before any implementation edits**, per §1 of the mandate. This file is the
scope record: if more files become necessary later, update the lists here first.

## 1. Audit findings (factual baseline, recorded 2026-10-25)

- Repo: `main`, clean working tree except an **intentionally preserved uncommitted
  edit** to `package.json` / `package-lock.json` (`@playwright/cli` `0.1.22` → `^0.1.22`).
  No resets performed.
- Latest commits at audit time: `db36428` (select popups), `78c38f0` (docs),
  `c24ba35` (Features A+B), `3e2d65e` (security fixes), `fa317c4` (registered email).
- Test status **before** this work: backend **451/451 passed** (~3.5 min run),
  frontend vitest **33/33 passed**, `tsc --noEmit` + production build clean,
  `scripts/smoke.py` 46 checks green against the running dev stack.
- Alembic chain is Postgres-compatible **by structural review** (dialect-aware
  column checks, `batch_alter_table` for FK-adds, no sqlite-only types; raw SQL
  limited to portable `UPDATE … (SELECT … LIMIT 1)` backfills). Chain: base
  `17855d545687` → … → head `e8f9a0b1c2d3`. **Not** executed against a real
  PostgreSQL here (no local server / psycopg not installed) — recorded as BLOCKED
  in the completion report rather than claimed.
- Secrets scan (git history, all 19 commits × 8 pattern categories, values never
  printed): **no committed secrets.** The only hit is `README.md` line 187, the
  intentional demo login documentation line — a documentation placeholder, not a
  credential. No baseline-secret stop condition triggers.
- OAuth remains frozen: `oauth_connectors_enabled=False` default; tests set a
  fixture connector only in-process. No Google/Gmail/LinkedIn/Instagram flows added.

### Feature A/B verification (no changes needed beyond existing tests)
- A (consent-gated XposedOrNot monitoring): consent + timestamp persisted
  (`users.breach_monitor_consent(+_at)`), first check on consent, 24h refresh
  window, login recheck is best-effort and never blocks, placeholder-domain
  warning on events, monitor panel in Breach tab. Sound.
- B (HIBP Pwned Passwords): SHA-1 computed transiently, only 5-char prefix sent,
  local suffix comparison, registration blocks on PWNED, login only records
  outcome, `UNAVAILABLE` never becomes safe, outbox/audit never logs tokens or
  hashes. Sound.
- One **defect found by audit against the larger mandate**: the real-accounts
  mandate requires ownership verification of a registered email (single-use,
  time-limited, hash-stored token) before consent-gated monitoring. `User.email_verified`
  exists, but **no email-verification flow exists** (no token table, no
  request/confirm endpoints; password-reset and invitation flows reuse the same
  SHA-256 hashing pattern). Gap → implemented in Phase 5 (below) with a new
  model + endpoints + a consent gate; no duplicate of invite/reset mechanics.

## 2. Feature gap table

| Feature | Exists today | Missing / to build |
|---|---|---|
| C. Phishing checker | `signals/phishing.py` TF-IDF classifier + AI-text detector, `POST /api/signals/phishing/analyze` + `/record`, events `PHISHING_MESSAGE_DETECTED`, `AI_GENERATED_MESSAGE_DETECTED`; URL extraction already inside classifier signals | No threat-intel provider layer (PhishTank/URLhaus), no `PHISHING_URL_DETECTED` event type, no risky-param/message redaction store pass, no provider timeout/429/JSON-failure handling in this module, no prompt-injection hardening tests, bounded-input test for oversized URLs |
| D. Domain/email posture | Nothing. `OrgAsset` can hold a DOMAIN asset but no DNS/TLS checks, no ownership challenge, no SSRF-safe fetch | Whole feature: DoH-based DNS checks (SPF, DMARC, optional-selector DKIM), TTL/HTTPS probe to **validated IPs only** (SNI to domain, redirects never followed), DNS TXT ownership challenge (hash-stored), `EMAIL_AUTH_WEAKNESS` / `TLS_POSTURE_WEAK` findings into SecurityEvents + one narrow correlation rule, per-org+domain rate limit |
| E. Repository secret scanner | Nothing (no zipfile/tarfile/secret-scan code anywhere) | Admit it: whole feature. zip-only ingestion (no extraction-to-disk; stream-validate entry names for traversal/symlinks, entry count, per-file + total size caps, decompression-ratio bomb check), pattern scanner (API keys, private keys, credential-style config values) with **redacted** evidence + sha256-8 fingerprint, findings as `SECRET_PATTERN_MATCHED` events bound to the repo asset, no history claims beyond what is scanned (working tree + `*.patch`/`*.diff` files if present), temp-file cleanup after success/failure |
| F. Access/permission audit | `Membership` RBAC, org/asset models, `signals/permissions.py` per-account app-permission audit, remediation tasks with verified states | No org-wide **asset access records** (member × asset × level), no removal/review history, no review-candidate detection (departed, stale, elevated), no RBAC-gated endpoints, no access→remediation wiring |

## 3. Planned implementation (file scope)

### Backend — new modules
- `backend/app/signals/url_intel.py` — URL extraction/normalization + query-param
  redaction + provider abstraction (PhishTank, optional key; URLhaus, opt-in with
  key; both `httpx` POST, strict timeouts, 429/timeout/invalid-JSON ⇒ UNAVAILABLE).
- `backend/app/signals/domain_posture.py` — DoH resolver + IP-range validation
  (SSRF), SPF/DMARC/DKIM TXT checks, HTTPS/TLS/HSTS probe to validated IPs,
  ownership challenge generation/verification (SHA-256-hashed token in
  `OrgAsset.metadata_json`), check result assembly.
- `backend/app/signals/secret_scan.py` — archive safety + pattern scanner.
- `backend/app/signals/access_audit.py` — candidate detection over access records.

### Backend — edited files
- `backend/app/config.py` — new bounded settings: phishtank/urlhaus toggles+keys+timeout,
  doh url/timeout, domain check limits, access review interval, verification TTLs.
- `backend/app/events.py` — add `PHISHING_URL_DETECTED`, `EMAIL_AUTH_WEAKNESS`,
  `TLS_POSTURE_WEAK`, `SECRET_PATTERN_MATCHED`, `ACCESS_REVIEW_NEEDED` (constants only).
- `backend/app/schemas.py` — extend `PhishingAnalyzeRequest` (optional `url`),
  `PhishingAnalyzeResponse` (provider report); new request/response models for
  domain registration/checks, repo-scan responses, access records.
- `backend/app/engine/risk.py` — only `EVENT_TO_FEATURE` additions:
  `PHISHING_URL_DETECTED→phishing`, `ACCESS_REVIEW_NEEDED→permissions`.
  Formula, weights, version untouched (regression-tested).
- `backend/app/engine/entities.py` — domain/asset canonical reuse only; no change
  expected.
- New routers `backend/app/routers/domains.py`, `backend/app/routers/repo_scan.py`,
  `backend/app/routers/access.py`, registered in `backend/app/main.py`.
- Edited: `backend/app/routers/phishing.py` (accept url, provider calls, redaction),
  `backend/app/routers/breach.py` (consent requires `email_verified` only when the
  verification flow is enabled — see Phase 5), `backend/app/routers/auth.py`
  (verify-email endpoints), `backend/app/models.py` (new tables below),
  `backend/app/data/correlation_rules.yaml` (one narrow rule + tests).
- Migration: one new Alembic revision adding
  `email_verification_tokens`, `asset_access_records`, `asset_access_record_history`
  (both new tables org-scoped, FK-CASCADE, Postgres-compatible types identical to
  neighboring tables). No downgrade of existing data; reversible via built-in
  `downgrade` dropping the three new tables.
- Tests: new `backend/tests/test_feature_c.py`, `test_feature_d.py`,
  `test_feature_e.py`, `test_feature_f.py`, `test_email_verification.py`;
  `backend/tests/conftest.py` gains a global `httpx.post` network block (mirrors
  the existing `httpx.get` block) + provider stub helpers.

### Frontend — edited files (no redesign; scope fixed now)
- `frontend/src/pages/SignalsPage.tsx` — Phishing tab: optional URL field next to
  the existing text box + provider report rows (reuses `Input`, `Badge`, cards).
- `frontend/src/lib/api.ts` + `frontend/src/lib/types.ts` — api methods `analyzeUrl…`
  / domain checks / repo scan / access audit + matching types (append-only).
- `frontend/src/pages/AssetsPage.tsx` — only if a domain/repo asset needs an
  existing asset picker upstream; expected **no change**.
- `frontend/src/pages/MembersPage.tsx` — access-records panel per member
  (admin) using existing card/table patterns.
- No route changes, no styling-system changes, no new pages.

## 4. Test plan (additions; existing 451 backend + 33 vitest must stay green)

C/D/E/F per the mandate's test lists: benign vs suspicious text; URL extraction/
normalization; known-phish response; no-match; conflicting sources; timeout, 429,
invalid JSON, network failure (>500 / ConnectError); oversized input; query-param
and message-content redaction; prompt-injection text cannot alter system behavior;
authz + tenant isolation; failed lookups never SAFE; provenance/status labels.
D: positive/negative SPF+DMARC, missing records, invalid domains, TXT ownership
(accept/reject/refresh), private/loopback/metadata IP blocking, redirect refusal,
timeouts, expiry flagging, response caps, duplicate findings, org isolation,
UNAVAILABLE-as-not-safe. E: pattern hits incl. private-key and token forms,
false-positive rejection, redaction of values, path traversal, symlink, bomb
(ratio), size/count limits, cleanup, unsupported format, org isolation.
F: record CRUD + tenant checks, invalid member/asset ids, departed/stale
candidates, role restrictions (member cannot read others' records: own only;
admin sees all), history preserved on removal, cross-org 404s. Pipeline:
correlation rule fires only with both predicates on one asset; risk regression
score checks unchanged for legacy event sets.

## 5. Real-accounts mandate piece kept from earlier session
Email verification (single-use 24h, SHA-256 hashed, invalidate on use/expiry,
rate-limited send, SMTP-only transport label in audit; `email_verified` gates
breach-consent). Deployed SMTP config documented in DEPLOYMENT.md.

## 6. Deployment prerequisites (details in docs/DEPLOYMENT.md written later)
- Frontend: Vercel, Vite build, production API base via existing convention.
- Backend: Render, single uvicorn worker, `CRIX_DATABASE_URL` server-side only,
  `assert_production_safe` items (JWT secret, token encryption key, SMTP host,
  explicit CORS, non-localhost public URL).
- DB: Supabase PostgreSQL; migrations run deliberately via Alembic; SQLite dev
  DB untouched. `VITE_*` never receives secrets.
- Provider env vars (names only): `CRIX_PHISHTANK_API_KEY` (optional),
  `CRIX_URLHAUS_API_KEY` (needed only if URLhaus enabled), DoH (no key),
  XON / HIBP Pwned keyless, domain checks no key, access audit no key,
  repo scanning no key. No optional provider blocks startup.
- Live Postgres/verification runs are **blocked** locally (no server) — reported
  honestly in the completion report.

## 7. Honesty invariants asserted by construction
No plaintext passwords/lookup hashes/secret values ever stored or logged; full
phishing bodies never stored (extracted indicators only); API errors never SAFE
(`UNAVAILABLE`/`UNAVAILABLE_THROUGH_PROVIDER` preserved by the normalizer);
provenance labels (`REAL`, `USER_ENTERED`-via-`USER_PROVIDED`, `SYNTHETIC`,
`FIXTURE`) visible on results; no numeric score invented inside any new module;
dedupe via `replace_module_events` (repeat scans don't inflate risk); tenant
isolation resolved server-side everywhere; untrusted submissions can never
change system instructions, evidence allowlists or org boundaries (deterministic
Python; no text is fed to any LLM).
