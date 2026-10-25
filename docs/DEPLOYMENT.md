# Deploying CRIX-SMB

This document describes the reviewed production configuration. It does **not**
claim that a public deployment has already been made.

CRIX-SMB uses its own CRIX email/password authentication. Supabase supplies
PostgreSQL only: do not enable Supabase Auth, expose a Supabase key to the
browser, or add Gmail inbox/OAuth access.

## Architecture

| Component           | Service          | Configuration                                               |
| ------------------- | ---------------- | ----------------------------------------------------------- |
| React/Vite SPA      | Vercel           | Project root: `frontend`                                  |
| FastAPI API         | Render           | Blueprint: `render.yaml`                                  |
| Persistent database | Supabase         | PostgreSQL session-pooler connection                        |
| Transactional mail  | Resend HTTPS API | API key held only in Render; sender domain must be verified |

The Vercel configuration proxies browser requests from `/api/*` to Render.
This makes the refresh cookie first-party to the public Vercel site. The
browser never receives a database URL, an email API credential, a HIBP key, or a
server JWT secret.

## Render API

`render.yaml` explicitly selects Render's `free` web-service plan. Omitting
`plan` defaults a new Blueprint web service to paid `0.5c-512mb` compute (an
existing service can retain its current plan). The Blueprint contains no
Render database, disk, or private service; Supabase PostgreSQL remains the
only application database.

The Free tier is not suitable for a production service that needs reliable
availability: Render advises against using Free web services for production.
They spin down after 15 minutes without inbound traffic, can take about a
minute to wake, have ephemeral filesystems and limited compute, and are
subject to monthly usage quotas. Excessive service-initiated traffic, including
external database/API requests, can also lead Render to suspend a Free service.
CRIX stores persistent application data in Supabase, not on the Render
filesystem. Configure sender-domain DNS in Resend and validate actual delivery
before relying on verification or reset email.

`render.yaml` installs the backend, applies the idempotent Alembic migration
chain, seeds **only curated reference records**, then starts one Uvicorn
process behind Render's proxy. It never runs `seed_demo.py`.

Use exactly one application instance while CRIX's rate limits remain
in-process. The start command enables Uvicorn proxy-header handling; CRIX uses
the proxy-normalized client address rather than parsing client-provided
`X-Forwarded-For` headers itself.

The service health check is `/api/ready`; it returns 503 if PostgreSQL cannot
execute `SELECT 1`. `/api/health` is the liveness/capability endpoint.

## Supabase PostgreSQL

1. Create a Supabase project in the dashboard.
2. In **Connect**, choose the **shared session pooler** connection string.
3. Add `?sslmode=require` (or a stronger SSL mode) if it is not already
   present.
4. Store the resulting URL only as Render's `CRIX_DATABASE_URL` Secret.
5. Deploy Render; its reviewed migration chain runs before the API starts.

CRIX does not use Supabase's Data API. The database credential belongs solely
to Render, so no frontend table exposure, RLS policy, or Supabase Auth setting
is needed for the CRIX API's authorization model.

## Vercel SPA

Create a Vercel project with `frontend` as its Root Directory. Before its
first production build, add the Render HTTPS origin as the Vercel **Config**
variable `CRIX_BACKEND_URL`. The tracked `frontend/vercel.mjs` refuses to
build without it and creates these routes:

| Browser path   | Destination       |
| -------------- | ----------------- |
| `/api/*`     | Render `/api/*` |
| all SPA routes | `/index.html`   |

After Vercel assigns the public URL, set that exact HTTPS origin in Render as
both `CRIX_PUBLIC_BASE_URL` and `CRIX_CORS_ORIGINS`. Redeploy Render, then
deploy Vercel. This ordering ensures emailed verification/reset links and CORS
have the final frontend origin.

## Render environment variable names

Set secrets privately in Render. Do not paste values into chat, source files,
or commit history.

| Name                              | Type                                                        |
| --------------------------------- | ----------------------------------------------------------- |
| `PYTHON_VERSION`                | Config: `3.13.7`                                          |
| `CRIX_ENV`                      | Config: `production`                                      |
| `CRIX_DATABASE_URL`             | Secret                                                      |
| `CRIX_JWT_SECRET`               | Secret                                                      |
| `CRIX_TOKEN_ENCRYPTION_KEY`     | Secret                                                      |
| `CRIX_CORS_ORIGINS`             | Config                                                      |
| `CRIX_PUBLIC_BASE_URL`          | Config                                                      |
| `CRIX_EMAIL_PROVIDER`           | Config: `resend`                                          |
| `CRIX_RESEND_API_KEY`           | Secret                                                      |
| `CRIX_EMAIL_FROM`               | Config                                                      |
| `CRIX_TRUST_PROXY_HEADERS`      | Config: `true`                                            |
| `CRIX_BREACH_EMAIL_PROVIDER`    | Config: `xposedornot` or `hibp`                         |
| `CRIX_HIBP_API_KEY`             | Optional Secret; required only for HIBP email-breach lookup |
| `CRIX_OAUTH_CONNECTORS_ENABLED` | Config: `false`                                           |
| `CRIX_ALLOW_FIXTURE_CONNECTORS` | Config: `false`                                           |

Optional rate/pool tuning names are documented in `.env.example`:
`CRIX_DATABASE_POOL_SIZE`, `CRIX_DATABASE_MAX_OVERFLOW`,
`CRIX_DATABASE_POOL_TIMEOUT_SECONDS`, and
`CRIX_DATABASE_POOL_RECYCLE_SECONDS`.

## Production checks

The app refuses production startup if the database is not
`postgresql+psycopg://` with TLS, if the CORS/public origins are not HTTPS, if
the selected email provider's credentials are incomplete, if proxy-header
support is disabled, or if legacy OAuth/fixture connectors are enabled.

Email breach monitoring is restricted to a verified employee's registered work
email. The employee must opt in before CRIX calls the provider; fresh results
are cached for 24 hours. Provider timeouts, rate limits, malformed responses,
or missing configuration produce an unavailable status, never a safe verdict.
Pwned Passwords checks use a padded HIBP range request and send only a
five-character SHA-1 prefix.

## Live acceptance checklist

After the service URLs are known, test the hosted system rather than assuming
deployment success:

1. `GET /api/health` and `GET /api/ready` through the public routes.
2. Register a real work address using a CRIX password.
3. Deliver and consume an email-verification link; confirm it is single-use.
4. Enable breach monitoring, verify the provider/status and a cached follow-up.
5. Request and complete a password reset.
6. Reload after login and confirm the secure refresh cookie keeps the session.
7. Confirm tenant isolation/RBAC with separate test organizations.
8. Confirm provider failure/rate-limit handling renders unavailable, not safe.

## Known limits

Render Free blocks outbound SMTP on ports 25, 465 and 587, so the Blueprint
uses Resend over HTTPS. Resend currently offers a free quota of 3,000 emails
per month with a 100-per-day limit; delivery has not been verified until a
real message is sent through the configured account and a verified sender
domain. XposedOrNot's free API quota is limited; CRIX throttles outbound
requests and does not silently fail over to a different provider. HIBP
email-breach lookup requires its own key, while Pwned Passwords range checks
do not. The current in-memory rate limiter requires a single Render
application instance. Supabase and Render plan limits, Resend sending limits,
and provider availability remain operational dependencies. Resend account/domain
setup and actual verification/reset delivery must be completed and tested
manually.
