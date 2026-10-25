# CRIX-SMB — Contextual Risk Intelligence for Small Businesses

CRIX-SMB is an organization-first cybersecurity risk and remediation platform
for small businesses. Employees create a CRIX account with their real work
email address and a CRIX-specific password. CRIX never requests or stores a
Gmail password, does not access employee inboxes, and has no OAuth integration
in its production product.

## What the application does

- Creates an organization on registration and assigns the creator the
  ORG_ADMIN role.
- Supports memberships, invitations, server-enforced RBAC, and tenant-scoped
  organization assets, dependencies, findings, correlations, tasks, history,
  and audit records.
- Normalizes security signals and computes a deterministic contextual risk
  score with exact Shapley attribution, a dependency graph, and remediation
  planning.
- Uses real email-breach intelligence only after email verification and an
  explicit employee opt-in. Results are cached; provider errors are
  unavailable/unknown, never safe.
- Uses HIBP Pwned Passwords k-anonymity for exposure checks. The browser sends
  only a five-character SHA-1 prefix for the password-hygiene tool; CRIX never
  stores plaintext passwords or complete lookup hashes.
- Delivers verification, reset, and invitation links through a configured
  server-side transactional email provider. The Render Free Blueprint uses
  Resend's HTTPS API; local development can use SMTP or an ignored outbox.

## Data honesty

Every signal is labeled by status and provenance. A failed, rate-limited, or
unconfigured provider becomes UNAVAILABLE, not CHECKED_SAFE. Simulated
scenarios remain explicitly SIMULATED; production startup rejects the legacy
fixture-connector switch and never runs the demo seeder.

## Local development

Prerequisites: Python 3.11+, Node 18+, and optionally Docker for local
PostgreSQL.

    python -m venv .venv
    .\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
    Copy-Item .env.example .env

    cd backend
    ..\.venv\Scripts\python.exe -m alembic upgrade head
    ..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload

In a second terminal:

    cd frontend
    npm install
    npm run dev

The local Vite proxy serves the API at /api. Do not use seed_demo.py against
production data; it is solely an explicitly invoked local demonstration script.

## Verification

    cd backend
    ..\.venv\Scripts\python.exe -m pytest

    cd ..\frontend
    npm.cmd run test
    npm.cmd run build

For the production architecture, environment-variable names, migration plan,
and hosted acceptance checklist, see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Deployment

The intended deployment split is Vercel (SPA), Render (FastAPI), Supabase
(PostgreSQL), and a transactional email provider. Render Free uses Resend's
HTTPS API because outbound SMTP ports are blocked. The repository includes
render.yaml and frontend/vercel.mjs, but a deployment is not considered live
until the public URLs have been tested end-to-end.
