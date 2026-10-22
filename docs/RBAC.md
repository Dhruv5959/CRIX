# CRIX RBAC — roles, scope and the admin-audit promise

CRIX is **organization-first**: every organization-scoped row belongs to exactly
one organization, and there is no personal or default tenant. Registration
creates a real organization and the registrant becomes its first `ORG_ADMIN`.

The role is resolved **server-side from the `memberships` table** on every
request (`app/deps.py::get_current_membership`). A client never sends an
`org_id` that is trusted, and a client cannot elevate its own role.

## Roles

| Role | Intent |
|---|---|
| `ORG_ADMIN` | Runs the company's CRIX workspace: assets, criticality, dependencies, invitations, org settings. |
| `MEMBER` | A colleague. Reads organization aggregates and manages their **own** member detail. |
| `VIEWER` | Read-only (e.g. an auditor or a manager who only wants dashboards). |

Verified in `tests/test_rbac.py` and `tests/test_admin_view_audit.py`.

## Role × action matrix

Legend: ✅ allowed · ⛔ `403` · 🔎 allowed **and** audit-logged · — no such route.

| Endpoint | ORG_ADMIN | MEMBER | VIEWER | Unauthenticated |
|---|---|---|---|---|
| `GET /api/org` | ✅ | ✅ | ✅ | `401` |
| `PATCH /api/org` | ✅ (audited) | ⛔ | ⛔ | `401` |
| `GET /api/members` (aggregates only) | ✅ | ✅ | ✅ | `401` |
| `GET /api/members/{id}` — own detail | ✅ | ✅ | ✅ | `401` |
| `GET /api/members/{id}` — someone else | 🔎 | ⛔ | ⛔ | `401` |
| `GET /api/org/admin-views` (my own audit trail) | ✅ | ✅ | ✅ | `401` |
| `GET /api/assets`, `GET /api/assets/{id}` | ✅ | ✅ | ✅ | `401` |
| `POST /api/assets` | ✅ (audited) | ⛔ | ⛔ | `401` |
| `PATCH /api/assets/{id}` | ✅ (audited) | ⛔ | ⛔ | `401` |
| `DELETE /api/assets/{id}` | ✅ (audited) | ⛔ | ⛔ | `401` |
| `GET /api/dependencies` | ✅ | ✅ | ✅ | `401` |
| `POST /api/dependencies` | ✅ (audited) | ⛔ | ⛔ | `401` |
| `DELETE /api/dependencies/{id}` | ✅ (audited) | ⛔ | ⛔ | `401` |
| `POST /api/invitations` | ✅ (audited) | ⛔ | ⛔ | `401` |
| `GET /api/invitations` | ✅ | ⛔ | ⛔ | `401` |
| `DELETE /api/invitations/{id}` | ✅ (audited) | ⛔ | ⛔ | `401` |
| `POST /api/invitations/accept` | public (token-authenticated) | — | — | uses the invite token |
| `GET /api/remediation/settings`, `GET /api/remediation/tasks`, `GET /api/remediation/tasks/{id}` | 🔎 | 🔎 | 🔎 | `401` |
| `PATCH /api/remediation/settings` (effort budget) | ✅ (audited) | ⛔ | ⛔ | `401` |
| `POST /api/remediation/tasks` | ✅ (audited) | ⛔ | ⛔ | `401` |
| `PATCH /api/remediation/tasks/{id}` (assign/effort/prereqs) | ✅ (audited) | ⛔ | ⛔ | `401` |
| `POST /api/remediation/tasks/{id}/complete` (attestation) | ✅ (audited) | ✅ (audited) | ⛔ | `401` |
| `POST /api/remediation/tasks/{id}/verify` | ✅ (audited) | ⛔ | ⛔ | `401` |
| `POST /api/remediation/tasks/{id}/reopen` | ✅ (audited) | ⛔ | ⛔ | `401` |
| `POST /api/remediation/plan` | ✅ (audited) | ✅ (audited) | ⛔ | `401` |

Every remediation **read** is audit-logged (`remediation.tasks_read` /
`task_read`) too, so task state — which drives decisions — has a trail of who
saw it. Verified in `tests/test_remediation_phase7.py` (RBAC + tenant
isolation + lifecycle audit set).

A signed-in user with **no active membership** gets `403` from every
organization-scoped route.

## Tenant isolation

Every organization query is filtered by the caller's `org_id`:

* An id from another organization is **indistinguishable from a missing one**
  (`404`), so existence is never leaked across tenants.
* Creating an asset with someone else's `owner_membership_id`, or a dependency
  whose endpoints live in another tenant, is rejected (`422` / `404`).
* `POST /api/dependencies` re-resolves **both** asset endpoints inside the
  caller's organization before writing, so correlation and the risk engine can
  never be handed a cross-tenant edge.

Verified in `tests/test_org_isolation.py`.

## The admin-audit promise (privacy boundary)

Member-level data is personal. CRIX therefore:

1. Shows admins **aggregates** in the member directory (`GET /api/members`:
   role, join date, count of owned assets — no findings, no scores).
2. Allows member-level detail (`GET /api/members/{id}`) only for the member
   themselves or an `ORG_ADMIN`.
3. Writes an `AdminViewAuditLog` row **every time** an admin opens another
   member's detail, including the admin identity, the subject, the action
   (`member_detail.viewed`), the resource (`membership:<id>`) and the source IP.
4. Exposes that trail **to the member**, via `GET /api/org/admin-views`
   ("who looked at my data").

Reading your own detail is never audited. No admin action is hidden from the
member it concerns.