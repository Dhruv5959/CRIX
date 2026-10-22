# CRIX-SMB Organization Asset Dependency Graph (Phase 6, §5)

This document specifies the organization-scoped company asset dependency
graph: the data model, relationship semantics, provenance labels, traversal
operations, security boundaries, and API contracts. It answers one question
and one question only:

> **If one company asset were compromised, which other assets might be
> exposed through documented relationships, along which paths, and why?**

The graph reports **potential exposure**. It never claims — and never
implies — that an attack or compromise occurred, has occurred, or is
occurring. Every API response carries that disclaimer verbatim.

---

## 1. Graph model

* **Nodes** are the organization's registered `OrgAsset` rows, keyed by the
  canonical asset id from `app.engine.entities.canonical_asset_id`. There is
  no name-based merging: two identifiers are the same node only when their
  canonical forms are exactly equal.
* **Edges** are the organization's `AssetDependency` rows, restricted to the
  documented relationship types below. CRIX never invents, infers, or
  guesses a relationship; a missing edge stays missing.
* The underlying structure is a **`networkx.MultiDiGraph`** — directed, with
  parallel edges permitted (one relationship id each). No other graph
  library is used.
* **Scope**: every query is filtered by `org_id` at the database layer. An
  asset or edge belonging to another organization can never enter the graph.

### Node attributes

| Attribute | Source |
|---|---|
| `asset_id` | `OrgAsset.asset_id` (canonical) |
| `asset_type` | `OrgAsset.asset_type` (validated company type) |
| `label` | `OrgAsset.label` (display name, never used for identity) |
| `criticality` | `OrgAsset.criticality` (1–5, admin-assigned) |
| `source_mode` | `OrgAsset.source_mode` |
| `provenance` | always `REGISTERED_ASSET` |

### Edge attributes

| Attribute | Source |
|---|---|
| `relationship_id` | `AssetDependency.id` |
| `declared_from` / `declared_to` | `AssetDependency.from_asset_id` / `to_asset_id` — the **declared** direction |
| `relationship_type` | canonical UPPERCASE form |
| `edge_source` | `AssetDependency.edge_source` (always `ADMIN_DECLARED` in this system) |
| `weight` / `note` / `declared_at` | the dependency row's own fields (evidence) |
| `provenance` | always `ADMIN_DECLARED` |

### Build statistics

`build_org_graph` reports honest counters instead of silently dropping
malformed data:

* `skipped_unsupported_type` — rows whose relationship type is not in the
  supported set (e.g. legacy or direct-ORM writes).
* `skipped_dangling_endpoint` — rows pointing at an asset id that is not
  registered in this organization (e.g. the asset was deleted).
* `duplicate_edges_skipped` — rows that deduplicate to an existing
  (canonical from, canonical to, canonical type) triple.

None of these rows is traversable; none is silently ignored.

---

## 2. Relationship types and exposure semantics

The exposure direction answers: **if the arc's source is compromised, what
could be exposed?** An arc `A → B` in the exposure graph means a compromise
of `A` *could* travel to `B` along the declared relationship.

| Type | Directed | Exposure | Meaning (declared direction: from → to) |
|---|---|---|---|
| `RESETS_PASSWORD` | yes | **forward** | The from-asset's password can be reset through the to-asset (e.g. mailbox → repository). Compromise of the from-asset may expose the to-asset. |
| `HAS_ACCESS_TO` | yes | **forward** | The from-asset has access to the to-asset. Compromise of the from-asset may expose the to-asset. |
| `DEPLOYS_TO` | yes | **forward** | The from-asset deploys to / pushes into the to-asset (e.g. CI → repository). |
| `DEPENDS_ON` | yes | **reverse** | The from-asset depends on the to-asset (e.g. repository → backup store). Compromise of the **to**-asset (the dependency) may expose the from-asset, so the exposure arc runs to → from. |
| `USES` | yes | **reverse** | The from-asset uses the to-asset (e.g. application → identity provider). Compromise of the to-asset may expose the from-asset. |
| `INTEGRATES_WITH` | no | **both** | A bidirectional integration. Exposure arcs run in both directions; the declared view stays one edge. |

### Canonicalization

`canonical_relationship_type` is case-insensitive and maps `-`/space to `_`;
unknown values return `None` and are **never coerced** into a supported type.
The API stores the canonical UPPERCASE form on write, so the engine matches
it exactly. A duplicate check compares canonical forms, so `uses` and `USES`
conflict honestly.

---

## 3. Provenance labels

Every node, edge, and derived path carries a provenance label:

| Label | Meaning | Produced by |
|---|---|---|
| `REGISTERED_ASSET` | The node is a registered company asset. | This system (Phase 2 asset registry) |
| `ADMIN_DECLARED` | The edge is a relationship an organization administrator declared explicitly. | This system (Phase 2 dependency API) |
| `DERIVED_PATH` | The path was derived by traversal over registered assets and declared relationships. | This system (Phase 6 engine) |
| `PROVIDER_DISCOVERED` | Documented for schema completeness. | **Not produced by this system.** |
| `MODEL_INFERRED` | Documented for schema completeness. | **Not produced by this system.** |

Evidence for each relationship step is the dependency row itself: its
`note` (empty → a `NOTE_MISSING` uncertainty flag, never dressed up), its
`declared_at` timestamp, and its `edge_source`. CRIX never fabricates
evidence for a relationship.

---

## 4. Traversal operations

All traversals are **directed along exposure arcs**, bounded, and
deterministic. Node visitation is once-only, so cyclic graphs terminate.
Path enumeration is simple-path only (no repeated nodes), so a cyclic graph
is never fully enumerated.

### Limits (`GRAPH_LIMITS`)

| Key | Default | Max | Notes |
|---|---|---|---|
| `default_depth` | 3 | — | Used when no depth is requested |
| `max_depth` | — | 5 | API rejects values above this (422) |
| `default_paths` | 10 | — | Used when no path count is requested |
| `max_paths` | — | 25 | API rejects values above this (422) |
| `max_nodes` | — | 1000 | Building beyond this raises `GraphTooLargeError` → API 413 |
| `max_expansions` | — | 20000 | Hard expansion budget per traversal |

Engine-side depth values are clamped into `[1, max_depth]`; path counts are
clamped into `[1, max_paths]`. Every response reports the depth/count that
was actually used plus a `truncated` flag when a bound was hit — the engine
never hides that results may be incomplete.

### Operations

| Op | Function | Question answered |
|---|---|---|
| A | `graph_payload(db, org_id)` | What does the organization's asset graph look like? Nodes, declared edges, stats, limits, provenance labels, disclaimer. |
| B | `direct_neighbors(graph, asset_id, direction)` | What is directly connected to this asset? `out` = what a compromise could expose; `in` = what could expose this asset; `both`. |
| C | `reachable(graph, asset_id, max_depth)` | Which assets are potentially reachable from this asset through exposure arcs, at what depth, and via which shortest documented path? |
| D | `paths_between(graph, source, target, max_depth, max_paths)` | Which documented exposure paths connect these two assets? Simple paths only, evidence-backed per step. |
| E | `blast_radius(graph, asset_id, max_depth)` | If this asset were compromised, which registered assets might be exposed, along which paths, and which are critical (criticality ≥ 4)? |
| F | `critical_exposure(graph, asset_id?, max_depth)` | With an asset: the critical subset of its blast radius. Without: for each critical asset, which assets have a documented exposure path *toward* it (reverse reachability, each path presented in true exposure direction). |
| G | (evidence in every response) | Why does each hop exist? Every step names its relationship id, type, exposure semantics, traversal condition, evidence (note, declared_at, edge_source), uncertainty flags, and provenance. |

### Determinism

Nodes, edges, neighbors, reachable sets, and paths are all sorted
(canonical asset id; paths by length then node sequence). Building the same
graph twice yields identical payloads. No traversal is randomized.

### Cycles, multiple paths, disconnected components

* A cycle (e.g. `A ↔ B`) terminates because each asset is visited once;
  paths through it are simple (no repeated node).
* Multiple paths between the same pair are all discovered up to the path
  limit, in deterministic order; hitting the limit sets `truncated`.
* A disconnected asset is a node with zero edges: present in the graph,
  empty neighbors/reachable/blast-radius results — absence of a relationship
  is never rendered as absence of the asset.

---

## 5. Security boundaries

* **Authentication**: every `/api/org/*` endpoint requires an active
  membership (`get_current_membership`); unauthenticated requests receive
  401.
* **Organization isolation**: every database query filters on the caller's
  `org_id`. An asset id belonging to another organization is
  indistinguishable from a missing one (generic 404, "Asset not found.") —
  the error never reveals another tenant's data. Both endpoints of any
  relationship must exist in the caller's organization before the edge is
  created.
* **No client-org bypass**: the organization is always resolved
  server-side from the caller's membership; no request parameter can select
  a different tenant.
* **No shared cache**: the engine holds no module-level cache; each call
  reads organization-scoped rows and builds a fresh graph (asserted by test).
* **Role enforcement**: relationship writes (create/update/delete) are
  ORG_ADMIN-only; every update is audited (`dependency.updated`).
* **Deleted / stale assets**: an edge whose endpoint is no longer a
  registered asset of the organization is skipped and counted
  (`skipped_dangling_endpoint`), never traversed.
* **Unsupported relationship types**: rejected at the API with an actionable
  422 listing the supported set; skipped and counted if present in legacy
  rows. Never coerced.
* **Traversal bounds**: depth, path count, node count, and expansion budget
  are all bounded; out-of-range API parameters are rejected with 422.

---

## 6. API contracts

All endpoints are org-scoped, require authentication, and include the
`disclaimer` field. Response shapes are typed in
`frontend/src/lib/types.ts` (`OrgGraphPayload`, `OrgGraphNeighbors`,
`OrgGraphPaths`, `OrgGraphBlastRadius`).

| Method & path | Purpose | Parameters | Notable responses |
|---|---|---|---|
| `GET /api/org/graph` | Operation A | — | 200 payload; 413 if the graph exceeds `max_nodes` |
| `GET /api/org/graph/neighbors` | Operation B | `asset_id` (required), `direction` (`in`/`out`/`both`, default `both`) | 200; 404 if the asset is not in this org |
| `GET /api/org/graph/paths` | Operation D | `source`, `target` (required), `max_depth` (1–5), `max_paths` (1–25) | 200 with evidence-backed steps; 404; 422 out of range |
| `GET /api/org/graph/blast-radius` | Operation E | `asset_id` (required), `max_depth` (1–5) | 200 with critical subset; 404; 422 |
| `GET /api/org/graph/critical-exposure` | Operation F | `asset_id` (optional), `max_depth` (1–5) | 200 scoped to asset or organization; 404; 422 |
| `GET /api/dependencies/{id}` | Relationship evidence | — | 200 (all roles); 404 org-scoped |
| `PATCH /api/dependencies/{id}` | Correct type/weight/note (ORG_ADMIN, audited) | partial body | 200; 403 non-admin; 404; 409 duplicate; 422 unsupported type |
| `POST /api/dependencies` | Declare a relationship (ORG_ADMIN, audited) | `from_asset_id`, `to_asset_id`, `relationship_type`, `weight`, `note` | 201; 403; 404 endpoints not both in this org; 409 duplicate; 422 unsupported type |

Endpoints cannot be rewritten by `PATCH`: moving a relationship to different
assets means deleting and re-declaring it, which stays explicit and
auditable.

### Relationship with the authoritative risk score

The graph **never** changes the risk score or its inputs (§5.9). There is no
new risk formula; the deterministic engine remains the only risk authority;
Shapley attribution still explains, never overrides. Compatibility tests
(#24, #25) assert that running every graph operation leaves the Phase 4
score, features, and criticality — and the Phase 5 attribution total —
bit-identical, and that `org_graph.py` imports neither the risk nor the
attribution engine.
