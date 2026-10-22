"""Phase 6 (§5): organization-scoped company asset dependency graph.

Every asset and relationship below is SYNTHETIC test data, registered or
declared exactly the way an organization administrator would (or inserted
directly via the ORM where the API would rightly reject it — e.g. a stale
edge pointing at a deleted asset, which the graph must tolerate honestly).

What is under test, in the spec's own words (§5.12):

1. graph construction from registered company assets
2. directed relationships
3. direct neighbors
4. reachability / bounded traversal
5. path retrieval
6. blast radius
7. critical assets reachable
8. cycles / repeated nodes
9. multiple paths
10. disconnected components
11. missing / stale relationships
12. duplicates
13. unsupported types
14. identity normalization
15. similar names do NOT become false relationships
16. cross-organization edge creation rejected
17. cross-organization queries return no data
18. org-aware cache isolation (there is no cache — asserted)
19. stable ordering / determinism
20. depth / path-count / resource limits
21. evidence and provenance preserved
22. API authentication and role checks
23. migration / persistence where applicable
24. Phase 4 risk-input compatibility
25. Phase 5 attribution compatibility

The graph documents POTENTIAL EXPOSURE along administrator-declared
relationships. No test — and no API response — ever claims a compromise.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.exc import IntegrityError

from app.engine import normalizer, org_graph, pipeline
from app.engine.org_graph import (
    CRITICAL_CRITICALITY,
    DISCLAIMER,
    GRAPH_LIMITS,
    PROVENANCE_LABELS,
    RELATIONSHIP_SEMANTICS,
    SUPPORTED_RELATIONSHIP_TYPES,
    canonical_relationship_type,
)
from app.models import AssetDependency, AuditLog, OrgAsset
from tests.conftest import login_headers, register_org_admin
from tests.helpers import ev, seed_org_for_user

APP = Path(__file__).resolve().parents[1] / "app"

# --------------------------------------------------------------------------- #
# SYNTHETIC fixtures
# --------------------------------------------------------------------------- #
DEMO_ASSETS = [
    ("alice@acme.example", "WORK_EMAIL", 4),
    ("github.com/acme/api", "CODE_REPOSITORY", 5),
    ("ci.acme.example", "CI_SYSTEM", 4),
    ("acme-backup", "CLOUD_STORAGE", 2),
]
# Declared direction on the left, exposure semantics on the right:
#   RESETS_PASSWORD (forward): alice -> repo
#   DEPLOYS_TO      (forward): ci    -> repo
#   DEPENDS_ON      (reverse): repo depends on backup, so backup -> repo
DEMO_EDGES = [
    ("alice@acme.example", "github.com/acme/api", "RESETS_PASSWORD"),
    ("ci.acme.example", "github.com/acme/api", "DEPLOYS_TO"),
    ("github.com/acme/api", "acme-backup", "DEPENDS_ON"),
]


def _asset(db, org_id, asset_id, asset_type="WORK_EMAIL", criticality=3):
    """Register a SYNTHETIC company asset exactly like the API stores one."""
    asset = OrgAsset(
        org_id=org_id,
        asset_id=asset_id,
        asset_type=asset_type,
        label=f"SYNTHETIC {asset_id}",
        criticality=criticality,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def _edge(db, org_id, from_id, to_id, rel_type, note="", weight=1.0):
    """Declare a SYNTHETIC relationship exactly like the API stores one."""
    edge = AssetDependency(
        org_id=org_id,
        from_asset_id=from_id,
        to_asset_id=to_id,
        relationship_type=rel_type,
        edge_source="ADMIN_DECLARED",
        weight=weight,
        note=note,
    )
    db.add(edge)
    db.commit()
    db.refresh(edge)
    return edge


def _demo_org(db, user_id="user-1"):
    """SYNTHETIC org with the canonical four assets and three relationships."""
    org_id = seed_org_for_user(db, user_id)
    for asset_id, asset_type, criticality in DEMO_ASSETS:
        _asset(db, org_id, asset_id, asset_type, criticality)
    for from_id, to_id, rel_type in DEMO_EDGES:
        _edge(db, org_id, from_id, to_id, rel_type)
    return org_id


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
            for alias in node.names:
                found.add(f"{node.module}.{alias.name}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
    return found


# --------------------------------------------------------------------------- #
# 1. Graph construction
# --------------------------------------------------------------------------- #
def test_graph_construction_uses_registered_assets_and_declared_edges_only(db_session):
    org_id = _demo_org(db_session)
    payload = org_graph.graph_payload(db_session, org_id)

    assert [n["asset_id"] for n in payload["nodes"]] == sorted(a for a, _, _ in DEMO_ASSETS)
    assert len(payload["edges"]) == 3
    assert payload["stats"]["assets"] == 4
    assert payload["stats"]["relationships"] == 3
    assert payload["stats"]["skipped_unsupported_type"] == 0
    assert payload["stats"]["skipped_dangling_endpoint"] == 0
    # Provenance is honest: registered nodes, administrator-declared edges.
    assert all(n["provenance"] == "REGISTERED_ASSET" for n in payload["nodes"])
    assert all(e["provenance"] == "ADMIN_DECLARED" for e in payload["edges"])
    assert all(e["edge_source"] == "ADMIN_DECLARED" for e in payload["edges"])
    # An asset with no relationships is still a node — absence is not deletion.
    assert "lonely@acme.example" not in {n["asset_id"] for n in payload["nodes"]}


# --------------------------------------------------------------------------- #
# 2. Directed relationships
# --------------------------------------------------------------------------- #
def test_directed_relationships_traverse_in_documented_exposure_direction(db_session):
    org_id = seed_org_for_user(db_session, "user-1")
    _asset(db_session, org_id, "app@acme.example", "BUSINESS_APP", 3)
    _asset(db_session, org_id, "idp.acme.example", "SAAS_DEPENDENCY", 4)
    _asset(db_session, org_id, "repo.acme.example", "CODE_REPOSITORY", 4)
    _asset(db_session, org_id, "storage.acme.example", "CLOUD_STORAGE", 2)
    # app USES idp -> reverse: compromise of the idp may expose the app.
    _edge(db_session, org_id, "app@acme.example", "idp.acme.example", "USES")
    # app DEPLOYS_TO repo -> forward: compromise of the app may expose the repo.
    _edge(db_session, org_id, "app@acme.example", "repo.acme.example", "DEPLOYS_TO")
    # repo INTEGRATES_WITH storage -> bidirectional.
    _edge(db_session, org_id, "repo.acme.example", "storage.acme.example", "INTEGRATES_WITH")

    graph, _ = org_graph.build_org_graph(db_session, org_id)

    # USES (reverse): the arc runs idp -> app, never app -> idp.
    assert ("idp.acme.example", "app@acme.example") in set(graph.edges())
    assert ("app@acme.example", "idp.acme.example") not in set(graph.edges())
    # DEPLOYS_TO (forward): the arc runs app -> repo.
    assert ("app@acme.example", "repo.acme.example") in set(graph.edges())
    # INTEGRATES_WITH: arcs in both directions.
    assert ("repo.acme.example", "storage.acme.example") in set(graph.edges())
    assert ("storage.acme.example", "repo.acme.example") in set(graph.edges())
    # Reachability follows the same semantics.
    forward = org_graph.reachable(graph, "app@acme.example")
    assert "repo.acme.example" in {e["asset_id"] for e in forward["reachable"]}
    assert "idp.acme.example" not in {e["asset_id"] for e in forward["reachable"]}
    reverse_from_idp = org_graph.reachable(graph, "idp.acme.example")
    assert "app@acme.example" in {e["asset_id"] for e in reverse_from_idp["reachable"]}


# --------------------------------------------------------------------------- #
# 3. Direct neighbors
# --------------------------------------------------------------------------- #
def test_direct_neighbors_respect_direction_and_semantics(db_session):
    org_id = _demo_org(db_session)
    graph, _ = org_graph.build_org_graph(db_session, org_id)

    out = org_graph.direct_neighbors(graph, "alice@acme.example", direction="out")
    assert [n["asset_id"] for n in out["neighbors"]] == ["github.com/acme/api"]
    assert out["neighbors"][0]["direction"] == "out"
    assert out["neighbors"][0]["relationship"]["relationship_type"] == "RESETS_PASSWORD"

    # What could expose the repository: all three exposure arcs point at it.
    incoming = org_graph.direct_neighbors(graph, "github.com/acme/api", direction="in")
    assert [n["asset_id"] for n in incoming["neighbors"]] == [
        "acme-backup",
        "alice@acme.example",
        "ci.acme.example",
    ]
    assert all(n["direction"] == "in" for n in incoming["neighbors"])

    both = org_graph.direct_neighbors(graph, "alice@acme.example", direction="both")
    assert [n["asset_id"] for n in both["neighbors"]] == ["github.com/acme/api"]

    # An unknown asset id is a generic 404, never a guess.
    with pytest.raises(LookupError):
        org_graph.direct_neighbors(graph, "nobody@acme.example")


# --------------------------------------------------------------------------- #
# 4. Reachability / bounded traversal
# --------------------------------------------------------------------------- #
def test_reachability_is_depth_bounded_and_reports_truncation(db_session):
    org_id = seed_org_for_user(db_session, "user-1")
    chain = [f"step{i}@acme.example" for i in range(1, 7)]
    for asset_id in chain:
        _asset(db_session, org_id, asset_id)
    for source, target in zip(chain, chain[1:]):
        # Forward type: the chain is traversable start to finish.
        _edge(db_session, org_id, source, target, "RESETS_PASSWORD")
    graph, _ = org_graph.build_org_graph(db_session, org_id)

    shallow = org_graph.reachable(graph, chain[0], max_depth=2)
    assert [e["asset_id"] for e in shallow["reachable"]] == chain[1:3]
    assert shallow["max_depth"] == 2
    # Nodes remain beyond the bound, and the engine says so rather than hiding it.
    assert shallow["truncated"] is True

    deep = org_graph.reachable(graph, chain[0], max_depth=GRAPH_LIMITS["max_depth"])
    assert [e["asset_id"] for e in deep["reachable"]] == chain[1:]
    assert deep["truncated"] is False


# --------------------------------------------------------------------------- #
# 5. Path retrieval
# --------------------------------------------------------------------------- #
def test_path_retrieval_returns_ordered_evidence_backed_steps(db_session):
    org_id = seed_org_for_user(db_session, "user-1")
    for asset_id, asset_type, criticality in DEMO_ASSETS:
        _asset(db_session, org_id, asset_id, asset_type, criticality)
    edge = _edge(
        db_session, org_id, "alice@acme.example", "github.com/acme/api",
        "RESETS_PASSWORD", note="SYNTHETIC: reset mailbox documented at onboarding",
    )
    graph, _ = org_graph.build_org_graph(db_session, org_id)

    result = org_graph.paths_between(graph, "alice@acme.example", "github.com/acme/api")
    assert result["count"] == 1
    path = result["paths"][0]
    assert path["assets"] == ["alice@acme.example", "github.com/acme/api"]
    assert path["length"] == 1
    assert path["provenance"] == "DERIVED_PATH"
    step = path["steps"][0]
    assert step["relationship_id"] == edge.id
    assert step["relationship_type"] == "RESETS_PASSWORD"
    assert step["traversed_from"] == "alice@acme.example"
    assert step["traversed_to"] == "github.com/acme/api"
    assert step["evidence"]["note"].startswith("SYNTHETIC")
    assert step["evidence"]["edge_source"] == "ADMIN_DECLARED"
    assert step["evidence"]["declared_at"] is not None
    assert step["uncertainty"] == []
    assert step["provenance"] == "ADMIN_DECLARED"

    # No path exists where no relationship was declared.
    none = org_graph.paths_between(graph, "alice@acme.example", "ci.acme.example")
    assert none["count"] == 0
    assert none["paths"] == []


# --------------------------------------------------------------------------- #
# 6. Blast radius
# --------------------------------------------------------------------------- #
def test_blast_radius_lists_potential_exposure_not_compromise(db_session):
    org_id = _demo_org(db_session)
    graph, _ = org_graph.build_org_graph(db_session, org_id)

    radius = org_graph.blast_radius(graph, "alice@acme.example")
    assert [e["asset_id"] for e in radius["potential_exposure"]] == ["github.com/acme/api"]
    assert radius["count"] == 1
    assert radius["critical_count"] == 1
    assert radius["critical_assets"][0]["asset_id"] == "github.com/acme/api"
    # The framing is potential exposure, and it says so.
    assert "not evidence" in radius["disclaimer"]
    assert radius["disclaimer"] == DISCLAIMER
    # No entry ever labels a reachable asset as breached or compromised.
    for entry in radius["potential_exposure"]:
        assert not any(
            key in entry for key in ("breached", "hacked", "compromised", "attacked")
        )

    # The backup has no outgoing exposure of its own beyond the repository.
    backup_radius = org_graph.blast_radius(graph, "acme-backup")
    assert [e["asset_id"] for e in backup_radius["potential_exposure"]] == [
        "github.com/acme/api"
    ]


# --------------------------------------------------------------------------- #
# 7. Critical assets reachable
# --------------------------------------------------------------------------- #
def test_critical_assets_reachable_through_documented_paths(db_session):
    org_id = _demo_org(db_session)
    graph, _ = org_graph.build_org_graph(db_session, org_id)

    # Organization-wide: which critical assets can exposures travel toward?
    org_view = org_graph.critical_exposure(graph)
    assert org_view["scope"] == "organization"
    by_id = {e["asset_id"]: e for e in org_view["critical_assets"]}
    assert set(by_id) == {
        "alice@acme.example",
        "github.com/acme/api",
        "ci.acme.example",
    }  # criticality >= 4; the backup (2) is excluded
    assert all(
        e["criticality"] >= CRITICAL_CRITICALITY for e in org_view["critical_assets"]
    )
    repo = by_id["github.com/acme/api"]
    assert repo["reachable_from_count"] == 3
    assert {e["asset_id"] for e in repo["reachable_from"]} == {
        "alice@acme.example",
        "ci.acme.example",
        "acme-backup",
    }
    # Paths read in the direction exposure would actually travel.
    first_step = repo["reachable_from"][0]["exposure_path"][0]
    assert first_step["traversed_to"] == "github.com/acme/api"
    assert first_step["traversed_from"] != "github.com/acme.example"

    # Asset-scoped: from alice, the critical subset of her potential blast radius.
    asset_view = org_graph.critical_exposure(graph, asset_id="alice@acme.example")
    assert asset_view["scope"] == "asset"
    assert [e["asset_id"] for e in asset_view["critical_assets"]] == [
        "github.com/acme/api"
    ]


# --------------------------------------------------------------------------- #
# 8. Cycles / repeated nodes
# --------------------------------------------------------------------------- #
def test_cycles_and_self_loops_terminate_with_simple_paths_only(db_session):
    org_id = seed_org_for_user(db_session, "user-1")
    for asset_id in ("a@acme.example", "b@acme.example", "c@acme.example"):
        _asset(db_session, org_id, asset_id)
    # A <-> B (bidirectional), B -> C, C -> A: a three-node cycle.
    _edge(db_session, org_id, "a@acme.example", "b@acme.example", "INTEGRATES_WITH")
    _edge(db_session, org_id, "b@acme.example", "c@acme.example", "RESETS_PASSWORD")
    _edge(db_session, org_id, "c@acme.example", "a@acme.example", "RESETS_PASSWORD")
    # A self-loop inserted directly (the API rejects from == to by design).
    _edge(db_session, org_id, "a@acme.example", "a@acme.example", "USES")
    graph, _ = org_graph.build_org_graph(db_session, org_id)

    # Termination and visited-set semantics: each asset appears once.
    reach = org_graph.reachable(graph, "a@acme.example", max_depth=GRAPH_LIMITS["max_depth"])
    reached = [e["asset_id"] for e in reach["reachable"]]
    assert reached == ["b@acme.example", "c@acme.example"]
    assert len(reached) == len(set(reached))
    assert reach["truncated"] is False

    # Simple paths only: the cycle never yields a path that repeats a node.
    result = org_graph.paths_between(
        graph, "a@acme.example", "c@acme.example",
        max_depth=GRAPH_LIMITS["max_depth"], max_paths=GRAPH_LIMITS["max_paths"],
    )
    assert result["count"] >= 1
    for path in result["paths"]:
        assert len(path["assets"]) == len(set(path["assets"])), path["assets"]
    # The direct chain a->b->c exists; the longer a->b->a... loop is excluded.
    assert ["a@acme.example", "b@acme.example", "c@acme.example"] in [
        p["assets"] for p in result["paths"]
    ]


# --------------------------------------------------------------------------- #
# 9. Multiple paths
# --------------------------------------------------------------------------- #
def test_multiple_paths_between_the_same_two_assets(db_session):
    org_id = seed_org_for_user(db_session, "user-1")
    for asset_id in (
        "src@acme.example", "mid1@acme.example", "mid2@acme.example", "dst@acme.example"
    ):
        _asset(db_session, org_id, asset_id)
    _edge(db_session, org_id, "src@acme.example", "mid1@acme.example", "HAS_ACCESS_TO")
    _edge(db_session, org_id, "src@acme.example", "mid2@acme.example", "HAS_ACCESS_TO")
    _edge(db_session, org_id, "mid1@acme.example", "dst@acme.example", "HAS_ACCESS_TO")
    _edge(db_session, org_id, "mid2@acme.example", "dst@acme.example", "HAS_ACCESS_TO")
    graph, _ = org_graph.build_org_graph(db_session, org_id)

    result = org_graph.paths_between(graph, "src@acme.example", "dst@acme.example")
    assert result["count"] == 2
    assert [p["assets"] for p in result["paths"]] == [
        ["src@acme.example", "mid1@acme.example", "dst@acme.example"],
        ["src@acme.example", "mid2@acme.example", "dst@acme.example"],
    ]
    assert result["truncated"] is False

    # Capping the count is honoured and disclosed.
    capped = org_graph.paths_between(
        graph, "src@acme.example", "dst@acme.example", max_paths=1
    )
    assert capped["count"] == 1
    assert capped["truncated"] is True


# --------------------------------------------------------------------------- #
# 10. Disconnected components
# --------------------------------------------------------------------------- #
def test_disconnected_assets_have_empty_but_valid_results(db_session):
    org_id = seed_org_for_user(db_session, "user-1")
    _asset(db_session, org_id, "island@acme.example")
    _asset(db_session, org_id, "main@acme.example")
    _asset(db_session, org_id, "other@acme.example")
    _edge(db_session, org_id, "main@acme.example", "other@acme.example", "HAS_ACCESS_TO")
    graph, _ = org_graph.build_org_graph(db_session, org_id)

    # The isolated asset is a node with no edges — present, not missing.
    assert "island@acme.example" in graph.nodes
    assert org_graph.direct_neighbors(graph, "island@acme.example")["count"] == 0
    assert org_graph.reachable(graph, "island@acme.example")["count"] == 0
    assert org_graph.blast_radius(graph, "island@acme.example")["count"] == 0
    # The disconnected component is simply not on any path between the other two.
    assert org_graph.paths_between(graph, "island@acme.example", "main@acme.example")["count"] == 0
    assert org_graph.paths_between(graph, "main@acme.example", "island@acme.example")["count"] == 0
    assert org_graph.paths_between(graph, "main@acme.example", "other@acme.example")["count"] == 1


# --------------------------------------------------------------------------- #
# 11. Missing / stale relationships
# --------------------------------------------------------------------------- #
def test_missing_or_stale_relationships_are_skipped_and_counted(db_session):
    org_id = seed_org_for_user(db_session, "user-1")
    _asset(db_session, org_id, "live@acme.example")
    _asset(db_session, org_id, "repo.acme.example")
    # A relationship whose endpoint was deleted (or never registered): the
    # dependency row has no foreign key, so it survives as a dangling pointer.
    _edge(db_session, org_id, "live@acme.example", "ghost@acme.example", "HAS_ACCESS_TO")

    payload = org_graph.graph_payload(db_session, org_id)
    assert payload["stats"]["skipped_dangling_endpoint"] == 1
    assert payload["edges"] == []  # never traversable, never guessed around
    assert [n["asset_id"] for n in payload["nodes"]] == ["live@acme.example", "repo.acme.example"]

    graph, _ = org_graph.build_org_graph(db_session, org_id)
    assert org_graph.reachable(graph, "live@acme.example")["count"] == 0


def test_deleting_an_asset_leaves_a_stale_edge_the_graph_skips(client, db_session):
    admin = register_org_admin(client, "admin@stale.example.com", org_name="Stale Co")
    for asset in (
        {"asset_id": "a@stale.example.com", "asset_type": "WORK_EMAIL", "label": "A"},
        {"asset_id": "b@stale.example.com", "asset_type": "WORK_EMAIL", "label": "B"},
    ):
        assert client.post("/api/assets", headers=admin, json=asset).status_code == 201
    assert client.post(
        "/api/dependencies", headers=admin,
        json={"from_asset_id": "a@stale.example.com", "to_asset_id": "b@stale.example.com",
              "relationship_type": "HAS_ACCESS_TO"},
    ).status_code == 201

    assert client.delete("/api/assets/b@stale.example.com", headers=admin).status_code == 204

    payload = client.get("/api/org/graph", headers=admin).json()
    assert payload["stats"]["skipped_dangling_endpoint"] == 1
    assert payload["edges"] == []
    radius = client.get(
        "/api/org/graph/blast-radius?asset_id=a@stale.example.com", headers=admin
    ).json()
    assert radius["count"] == 0


# --------------------------------------------------------------------------- #
# 12. Duplicates
# --------------------------------------------------------------------------- #
def test_duplicate_relationships_are_deduplicated_and_rejected(db_session):
    org_id = seed_org_for_user(db_session, "user-1")
    _asset(db_session, org_id, "x@acme.example")
    _asset(db_session, org_id, "y@acme.example")
    _edge(db_session, org_id, "x@acme.example", "y@acme.example", "USES")
    # A case-variant duplicate inserted past the API (the unique constraint
    # compares raw strings, so "uses" slips in beside "USES").
    _edge(db_session, org_id, "x@acme.example", "y@acme.example", "uses")

    graph, stats = org_graph.build_org_graph(db_session, org_id)
    assert stats["relationships"] == 1
    assert stats["duplicate_edges_skipped"] == 1
    # Only one exposure arc exists, so reachability is not double-counted.
    assert org_graph.reachable(graph, "y@acme.example")["count"] == 1

    # The database refuses an exact duplicate outright.
    db_session.add(AssetDependency(
        org_id=org_id, from_asset_id="x@acme.example", to_asset_id="y@acme.example",
        relationship_type="USES", edge_source="ADMIN_DECLARED",
    ))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_api_rejects_duplicate_and_case_variant_relationships(client):
    admin = register_org_admin(client, "admin@dup.example.com", org_name="Dup Co")
    for asset in (
        {"asset_id": "one@dup.example.com", "asset_type": "WORK_EMAIL", "label": "One"},
        {"asset_id": "two@dup.example.com", "asset_type": "WORK_EMAIL", "label": "Two"},
    ):
        assert client.post("/api/assets", headers=admin, json=asset).status_code == 201

    first = client.post(
        "/api/dependencies", headers=admin,
        json={"from_asset_id": "one@dup.example.com", "to_asset_id": "two@dup.example.com",
              "relationship_type": "uses"},
    )
    assert first.status_code == 201
    # Stored in canonical form so the graph engine matches it exactly.
    assert first.json()["relationship_type"] == "USES"

    exact = client.post(
        "/api/dependencies", headers=admin,
        json={"from_asset_id": "one@dup.example.com", "to_asset_id": "two@dup.example.com",
              "relationship_type": "USES"},
    )
    assert exact.status_code == 409
    case_variant = client.post(
        "/api/dependencies", headers=admin,
        json={"from_asset_id": "one@dup.example.com", "to_asset_id": "two@dup.example.com",
              "relationship_type": "uses"},
    )
    assert case_variant.status_code == 409


# --------------------------------------------------------------------------- #
# 13. Unsupported types
# --------------------------------------------------------------------------- #
def test_unsupported_relationship_types_are_rejected_and_never_traversed(db_session):
    org_id = seed_org_for_user(db_session, "user-1")
    _asset(db_session, org_id, "p@acme.example")
    _asset(db_session, org_id, "q@acme.example")
    # An unsupported type inserted past the API (legacy or direct write).
    _edge(db_session, org_id, "p@acme.example", "q@acme.example", "MYSTERY_TYPE")

    payload = org_graph.graph_payload(db_session, org_id)
    assert payload["stats"]["skipped_unsupported_type"] == 1
    assert payload["edges"] == []
    graph, _ = org_graph.build_org_graph(db_session, org_id)
    assert org_graph.reachable(graph, "p@acme.example")["count"] == 0

    # The canonicaliser never coerces an unknown type into a supported one.
    assert canonical_relationship_type("mystery_type") is None
    assert canonical_relationship_type("depends_on") == "DEPENDS_ON"
    assert canonical_relationship_type("  integrates-with ") == "INTEGRATES_WITH"
    assert canonical_relationship_type("") is None
    assert canonical_relationship_type(None) is None


def test_api_rejects_unsupported_relationship_types_with_actionable_detail(client):
    admin = register_org_admin(client, "admin@badtype.example.com", org_name="BadType Co")
    for asset in (
        {"asset_id": "m@badtype.example.com", "asset_type": "WORK_EMAIL", "label": "M"},
        {"asset_id": "n@badtype.example.com", "asset_type": "WORK_EMAIL", "label": "N"},
    ):
        assert client.post("/api/assets", headers=admin, json=asset).status_code == 201

    response = client.post(
        "/api/dependencies", headers=admin,
        json={"from_asset_id": "m@badtype.example.com", "to_asset_id": "n@badtype.example.com",
              "relationship_type": "totally_made_up"},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert "Unsupported relationship_type" in detail
    # Actionable: the accepted set is named, and nothing was stored.
    for supported in SUPPORTED_RELATIONSHIP_TYPES:
        assert supported in detail
    assert client.get("/api/dependencies", headers=admin).json() == []


# --------------------------------------------------------------------------- #
# 14. Identity normalization
# --------------------------------------------------------------------------- #
def test_identity_normalization_maps_url_variants_to_one_node(client, db_session):
    admin = register_org_admin(client, "admin@ident.example.com", org_name="Ident Co")
    # Register with a full URL; the API stores the canonical form.
    created = client.post(
        "/api/assets", headers=admin,
        json={"asset_id": "https://GitHub.com/acme/api/", "asset_type": "CODE_REPOSITORY",
              "label": "API repo", "criticality": 5},
    )
    assert created.status_code == 201
    assert created.json()["asset_id"] == "github.com/acme/api"
    assert client.post(
        "/api/assets", headers=admin,
        json={"asset_id": "dev@ident.example.com", "asset_type": "WORK_EMAIL", "label": "Dev"},
    ).status_code == 201

    # Declare the relationship using a different variant of the same identity.
    declared = client.post(
        "/api/dependencies", headers=admin,
        json={"from_asset_id": "dev@ident.example.com",
              "to_asset_id": "HTTPS://github.com/acme/api.git",
              "relationship_type": "RESETS_PASSWORD"},
    )
    assert declared.status_code == 201
    assert declared.json()["to_asset_id"] == "github.com/acme/api"

    payload = client.get("/api/org/graph", headers=admin).json()
    assert [n["asset_id"] for n in payload["nodes"]] == [
        "dev@ident.example.com", "github.com/acme/api",
    ]
    assert len(payload["edges"]) == 1
    # A query using the variant form resolves to the same single node.
    neighbors = client.get(
        "/api/org/graph/neighbors?asset_id=https://github.com/acme/api", headers=admin
    )
    assert neighbors.status_code == 200
    assert neighbors.json()["asset_id"] == "github.com/acme/api"
    assert [n["asset_id"] for n in neighbors.json()["neighbors"]] == ["dev@ident.example.com"]


# --------------------------------------------------------------------------- #
# 15. Similar names are NOT relationships
# --------------------------------------------------------------------------- #
def test_similar_names_never_create_false_relationships(db_session):
    org_id = seed_org_for_user(db_session, "user-1")
    # Three deliberately similar identifiers, registered as separate assets.
    _asset(db_session, org_id, "github.com/acme/api", "CODE_REPOSITORY", 5)
    _asset(db_session, org_id, "github.com/acme/api-server", "CODE_REPOSITORY", 4)
    _asset(db_session, org_id, "alice@gmail.com", "WORK_EMAIL", 3)
    _asset(db_session, org_id, "gmail.com", "DOMAIN", 3)

    graph, stats = org_graph.build_org_graph(db_session, org_id)
    # No edges exist: similarity never invents a relationship.
    assert stats["relationships"] == 0
    assert graph.number_of_edges() == 0
    assert set(graph.nodes) == {
        "github.com/acme/api",
        "github.com/acme/api-server",
        "alice@gmail.com",
        "gmail.com",
    }
    # And the near-miss asset is not a neighbor of its near-name.
    neighbors = org_graph.direct_neighbors(graph, "github.com/acme/api")
    assert neighbors["count"] == 0
    assert org_graph.reachable(graph, "alice@gmail.com")["count"] == 0


# --------------------------------------------------------------------------- #
# 16. Cross-organization edge creation is rejected
# --------------------------------------------------------------------------- #
def test_cross_organization_edge_creation_is_rejected(client, db_session):
    org_a = register_org_admin(client, "admin-a@xorg.example.com", org_name="Org A")
    org_b = register_org_admin(client, "admin-b@xorg.example.com", org_name="Org B")
    assert client.post(
        "/api/assets", headers=org_a,
        json={"asset_id": "asset-a@xorg.example.com", "asset_type": "WORK_EMAIL",
              "label": "Org A asset"},
    ).status_code == 201
    assert client.post(
        "/api/assets", headers=org_b,
        json={"asset_id": "asset-b@xorg.example.com", "asset_type": "WORK_EMAIL",
              "label": "Org B asset"},
    ).status_code == 201

    # Org B cannot declare a relationship touching Org A's asset.
    crossed = client.post(
        "/api/dependencies", headers=org_b,
        json={"from_asset_id": "asset-b@xorg.example.com",
              "to_asset_id": "asset-a@xorg.example.com", "relationship_type": "USES"},
    )
    assert crossed.status_code == 404
    assert crossed.json()["detail"] == "Asset not found."
    # The error reveals nothing about Org A existing at all.
    assert "Org A" not in crossed.text and "xorg" not in crossed.json()["detail"]

    # No edge was created in either organization.
    assert client.get("/api/dependencies", headers=org_a).json() == []
    assert client.get("/api/dependencies", headers=org_b).json() == []


# --------------------------------------------------------------------------- #
# 17. Cross-organization queries return no data
# --------------------------------------------------------------------------- #
def test_cross_organization_graph_queries_return_no_data(client, db_session):
    org_a = register_org_admin(client, "admin-a2@xorg2.example.com", org_name="Org A2")
    org_b = register_org_admin(client, "admin-b2@xorg2.example.com", org_name="Org B2")
    for headers, prefix in ((org_a, "a"), (org_b, "b")):
        for asset in (
            {"asset_id": f"{prefix}1@xorg2.example.com", "asset_type": "WORK_EMAIL",
             "label": f"{prefix}1"},
            {"asset_id": f"{prefix}2@xorg2.example.com", "asset_type": "WORK_EMAIL",
             "label": f"{prefix}2"},
        ):
            assert client.post("/api/assets", headers=headers, json=asset).status_code == 201
        assert client.post(
            "/api/dependencies", headers=headers,
            json={"from_asset_id": f"{prefix}1@xorg2.example.com",
                  "to_asset_id": f"{prefix}2@xorg2.example.com",
                  "relationship_type": "HAS_ACCESS_TO"},
        ).status_code == 201

    # Org B's graph contains only Org B's data.
    payload_b = client.get("/api/org/graph", headers=org_b).json()
    assert [n["asset_id"] for n in payload_b["nodes"]] == [
        "b1@xorg2.example.com", "b2@xorg2.example.com",
    ]
    assert len(payload_b["edges"]) == 1
    assert "a1@xorg2.example.com" not in str(payload_b)

    # Org A's asset ids are indistinguishable from missing ones for Org B.
    for path in (
        "/api/org/graph/neighbors?asset_id=a1@xorg2.example.com",
        "/api/org/graph/blast-radius?asset_id=a1@xorg2.example.com",
        "/api/org/graph/critical-exposure?asset_id=a1@xorg2.example.com",
        "/api/org/graph/paths?source=a1@xorg2.example.com&target=b1@xorg2.example.com",
        "/api/org/graph/paths?source=b1@xorg2.example.com&target=a1@xorg2.example.com",
    ):
        response = client.get(path, headers=org_b)
        assert response.status_code == 404, path
        assert response.json()["detail"] == "Asset not found."


# --------------------------------------------------------------------------- #
# 18. Org-aware isolation (there is no cache — asserted, not assumed)
# --------------------------------------------------------------------------- #
def test_graph_queries_are_org_isolated_without_a_shared_cache(db_session):
    # The engine module defines no cache structure: every call reads
    # organization-scoped rows and builds a fresh graph.
    tree = ast.parse((APP / "engine" / "org_graph.py").read_text(encoding="utf-8"))
    module_assignments = [
        target.id
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    ]
    assert not [name for name in module_assignments if "cache" in name.lower()]

    org_one = seed_org_for_user(db_session, "user-1")
    org_two = seed_org_for_user(db_session, "user-2", org_name="Second Co")
    _asset(db_session, org_one, "one@iso.example.com")
    _asset(db_session, org_one, "one-backup@iso.example.com")
    _edge(db_session, org_one, "one@iso.example.com", "one-backup@iso.example.com", "USES")
    _asset(db_session, org_two, "two@iso.example.com")

    # Interleaved builds never leak structure across organizations.
    graph_one = org_graph.build_org_graph(db_session, org_one)[0]
    graph_two = org_graph.build_org_graph(db_session, org_two)[0]
    again_one = org_graph.build_org_graph(db_session, org_one)[0]
    assert set(graph_one.nodes) == {"one@iso.example.com", "one-backup@iso.example.com"}
    assert set(graph_two.nodes) == {"two@iso.example.com"}
    assert org_graph.reachable(graph_two, "two@iso.example.com")["count"] == 0
    # Rebuilding org one is unaffected by the interleaved org-two build.
    assert set(again_one.nodes) == set(graph_one.nodes)
    assert set(again_one.edges()) == set(graph_one.edges())


# --------------------------------------------------------------------------- #
# 19. Stable ordering / determinism
# --------------------------------------------------------------------------- #
def test_ordering_is_stable_and_deterministic(db_session):
    org_id = seed_org_for_user(db_session, "user-1")
    for asset_id in (
        "z@acme.example", "m@acme.example", "a@acme.example",
        "dst@acme.example", "alt@acme.example",
    ):
        _asset(db_session, org_id, asset_id)
    # Inserted in deliberately scrambled order.
    _edge(db_session, org_id, "z@acme.example", "dst@acme.example", "HAS_ACCESS_TO")
    _edge(db_session, org_id, "m@acme.example", "dst@acme.example", "HAS_ACCESS_TO")
    _edge(db_session, org_id, "a@acme.example", "alt@acme.example", "USES")

    first = org_graph.graph_payload(db_session, org_id)
    second = org_graph.graph_payload(db_session, org_id)
    assert first == second
    assert [n["asset_id"] for n in first["nodes"]] == sorted(
        n["asset_id"] for n in first["nodes"]
    )
    edge_keys = [(e["from_asset_id"], e["to_asset_id"], e["relationship_type"])
                 for e in first["edges"]]
    assert edge_keys == sorted(edge_keys)

    graph, _ = org_graph.build_org_graph(db_session, org_id)
    paths_one = org_graph.paths_between(graph, "z@acme.example", "dst@acme.example")
    paths_two = org_graph.paths_between(graph, "z@acme.example", "dst@acme.example")
    assert paths_one == paths_two
    neighbors_one = org_graph.direct_neighbors(graph, "dst@acme.example", direction="in")
    neighbors_two = org_graph.direct_neighbors(graph, "dst@acme.example", direction="in")
    assert neighbors_one == neighbors_two


# --------------------------------------------------------------------------- #
# 20. Depth / path-count / resource limits
# --------------------------------------------------------------------------- #
def test_engine_limits_are_clamped_and_disclosed(db_session):
    org_id = seed_org_for_user(db_session, "user-1")
    chain = [f"hop{i}@acme.example" for i in range(1, 8)]
    for asset_id in chain:
        _asset(db_session, org_id, asset_id)
    for source, target in zip(chain, chain[1:]):
        _edge(db_session, org_id, source, target, "HAS_ACCESS_TO")
    graph, _ = org_graph.build_org_graph(db_session, org_id)

    # An absurd depth request is clamped to the documented maximum.
    over = org_graph.reachable(graph, chain[0], max_depth=999)
    assert over["max_depth"] == GRAPH_LIMITS["max_depth"]
    zero = org_graph.reachable(graph, chain[0], max_depth=0)
    assert zero["max_depth"] == 1
    # An absurd path-count request is clamped too.
    many = org_graph.paths_between(graph, chain[0], chain[-1], max_paths=999)
    assert many["max_paths"] == GRAPH_LIMITS["max_paths"]


def test_api_rejects_out_of_range_traversal_parameters(client):
    admin = register_org_admin(client, "admin@limits.example.com", org_name="Limits Co")
    for asset in (
        {"asset_id": "l1@limits.example.com", "asset_type": "WORK_EMAIL", "label": "L1"},
        {"asset_id": "l2@limits.example.com", "asset_type": "WORK_EMAIL", "label": "L2"},
    ):
        assert client.post("/api/assets", headers=admin, json=asset).status_code == 201

    base = "/api/org/graph/paths?source=l1@limits.example.com&target=l2@limits.example.com"
    assert client.get(f"{base}&max_depth=99", headers=admin).status_code == 422
    assert client.get(f"{base}&max_depth=0", headers=admin).status_code == 422
    assert client.get(f"{base}&max_paths=99", headers=admin).status_code == 422
    radius = client.get(
        "/api/org/graph/blast-radius?asset_id=l1@limits.example.com&max_depth=99",
        headers=admin,
    )
    assert radius.status_code == 422
    # In-range values work.
    assert client.get(f"{base}&max_depth=2&max_paths=3", headers=admin).status_code == 200


# --------------------------------------------------------------------------- #
# 21. Evidence and provenance preserved
# --------------------------------------------------------------------------- #
def test_evidence_and_provenance_are_preserved_through_traversal(db_session):
    org_id = seed_org_for_user(db_session, "user-1")
    _asset(db_session, org_id, "e1@acme.example", "WORK_EMAIL", 4)
    _asset(db_session, org_id, "e2@acme.example", "CODE_REPOSITORY", 5)
    _edge(
        db_session, org_id, "e1@acme.example", "e2@acme.example", "RESETS_PASSWORD",
        note="SYNTHETIC: verified by the platform team in January",
    )
    graph, _ = org_graph.build_org_graph(db_session, org_id)

    # Node provenance.
    payload = org_graph.graph_payload(db_session, org_id)
    assert payload["provenance_labels"] == PROVENANCE_LABELS
    # The two labels this system cannot produce are documented as absent,
    # never fabricated into a plausible-sounding claim.
    assert payload["provenance_labels"]["PROVIDER_DISCOVERED"] == "Not produced by this system."
    assert payload["provenance_labels"]["MODEL_INFERRED"] == "Not produced by this system."

    # A path carries the relationship's evidence end to end.
    path = org_graph.paths_between(graph, "e1@acme.example", "e2@acme.example")
    step = path["paths"][0]["steps"][0]
    assert step["evidence"]["note"] == "SYNTHETIC: verified by the platform team in January"
    assert step["evidence"]["note_present"] is True
    assert step["uncertainty"] == []
    assert step["provenance"] == "ADMIN_DECLARED"
    assert step["directed"] is True
    assert step["exposure"] == "forward"
    assert "documented direction" in step["traversal_condition"]
    assert step["criticality_of_target"] == 5

    # A relationship without a note is flagged as uncertain, not dressed up.
    _edge(db_session, org_id, "e2@acme.example", "e1@acme.example", "INTEGRATES_WITH")
    graph, _ = org_graph.build_org_graph(db_session, org_id)
    neighbors = org_graph.direct_neighbors(graph, "e1@acme.example", direction="both")
    without_note = [
        n for n in neighbors["neighbors"]
        if n["relationship"]["relationship_id"] != step["relationship_id"]
    ][0]
    assert without_note["relationship"]["evidence"]["note_present"] is False
    assert without_note["relationship"]["uncertainty"] == ["NOTE_MISSING"]


# --------------------------------------------------------------------------- #
# 22. API authentication and role checks
# --------------------------------------------------------------------------- #
def test_api_requires_auth_and_enforces_roles_on_graph_and_writes(client, db_session):
    admin = register_org_admin(client, "admin@authz.example.com", org_name="Authz Co")
    assert client.post(
        "/api/assets", headers=admin,
        json={"asset_id": "a@authz.example.com", "asset_type": "WORK_EMAIL", "label": "A"},
    ).status_code == 201
    assert client.post(
        "/api/assets", headers=admin,
        json={"asset_id": "b@authz.example.com", "asset_type": "WORK_EMAIL", "label": "B"},
    ).status_code == 201
    created = client.post(
        "/api/dependencies", headers=admin,
        json={"from_asset_id": "a@authz.example.com", "to_asset_id": "b@authz.example.com",
              "relationship_type": "USES", "note": "SYNTHETIC note"},
    )
    assert created.status_code == 201
    dependency_id = created.json()["id"]

    # Every org-graph read requires authentication.
    for path in (
        "/api/org/graph",
        "/api/org/graph/neighbors?asset_id=a@authz.example.com",
        "/api/org/graph/paths?source=a@authz.example.com&target=b@authz.example.com",
        "/api/org/graph/blast-radius?asset_id=a@authz.example.com",
        "/api/org/graph/critical-exposure",
    ):
        assert client.get(path).status_code == 401, path

    # A VIEWER may read the graph but never write a relationship.
    invited = client.post(
        "/api/invitations", headers=admin,
        json={"email": "viewer@authz.example.com", "role": "VIEWER"},
    )
    assert invited.status_code == 201
    token = invited.json()["invite_link"].split("token=", 1)[1]
    assert client.post(
        "/api/invitations/accept", json={"token": token, "password": "correct horse battery"}
    ).status_code == 200
    viewer = login_headers(client, "viewer@authz.example.com", "correct horse battery")

    assert client.get("/api/org/graph", headers=viewer).status_code == 200
    assert client.get(f"/api/dependencies/{dependency_id}", headers=viewer).status_code == 200
    assert client.post(
        "/api/dependencies", headers=viewer,
        json={"from_asset_id": "a@authz.example.com", "to_asset_id": "b@authz.example.com",
              "relationship_type": "USES"},
    ).status_code == 403
    assert client.patch(
        f"/api/dependencies/{dependency_id}", headers=viewer, json={"note": "nope"}
    ).status_code == 403

    # The admin may correct the relationship, and the change is audited.
    updated = client.patch(
        f"/api/dependencies/{dependency_id}", headers=admin,
        json={"note": "SYNTHETIC corrected note", "weight": 0.5},
    )
    assert updated.status_code == 200
    assert updated.json()["note"] == "SYNTHETIC corrected note"
    assert updated.json()["weight"] == 0.5
    assert updated.json()["from_asset_id"] == "a@authz.example.com"  # endpoints unchanged
    audits = [
        row for row in db_session.query(AuditLog).all()
        if row.action == "dependency.updated"
    ]
    assert len(audits) == 1
    assert audits[0].detail["dependency_id"] == dependency_id
    # Nothing resembling a secret is stored in the audit detail.
    assert "password" not in str(audits[0].detail).lower()

    # An unsupported type on update is rejected with the accepted set.
    bad = client.patch(
        f"/api/dependencies/{dependency_id}", headers=admin,
        json={"relationship_type": "mystery"},
    )
    assert bad.status_code == 422
    assert "Unsupported relationship_type" in bad.json()["detail"]
    # An unknown dependency id is a generic 404.
    assert client.patch(
        "/api/dependencies/does-not-exist", headers=admin, json={"note": "x"}
    ).status_code == 404
    assert client.get("/api/dependencies/does-not-exist", headers=admin).status_code == 404


# --------------------------------------------------------------------------- #
# 23. Migration / persistence
# --------------------------------------------------------------------------- #
def test_schema_constraints_persist_without_a_phase6_migration(db_session):
    """Phase 6 reuses the Phase 2 schema: no new tables, columns or migration.

    The unique constraint stops exact duplicates at the database level, and
    the org_id indexes keep every graph query tenant-scoped at the storage
    layer (§5.11).
    """
    inspector = sa_inspect(db_session.bind)

    tables = set(inspector.get_table_names())
    assert {"org_assets", "asset_dependencies"} <= tables

    unique_names = {
        c["name"] for c in inspector.get_unique_constraints("asset_dependencies")
    }
    assert "uq_asset_dependency" in unique_names

    asset_indexes = {i["name"] for i in inspector.get_indexes("asset_dependencies")}
    assert "ix_asset_dependencies_org_id" in asset_indexes
    assert "ix_asset_dependencies_from_asset_id" in asset_indexes
    assert "ix_asset_dependencies_to_asset_id" in asset_indexes
    org_asset_indexes = {i["name"] for i in inspector.get_indexes("org_assets")}
    assert "ix_org_assets_org_id" in org_asset_indexes

    # The engine reads only these two existing models — no new persistence.
    imports = _imported_modules(APP / "engine" / "org_graph.py")
    imported_bare = {m.split(".")[-1] for m in imports}
    from app import models as models_module
    model_names = {
        name for name, value in vars(models_module).items()
        if isinstance(value, type) and getattr(value, "__tablename__", None)
    }
    assert {"OrgAsset", "AssetDependency"} <= imported_bare
    assert not (imported_bare & (model_names - {"OrgAsset", "AssetDependency"}))


# --------------------------------------------------------------------------- #
# 24. Phase 4 risk-input compatibility
# --------------------------------------------------------------------------- #
def test_phase4_risk_inputs_are_unchanged_by_graph_operations(db_session):
    user_id = "user-1"
    org_id = seed_org_for_user(db_session, user_id)
    _asset(db_session, org_id, "risk@acme.example", "WORK_EMAIL", 4)
    normalizer.persist_events(db_session, [
        ev("BREACH_EXPOSURE", account_id="risk@acme.example", severity=0.7,
           event_id="evt_graph_breach", user_id=user_id),
        ev("MFA_MISSING", account_id="risk@acme.example", severity=0.6,
           event_id="evt_graph_mfa", user_id=user_id),
    ])

    before = pipeline.run_analysis(db_session, user_id, persist=False)

    # Declare relationships, then exercise every graph operation.
    _edge(db_session, org_id, "risk@acme.example", "ci@acme.example", "USES")
    _asset(db_session, org_id, "ci@acme.example", "CI_SYSTEM", 5)
    _edge(db_session, org_id, "ci@acme.example", "repo@acme.example", "DEPLOYS_TO")
    _asset(db_session, org_id, "repo@acme.example", "CODE_REPOSITORY", 5)
    graph, _ = org_graph.build_org_graph(db_session, org_id)
    org_graph.direct_neighbors(graph, "risk@acme.example")
    org_graph.reachable(graph, "risk@acme.example")
    org_graph.paths_between(graph, "risk@acme.example", "repo@acme.example")
    org_graph.blast_radius(graph, "risk@acme.example")
    org_graph.critical_exposure(graph)

    after = pipeline.run_analysis(db_session, user_id, persist=False)

    # The graph never changes the authoritative score or its inputs.
    assert after["risk"].score == before["risk"].score
    assert after["features"] == before["features"]
    assert after["criticality"] == before["criticality"]


def test_org_graph_module_never_imports_the_risk_or_attribution_engines():
    """§5.9: the graph explains exposure; it has no scoring logic of its own."""
    imports = _imported_modules(APP / "engine" / "org_graph.py")
    forbidden = {"risk", "shapley", "pipeline", "correlation"}
    assert not {m for m in imports if m.split(".")[-1] in forbidden}


# --------------------------------------------------------------------------- #
# 25. Phase 5 attribution compatibility
# --------------------------------------------------------------------------- #
def test_phase5_attribution_is_unchanged_by_graph_operations(db_session):
    user_id = "user-1"
    org_id = seed_org_for_user(db_session, user_id)
    _asset(db_session, org_id, "attr@acme.example", "WORK_EMAIL", 4)
    normalizer.persist_events(db_session, [
        ev("BREACH_EXPOSURE", account_id="attr@acme.example", severity=0.7,
           event_id="evt_attr_breach", user_id=user_id),
        ev("MFA_MISSING", account_id="attr@acme.example", severity=0.6,
           event_id="evt_attr_mfa", user_id=user_id),
    ])

    # Relationships exist before the analysis, so attribution sees them.
    _asset(db_session, org_id, "vault@acme.example", "CLOUD_STORAGE", 5)
    _edge(db_session, org_id, "attr@acme.example", "vault@acme.example", "HAS_ACCESS_TO")
    graph, _ = org_graph.build_org_graph(db_session, org_id)
    org_graph.blast_radius(graph, "attr@acme.example")

    result = pipeline.run_analysis(db_session, user_id, persist=False)
    attribution = result["attribution"]

    # The cooperative-game attribution still sums to the authoritative score.
    assert attribution["total_risk"] == pytest.approx(result["risk"].score)
    assert attribution["efficiency_error"] < 1e-6
    # Graph relationships are not attribution players: the game is unchanged.
    player_names = {
        player.get("name") or player.get("player")
        for player in attribution.get("players", [])
    }
    assert "org_graph" not in player_names
    assert not any("graph" in str(name).lower() for name in player_names if name)
