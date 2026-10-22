"""Account dependency graph + GraphRAG tests (§8, §11)."""
from __future__ import annotations

from app.engine import graph, graphrag


def test_graph_loads_curated_edges(db_session):
    g = graph.build_graph(db_session)
    assert g.number_of_nodes() > 0
    assert g.number_of_edges() > 0
    # Every edge is marked curated.
    for _, _, data in g.edges(data=True):
        assert data["curated"] is True
        assert data["source"]


def test_ranking_is_computed_not_hardcoded(db_session):
    ranked = graph.rank_accounts(graph.build_graph(db_session))
    assert len(ranked) > 0
    # PageRank drives ordering; verify it is monotonic on the primary key.
    pageranks = [r["pagerank"] for r in ranked]
    assert pageranks == sorted(pageranks, reverse=True)
    assert ranked[0]["rank"] == 1
    # Google (a common recovery hub) should have dependents.
    google = next((r for r in ranked if r["service"] == "Google"), None)
    assert google is not None
    assert len(google["dependents"]) > 0


def test_dependency_events_emitted_for_compromised_service(db_session):
    events = graph.dependency_events(
        user_id="u1", db=db_session, compromised_services={"Google"}
    )
    types = {e.event_type for e in events}
    assert "ACCOUNT_DEPENDENCY" in types


def test_graphrag_explanation_is_grounded(db_session):
    from app.engine import pipeline

    # Seed some events so the pipeline has context.
    from app.engine import normalizer
    from tests.helpers import ev

    normalizer.persist_events(
        db_session,
        [
            ev("BREACH_EXPOSURE", account_id="acct", metadata={"service_name": "Google"}),
            ev("PASSWORD_REUSE", account_id="acct", metadata={"service_name": "Google"}),
        ],
    )
    explained = pipeline.explain_run(db_session, "user-1")
    explanation = explained["explanation"]
    assert explanation.grounded is True
    assert explanation.unsupported_claims == []
    # Every security statement cites a KG edge or the engine itself.
    for statement in explanation.statements:
        assert statement.citations


def test_graphrag_context_contains_no_secrets():
    import json

    context = graphrag.sanitize_context(
        event_types=["SESSION_EXPOSURE"],
        correlations=[{"rule_id": "x", "severity": 0.5}],
        risk={"score": 70, "band": "HIGH", "range_low": 60, "range_high": 80},
        graph_edges=[{"from": "Google", "to": "GitHub"}],
    )
    assert context["sanitized"] is True
    serialized = json.dumps(context).lower()
    for forbidden in ("password", "token", "secret", "sha1", "bearer"):
        assert forbidden not in serialized


def test_graphrag_flags_uncited_claims(db_session):
    """A statement with no citation must be flagged by the validator."""
    explanation = graphrag.Explanation(
        summary="test",
        statements=[graphrag.Statement(text="Unsupported assertion with no source.", citations=[])],
        citations=[],
        context={},
        grounded=True,
        unsupported_claims=[],
    )
    from app.models import KnowledgeEdge
    from sqlalchemy import select

    edges = db_session.scalars(select(KnowledgeEdge)).all()
    unsupported = graphrag.validate(explanation, edges)
    assert unsupported
    assert any("No citation" in item for item in unsupported)


def test_graphrag_flags_unknown_citation(db_session):
    explanation = graphrag.Explanation(
        summary="test",
        statements=[graphrag.Statement(text="Claim.", citations=["not_a_real_edge"])],
        citations=[],
        context={},
        grounded=True,
        unsupported_claims=[],
    )
    from app.models import KnowledgeEdge
    from sqlalchemy import select

    edges = db_session.scalars(select(KnowledgeEdge)).all()
    unsupported = graphrag.validate(explanation, edges)
    assert any("Unknown citation" in item for item in unsupported)


def test_passkey_prevents_exactly_three_of_four_techniques(db_session):
    """The curated KG claim: passkeys prevent 3 of {AiTM, push bombing, SIM swap,
    session hijacking} and are defeated by session hijacking."""
    from sqlalchemy import select

    from app.models import KnowledgeEdge

    edges = db_session.scalars(select(KnowledgeEdge)).all()
    prevented = {
        e.to_node
        for e in edges
        if e.from_node == "passkey" and e.predicate == "prevents"
    }
    targets = {"aitm_phishing", "push_bombing", "sim_swapping", "session_hijacking"}
    assert prevented == {"aitm_phishing", "push_bombing", "sim_swapping"}
    assert len(prevented & targets) == 3
    # And session hijacking defeats passkey (the fourth is NOT prevented).
    defeated = any(
        e.from_node == "session_hijacking" and e.to_node == "passkey" and e.predicate == "defeats"
        for e in edges
    )
    assert defeated