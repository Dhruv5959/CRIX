"""GraphRAG explanation layer (§11).

Contract (locked):
- GraphRAG EXPLAINS. The deterministic risk engine DECIDES. GraphRAG never
  computes or overrides risk.
- Every security claim must be traceable to (a) a curated knowledge-graph edge or
  (b) CRIX's own engine output. Claims that are not traceable are flagged by
  ``validate`` and surfaced as ``unsupported_claims``.
- GraphRAG receives ONLY pre-sanitized context (event types, correlation ids,
  risk numbers, graph relationship ids). It NEVER receives plaintext passwords,
  secrets, tokens, or raw message text.

The generator is deliberately deterministic and template-based. It selects
relevant curated KG edges for the current decision context and renders sentences
that each carry explicit citations. There is no free-form invention.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import KnowledgeEdge, KnowledgeNode


@dataclass
class Statement:
    text: str
    citations: list[str] = field(default_factory=list)  # edge_ids or engine refs


@dataclass
class Explanation:
    summary: str
    statements: list[Statement]
    citations: list[dict]
    context: dict
    grounded: bool
    unsupported_claims: list[str]


# Map engine signals -> relevant KG node ids to retrieve around.
_EVENT_TO_NODES = {
    "SESSION_EXPOSURE": ["session_hijacking", "stolen_session_cookie"],
    "COMPROMISED_RECOVERY_ACCOUNT": ["session_hijacking"],
    "SIM_SWAP_VULNERABLE": ["sim_swapping", "sms_otp"],
    "PUSH_BOMBING_REPORTED": ["push_bombing", "push_approval", "number_matching"],
    "PHISHING_MESSAGE_DETECTED": ["aitm_phishing"],
    "AI_GENERATED_MESSAGE_DETECTED": ["aitm_phishing"],
    "PASSWORD_REUSE": ["password_reuse", "credential_stuffing"],
    "BREACH_EXPOSURE": ["exposed_credentials", "credential_stuffing"],
}

_KNOWN_NODE_IDS = None  # populated at runtime from DB


def sanitize_context(
    *,
    event_types: list[str],
    correlations: list[dict],
    risk: dict,
    graph_edges: list[dict] | None = None,
) -> dict:
    """Build the ONLY context object GraphRAG is allowed to receive.

    Explicitly whitelists fields; raw text, metadata dicts, and anything that
    could contain secrets are dropped. The security test suite checks this.
    """
    return {
        "event_types": sorted(set(event_types)),
        "correlations": [
            {"rule_id": c.get("rule_id"), "severity": c.get("severity")} for c in correlations
        ],
        "risk": {
            "score": risk.get("score"),
            "band": risk.get("band"),
            "range_low": risk.get("range_low"),
            "range_high": risk.get("range_high"),
        },
        "graph_edges": [
            {"from": e.get("from"), "to": e.get("to")} for e in (graph_edges or [])
        ],
        "sanitized": True,
    }


def _fetch_kg(db: Session) -> tuple[dict[str, KnowledgeNode], list[KnowledgeEdge]]:
    nodes = {n.node_id: n for n in db.scalars(select(KnowledgeNode)).all()}
    edges = list(db.scalars(select(KnowledgeEdge)).all())
    return nodes, edges


def _relevant_edges(
    context: dict, edges: list[KnowledgeEdge]
) -> list[KnowledgeEdge]:
    relevant_nodes: set[str] = set()
    for event_type in context["event_types"]:
        relevant_nodes.update(_EVENT_TO_NODES.get(event_type, []))
    # Correlations can add nodes too.
    for corr in context["correlations"]:
        rule_id = corr.get("rule_id", "")
        if "mfa" in rule_id:
            relevant_nodes.update(["push_bombing", "push_approval"])
        if "credential" in rule_id:
            relevant_nodes.update(["credential_stuffing", "password_reuse"])
        if "session" in rule_id:
            relevant_nodes.update(["session_hijacking", "stolen_session_cookie"])
    selected = [
        edge
        for edge in edges
        if edge.from_node in relevant_nodes or edge.to_node in relevant_nodes
    ]
    # Stable ordering for reproducibility.
    selected.sort(key=lambda e: e.edge_id)
    return selected


def _cite(edge: KnowledgeEdge, nodes: dict[str, KnowledgeNode]) -> dict:
    return {
        "edge_id": edge.edge_id,
        "predicate": edge.predicate,
        "from": nodes.get(edge.from_node).label if nodes.get(edge.from_node) else edge.from_node,
        "to": nodes.get(edge.to_node).label if nodes.get(edge.to_node) else edge.to_node,
        "evidence": edge.evidence,
        "source": edge.source,
    }


def explain(db: Session, context: dict) -> Explanation:
    nodes, edges = _fetch_kg(db)
    selected = _relevant_edges(context, edges)
    citations = [_cite(edge, nodes) for edge in selected]

    statements: list[Statement] = []

    risk = context.get("risk", {})
    band = risk.get("band")
    score = risk.get("score")
    if score is not None:
        statements.append(
            Statement(
                text=(
                    f"CRIX's deterministic risk engine places this account at a "
                    f"{band} contextual risk score of {score} (range "
                    f"{risk.get('range_low')}-{risk.get('range_high')}). This is a "
                    f"relative prioritization, not a probability."
                ),
                citations=["engine:risk"],
            )
        )

    for corr in context.get("correlations", []):
        statements.append(
            Statement(
                text=(
                    f"Correlation '{corr.get('rule_id')}' fired (severity "
                    f"{corr.get('severity')}), meaning multiple independent signals "
                    f"combine into one path."
                ),
                citations=[f"engine:correlation:{corr.get('rule_id')}"],
            )
        )

    # KG-grounded technique/defense statements.
    for edge in selected:
        from_label = nodes.get(edge.from_node).label if nodes.get(edge.from_node) else edge.from_node
        to_label = nodes.get(edge.to_node).label if nodes.get(edge.to_node) else edge.to_node
        verb = {"prevents": "prevents", "defeats": "defeats", "enables": "enables"}.get(
            edge.predicate, edge.predicate
        )
        statements.append(
            Statement(
                text=f"{from_label} {verb} {to_label}.",
                citations=[edge.edge_id],
            )
        )

    summary = _render_summary(context, selected, nodes)
    explanation = Explanation(
        summary=summary,
        statements=statements,
        citations=citations,
        context=context,
        grounded=True,
        unsupported_claims=[],
    )
    explanation.unsupported_claims = validate(explanation, edges)
    explanation.grounded = not explanation.unsupported_claims
    return explanation


def _render_summary(context: dict, edges: list[KnowledgeEdge], nodes: dict[str, KnowledgeNode]) -> str:
    event_types = context.get("event_types", [])
    parts: list[str] = []
    if "SESSION_EXPOSURE" in event_types:
        parts.append(
            "An exposed session is the dominant factor: a valid session cookie "
            "authenticates without a credential challenge, so credential-based "
            "controls do not apply to it."
        )
    if "PHISHING_MESSAGE_DETECTED" in event_types:
        parts.append(
            "A likely phishing message is present; adversary-in-the-middle pages "
            "can relay one-time codes in real time."
        )
    if "SIM_SWAP_VULNERABLE" in event_types:
        parts.append("SMS-based recovery exposes the account to SIM swapping.")
    if "PUSH_BOMBING_REPORTED" in event_types:
        parts.append("Repeated push prompts suggest an MFA-fatigue (push-bombing) attempt.")
    if not parts:
        parts.append(
            "No compounding technique chain is indicated by the curated knowledge "
            "graph for the current signals."
        )
    parts.append(
        "All technique and defense statements above are cited from the curated "
        "security knowledge graph; the risk score itself is produced by CRIX's "
        "deterministic engine."
    )
    return " ".join(parts)


def validate(explanation: Explanation, edges: list[KnowledgeEdge]) -> list[str]:
    """Return descriptions of any unsupported claims.

    A claim is supported iff:
    - it cites at least one source, AND
    - every citation is either a real KG edge_id or an ``engine:`` reference to
      CRIX's own output.
    """
    valid_edge_ids = {edge.edge_id for edge in edges}
    unsupported: list[str] = []
    for statement in explanation.statements:
        if not statement.citations:
            unsupported.append(f"No citation: '{statement.text}'")
            continue
        for citation in statement.citations:
            if citation.startswith("engine:"):
                continue
            if citation not in valid_edge_ids:
                unsupported.append(
                    f"Unknown citation '{citation}' in: '{statement.text}'"
                )
    return unsupported