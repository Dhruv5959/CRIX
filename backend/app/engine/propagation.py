"""Compromise propagation analysis (live-OAuth scope, §6–§9).

Answers: *if the user selects account U as compromised in a what-if scenario,
which connected accounts sit downstream, and how exposed are they?*

Scope & honesty contract
------------------------
- This is a **defensive what-if simulation**. It does not hack, touch, or alter
  any real account, does not disable controls, and does not send anything.
- The result is a **DOWNSTREAM EXPOSURE SCORE**: a *relative prioritization*
  measure in [0,100]. It is **NOT** a probability of being hacked and **NOT** a
  prediction that a downstream account "will be" compromised.
- Relationships are **USER_CONFIRMED** — OAuth never proves a recovery path.
- Edges are **weighted**; not every graph edge is treated equally.

Formula (documented parameters, deterministic, tested):

    exposure(d) = clamp0_100(
        100 × (
            dependency_strength   # edge weight x path strength across U..d
            × account_criticality # centrality of d (0.5 .. 1.0)
            × auth_weakness       # credential/auth weakness of d (0 .. 1)
            × path_exposure       # decays with path length (0..1)
        )
        − 100 × mitigation_credit # mitigation_state of d (0 .. cap)
    )

Every factor is derived from stored events/relationships — no hard-coded
propagation score exists anywhere in the codebase (§19 acceptance).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    AccountRelationship,
    ConnectedSignal,
    ProviderConnection,
    SecurityEvent,
)
from app.schemas import SecurityEventSchema, SourceMode

# --------------------------------------------------------------------------- #
# Documented parameters (single place, tunable)
# --------------------------------------------------------------------------- #
PROPAGATION_PARAMS = {
    # Edge-type weights: how strongly a relationship transmits exposure.
    # USER_CONFIRMED relationship types only. Curated service-level edges use
    # their own stored weight.
    "relationship_weights": {
        "recovery_email": 1.0,
        "recovery_phone": 0.9,
        "recovery": 1.0,
        "sso": 0.85,
        "sso_dependency": 0.85,
        "login_dependency": 0.8,
        "oauth_dependency": 0.7,
        "same_email_identity": 0.6,
        "shared_identity": 0.6,
        "other": 0.4,
    },
    # Multi-hop strength multiplier per extra hop (compound paths weaken).
    "path_decay_per_hop": 0.75,
    # account_criticality is derived from weighted in-degree/centrality and
    # mapped into [MIN_CRITICALITY, 1.0].
    "min_criticality": 0.5,
    # Mitigation credit subtracted (capped) — mitigation_state in [0,1].
    "max_mitigation_credit": 0.35,
    # Exposure band thresholds (relative prioritization, not probability).
    "bands": {"HIGH": 60.0, "MODERATE": 30.0, "LOW": 0.0},
    # Strength applied when an account has NO auth telemetry at all.
    #
    # This is the propagation engine honoring CRIX's core rule: *couldn't check
    # != safe*. Weakness is otherwise a sum of FINDING events, so an account
    # with zero recorded events would score 0.0 — i.e. "no exposure" — which is
    # an unsupported claim of safety. Instead an un-telemetered account is
    # treated as having unknown strength at this neutral floor, and the UI says
    # so explicitly. An account that HAS been checked (even all CHECKED_SAFE)
    # is scored from evidence, not from this floor.
    "unknown_weakness": 0.5,
}

# event_type -> affects which weakness factor (0..1)
_WEAKNESS_EVENTS = {
    "PASSWORD_REUSE": 0.35,
    "BREACH_EXPOSURE": 0.30,
    "MFA_MISSING": 0.25,
    "SIM_SWAP_VULNERABLE": 0.15,
    "SESSION_EXPOSURE": 0.20,
    "PUSH_BOMBING_REPORTED": 0.10,
}

# mitigation event_type -> credit contribution (sums, capped)
_MITIGATION_EVENTS = {
    "PASSKEY_ENABLED": 0.35,
    "MFA_ENABLED": 0.20,
}


def band_for(score: float, params: dict | None = None) -> str:
    bands = (params or PROPAGATION_PARAMS)["bands"]
    if score >= bands["HIGH"]:
        return "HIGH"
    if score >= bands["MODERATE"]:
        return "MODERATE"
    return "LOW"


@dataclass
class DownstreamResult:
    account_id: str
    label: str
    provider: str | None
    source_mode: str
    exposure: float
    band: str
    path: list[str]
    path_length: int
    reasons: list[str] = field(default_factory=list)
    # Component breakdown so the UI can explain the score (transparency).
    components: dict = field(default_factory=dict)
    # The CRIX contextual risk score recomputed WITH the simulated scenario.
    scenario_risk: float | None = None
    scenario_band: str | None = None


def _accounts(db: Session, user_id: str) -> dict[str, ConnectedSignal]:
    rows = db.scalars(
        select(ConnectedSignal).where(ConnectedSignal.user_id == user_id)
    ).all()
    return {row.account_id: row for row in rows}


def _provider_account_id_map(db: Session, user_id: str) -> dict[str, str]:
    """Map provider_account_id -> CRIX account_id for OAuth connections."""
    conns = db.scalars(
        select(ProviderConnection).where(ProviderConnection.user_id == user_id)
    ).all()
    return {c.provider_account_id: c.account_id for c in conns if c.account_id}


def _relationships(db: Session, user_id: str) -> list[AccountRelationship]:
    return list(
        db.scalars(
            select(AccountRelationship).where(AccountRelationship.user_id == user_id)
        ).all()
    )


def _events(db: Session, user_id: str) -> list[SecurityEvent]:
    return list(
        db.scalars(select(SecurityEvent).where(SecurityEvent.user_id == user_id)).all()
    )


def _edges_for_user(db: Session, user_id: str) -> dict[str, list[tuple[str, str, float]]]:
    """Build a directed adjacency: from -> [(to, relationship_type, weight)].

    Sources, in priority order:
      1. USER_CONFIRMED account relationships (explicit, typed, weighted).
      2. Curated service-level graph relationships (static, weighted) matched by
         the connected accounts' service names.
    """
    adjacency: dict[str, list[tuple[str, str, float]]] = {}

    rels = _relationships(db, user_id)
    for rel in rels:
        weight = float(rel.weight) or PROPAGATION_PARAMS["relationship_weights"].get(
            rel.relationship_type, 0.5
        )
        adjacency.setdefault(rel.from_account_id, []).append(
            (rel.to_account_id, rel.relationship_type, weight)
        )

    # Curated service-level edges fill gaps (only where both endpoints exist).
    accounts = _accounts(db, user_id)
    if accounts:
        from app.models import GraphRelationship

        service_to_account = {}
        for account in accounts.values():
            service = (account.metadata_json or {}).get("service_name") or account.service_name
            if service:
                service_to_account.setdefault(service, account.account_id)

        curated = db.scalars(select(GraphRelationship)).all()
        for edge in curated:
            a = service_to_account.get(edge.from_service)
            b = service_to_account.get(edge.to_service)
            if a and b and a != b:
                adjacency.setdefault(a, []).append((b, edge.relationship_type, float(edge.weight)))

    return adjacency


def _walk(
    adjacency: dict[str, list[tuple[str, str, float]]],
    start: str,
    max_hops: int = 4,
) -> dict[str, tuple[list[str], float]]:
    """BFS from ``start`` accumulating path strength (product of edge weights
    with per-hop decay). Returns downstream -> (path, path_strength)."""
    best: dict[str, tuple[list[str], float]] = {}
    frontier: list[tuple[str, list[str], float]] = [(start, [start], 1.0)]

    for _ in range(max_hops):
        nxt: list[tuple[str, list[str], float]] = []
        for node, path, strength in frontier:
            for target, _rel, weight in adjacency.get(node, []):
                if target in path:
                    continue
                new_strength = strength * weight * PROPAGATION_PARAMS["path_decay_per_hop"]
                candidate = path + [target]
                existing = best.get(target)
                if existing is None or new_strength > existing[1]:
                    best[target] = (candidate, new_strength)
                    nxt.append((target, candidate, new_strength))
        frontier = nxt
        if not frontier:
            break
    return best


def _auth_weakness(
    events: list[SecurityEvent], account_id: str
) -> tuple[float, list[str], bool]:
    """Sum weighted weakness factors from this account's FINDING events.

    Returns ``(score, reasons, has_telemetry)``. ``has_telemetry`` is False when
    the account has **no** recorded security events at all — the caller then
    applies ``PROPAGATION_PARAMS["unknown_weakness"]`` instead of 0, because an
    account we have never checked must not be reported as having no exposure.
    """
    score = 0.0
    reasons: list[str] = []
    seen_any = False
    for event in events:
        if event.account_id != account_id:
            continue
        seen_any = True
        if event.status != "FINDING":
            continue
        weight = _WEAKNESS_EVENTS.get(event.event_type)
        if weight:
            score += weight
            reasons.append(event.event_type)
    return min(1.0, score), sorted(set(reasons)), seen_any


def _mitigation_state(events: list[SecurityEvent], account_id: str) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []
    for event in events:
        if event.account_id != account_id:
            continue
        credit = _MITIGATION_EVENTS.get(event.event_type)
        if credit and event.status in ("CHECKED_SAFE", "FINDING"):
            score += credit
            reasons.append(event.event_type)
    return min(1.0, score), sorted(set(reasons))


def _criticality(adjacency: dict, account_id: str, all_ids: set[str]) -> tuple[float, int]:
    """Weighted in-degree centrality mapped into [min_criticality, 1.0]."""
    in_weight = 0.0
    for _src, targets in adjacency.items():
        for target, _rel, weight in targets:
            if target == account_id:
                in_weight += weight
    dependents = sum(
        1
        for targets in adjacency.values()
        for target, _rel, _w in targets
        if target == account_id
    )
    # Normalize: 0 dependents -> min criticality; 3+ -> ~1.0.
    normalized = min(1.0, in_weight / 3.0)
    floor = PROPAGATION_PARAMS["min_criticality"]
    criticality = floor + (1.0 - floor) * normalized
    return round(criticality, 4), dependents


def _path_exposure(path_length: int) -> float:
    if path_length <= 1:
        return 1.0
    return PROPAGATION_PARAMS["path_decay_per_hop"] ** (path_length - 1)


def compute_downstream_exposure(
    db: Session,
    user_id: str,
    upstream_account_id: str,
    *,
    max_hops: int = 4,
) -> dict:
    """Full propagation analysis for a simulated compromise of ``upstream``."""
    accounts = _accounts(db, user_id)
    events = _events(db, user_id)
    adjacency = _edges_for_user(db, user_id)

    if upstream_account_id not in accounts:
        raise KeyError(f"Unknown account: {upstream_account_id}")

    reachable = _walk(adjacency, upstream_account_id, max_hops=max_hops)

    all_ids = set(accounts)
    results: list[DownstreamResult] = []
    for account_id, (path, path_strength) in reachable.items():
        account = accounts.get(account_id)
        if account is None:
            continue
        criticality, dependents = _criticality(adjacency, account_id, all_ids)
        weakness, weakness_reasons, has_telemetry = _auth_weakness(events, account_id)
        weakness_unknown = not has_telemetry
        if weakness_unknown:
            # couldn't check != safe: never score an un-checked account as 0.
            weakness = PROPAGATION_PARAMS["unknown_weakness"]
        mitigation, mitigation_reasons = _mitigation_state(events, account_id)
        hops = len(path) - 1
        path_exp = _path_exposure(hops)

        raw = (
            100.0
            * (min(1.0, path_strength) * criticality * weakness * path_exp)
        )
        mitigation_credit = (
            PROPAGATION_PARAMS["max_mitigation_credit"] * mitigation * 100.0
        )
        exposure = max(0.0, min(100.0, raw - mitigation_credit))

        reasons: list[str] = []
        if path_strength >= 0.6:
            reasons.append("direct recovery/authentication dependency")
        elif hops > 1:
            reasons.append(f"indirect path ({hops} hops)")
        else:
            reasons.append("weaker dependency path")
        if weakness_reasons:
            reasons.append("credential/auth weakness: " + ", ".join(weakness_reasons))
        if weakness_unknown:
            reasons.append(
                "no auth telemetry recorded for this account — unknown, not safe "
                f"(neutral strength {PROPAGATION_PARAMS['unknown_weakness']:.2f} applied)"
            )
        if mitigation_reasons:
            reasons.append("mitigated by: " + ", ".join(mitigation_reasons))
        if dependents:
            reasons.append(f"account is a recovery route for {dependents} other(s)")

        results.append(
            DownstreamResult(
                account_id=account_id,
                label=account.label,
                provider=account.service_name or account.platform,
                source_mode=_source_mode_for(db, user_id, account_id),
                exposure=round(exposure, 4),
                band=band_for(exposure),
                path=path,
                path_length=hops,
                reasons=reasons,
                components={
                    "dependency_strength": round(min(1.0, path_strength), 4),
                    "account_criticality": criticality,
                    "credential_auth_weakness": round(weakness, 4),
                    "weakness_unknown": weakness_unknown,
                    "path_exposure": round(path_exp, 4),
                    "mitigation_credit": round(mitigation_credit / 100.0, 4),
                },
            )
        )

    results.sort(key=lambda item: item.exposure, reverse=True)

    highest = results[0] if results else None
    overall_band = band_for(highest.exposure) if highest else "LOW"

    return {
        "upstream_account_id": upstream_account_id,
        "upstream_label": accounts[upstream_account_id].label,
        "source_mode": SourceMode.SIMULATED.value,
        "affected_count": len(results),
        "overall_band": overall_band,
        "highest_risk_account_id": highest.account_id if highest else None,
        "highest_risk_account_label": highest.label if highest else None,
        "downstream": [
            {
                "account_id": r.account_id,
                "label": r.label,
                "provider": r.provider,
                "source_mode": r.source_mode.value if hasattr(r.source_mode, "value") else r.source_mode,
                "exposure": r.exposure,
                "band": r.band,
                "path": r.path,
                "path_length": r.path_length,
                "reasons": r.reasons,
                "components": r.components,
            }
            for r in results
        ],
        "formula": (
            "exposure = clamp0_100( 100 x (dependency_strength x "
            "account_criticality x credential_auth_weakness x path_exposure) "
            "- 100 x mitigation_credit )"
        ),
        "params": PROPAGATION_PARAMS,
        "disclaimer": (
            "Relative downstream exposure within the user's account-dependency "
            "graph under a simulated compromise. Not a probability of being "
            "hacked and not a prediction that any account will be compromised."
        ),
    }


def _source_mode_for(db: Session, user_id: str, account_id: str) -> SourceMode:
    """OAuth connections are REAL; manually-added accounts are USER_PROVIDED."""
    conn = db.scalar(
        select(ProviderConnection).where(
            ProviderConnection.user_id == user_id,
            ProviderConnection.account_id == account_id,
        )
    )
    if conn is not None:
        return SourceMode(conn.source_mode)
    return SourceMode.USER_PROVIDED
