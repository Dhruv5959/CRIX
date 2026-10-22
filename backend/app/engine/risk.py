"""Contextual risk engine (§6, Phase 4).

Deterministic. Non-additive. Documented parameters.

    risk = clip( m(c) * (base_risk + interaction_risk) - mitigation_credit,
                0, 100 )

where ``m(c) = 1 + step * (c - neutral)`` is the **asset-criticality
multiplier**: ``c`` is the criticality (1..5) the company assigned to the most
important registered asset affected by the findings, and ``m`` scales the
evidence-based exposure by how much the company cares about that asset
(``RISK_PARAMS["criticality"]``; ``c = None`` → ``m = 1.0``, an explicit
"unadjusted", never a claim of safety). Criticality alone never creates risk:
with no findings the score is 0 for every ``c``.

The additive identity used by the UI is::

    risk = base_risk + interaction_risk + criticality_adjustment
           - mitigation_credit        (before clipping)

with ``criticality_adjustment = (m - 1) * (base_risk + interaction_risk)``.

The function is a pure function of a *feature vector* (mapping feature group ->
intensity in [0,1]) plus the criticality context. Feature groups are the
players in the cooperative game used for exact Shapley attribution, which
guarantees the attribution sums to the total risk (efficiency property).

Design notes / honest caveats
----------------------------
- Weights are expert-set parameters for a *relative* prioritization score, not a
  probability. The score orders and explains; it does not predict events.
- interaction_risk encodes that problems compound (breach + reuse is worse than
  the sum of the parts) — this is CRIX's thesis, made explicit and inspectable.
  Interaction terms are computed FROM the findings themselves; grouped-link
  results produced elsewhere in the engine never enter this function and can
  never add points outside the formula documented here.
- Asset criticality enters only through the single documented multiplier ``m``.
  There is no second, hidden importance bonus anywhere in this module.
- mitigation_credit is reduced when session exposure is present: a stolen session
  bypasses credential-based controls. This mirrors the curated knowledge graph
  (`session_hijacking --defeats--> passkey`) and is documented in RISK_PARAMS.
- The confidence range is produced by a bounded perturbation sweep over feature
  intensities (see SENSITIVITY_DELTA); it is a sensitivity interval, not a
  statistical confidence interval, and is labeled as such.

Model versioning
----------------
``RISK_MODEL_VERSION`` is stamped on every breakdown and persisted snapshot.
Rows produced before asset criticality existed carry ``risk-1.0`` (back-filled
by the Phase 4 migration); current calculations produce ``risk-2.0``. Historical
rows are never rewritten when the formula changes.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.schemas import SecurityEventSchema

# Version of the documented formula implemented in this file. Persisted with
# every score so a snapshot produced by an older formula stays identifiable.
RISK_MODEL_VERSION = "risk-2.0"

# --------------------------------------------------------------------------- #
# Feature groups (also the Shapley players). Order is stable & meaningful.
# --------------------------------------------------------------------------- #
RISK_FEATURES = [
    "breach", "session", "identity", "reuse", "no_mfa",
    "sim_swap", "push_bombing", "phishing", "permissions", "dependency",
]
MITIGATION_FEATURES = ["passkey", "mfa"]
ALL_FEATURES = RISK_FEATURES + MITIGATION_FEATURES

# event_type -> feature group
EVENT_TO_FEATURE = {
    "BREACH_EXPOSURE": "breach",
    "SESSION_EXPOSURE": "session",
    "IDENTITY_EXPOSED": "identity",
    "PASSWORD_REUSE": "reuse",
    "MFA_MISSING": "no_mfa",
    "SIM_SWAP_VULNERABLE": "sim_swap",
    "PUSH_BOMBING_REPORTED": "push_bombing",
    "PHISHING_MESSAGE_DETECTED": "phishing",
    "AI_GENERATED_MESSAGE_DETECTED": "phishing",
    "RISKY_PERMISSION_GRANTED": "permissions",
    "STALE_PERMISSION_GRANTED": "permissions",
    "ACCOUNT_DEPENDENCY": "dependency",
    "COMPROMISED_RECOVERY_ACCOUNT": "dependency",
    "MFA_ENABLED": "mfa",
    "PASSKEY_ENABLED": "passkey",
}

# Documented parameters (all tunable in one place).
RISK_PARAMS = {
    # base weights — sum to 1.00 so "everything at full intensity" ~= 100 pre-interaction
    "base_weights": {
        "breach": 0.15, "session": 0.16, "identity": 0.05, "reuse": 0.10,
        "no_mfa": 0.12, "sim_swap": 0.08, "push_bombing": 0.08,
        "phishing": 0.10, "permissions": 0.08, "dependency": 0.08,
    },
    # pairwise interactions (non-additive compounding), coefficient on 0..100 scale
    "interactions": {
        ("breach", "reuse"): 0.10,
        ("breach", "no_mfa"): 0.10,
        ("session", "no_mfa"): 0.08,
        ("phishing", "identity"): 0.06,
        ("dependency", "session"): 0.08,
        ("reuse", "no_mfa"): 0.06,
        ("permissions", "phishing"): 0.05,
        ("sim_swap", "no_mfa"): 0.05,
    },
    # mitigation credit weights
    "mitigation_weights": {"passkey": 0.20, "mfa": 0.12},
    # a stolen session bypasses credential-based controls => discount mitigation
    "session_mitigation_discount": 0.70,
    "max_mitigation_credit": 0.45,   # cap total credit at 45% of pre-mitigation risk
    # Asset criticality: the importance (1 = low .. 5 = business-critical) an
    # admin assigned to the affected registered asset. Neutral level 3 is the
    # registration default, so a default asset neither raises nor lowers the
    # score; the ±step-per-level bound keeps the whole effect inside
    # multiplier m ∈ [0.8, 1.2] — important, but never allowed to dominate the
    # evidence itself. Missing criticality → m = 1.0 (explicitly unadjusted).
    "criticality": {"min": 1, "max": 5, "neutral": 3, "step_per_level": 0.10},
}

# Bounded perturbation used to produce a sensitivity range (+/- this fraction
# of each feature's intensity). Small by design: it answers "how much does the
# score move if each input is nudged slightly?", not a worst-case analysis.
SENSITIVITY_DELTA = 0.05


@dataclass
class RiskBreakdown:
    base_risk: float
    interaction_risk: float
    mitigation_credit: float
    score: float
    band: str
    confidence: str
    range_low: float
    range_high: float
    # Additive criticality term: (m - 1) * (base + interaction). 0 whenever the
    # multiplier is neutral (criticality missing or level 3), so the UI identity
    # base + interaction + adjustment − mitigation = score stays exact pre-clip.
    criticality_adjustment: float = 0.0
    components: dict = field(default_factory=dict)


def criticality_multiplier(criticality: int | None) -> float:
    """The single, documented way asset importance enters the score.

    ``m(c) = 1 + step * (c - neutral)`` with ``m(3) = 1.0`` (the registration
    default is neutral) and ``m ∈ [0.8, 1.2]`` for ``c ∈ [1, 5]``.

    ``None`` means "no registered-asset criticality available" and maps to the
    neutral 1.0 — the score is left UNADJUSTED and the caller must record that
    the input was missing (never treated as an asset that does not matter).
    Any other value is a programming/data error and raises ``ValueError``: an
    out-of-range criticality must never silently bend a score.
    """
    params = RISK_PARAMS["criticality"]
    if criticality is None:
        return 1.0
    if isinstance(criticality, bool) or not isinstance(criticality, int):
        raise ValueError(
            f"asset criticality must be an integer "
            f"{params['min']}..{params['max']} or None, got {criticality!r}"
        )
    if not params["min"] <= criticality <= params["max"]:
        raise ValueError(
            f"asset criticality must be within {params['min']}..{params['max']}, "
            f"got {criticality!r}"
        )
    return round(1.0 + params["step_per_level"] * (criticality - params["neutral"]), 6)


def _validate_features(features: dict) -> dict[str, float]:
    """Normalize the feature vector and reject out-of-range intensities.

    Every intensity must be a real number in [0, 1] (the documented severity
    normalization: an event's severity IS its feature intensity). Anything else
    — a string, ``None``, ``NaN``, a value above 1 — raises ``ValueError``
    instead of quietly producing a bent score. Unknown keys are ignored, as
    before, so callers may carry extra context alongside the vector.
    """
    cleaned: dict[str, float] = {}
    for name in ALL_FEATURES:
        raw = features.get(name, 0.0)
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise ValueError(f"feature {name!r} must be a number in [0, 1], got {raw!r}")
        value = float(raw)
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"feature {name!r} must be within [0, 1], got {raw!r}")
        cleaned[name] = value
    return cleaned


def extract_features(events: list[SecurityEventSchema]) -> dict[str, float]:
    """Build the feature vector from normalized events.

    Risk features take the maximum severity among FINDING events in the group
    (an event's severity is its observation strength). Mitigation features are
    1.0 when the corresponding control is present. UNAVAILABLE / CHECKED_SAFE /
    NOT_CHECKED never contribute risk.
    """
    features = {name: 0.0 for name in ALL_FEATURES}
    for event in events:
        group = EVENT_TO_FEATURE.get(event.event_type)
        if group is None:
            continue
        if group in MITIGATION_FEATURES:
            if event.status == "CHECKED_SAFE":
                features[group] = max(features[group], 1.0)
            continue
        if event.status != "FINDING":
            continue
        features[group] = max(features[group], float(event.severity))
    return features


def risk_from_features(
    features: dict[str, float], *, criticality: int | None = None
) -> tuple[float, dict[str, float]]:
    """Compute the raw risk score in [0,100] from a feature vector.

    Pure and side-effect free so Shapley can call it over arbitrary subsets.
    ``criticality`` is the affected asset's importance (1..5) or ``None``; it
    scales the evidence-based exposure through the single documented multiplier
    ``m(c)`` and changes nothing else. The formula (see module docstring)::

        score = clip( m(c) * (base + interaction) - mitigation, 0, 100 )

    Returns (score, component_breakdown) where the breakdown also carries the
    additive criticality term so consumers can show an exact composition.
    """
    f = _validate_features(features)
    multiplier = criticality_multiplier(criticality)

    base = sum(RISK_PARAMS["base_weights"][name] * f[name] for name in RISK_FEATURES)
    base *= 100.0

    interaction = 0.0
    for (a, b), coef in RISK_PARAMS["interactions"].items():
        interaction += coef * f[a] * f[b]
    interaction *= 100.0

    # Evidence-based exposure, scaled by how important the affected asset is.
    exposure = multiplier * (base + interaction)

    mitigation = _mitigation_credit(f, exposure)

    score = max(0.0, min(100.0, exposure - mitigation))
    return round(score, 4), {
        "base_risk": round(base, 4),
        "interaction_risk": round(interaction, 4),
        "criticality_adjustment": round(exposure - (base + interaction), 4),
        "mitigation_credit": round(mitigation, 4),
        "criticality": criticality,
        "criticality_multiplier": multiplier,
    }


def _mitigation_credit(f: dict[str, float], exposure: float) -> float:
    """Mitigation credit, discounted by session exposure (a stolen session
    bypasses credential-based controls — see the curated knowledge graph).

    The credit is capped at ``max_mitigation_credit`` of the *scaled* exposure,
    so a control can offset at most 45% of what the model says the (importance
    adjusted) situation is worth — mitigations never erase the evidence.
    """
    discount = 1.0 - RISK_PARAMS["session_mitigation_discount"] * f["session"]
    raw_credit = sum(
        RISK_PARAMS["mitigation_weights"][name] * f[name] for name in MITIGATION_FEATURES
    )
    raw_credit *= 100.0 * max(0.0, discount)
    return min(raw_credit, RISK_PARAMS["max_mitigation_credit"] * exposure)


def _band(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MODERATE"
    return "LOW"


def band_for(score: float) -> str:
    """Public alias for the risk banding function."""
    return _band(score)


def confidence_for(events: list[SecurityEventSchema]) -> str:
    """Public alias for the confidence estimator."""
    return _confidence(events)


def sensitivity_range(
    features: dict[str, float], *, criticality: int | None = None
) -> tuple[float, float]:
    """Public alias for the sensitivity interval."""
    return _sensitivity_range(features, criticality=criticality)


def _confidence(events: list[SecurityEventSchema]) -> str:
    confidences = [e.confidence for e in events if e.status == "FINDING"]
    if not confidences:
        return "low"
    avg = sum(confidences) / len(confidences)
    if avg >= 0.75:
        return "high"
    if avg >= 0.55:
        return "medium"
    return "low"


def _sensitivity_range(
    features: dict[str, float], *, criticality: int | None = None
) -> tuple[float, float]:
    """Perturb every feature toward/away from the middle and take the extremes.

    This is a sensitivity interval answering: "how much does the score move if
    each input is nudged by a small amount?" It is NOT a probability interval.
    The asset criticality is an INPUT held FIXED here — only feature
    intensities are perturbed, so the interval always brackets the point
    estimate computed with the same criticality.
    """
    low_features = {}
    high_features = {}
    for name, value in features.items():
        if value <= 0.0:
            low_features[name] = 0.0
            high_features[name] = min(1.0, SENSITIVITY_DELTA)
        else:
            up = min(1.0, value + SENSITIVITY_DELTA)
            down = max(0.0, value - SENSITIVITY_DELTA)
            low_features[name] = down
            high_features[name] = up
    low, _ = risk_from_features(low_features, criticality=criticality)
    high, _ = risk_from_features(high_features, criticality=criticality)
    return round(min(low, high), 4), round(max(low, high), 4)


def _interaction_terms(features: dict[str, float]) -> list[dict]:
    """Every documented interaction that actually fired, with its value.

    Traceability only — the terms are ALREADY included in ``interaction_risk``;
    this list never adds points. Order follows ``RISK_PARAMS["interactions"]``,
    so two identical inputs produce byte-identical output. Zero-valued terms
    are omitted (they contributed nothing).
    """
    terms: list[dict] = []
    for (a, b), coef in RISK_PARAMS["interactions"].items():
        value = round(coef * features.get(a, 0.0) * features.get(b, 0.0) * 100.0, 4)
        if value == 0.0:
            continue
        terms.append({"pair": [a, b], "coefficient": coef, "value": value})
    return terms


def _status_value(event: SecurityEventSchema) -> str:
    """The plain status string (``EventStatus`` members stringify as
    ``EventStatus.X``, so the value must be unwrapped explicitly)."""
    status = event.status
    value = getattr(status, "value", None)
    return value if isinstance(value, str) else str(status)


def _unavailable_inputs(events: list[SecurityEventSchema]) -> list[dict]:
    """Checks that produced NO answer (not run / provider unavailable).

    Explicit, sorted, and id-only: these contributed nothing to the score, and
    "nothing contributed" must stay visible so it is never mistaken for a
    clean result.
    """
    non_answers = {"NOT_CHECKED", "UNAVAILABLE", "UNAVAILABLE_THROUGH_PROVIDER"}
    rows = [
        {"event_id": e.event_id, "event_type": e.event_type, "status": _status_value(e)}
        for e in events
        if _status_value(e) in non_answers
    ]
    return sorted(rows, key=lambda row: row["event_id"])


def _uncertainty_notes(events: list[SecurityEventSchema], criticality: int | None) -> list[str]:
    """What this score does not know — stated next to the score itself."""
    notes = [
        "Prioritization measure: it orders what to fix first; it is not a "
        "forecast of attacks and not the likelihood of any event.",
        "The sensitivity range is a bounded ±5% input perturbation, not a "
        "statistical confidence interval.",
    ]
    if criticality is None:
        notes.append(
            "No registered-asset criticality was available, so the score was "
            "not adjusted for asset importance. This is an unknown input, not "
            "evidence that the asset does not matter."
        )
    missing = _unavailable_inputs(events)
    if missing:
        notes.append(
            f"{len(missing)} input check(s) were unavailable or not run and "
            "contributed nothing; unavailable is not the same as safe."
        )
    return notes


def compute_risk(
    events: list[SecurityEventSchema], *, criticality: int | None = None
) -> RiskBreakdown:
    """Score one run's findings with full traceability.

    ``criticality`` is resolved SERVER-SIDE by the pipeline from the calling
    organization's registered assets (see ``pipeline.resolve_run_criticality``)
    — never from anything a client sends. ``None`` means no registered asset
    was bound to the findings; the score is then simply unadjusted.
    """
    features = extract_features(events)
    score, breakdown = risk_from_features(features, criticality=criticality)
    low, high = _sensitivity_range(features, criticality=criticality)
    return RiskBreakdown(
        base_risk=breakdown["base_risk"],
        interaction_risk=breakdown["interaction_risk"],
        mitigation_credit=breakdown["mitigation_credit"],
        criticality_adjustment=breakdown["criticality_adjustment"],
        score=score,
        band=_band(score),
        confidence=_confidence(events),
        range_low=low,
        range_high=high,
        components={
            "features": features,
            "model_version": RISK_MODEL_VERSION,
            "criticality": criticality,
            "criticality_multiplier": breakdown["criticality_multiplier"],
            # Every event id this calculation consumed (findings, mitigation
            # checks, and non-answers alike) — sorted, so equal inputs give
            # equal traces regardless of storage order.
            "finding_ids": sorted({e.event_id for e in events}),
            "interaction_terms": _interaction_terms(features),
            "unavailable_inputs": _unavailable_inputs(events),
            "uncertainty": _uncertainty_notes(events, criticality),
        },
    )