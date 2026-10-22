"""Contextual risk engine (§6).

Deterministic. Non-additive. Documented parameters.

    risk = clip(base_risk + interaction_risk - mitigation_credit, 0, 100)

The function is a pure function of a *feature vector*: a mapping from feature
group -> intensity in [0,1]. Feature groups are the players in the cooperative
game used for exact Shapley attribution (Phase 6), which guarantees the
attribution sums to the total risk (efficiency property).

Design notes / honest caveats
----------------------------
- Weights are expert-set parameters for a *relative* prioritization score, not a
  probability. The score orders and explains; it does not predict events.
- interaction_risk encodes that problems compound (breach + reuse is worse than
  the sum of the parts) — this is CRIX's thesis, made explicit and inspectable.
- mitigation_credit is reduced when session exposure is present: a stolen session
  bypasses credential-based controls. This mirrors the curated knowledge graph
  (`session_hijacking --defeats--> passkey`) and is documented in RISK_PARAMS.
- The confidence range is produced by a bounded perturbation sweep over feature
  intensities (see SENSITIVITY_DELTA); it is a sensitivity interval, not a
  statistical confidence interval, and is labeled as such.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.schemas import SecurityEventSchema

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
    components: dict = field(default_factory=dict)


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


def risk_from_features(features: dict[str, float]) -> tuple[float, dict[str, float]]:
    """Compute the raw risk score in [0,100] from a feature vector.

    Pure and side-effect free so Shapley can call it over arbitrary subsets.
    Returns (score, component_breakdown).
    """
    f = {name: float(features.get(name, 0.0)) for name in ALL_FEATURES}

    base = sum(RISK_PARAMS["base_weights"][name] * f[name] for name in RISK_FEATURES)
    base *= 100.0

    interaction = 0.0
    for (a, b), coef in RISK_PARAMS["interactions"].items():
        interaction += coef * f[a] * f[b]
    interaction *= 100.0

    pre_mitigation = base + interaction

    mitigation = _mitigation_credit(f, pre_mitigation)

    score = max(0.0, min(100.0, pre_mitigation - mitigation))
    return round(score, 4), {
        "base_risk": round(base, 4),
        "interaction_risk": round(interaction, 4),
        "mitigation_credit": round(mitigation, 4),
    }


def _mitigation_credit(f: dict[str, float], pre_mitigation: float) -> float:
    """Mitigation credit, discounted by session exposure (a stolen session
    bypasses credential-based controls — see the curated knowledge graph)."""
    discount = 1.0 - RISK_PARAMS["session_mitigation_discount"] * f["session"]
    raw_credit = sum(
        RISK_PARAMS["mitigation_weights"][name] * f[name] for name in MITIGATION_FEATURES
    )
    raw_credit *= 100.0 * max(0.0, discount)
    return min(raw_credit, RISK_PARAMS["max_mitigation_credit"] * pre_mitigation)


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


def sensitivity_range(features: dict[str, float]) -> tuple[float, float]:
    """Public alias for the sensitivity interval."""
    return _sensitivity_range(features)


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


def _sensitivity_range(features: dict[str, float]) -> tuple[float, float]:
    """Perturb every feature toward/away from the middle and take the extremes.

    This is a sensitivity interval answering: "how much does the score move if
    each input is nudged by a small amount?" It is NOT a probability interval.
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
    low, _ = risk_from_features(low_features)
    high, _ = risk_from_features(high_features)
    return round(min(low, high), 4), round(max(low, high), 4)


def compute_risk(events: list[SecurityEventSchema]) -> RiskBreakdown:
    features = extract_features(events)
    score, breakdown = risk_from_features(features)
    low, high = _sensitivity_range(features)
    return RiskBreakdown(
        base_risk=breakdown["base_risk"],
        interaction_risk=breakdown["interaction_risk"],
        mitigation_credit=breakdown["mitigation_credit"],
        score=score,
        band=_band(score),
        confidence=_confidence(events),
        range_low=low,
        range_high=high,
        components={"features": features},
    )