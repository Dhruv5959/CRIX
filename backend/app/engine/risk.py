"""Contextual risk engine (§6, Phase 4; dependency-exposure term added 6b).

Deterministic. Non-additive. Documented parameters.

    risk = clip( m(c) * (base_risk + interaction_risk) + dependency_exposure
                - mitigation_credit, 0, 100 )

where ``m(c) = 1 + step * (c - neutral)`` is the **asset-criticality
multiplier**: ``c`` is the criticality (1..5) the company assigned to the most
important registered asset affected by the findings, and ``m`` scales the
evidence-based exposure by how much the company cares about that asset
(``RISK_PARAMS["criticality"]``; ``c = None`` → ``m = 1.0``, an explicit
"unadjusted", never a claim of safety). Criticality alone never creates risk:
with no findings the score is 0 for every ``c``.

``dependency_exposure = 100 * w_dep * d`` is the **Phase 6b term**: how much
potential exposure the affected registered asset has through the
organization's documented dependency graph, from the bounded
``org_graph.blast_radius`` query (``d ∈ [0, 1)`` is the criticality-weighted
reachable mass; ``RISK_PARAMS["dependency_exposure"]``). It is resolved
server-side by the pipeline from admin-declared edges only and enters as a
normal feature intensity (the ``dependency_exposure`` feature group), so it is
bounded (at most ``100 * w_dep`` points), ablatable (set the intensity to 0 or
run with ``CRIX_RISK_DEPENDENCY_EXPOSURE_ENABLED=false``), and attributed like
every other factor. When no graph input is supplied the term is exactly 0 and
the score equals the Phase 4 formula bit-for-bit.

The additive identity used by the UI is::

    risk = base_risk + interaction_risk + criticality_adjustment
           + dependency_exposure - mitigation_credit        (before clipping)

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
- The ``dependency_exposure`` intensity is *not* computed here — this module
  never touches the database or the graph. The pipeline resolves it
  server-side (org-scoped, documented edges only) and passes it in; with no
  input, the term is 0 (unknown graph input is recorded by the caller, never
  assumed safe).
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
by the Phase 4 migration); rows produced before the dependency-exposure term
existed carry ``risk-2.0``; current calculations produce ``risk-2.1``.
Historical rows are never rewritten when the formula changes.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.schemas import SecurityEventSchema

# Version of the documented formula implemented in this file. Persisted with
# every score so a snapshot produced by an older formula stays identifiable.
RISK_MODEL_VERSION = "risk-2.1"

# --------------------------------------------------------------------------- #
# Feature groups (also the Shapley players). Order is stable & meaningful.
# --------------------------------------------------------------------------- #
RISK_FEATURES = [
    "breach", "session", "identity", "reuse", "no_mfa",
    "sim_swap", "push_bombing", "phishing", "permissions", "dependency",
]
# Phase 6b: the org dependency-graph exposure intensity. A first-class feature
# (player) rather than hidden context: it is an input like any other, so
# attribution can show how many points the graph contributes, the planner and
# what-if re-evaluate it with the real function, and an absent graph stays
# absent (0) instead of inflating the empty-coalition baseline.
DEPENDENCY_EXPOSURE_FEATURE = "dependency_exposure"
MITIGATION_FEATURES = ["passkey", "mfa"]
ALL_FEATURES = RISK_FEATURES + [DEPENDENCY_EXPOSURE_FEATURE] + MITIGATION_FEATURES

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
    # Feature C: a live threat feed flagged a submitted URL. It feeds the
    # EXISTING phishing feature pool (max-severity aggregation), so no new
    # weight, interaction, or formula version appears here — documented in
    # docs/RISK_MODEL.md and regression-tested in test_risk_regression (§6.C).
    "PHISHING_URL_DETECTED": "phishing",
    # Feature F: organization-wide access records are used hygiene evidence;
    # they feed the EXISTING permissions pool for the same reason.
    "ACCESS_REVIEW_NEEDED": "permissions",
    # Feature D findings are persisted and correlated elsewhere but
    # intentionally NOT in the feature map: DNS/TLS posture is a
    # company-domain property, not an account-breach observation, and mapping
    # it into an existing pool would be an undocumented model change.
    # Declarative matching rules may still combine them with mapped event
    # types (narrowly, with tests).
    # EMAIL_AUTH_WEAKNESS / TLS_POSTURE_WEAK: deliberately unmapped.
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
    # Phase 6b — DependencyExposure (docs/RISK_MODEL.md §1.3). Intensity
    # d ∈ [0, 1) comes from the org graph's bounded blast-radius query:
    #   raw   = sum over reachable assets of  ((criticality - 1) / 4) * (1 / depth)
    #   d     = raw / (raw + saturation)          (saturating, always < 1)
    #   points = 100 * weight * d                 (bounded by 100 * weight)
    # weight 0.08 mirrors the mid-tier evidence groups (permissions /
    # dependency / sim_swap), so even a fully saturated graph adds less than a
    # top-weighted finding group: importance of connected assets can re-rank
    # close cases, never dominate the findings themselves. saturation 4.0
    # means a criticality-5 asset one hop away contributes a quarter of the
    # maximum.
    "dependency_exposure": {"weight": 0.08, "saturation": 4.0},
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
    # base + interaction + adjustment + dependency_exposure − mitigation = score
    # stays exact pre-clip.
    criticality_adjustment: float = 0.0
    # Phase 6b additive dependency-exposure term (points, 0..100*w_dep). 0 when
    # no graph input was supplied — never a claim that no exposure exists.
    dependency_exposure: float = 0.0
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

    Risk features take the max severity among FINDING events in the group
    (an event's severity is its observation strength). Mitigation features are
    1.0 when the corresponding control is present. UNAVAILABLE / CHECKED_SAFE /
    NOT_CHECKED never contribute risk.

    ``dependency_exposure`` is deliberately NOT derived from events: no finding
    type maps to it. It is resolved from the organization's dependency graph by
    the pipeline and merged in afterwards (``compute_risk``), so an event row
    can never fabricate graph exposure.
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


def dependency_exposure_points(intensity: float) -> float:
    """Points the Phase 6b dependency term contributes for intensity ``d``.

    ``points = 100 * weight * d`` with ``d ∈ [0, 1]`` — bounded by
    ``100 * weight`` (8 points at weight 0.08). Out-of-range or non-numeric
    intensities raise ``ValueError`` (defense in depth behind
    ``_validate_features``): an invalid graph input must never bend a score.
    """
    if isinstance(intensity, bool) or not isinstance(intensity, (int, float)):
        raise ValueError(
            f"dependency exposure intensity must be a number in [0, 1], got {intensity!r}"
        )
    value = float(intensity)
    if not 0.0 <= value <= 1.0:
        raise ValueError(
            f"dependency exposure intensity must be within [0, 1], got {intensity!r}"
        )
    weight = RISK_PARAMS["dependency_exposure"]["weight"]
    return round(100.0 * weight * value, 4)


def risk_from_features(
    features: dict[str, float], *, criticality: int | None = None
) -> tuple[float, dict[str, float]]:
    """Compute the raw risk score in [0,100] from a feature vector.

    Pure and side-effect free so Shapley can call it over arbitrary subsets.
    ``criticality`` is the affected asset's importance (1..5) or ``None``; it
    scales the evidence-based exposure through the single documented multiplier
    ``m(c)`` and changes nothing else. The formula (see module docstring)::

        score = clip( m(c) * (base + interaction) + dependency_exposure
                      - mitigation, 0, 100 )

    ``dependency_exposure`` is read from the ``dependency_exposure`` feature
    (resolved from the org graph by the pipeline; 0 when not supplied) and is
    deliberately OUTSIDE ``m(c)``: the multiplier's documented scope — the
    affected asset's importance — is unchanged from Phase 4, and the graph term
    carries its own criticality weighting (of the *reachable* assets).

    Returns (score, component_breakdown) where the breakdown also carries the
    additive criticality and dependency terms so consumers can show an exact
    composition.
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

    # Phase 6b: documented-dependency-graph exposure (0 without a graph input).
    dependency_points = dependency_exposure_points(f[DEPENDENCY_EXPOSURE_FEATURE])

    # Pre-mitigation total: the cap base includes the graph term, so mitigation
    # can never erase more than 45% of ANY documented evidence.
    pre_mitigation = exposure + dependency_points
    mitigation = _mitigation_credit(f, pre_mitigation)

    score = max(0.0, min(100.0, pre_mitigation - mitigation))
    return round(score, 4), {
        "base_risk": round(base, 4),
        "interaction_risk": round(interaction, 4),
        "criticality_adjustment": round(exposure - (base + interaction), 4),
        "dependency_exposure": dependency_points,
        "mitigation_credit": round(mitigation, 4),
        "criticality": criticality,
        "criticality_multiplier": multiplier,
    }


def _mitigation_credit(f: dict[str, float], exposure: float) -> float:
    """Mitigation credit, discounted by session exposure (a stolen session
    bypasses credential-based controls — see the curated knowledge graph).

    ``exposure`` is the PRE-mitigation total (criticality-scaled evidence PLUS
    the Phase 6b dependency-exposure term). The credit is capped at
    ``max_mitigation_credit`` of that total, so a control can offset at most
    45% of what the model says the (importance adjusted) situation is worth —
    mitigations never erase the evidence, graph-derived or otherwise.
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


def _uncertainty_notes(
    events: list[SecurityEventSchema],
    criticality: int | None,
    dependency_status: str | None = None,
) -> list[str]:
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
    if dependency_status == "UNAVAILABLE":
        notes.append(
            "The organization's dependency graph could not be evaluated, so "
            "the score was not adjusted for potential exposure paths through "
            "declared relationships. Unavailable is not the same as safe."
        )
    elif dependency_status == "NO_ORGANIZATION":
        notes.append(
            "No organization context was available, so no dependency-graph "
            "input could be resolved and the score was not adjusted for "
            "potential exposure paths. This is an unknown input, not an "
            "absence of exposure."
        )
    missing = _unavailable_inputs(events)
    if missing:
        notes.append(
            f"{len(missing)} input check(s) were unavailable or not run and "
            "contributed nothing; unavailable is not the same as safe."
        )
    return notes


# Statuses the pipeline (or a test) may hand to compute_risk. Anything else is
# a programming error — an unrecognized dependency status must never silently
# bend a score.
DEPENDENCY_EXPOSURE_STATUSES = frozenset({
    "AVAILABLE",          # graph evaluated; intensity is the documented d
    "NO_AFFECTED_ASSET",  # no registered asset bound to the findings
    "NO_ORGANIZATION",    # run has no org context -> graph cannot be read
    "UNAVAILABLE",        # graph build failed / too large -> unknown input
    "DISABLED",           # config flag off (ablation) -> term excluded on purpose
    "NOT_PROVIDED",       # caller did not evaluate the graph (engine-level use)
})

_NOT_PROVIDED_NOTE = (
    "Dependency exposure was not evaluated by this caller; the score "
    "excludes the graph term (0 points), which is an unevaluated input — "
    "not a statement that no exposure path exists."
)


def compute_risk(
    events: list[SecurityEventSchema],
    *,
    criticality: int | None = None,
    dependency: dict | None = None,
) -> RiskBreakdown:
    """Score one run's findings with full traceability.

    ``criticality`` is resolved SERVER-SIDE by the pipeline from the calling
    organization's registered assets (see ``pipeline.resolve_run_criticality``)
    — never from anything a client sends. ``None`` means no registered asset
    was bound to the findings; the score is then simply unadjusted.

    ``dependency`` is the Phase 6b graph context resolved SERVER-SIDE by
    ``pipeline.resolve_org_dependency_exposure`` (org-scoped, documented edges
    only). It must carry a ``status`` from
    :data:`DEPENDENCY_EXPOSURE_STATUSES`; when ``status == "AVAILABLE"`` it
    must also carry ``intensity`` (d ∈ [0,1]), which is merged into the feature
    vector. Any other status contributes 0 points and is recorded in
    ``components["dependency_exposure"]`` with an explicit note — an unknown
    graph is never scored as an absent one.
    """
    features = extract_features(events)

    if dependency is None:
        dep_context: dict = {
            "status": "NOT_PROVIDED",
            "intensity": None,
            "points": 0.0,
            "note": _NOT_PROVIDED_NOTE,
        }
    else:
        dep_context = dict(dependency)
        status = dep_context.get("status")
        if status not in DEPENDENCY_EXPOSURE_STATUSES:
            raise ValueError(
                f"unknown dependency-exposure status {status!r}; "
                f"expected one of {sorted(DEPENDENCY_EXPOSURE_STATUSES)}"
            )
        if status == "AVAILABLE":
            intensity = dep_context.get("intensity")
            if intensity is None:
                raise ValueError(
                    "dependency-exposure status 'AVAILABLE' requires an intensity"
                )
            features[DEPENDENCY_EXPOSURE_FEATURE] = float(intensity)
        else:
            # Non-AVAILABLE statuses never carry points; keep any stray value
            # out of the vector so the recorded status and the math agree.
            dep_context["intensity"] = None
        dep_context.setdefault("points", 0.0)

    score, breakdown = risk_from_features(features, criticality=criticality)
    # Keep the recorded points in step with what the formula actually applied.
    dep_context["points"] = breakdown["dependency_exposure"]
    low, high = _sensitivity_range(features, criticality=criticality)
    return RiskBreakdown(
        base_risk=breakdown["base_risk"],
        interaction_risk=breakdown["interaction_risk"],
        mitigation_credit=breakdown["mitigation_credit"],
        criticality_adjustment=breakdown["criticality_adjustment"],
        dependency_exposure=breakdown["dependency_exposure"],
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
            # Phase 6b graph context: status, intensity, points, provenance of
            # the input and the honest note for whatever could not be resolved.
            "dependency_exposure": dep_context,
            # Every event id this calculation consumed (findings, mitigation
            # checks, and non-answers alike) — sorted, so equal inputs give
            # equal traces regardless of storage order.
            "finding_ids": sorted({e.event_id for e in events}),
            "interaction_terms": _interaction_terms(features),
            "unavailable_inputs": _unavailable_inputs(events),
            "uncertainty": _uncertainty_notes(
                events, criticality, dep_context.get("status")
            ),
        },
    )