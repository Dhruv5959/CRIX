"""Declarative correlation engine (§5, reworked for Phase 3).

Rules live in ``app/data/correlation_rules.yaml`` as DATA. This module contains
NO hardcoded correlation conditionals — it interprets the rule schema uniformly.
Adding a correlation means editing the YAML, not the Python.

Phase 3 guarantees (each one is covered by ``tests/test_correlation_org.py``):

* **No cross-org correlation.** Findings are grouped by organization FIRST; a
  finding whose organization is unknown is excluded (fail-closed) instead of
  being mixed with another tenant's findings. Two findings that share an
  account id but belong to different organizations never correlate.
* **Explicit scope.** ``same_account`` (default), ``same_asset`` (every finding
  must be bound to the SAME registered company asset) or ``linked_assets``
  (the two assets are joined by an ADMIN-DECLARED dependency edge — CRIX never
  invents an edge from name similarity).
* **Stable identity.** ``correlation_id`` is a deterministic hash of
  (org_id | rule_id | rule_version | sorted finding ids). Re-evaluating the
  same findings yields the same id, so persistence upserts instead of
  duplicating, and identical repeats are recognizably identical.
* **No duplication or mutation of findings.** A correlation only REFERENCES the
  finding ids it combined plus the small set of facts it cites as evidence;
  findings themselves are never copied, moved or rewritten.
* **Explicit result.** Every correlation carries: stable ``correlation_id``,
  ``org_id``, ``rule_id`` + ``rule_version``, ``finding_ids``, ``asset_ids``,
  ``evidence``, ``explanation`` (rendered from the rule template with the real
  values), ``chain`` (the reasoning in plain language), ``evaluated_at``, and
  ``confidence`` with an explicit ``uncertainty`` statement of what that
  confidence means and does not mean.
* **Deterministic ordering.** Results are sorted by ``(-severity, rule_id,
  correlation_id)`` — never by dict/set iteration order.

Severity and confidence are computed by the SAME formulas as before this phase
(base + per_event with documented multipliers; min/max/mean confidence).
Phase 3 adds organization scope and explicitness, **not** new risk: a
correlation never adds a bonus and the risk engine does not consume it.
"""
from __future__ import annotations

import datetime as dt
import hashlib
from dataclasses import dataclass
from typing import Iterable, Sequence

from app.data.loader import correlation_rules
from app.schemas import SecurityEventSchema

DEFAULT_SCOPE = "same_account"
KNOWN_SCOPES = ("same_account", "same_asset", "linked_assets")

#: Template placeholders a rule explanation may use. ``tests/test_correlation_org.py``
#: fails if a rule template references anything outside this set.
TEMPLATE_KEYS = (
    "asset_id",
    "asset_ids",
    "account_id",
    "org_id",
    "finding_ids",
    "first_seen",
    "last_seen",
    "window_hours",
)

UNCERTAINTY_NOTE = (
    "Correlation confidence aggregates how strong the contributing findings are "
    "as observations. It is not a forecast that anything will happen."
)


@dataclass
class Correlation:
    """One rule firing over a set of findings in exactly one organization."""

    correlation_id: str
    org_id: str
    rule_id: str
    rule_version: str
    title: str
    correlation_type: str
    severity: float
    confidence: float
    uncertainty: dict
    explanation: str
    chain: list[str]
    finding_ids: list[str]
    asset_ids: list[str]
    evidence: dict
    evaluated_at: dt.datetime

    # Backward-compatible alias: the pre-Phase-3 field name. Same list.
    @property
    def contributing_event_ids(self) -> list[str]:
        return self.finding_ids


# --------------------------------------------------------------------------- #
# Predicate interpretation (uniform; no per-rule branching)
# --------------------------------------------------------------------------- #
def _predicate_matches(predicate: dict, event: SecurityEventSchema) -> bool:
    if event.event_type != predicate["event_type"]:
        return False
    if event.status != predicate.get("status", "FINDING"):
        return False
    if "exposure_type" in predicate:
        allowed = predicate["exposure_type"]
        if isinstance(allowed, str):
            allowed = [allowed]
        if event.exposure_type is None or event.exposure_type.value not in allowed:
            return False
    if "metadata" in predicate:
        for key, expected in predicate["metadata"].items():
            if event.metadata.get(key) != expected:
                return False
    return True


def _severity(rule: dict, matched_events: list[SecurityEventSchema]) -> float:
    logic = rule["severity"]
    value = float(logic["base"]) + float(logic.get("per_event", 0.0)) * max(
        0, len(matched_events) - 1
    )
    for multiplier in logic.get("multiplier_rules", []):
        when = multiplier.get("when", {})
        if _multiplier_applies(when, matched_events):
            value *= float(multiplier["factor"])
    return round(min(float(logic.get("cap", 1.0)), value), 4)


def _multiplier_applies(when: dict, matched_events: list[SecurityEventSchema]) -> bool:
    exposure_types = when.get("exposure_type")
    if exposure_types is not None:
        if isinstance(exposure_types, str):
            exposure_types = [exposure_types]
        for event in matched_events:
            if event.exposure_type and event.exposure_type.value in exposure_types:
                return True
    return False


def _confidence(rule: dict, matched_events: list[SecurityEventSchema]) -> float:
    aggregation = rule.get("confidence", "min")
    if not matched_events:
        return 0.0
    values = [event.confidence for event in matched_events]
    if aggregation == "min":
        return round(min(values), 4)
    if aggregation == "max":
        return round(max(values), 4)
    return round(sum(values) / len(values), 4)


# --------------------------------------------------------------------------- #
# Scope grouping (organization first — this is where cross-org mixing is
# structurally impossible)
# --------------------------------------------------------------------------- #
def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


def _iso(value: dt.datetime | None) -> str | None:
    return None if value is None else _as_utc(value).isoformat()


def _scope_of(rule: dict) -> str:
    scope = rule.get("scope", DEFAULT_SCOPE)
    if scope not in KNOWN_SCOPES:
        raise ValueError(
            f"rule {rule.get('rule_id')!r} declares unknown scope {scope!r}; "
            f"expected one of {sorted(KNOWN_SCOPES)}"
        )
    return scope


def _groups(
    rule: dict,
    events: list[SecurityEventSchema],
    declared_asset_dependencies: Sequence[tuple[str, str, str]],
) -> list[tuple[str, list[SecurityEventSchema], dict]]:
    """Partition findings into the candidate sets a rule may combine.

    Returns ``(group_key, group_events, context)`` triples. Events without a
    resolved ``org_id`` never enter a group (fail-closed: an unknown
    organization can never be correlated with anything).
    """
    scope = _scope_of(rule)
    grouped: list[tuple[str, list[SecurityEventSchema], dict]] = []

    if scope == "same_account":
        bucket: dict[tuple[str, str], list[SecurityEventSchema]] = {}
        for event in events:
            if not event.org_id:
                continue
            bucket.setdefault((event.org_id, event.account_id), []).append(event)
        for (org_id, account_id), group in sorted(bucket.items()):
            grouped.append(
                (
                    f"{scope}:{org_id}:{account_id}",
                    group,
                    {"scope": scope, "org_id": org_id, "account_id": account_id},
                )
            )
        return grouped

    if scope == "same_asset":
        bucket = {}
        for event in events:
            if not event.org_id or not event.asset_id:
                continue
            bucket.setdefault((event.org_id, event.asset_id), []).append(event)
        for (org_id, asset_id), group in sorted(bucket.items()):
            grouped.append(
                (
                    f"{scope}:{org_id}:{asset_id}",
                    group,
                    {"scope": scope, "org_id": org_id, "asset_id": asset_id},
                )
            )
        return grouped

    # linked_assets: only edges the company declared. The caller (the pipeline)
    # resolves them from ``asset_dependencies`` inside the caller's own
    # organization, so an edge can never cross tenants or be inferred.
    pairs = sorted(
        {
            (org_id, from_asset_id, to_asset_id)
            for org_id, from_asset_id, to_asset_id in declared_asset_dependencies
            if org_id and from_asset_id and to_asset_id and from_asset_id != to_asset_id
        }
    )
    for org_id, from_asset_id, to_asset_id in pairs:
        endpoints = {from_asset_id, to_asset_id}
        group = [
            e for e in events if e.org_id == org_id and e.asset_id in endpoints
        ]
        if group:
            grouped.append(
                (
                    f"{scope}:{org_id}:{from_asset_id}:{to_asset_id}",
                    group,
                    {
                        "scope": scope,
                        "org_id": org_id,
                        "from_asset_id": from_asset_id,
                        "to_asset_id": to_asset_id,
                    },
                )
            )
    return grouped


# --------------------------------------------------------------------------- #
# Explanation, chain, evidence (all cite the findings actually matched)
# --------------------------------------------------------------------------- #
def _template_context(
    rule: dict,
    matched: list[SecurityEventSchema],
    group_context: dict,
    window_hours: float | None,
    first_seen: dt.datetime | None,
    last_seen: dt.datetime | None,
) -> dict[str, str]:
    asset_ids = sorted({e.asset_id for e in matched if e.asset_id})
    account_ids = sorted({e.account_id for e in matched})
    finding_ids = sorted(e.event_id for e in matched)
    return {
        "asset_id": ", ".join(asset_ids),
        "asset_ids": ", ".join(asset_ids),
        "account_id": ", ".join(account_ids),
        "org_id": group_context.get("org_id", ""),
        "finding_ids": ", ".join(finding_ids),
        "first_seen": _iso(first_seen) or "",
        "last_seen": _iso(last_seen) or "",
        "window_hours": "" if window_hours is None else str(window_hours),
    }


def _render(template: str, context: dict[str, str]) -> str:
    """Fill ``{placeholder}`` values. Unknown placeholders are left literal so a
    rule typo is visible (and caught by the rule-template test) instead of
    silently producing an empty sentence."""
    out = template
    for key, value in context.items():
        out = out.replace("{" + key + "}", value)
    return out


def _chain(
    rule: dict,
    group_context: dict,
    matched: list[SecurityEventSchema],
    window_hours: float | None,
    first_seen: dt.datetime | None,
    last_seen: dt.datetime | None,
) -> list[str]:
    """The reasoning as plain-language steps: what was combined and why it is
    allowed to be combined. No scores, no claims beyond the findings."""
    scope = group_context["scope"]
    org_id = group_context["org_id"]
    steps: list[str] = []
    for event in sorted(matched, key=lambda e: e.event_id):
        where = (
            f"company asset {event.asset_id}"
            if event.asset_id
            else f"account {event.account_id}"
        )
        seen = _iso(event.first_seen or event.detected_at)
        steps.append(
            f"{event.event_type} finding {event.event_id} on {where} "
            f"(status {str(event.status)}, source {event.source}, observed {seen})."
        )
    if scope == "same_account":
        steps.append(
            f"Both findings belong to account {group_context['account_id']} in "
            f"organization {org_id}, so the rule combines them."
        )
    elif scope == "same_asset":
        steps.append(
            f"Both findings are attached to the same registered company asset "
            f"{group_context['asset_id']} in organization {org_id}."
        )
    else:
        steps.append(
            f"The company declared that asset {group_context['from_asset_id']} "
            f"depends on asset {group_context['to_asset_id']} "
            f"(organization {org_id}); the findings sit on those two assets."
        )
    if window_hours is not None:
        steps.append(
            f"The observations fall within the rule's {int(window_hours)}-hour "
            f"window ({_iso(first_seen)} to {_iso(last_seen)})."
        )
    steps.append(
        f"Rule {rule['rule_id']} v{rule['version']} combined exactly these "
        f"findings; severity and confidence were computed from them server-side."
    )
    return steps


def _evidence(
    rule: dict,
    group_context: dict,
    matched: list[SecurityEventSchema],
    window_hours: float | None,
    first_seen: dt.datetime | None,
    last_seen: dt.datetime | None,
) -> dict:
    """The small set of facts this correlation cites. Per-finding evidence stays
    on the findings — it is never copied here."""
    evidence: dict = {
        "scope": group_context["scope"],
        "rule_id": rule["rule_id"],
        "rule_version": rule["version"],
        "matched_event_types": sorted({e.event_type for e in matched}),
        "matched_sources": sorted({e.source for e in matched}),
        "source_modes": sorted({str(e.source_mode) for e in matched}),
        "asset_ids": sorted({e.asset_id for e in matched if e.asset_id}),
        "account_ids": sorted({e.account_id for e in matched}),
        "window_hours": window_hours,
        "observation_window": {
            "first_seen": _iso(first_seen),
            "last_seen": _iso(last_seen),
        },
    }
    if group_context["scope"] == "linked_assets":
        evidence["declared_dependency"] = {
            "from_asset_id": group_context["from_asset_id"],
            "to_asset_id": group_context["to_asset_id"],
            "declared_by": "organization administrator",
        }
    return evidence


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #
def evaluate(
    events: list[SecurityEventSchema],
    *,
    declared_asset_dependencies: Iterable[tuple[str, str, str]] = (),
    evaluated_at: dt.datetime | None = None,
) -> list[Correlation]:
    """Run every declarative rule.

    Findings are partitioned per organization before any rule sees them, so a
    finding on one tenant's account never borrows severity from another
    tenant's, and a finding with no resolved organization is excluded
    (fail-closed) rather than guessed.

    ``declared_asset_dependencies`` are ``(org_id, from_asset_id, to_asset_id)``
    triples the pipeline resolved from the ``asset_dependencies`` table of the
    caller's organization. They are the ONLY relationships a ``linked_assets``
    rule may use.
    """
    deps = list(declared_asset_dependencies)
    evaluated_at = evaluated_at or dt.datetime.now(dt.timezone.utc)
    correlations: list[Correlation] = []

    for rule in correlation_rules():
        predicates = rule["predicates"]
        window_hours = rule.get("window_hours")
        window_delta = (
            dt.timedelta(hours=float(window_hours)) if window_hours is not None else None
        )

        for _group_key, group_events, group_context in _groups(rule, events, deps):
            matched: list[SecurityEventSchema] = []
            all_predicates_met = True
            for predicate in predicates:
                hits = [
                    e for e in group_events if _predicate_matches(predicate, e)
                ]
                if len(hits) < int(predicate.get("min_events", 1)):
                    all_predicates_met = False
                    break
                matched.extend(hits)
            if not all_predicates_met:
                continue

            # Deduplicate (one event may satisfy several predicates) and impose
            # a deterministic order before anything else reads the list.
            deduped = {e.event_id: e for e in matched}
            contributing = [deduped[k] for k in sorted(deduped)]

            first_seen = min((_as_utc(e.first_seen or e.detected_at) for e in contributing), default=None)
            last_seen = max((_as_utc(e.last_seen or e.detected_at) for e in contributing), default=None)
            if window_delta is not None and first_seen is not None and last_seen is not None:
                if last_seen - first_seen > window_delta:
                    continue

            severity = _severity(rule, contributing)
            confidence = _confidence(rule, contributing)
            aggregation = rule.get("confidence", "min")
            context = _template_context(
                rule, contributing, group_context, window_hours, first_seen, last_seen
            )
            finding_ids = [e.event_id for e in contributing]
            asset_ids = sorted({e.asset_id for e in contributing if e.asset_id})

            correlations.append(
                Correlation(
                    correlation_id=_correlation_id(
                        group_context["org_id"], rule["rule_id"], rule["version"], finding_ids
                    ),
                    org_id=group_context["org_id"],
                    rule_id=rule["rule_id"],
                    rule_version=rule["version"],
                    title=rule["title"],
                    correlation_type=rule["correlation_type"],
                    severity=severity,
                    confidence=confidence,
                    uncertainty={
                        "basis": f"{aggregation}_of_contributing_finding_confidence",
                        "value": confidence,
                        "note": UNCERTAINTY_NOTE,
                    },
                    explanation=_render(rule["explanation"].strip(), context),
                    chain=_chain(rule, group_context, contributing, window_hours, first_seen, last_seen),
                    finding_ids=finding_ids,
                    asset_ids=asset_ids,
                    evidence=_evidence(
                        rule, group_context, contributing, window_hours, first_seen, last_seen
                    ),
                    evaluated_at=evaluated_at,
                )
            )

    correlations.sort(key=lambda c: (-c.severity, c.rule_id, c.correlation_id))
    return correlations


def _correlation_id(org_id: str, rule_id: str, version: str, finding_ids: list[str]) -> str:
    """Stable identity: the same findings + rule + version always produce the
    same id, in any organization, at any time."""
    key = "|".join([org_id, rule_id, version, *sorted(finding_ids)])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def describe_rules() -> list[dict]:
    """Human-readable rule catalog for the UI/tests."""
    return [
        {
            "rule_id": rule["rule_id"],
            "version": rule["version"],
            "title": rule["title"],
            "correlation_type": rule["correlation_type"],
            "scope": _scope_of(rule),
            "window_hours": rule.get("window_hours"),
            "predicates": [p["event_type"] for p in rule["predicates"]],
            "explanation": rule["explanation"].strip(),
        }
        for rule in correlation_rules()
    ]
