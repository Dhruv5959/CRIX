"""Declarative correlation engine (§5).

Rules live in ``app/data/correlation_rules.yaml`` as DATA. This module contains
NO hardcoded correlation conditionals — it interprets the rule schema uniformly.
Adding a correlation means editing the YAML, not the Python.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.data.loader import correlation_rules
from app.schemas import SecurityEventSchema


@dataclass
class Correlation:
    rule_id: str
    title: str
    correlation_type: str
    severity: float
    confidence: float
    explanation: str
    contributing_event_ids: list[str]


def _predicate_matches(predicate: dict, event: SecurityEventSchema) -> bool:
    if event.event_type != predicate["event_type"]:
        return False
    if event.status != "FINDING":
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


def evaluate(events: list[SecurityEventSchema]) -> list[Correlation]:
    """Run every declarative rule. Correlations are evaluated per account so a
    finding on one account never borrows severity from another."""
    by_account: dict[str, list[SecurityEventSchema]] = {}
    for event in events:
        by_account.setdefault(event.account_id, []).append(event)

    correlations: list[Correlation] = []
    for rule in correlation_rules():
        predicates = rule["predicates"]
        for account_id, account_events in by_account.items():
            matched: list[SecurityEventSchema] = []
            all_predicates_met = True
            for predicate in predicates:
                hits = [e for e in account_events if _predicate_matches(predicate, e)]
                if hits:
                    matched.extend(hits)
                else:
                    all_predicates_met = False
                    break
            if not all_predicates_met:
                continue
            # Deduplicate contributing events (an event may satisfy 1 predicate).
            seen: dict[str, SecurityEventSchema] = {e.event_id: e for e in matched}
            contributing = list(seen.values())
            correlations.append(
                Correlation(
                    rule_id=rule["rule_id"],
                    title=rule["title"],
                    correlation_type=rule["correlation_type"],
                    severity=_severity(rule, contributing),
                    confidence=_confidence(rule, contributing),
                    explanation=rule["explanation"].strip(),
                    contributing_event_ids=[e.event_id for e in contributing],
                )
            )
    correlations.sort(key=lambda c: c.severity, reverse=True)
    return correlations


def describe_rules() -> list[dict]:
    """Human-readable rule catalog for the UI/tests."""
    return [
        {
            "rule_id": rule["rule_id"],
            "title": rule["title"],
            "correlation_type": rule["correlation_type"],
            "predicates": [p["event_type"] for p in rule["predicates"]],
            "explanation": rule["explanation"].strip(),
        }
        for rule in correlation_rules()
    ]