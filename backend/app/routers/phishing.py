"""Phishing / scam analysis endpoints (§3.C, §6.C).

Two flows share one submission contract:

* ``post /phishing/analyze``       — inspect text and/or a URL; nothing persisted.
* ``post /phishing/{account}/record`` — inspect AND persist normalized events for
  an owned account (repeat submissions for the same account replace the module's
  events — repeat submissions never inflate risk).

Honesty: the classifier's label and each configured threat feed's verdict are
kept separate; a failed/missing provider never becomes SAFE (§3 data rules).
The submitted message text is never stored — only derived, structured signals.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, events
from app.config import Settings, get_settings
from app.db import get_db
from app.deps import get_current_user
from app.engine import normalizer
from app.models import SecurityEvent, User
from app.rate_limit import client_ip, enforce, phishing_analyze_limiter
from app.routers.accounts import _get_owned_account
from app.schemas import (
    PhishingAnalyzeRequest,
    PhishingAnalyzeResponse,
    UrlProviderResult,
)
from app.signals.phishing import analyze_text, artifacts_available, build_phishing_events
from app.signals.url_intel import (
    ProviderVerdict,
    aggregate_outcome,
    build_url_events,
    check_url,
    extract_urls,
    host_of,
    redact_url,
)

router = APIRouter(prefix="/api/signals", tags=["phishing"])

_PHISHING_EVENT_TYPES = [
    "PHISHING_MESSAGE_DETECTED",
    "AI_GENERATED_MESSAGE_DETECTED",
    "PHISHING_URL_DETECTED",
]


@router.get("/phishing/status")
def phishing_status(settings: Settings = Depends(get_settings)) -> dict:
    return {
        "artifacts_available": artifacts_available(),
        "providers_configured": {
            "phishtank": settings.phishtank_enabled,
            "urlhaus": settings.urlhaus_enabled and bool(settings.urlhaus_api_key),
        },
        "note": "Run scripts/train_phishing.py to train the classifier before analysis.",
    }


def _run_text_classifier(text: str) -> PhishingAnalyzeResponse:
    """Text classification keeps its product identity even when only a URL was
    submitted: with no text the classifier is simply NOT_RUN — never a fake
    verdict about the URL."""
    if not text.strip():
        return PhishingAnalyzeResponse(
            label="NOT_RUN",
            confidence=0.0,
            ai_generated_label=None,
            ai_generated_confidence=None,
            model_version="tfidf-lr-v1",
            signals=[],
            provenance="No message text was submitted; the text classifier did not run.",
            note="This is not a verdict about the submitted URL.",
        )
    return analyze_text(text)


def _run_url_checks(
    url_field: str, text: str, settings: Settings
) -> tuple[dict[str, dict], list[UrlProviderResult]]:
    """Validate + look up the explicit ``url`` field and every URL extracted
    from the text. Returns ``{redacted_url: report}`` keyed by the REDACTED url
    for response stability. Validation errors are surfaced, never silent.
    """
    candidates: list[str] = []
    if url_field.strip():
        candidates.append(url_field.strip())
    candidates.extend(extract_urls(text))

    seen: set[str] = set()
    reports: dict[str, dict] = {}
    for raw in candidates:
        normalized, error, verdicts = check_url(raw, settings=settings)
        if error:
            redacted, _ = redact_url(raw[:2048])
            key = redacted or raw[:64]
            if key not in seen:
                seen.add(key)
                reports[key] = {
                    "url_valid": False,
                    "validation_error": error,
                    "url_redacted": redacted,
                    "provider_results": [],
                    "aggregate_outcome": "UNAVAILABLE",
                }
            continue
        if normalized is None:
            continue
        redacted, _count = redact_url(normalized)
        key = redacted
        if key in seen:
            continue
        seen.add(key)
        reports[key] = {
            "url_valid": True,
            "url_redacted": redacted,
            "url_host": host_of(redacted),
            "provider_results": [v.to_api(redacted) for v in verdicts],
            "aggregate_outcome": aggregate_outcome(verdicts),
        }
    return reports, [
        UrlProviderResult(
            provider=_first(entry, "provider", default="none"),
            provider_label=_first(entry, "provider_label", default=entry.get("url_host") or "url"),
            outcome=entry["aggregate_outcome"],
            reason=_first(entry, "reason", default=""),
            url_redacted=entry.get("url_redacted", ""),
            evidence=entry,
        )
        for entry in reports.values()
    ]


def _first(entry: dict, key: str, *, default: str) -> str:
    """The value from the DECISIVE provider's row first (FINDING/REPORTED),
    then any row — so the human-readable provider name matches the outcome."""
    rows = list(entry.get("provider_results", []))
    for provider_result in rows:
        if provider_result.get("outcome") in ("FINDING", "REPORTED_UNVERIFIED"):
            value = provider_result.get(key, "")
            if value:
                return str(value)[:80]
    for provider_result in rows:
        value = provider_result.get(key, "")
        if value:
            return str(value)[:80]
    return default


@router.post("/phishing/analyze", response_model=PhishingAnalyzeResponse)
def analyze(
    payload: PhishingAnalyzeRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> PhishingAnalyzeResponse:
    enforce(
        phishing_analyze_limiter,
        request,
        limit=settings.phishing_analyze_rate_limit_per_minute,
    )
    result = _run_text_classifier(payload.text)
    reports, url_providers = _run_url_checks(payload.url, payload.text, settings)
    result.url_report = url_providers
    # We do NOT store the raw message text; only derived, structured signals.
    audit.record(
        db, action="signal.phishing.analyze", user_id=current_user.id,
        ip_address=client_ip(request),
        detail={
            "label": result.label,
            "model_version": result.model_version,
            "urls_checked": len(reports),
        },
    )
    return result


@router.post("/phishing/{account_id}/record")
def record_analysis(
    account_id: str,
    payload: PhishingAnalyzeRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> dict:
    """Run analysis and persist it as normalized events for an owned account
    (path account id must belong to the caller). Raw text is discarded after
    scoring; only structured signals are stored. URL findings bind by the URL
    host identity so a registered DOMAIN/WEBMAIL asset with that exact identity
    picks them up in the same organization."""
    enforce(
        phishing_analyze_limiter,
        request,
        limit=settings.phishing_analyze_rate_limit_per_minute,
    )
    account = _get_owned_account(db, current_user.id, account_id)
    result = _run_text_classifier(payload.text)
    reports, url_providers = _run_url_checks(payload.url, payload.text, settings)
    result.url_report = url_providers

    schemas = build_phishing_events(
        user_id=current_user.id, account_id=account.account_id, text=payload.text, result=result
    ) if payload.text.strip() else []

    from app.signals.url_intel import ProviderVerdict

    for entry in reports.values():
        if not entry.get("url_valid"):
            # A URL that failed validation is reported to the caller in the
            # response never stored — it is not evidence about the company.
            continue
        verdicts = [
            ProviderVerdict(
                provider=pr["provider"],
                outcome=pr["outcome"],
                reason=pr.get("reason", ""),
                evidence=pr.get("evidence", {}),
            )
            for pr in entry.get("provider_results", [])
        ]
        # URL findings are identified by the host they impersonate (bounded to
        # the 64-char identity column), so a registered asset carrying that
        # exact identity picks the finding up; otherwise it stays unbound
        # (asset_id NULL) — never attached to a guessed asset.
        target_account = entry.get("url_host", "")[:64] or account.account_id
        schemas.extend(
            build_url_events(
                user_id=current_user.id,
                account_id=target_account,
                redacted_url=entry["url_redacted"],
                verdicts=verdicts,
            )
        )

    # URL findings are keyed to the host they impersonate, which can differ
    # from the submission account. Replace them per target identity so a
    # repeat URL check never accumulates duplicate findings (§10.6): the
    # module's events for this (user, host) pair are deleted before insert —
    # the same invariant replace_module_events applies to account events.
    url_targets = {
        (entry.get("url_host", "")[:64] or account.account_id)
        for entry in reports.values()
        if entry.get("url_valid")
    }
    for target in url_targets:
        for stale in db.scalars(
            select(SecurityEvent).where(
                SecurityEvent.user_id == current_user.id,
                SecurityEvent.event_type == events.PHISHING_URL_DETECTED,
                SecurityEvent.account_id == target,
            )
        ).all():
            db.delete(stale)

    rows = normalizer.replace_module_events(
        db, current_user.id, account.account_id, _PHISHING_EVENT_TYPES, schemas
    )
    audit.record(
        db, action="signal.phishing.record", user_id=current_user.id,
        ip_address=client_ip(request),
        detail={
            "account_id": account.account_id,
            "label": result.label,
            "urls_checked": len(reports),
            "events_stored": len(rows),
        },
    )
    return {
        "result": result.model_dump(),
        "events": [normalizer.schema_to_response(normalizer.to_schema(row)) for row in rows],
    }
