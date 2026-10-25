"""Threat-intelligence checks for employee-submitted URLs (§6.C).

Submission semantics (§6.C): an authorized member can submit suspicious text
and/or a URL. CRIX NEVER opens the URL locally — no fetch, no redirect walk,
no HTML parse. The URL string is only:

1. syntax-validated and normalized,
2. compared against the deterministic message classifier's extracted signals,
3. POSTed verbatim (minus nothing sensitive: the URL is what the employee
   already received) to configured threat feeds — PhishTank (optional app key)
   and/or URLhaus (requires a free auth key, so it is opt-in),
4. normalized into SecurityEventSchema findings with per-provider evidence.

Honesty contract — hard rules enforced here:

* every failure mode (429, timeout, invalid JSON, network error, 5xx) returns
  ``UNAVAILABLE`` for that provider — never "clean";
* "no match" is reported as ``NO_MATCH_IN_CONFIGURED_FEEDS`` — a feed miss is
  NOT safety;
* if two providers disagree, both verdicts are kept side by side; no single
  most-reassuring answer is selected;
* if no provider is configured, external checks are ``UNAVAILABLE`` while the
  local classifier still runs;
* the module never invents a numeric risk score: the deterministic engine in
  ``app/engine/risk.py`` remains the only scorer;
* redaction: URLs stored in events/evidence carry no query values (keys are
  kept, values replaced) and never any userinfo, so `?token=...`-style links
  can't leak credentials into the database, API responses or logs.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import httpx

from app import events
from app.config import Settings, get_settings
from app.rate_limit import RateLimiter
from app.schemas import EventStatus, SecurityEventSchema, SourceMode

USER_AGENT = "CRIX-Capstone/0.1 (security-signal-correlator)"

PROVIDER_LABELS = {
    "phishtank": "PhishTank (OpenPhish-community URL feed)",
    "urlhaus": "URLhaus (abuse.ch URL database)",
}

FINDING = "FINDING"
REPORTED_UNVERIFIED = "REPORTED_UNVERIFIED"
NO_MATCH = "NO_MATCH_IN_CONFIGURED_FEEDS"
UNAVAILABLE = "UNAVAILABLE"
NOT_CONFIGURED = "NOT_CONFIGURED"

_URL_RE = re.compile(r"(?:https?://|www\.)[^\s\"'<>()\[\]]+", re.IGNORECASE)

# Outbound throttle state is process-wide and reset by tests.
_per_hour: dict[str, RateLimiter] = {
    "phishtank": RateLimiter(),
    "urlhaus": RateLimiter(),
}
_cooldown_until: dict[str, float] = {"phishtank": 0.0, "urlhaus": 0.0}


def reset_provider_state() -> None:
    for limiter in _per_hour.values():
        limiter.reset()
    for key in _cooldown_until:
        _cooldown_until[key] = 0.0


@dataclass(frozen=True)
class ProviderVerdict:
    """One provider's verdict for one URL. A value, never an exception."""

    provider: str
    outcome: str
    reason: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    rate_limited: bool = False

    def to_api(self, url_redacted: str) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "provider_label": PROVIDER_LABELS.get(self.provider, self.provider),
            "outcome": self.outcome,
            "reason": self.reason,
            "url_redacted": url_redacted,
            "evidence": self.evidence,
        }


# --------------------------------------------------------------------------- #
# URL handling: extraction, validation, normalization, redaction
# --------------------------------------------------------------------------- #

def extract_urls(text: str) -> list[str]:
    """Extract candidate URLs from untrusted text. No scheme invention beyond
    the ``www.`` shorthand mainstream clients already auto-link."""
    if not isinstance(text, str) or not text:
        return []
    candidates: list[str] = []
    for match in _URL_RE.findall(text):
        candidate = match.rstrip(".,;:!?)>'\"")
        if candidate:
            candidates.append(candidate)
    return candidates


def normalize_and_validate_url(raw: str) -> tuple[str | None, str | None]:
    """Validate an untrusted URL string; return ``(scheme_added_form, error)``.

    * schemes limited to http/https (no file:, data:, ftp:, ws:) — this module
      only ever POSTs the string to threat feeds, but validation keeps the
      data contract narrow anyway;
    * userinfo (`user:pass@`) is rejected outright — treat it as malformed
      rather than laundering credentials into lookups or storage;
    * a host is mandatory, IDs/punycode pass through unchanged;
    * max length 2048 (schema-bounded; defense in depth here).
    """
    raw = (raw or "").strip()
    if not raw:
        return None, "empty URL."
    if len(raw) > 2048:
        return None, "URL exceeds the 2048-character limit."
    candidate = raw
    if not re.match(r"[a-zA-Z][a-zA-Z0-9+.\-]*:", raw):
        candidate = "https://" + raw  # www.-style shorthand keeps working
    try:
        parts = urlsplit(candidate)
    except ValueError as exc:  # malformed IPv6 etc.
        return None, f"URL failed to parse ({type(exc).__name__})."
    if parts.scheme.lower() not in ("http", "https"):
        return None, "Only http:// and https:// URLs are accepted."
    if not parts.netloc:
        return None, "URL has no host."
    if "@" in parts.netloc:
        return None, "URLs containing userinfo (credentials) are rejected."
    try:
        host = parts.hostname
    except ValueError:
        return None, "URL host could not be parsed."
    if not host:
        return None, "URL has no host."
    rebuilt = urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, ""))
    return rebuilt, None


def redact_url(url: str) -> tuple[str, int]:
    """Redact query values and drop fragments; keep scheme/host/path/keys.

    Returns ``(redacted, redacted_value_count)``. ``?ticket=xxx&loid=yyy``
    becomes ``?ticket=[REDACTED]&loid=[REDACTED]``. Fragment (#...) is
    client-only, unverifiable, and commonly a token — dropped entirely.
    """
    if not url:
        return "", 0
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    redacted_pairs = [(k, "[REDACTED]") for k, _ in pairs]
    # quote_via identity: "[REDACTED]" stays literal — it is CRIX's own marker,
    # and re-encoding would hide which parts were redacted from evidence readers.
    cleaned = urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path, urlencode(redacted_pairs, quote_via=lambda value, *a, **kw: value), "")
    )
    return cleaned, len(redacted_pairs)


def host_of(url: str) -> str:
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        host = ""
    return host.lower()


# --------------------------------------------------------------------------- #
# Provider clients
# --------------------------------------------------------------------------- #

def _throttle_reason(provider: str, settings: Settings, clock=time.monotonic) -> str | None:
    now = clock()
    if now < _cooldown_until[provider]:
        wait = int(_cooldown_until[provider] - now) + 1
        return f"{provider} returned HTTP 429; CRIX is cooling down for ~{wait}s."
    limit = _hour_limit(provider, settings)
    if not _per_hour[provider].check(provider, limit=limit, window_seconds=3600).allowed:
        return f"{provider} budget exhausted ({limit}/hour). Retry later."
    return None


def _hour_limit(provider: str, settings: Settings) -> int:
    if provider == "phishtank":
        return max(1, settings.phishtank_requests_per_hour)
    return max(1, settings.urlhaus_requests_per_hour)


def _enter_cooldown(provider: str, retry_after: str | None, clock=time.monotonic) -> None:
    seconds = 60.0
    if retry_after:
        try:
            seconds = min(max(float(int(str(retry_after).strip())), 1.0), 3600.0)
        except (TypeError, ValueError):
            seconds = 60.0
    _cooldown_until[provider] = clock() + seconds


def _post(
    url: str,
    *,
    provider: str,
    settings: Settings,
    timeout: float,
    **request_kwargs: Any,
) -> httpx.Response | ProviderVerdict:
    """Shared POST path. On transport trouble returns an UNAVAILABLE verdict."""
    blocked = _throttle_reason(provider, settings)
    if blocked:
        return ProviderVerdict(provider, UNAVAILABLE, reason=blocked, rate_limited=True)  # type: ignore[arg-type]
    try:
        response = httpx.post(
            url,
            headers={"user-agent": USER_AGENT, "accept": "application/json"},
            timeout=timeout,
            follow_redirects=False,
            **request_kwargs,
        )
    except httpx.HTTPError as exc:
        return ProviderVerdict(provider, UNAVAILABLE, reason=f"{provider} request failed ({type(exc).__name__}).")  # type: ignore[arg-type]
    if response.status_code == 429:
        _enter_cooldown(provider, response.headers.get("Retry-After"))
        return ProviderVerdict(provider, UNAVAILABLE, rate_limited=True, reason=(
            f"{provider} rate limit reached (HTTP 429) with the configured limits."
        ))  # type: ignore[arg-type]
    return response


def check_phishtank(url: str, settings: Settings) -> ProviderVerdict:
    """PhishTank ``checkurl`` POST. Application key optional; response fields
    per PhishTank's API doc: ``results["<url>"]["in_database"|"verified"|"status"]``."""
    if not settings.phishtank_enabled:
        return ProviderVerdict("phishtank", NOT_CONFIGURED, reason="PhishTank is not enabled (CRIX_PHISHTANK_ENABLED).")
    timeout = float(settings.phishtank_timeout_seconds)
    data: dict[str, Any] = {"url": url, "format": "json"}
    if settings.phishtank_api_key:
        data["appkey"] = settings.phishtank_api_key
    response = _post(
        settings.phishtank_base_url,
        provider="phishtank",
        settings=settings,
        timeout=timeout,
        data=data,
    )
    if isinstance(response, ProviderVerdict):
        return response
    verdict = _json_or_none(response)
    if verdict is None:
        return ProviderVerdict("phishtank", UNAVAILABLE, reason=f"PhishTank returned HTTP {response.status_code} with a non-JSON body.")
    if response.status_code >= 500:
        return ProviderVerdict("phishtank", UNAVAILABLE, reason=f"PhishTank error HTTP {response.status_code}.")
    results = verdict.get("results")
    if not isinstance(results, dict) or not results:
        return ProviderVerdict("phishtank", UNAVAILABLE, reason="PhishTank returned an unrecognised response shape.")
    detail = next(iter(results.values()))
    if not isinstance(detail, dict):
        return ProviderVerdict("phishtank", UNAVAILABLE, reason="PhishTank result entry was not an object.")
    status_str = str(detail.get("status", "")).lower()
    in_database = bool(detail.get("in_database"))
    verified = detail.get("verified")
    verified_bool = bool(verified) if isinstance(verified, bool) else str(verified).lower() == "true"
    if in_database and status_str == "phish" and verified_bool:
        return ProviderVerdict("phishtank", FINDING, evidence={
            "phish_id": str(detail.get("phish_id", ""))[:32],
            "verified": True,
            "url_id": str(detail.get("url_id", ""))[:32],
        })
    if in_database and status_str == "phish":
        return ProviderVerdict("phishtank", REPORTED_UNVERIFIED, reason=(
            "PhishTank has a report for this URL but the report is not yet "
            "verified by the community. Treat as suspect, not confirmed."
        ), evidence={"phish_id": str(detail.get("phish_id", ""))[:32], "verified": False})
    if in_database:
        return ProviderVerdict("phishtank", NO_MATCH, reason=(
            "The URL is in PhishTank's database without a phish status."
        ), evidence={"phish_status": status_str[:32]})
    return ProviderVerdict("phishtank", NO_MATCH, reason=(
        "No entry for this URL in PhishTank's database."
    ), evidence={"in_database": False})


def check_urlhaus(url: str, settings: Settings) -> ProviderVerdict:
    """URLhaus URL lookup API (JSON POST). Needs a free auth key by policy, so
    it is opt-in via ``CRIX_URLHAUS_ENABLED`` + ``CRIX_URLHAUS_API_KEY``."""
    if not settings.urlhaus_enabled:
        return ProviderVerdict("urlhaus", NOT_CONFIGURED, reason="URLhaus is not enabled (CRIX_URLHAUS_ENABLED).")
    if not settings.urlhaus_api_key:
        return ProviderVerdict("urlhaus", NOT_CONFIGURED, reason="URLhaus is enabled but no auth key is configured.")
    response = _post(
        settings.urlhaus_base_url,
        provider="urlhaus",
        settings=settings,
        timeout=float(settings.urlhaus_timeout_seconds),
        json={"url": url, "auth_key": settings.urlhaus_api_key},
    )
    if isinstance(response, ProviderVerdict):
        return response
    body = _json_or_none(response)
    if body is None:
        return ProviderVerdict("urlhaus", UNAVAILABLE, reason=f"URLhaus returned HTTP {response.status_code} with a non-JSON body.")
    if response.status_code >= 500:
        return ProviderVerdict("urlhaus", UNAVAILABLE, reason=f"URLhaus error HTTP {response.status_code}.")
    if body.get("query_status") in ("ok", "ok, no_results"):
        url_status = str(body.get("url_status", "")).lower()
        if url_status in ("phishing", "malware_distribution", "malfamious"):
            return ProviderVerdict("urlhaus", FINDING, evidence={
                "url_status": url_status,
                "url_id": str(body.get("id", ""))[:32],
            })
        if url_status == "clean":
            return ProviderVerdict("urlhaus", NO_MATCH, reason="URLhaus reported this URL as clean.", evidence={"url_status": "clean"})
        # An "ok" without a usable url_status is ambiguous — never clean.
        return ProviderVerdict("urlhaus", UNAVAILABLE, reason="URLhaus returned an unrecognised url_status.")
    if body.get("query_status") == "no_results":
        return ProviderVerdict("urlhaus", NO_MATCH, reason="No entry for this URL in URLhaus (URLhaus keeps only recently reported URLs).")
    return ProviderVerdict("urlhaus", UNAVAILABLE, reason=f"URLhaus returned query_status {str(body.get('query_status'))[:32]!r}.")


def _json_or_none(response: httpx.Response):
    try:
        return response.json()
    except ValueError:
        return None


def configured_providers(settings: Settings) -> list[str]:
    configured: list[str] = []
    if settings.phishtank_enabled:
        configured.append("phishtank")
    if settings.urlhaus_enabled and settings.urlhaus_api_key:
        configured.append("urlhaus")
    return configured


def check_url(raw_url: str, settings: Settings | None = None) -> tuple[str | None, str | None, list[ProviderVerdict]]:
    """Full pipeline for ONE untrusted URL string.

    Returns ``(redacted_url_or_None, validation_error, verdicts|[])``.
    """
    settings = settings if settings is not None else get_settings()
    normalized, error = normalize_and_validate_url(raw_url)
    if error:
        return None, error, []
    redacted, _count = redact_url(normalized)  # type: ignore[arg-type]
    verdicts = [check_phishtank(normalized, settings), check_urlhaus(normalized, settings)]
    return redacted, None, verdicts


# --------------------------------------------------------------------------- #
# Event building
# --------------------------------------------------------------------------- #

def build_url_events(
    *,
    user_id: str,
    account_id: str,
    redacted_url: str,
    verdicts: list[ProviderVerdict],
) -> list[SecurityEventSchema]:
    """One aggregated PHISHING_URL_DETECTED event per URL, bound to **the
    account id the URL impersonates** (its host when the caller supplies it).

    Deliberate: the normalizer's same-org candidates are [email, account_id],
    so a host that matches a registered DOMAIN asset binds the finding to that
    exact asset — and nothing else can be claimed.
    """
    severity_by_outcome = {FINDING: 0.9, REPORTED_UNVERIFIED: 0.6}
    statuses = [v.outcome for v in verdicts]
    if FINDING in statuses or REPORTED_UNVERIFIED in statuses:
        status = EventStatus.FINDING
    elif UNAVAILABLE in statuses:
        status = EventStatus.UNAVAILABLE
    elif NO_MATCH in statuses:
        status = EventStatus.NO_MATCH_IN_CONFIGURED_FEEDS
    else:
        status = EventStatus.UNAVAILABLE
    decisive = next((v for v in verdicts if v.outcome in (FINDING, REPORTED_UNVERIFIED)), None)
    any_configured_failure = any(v.outcome == UNAVAILABLE for v in verdicts)
    severity = severity_by_outcome.get(decisive.outcome, 0.0) if decisive else 0.0
    provider_names = [v.provider for v in verdicts if v.outcome != NOT_CONFIGURED]
    event_source = decisive.provider if decisive else (provider_names[0] if provider_names else "threat_intel")
    evidence = {
        "url_redacted": redacted_url,
        "url_host": host_of(redacted_url),
        "verdicts": [v.to_api(redacted_url) for v in verdicts],
        "providers_contacted": provider_names,
        "provider_failures": [
            {"provider": v.provider, "reason": v.reason[:200]}
            for v in verdicts
            if v.outcome == UNAVAILABLE
        ],
        "never_fetched": True,
        "url_query_values_redacted": True,
    }
    provenance_parts = []
    if decisive:
        provenance_parts.append(
            f"{evidence['verdicts'][verdicts.index(decisive)]['provider_label']} "
            f"reported outcome {decisive.outcome}."
        )
    if any_configured_failure:
        provenance_parts.append(
            "Some configured feeds could not be queried; their reports stay UNAVAILABLE, "
            "never clean."
        )
    provenance_parts.append(
        "A feed match is strong evidence about the URL; a feed miss is NOT safety."
    )
    return [
        SecurityEventSchema(
            event_id=events.new_event_id(),
            user_id=user_id,
            account_id=account_id,
            event_type=events.PHISHING_URL_DETECTED,
            exposure_type=None,
            severity=round(min(max(severity, 0.0), 1.0), 4),
            confidence=0.9 if status == EventStatus.FINDING else 0.6,
            source=event_source,
            # The verdict came from a live provider call in this request — REAL
            # provenance, independent of whether that provider judged FINDING
            # or NO_MATCH (evidence records which).
            source_mode=SourceMode.REAL,
            status=status,
            evidence=events_sanitize(evidence),
            metadata={"url_redacted": redacted_url, "verdict_count": len(verdicts)},
            provenance=" ".join(provenance_parts),
        )
    ]


def events_sanitize(evidence: dict[str, Any]) -> dict[str, Any]:
    """Last-line redaction for anything that might arrive in evidence.

    The schema's ``sanitize_evidence`` already enforces denylists/length caps;
    this helper enforces the same invariant at the module boundary and strips
    query values defensively (belt and braces).
    """
    safe: dict[str, Any] = {}
    for key, value in evidence.items():
        if not key:
            continue
        if isinstance(value, str):
            safe[key] = _strip_query_values(value)
        elif isinstance(value, dict):
            safe[key] = {
                k: (_strip_query_values(v2) if isinstance(v2, str) else v2)
                for k, v2 in value.items()
                if k
            }
        else:
            safe[key] = value
    return safe


def _strip_query_values(text: str) -> str:
    """Replace any ``key=value`` fragment's value with [REDACTED]."""
    if "=" not in text or "?" not in text:
        return text
    parts = urlsplit(text)
    if parts.query:
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        cleaned = urlencode(
            [(k, "[REDACTED]") for k, _ in pairs],
            quote_via=lambda value, *a, **kw: value,
        )
        return urlunsplit((parts.scheme, parts.netloc, parts.path, cleaned, ""))
    return text


def aggregate_outcome(verdicts: list[ProviderVerdict]) -> str:
    """The response-level outcome, preserving disagreement (§6.C).

    Suspicion wins over reassurance; a configured provider that failed makes
    the aggregate UNAVAILABLE even when another answered NO_MATCH — the
    provider-level results keep every individual verdict visible.
    """
    outcomes = [v.outcome for v in verdicts]
    if FINDING in outcomes:
        return FINDING
    if REPORTED_UNVERIFIED in outcomes:
        return REPORTED_UNVERIFIED
    if UNAVAILABLE in outcomes:
        return UNAVAILABLE
    if NO_MATCH in outcomes:
        return NO_MATCH
    return UNAVAILABLE  # nothing configured, or only NOT_CONFIGURED verdicts
