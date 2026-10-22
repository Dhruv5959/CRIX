"""XposedOrNot (XON) free community breach-lookup client — REAL external source.

    GET https://api.xposedornot.com/v1/check-email/{url_encoded_email}

Free for personal / low-volume use and **no API key required** (only the
domain-ownership endpoints need one). Published free-tier limits for *this*
endpoint: 2 requests/second, 25/hour, 100/day, per IP.

Contract — verified against the live endpoint, not just the docs. Two observed
behaviours differ from the published documentation and both matter for honesty:

1. "no record" arrives as **HTTP 200** with ``{"Error": "Not found", "email":
   null}`` — not the HTTP 404 that the docs' response-code table implies.
2. A *malformed* address returns the **same** body. The provider does not
   distinguish "invalid input" from "not found", so this body is only accepted
   as a verified negative when the address already passed CRIX's own validation.
   Otherwise it is UNAVAILABLE — bad input must never become SAFE (§7).
3. A hit is ``{"breaches": [["Name", "Name", ...]]}`` — a list of lists (this
   module also tolerates a flat list defensively).

Every failure mode (429, timeout, DNS failure, 5xx, non-JSON, unknown shape,
empty breach list) returns UNAVAILABLE with a reason. Nothing here decides
CRIX's authoritative score (§8): the return value is an *observation* that the
normalizer turns into a SecurityEvent, and the deterministic risk engine in
``app/engine/risk.py`` remains the only thing that scores.

The address is never echoed into a reason string, so no sensitive value can leak
into metadata, the audit log, or an error message.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx

from app.rate_limit import RateLimiter

PROVIDER_KEY = "xposedornot"
PROVIDER_LABEL = "XposedOrNot (free community API)"

BASE_URL = "https://api.xposedornot.com"
CHECK_EMAIL_PATH = "/v1/check-email/{email}"
USER_AGENT = "CRIX-Capstone/0.1 (security-signal-correlator)"

# Outcome vocabulary shared with the signal module (mirrors EventStatus values).
FINDING = "FINDING"
CHECKED_SAFE = "CHECKED_SAFE"
UNAVAILABLE = "UNAVAILABLE"

NOT_FOUND_REASON = "XposedOrNot reported no indexed breach for this address."

# The free tier is enforced per IP, so the outbound gate is process-wide rather
# than per client instance.
_per_second = RateLimiter()
_per_hour = RateLimiter()

# Set after an HTTP 429 so we stop hammering a provider that asked us to slow down.
_state: dict[str, float] = {"cooldown_until": 0.0}

# Second line of defence behind the request schema's EmailStr: the provider
# answers "Not found" for garbage, so we refuse to ask about malformed input at
# all (which also keeps our error path from being mistaken for a clean result).
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+$")


@dataclass(frozen=True)
class XonLookup:
    """One provider verdict.

    Deliberately a *value*, not an exception: every path returns one, so a caller
    cannot accidentally treat "we could not ask" as "all clear".
    """

    outcome: str
    breaches: list[str] = field(default_factory=list)
    reason: str = ""
    rate_limited: bool = False


def is_well_formed_email(email: object) -> bool:
    """Strict RFC-ish structural check. Conservative on purpose."""
    if not isinstance(email, str):
        return False
    candidate = email.strip()
    if not (3 <= len(candidate) <= 320):
        return False
    if candidate.count("@") != 1:
        return False
    return bool(_EMAIL_RE.match(candidate))


def reset_provider_state() -> None:
    """Clear the process-wide throttle and 429 cooldown.

    Used by tests, and by anything that reconfigures the provider at runtime.
    """
    _per_second.reset()
    _per_hour.reset()
    _state["cooldown_until"] = 0.0


class XposedOrNotClient:
    """Thin, rate-limit-aware client for the XON ``check-email`` endpoint."""

    def __init__(
        self,
        *,
        base_url: str = BASE_URL,
        timeout: float = 10.0,
        per_second: int = 2,
        per_hour: int = 25,
        clock=time.monotonic,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = float(timeout)
        self._per_second = max(1, int(per_second))
        self._per_hour = max(1, int(per_hour))
        self._clock = clock

    # -- public API --------------------------------------------------------- #

    def check_email(self, email: str) -> XonLookup:
        """Ask the provider about one address. Never raises for provider trouble."""
        if not is_well_formed_email(email):
            return XonLookup(
                UNAVAILABLE,
                reason="Email address failed validation, so nothing was queried.",
            )

        blocked = self._throttle_reason()
        if blocked:
            return XonLookup(UNAVAILABLE, reason=blocked, rate_limited=True)

        url = self._base_url + CHECK_EMAIL_PATH.format(email=quote(email.strip(), safe=""))
        try:
            response = httpx.get(
                url,
                headers={"user-agent": USER_AGENT, "accept": "application/json"},
                timeout=self._timeout,
                follow_redirects=True,
            )
        except httpx.HTTPError as exc:
            # Exception type only — never the address.
            return XonLookup(
                UNAVAILABLE,
                reason=f"XposedOrNot request failed ({type(exc).__name__}).",
            )
        return self._interpret(response)

    # -- internals ---------------------------------------------------------- #

    def _throttle_reason(self) -> str | None:
        """Return a reason when we must NOT make the call, else None."""
        now = self._clock()
        if now < _state["cooldown_until"]:
            wait = int(_state["cooldown_until"] - now) + 1
            return (
                "XposedOrNot returned HTTP 429; CRIX is cooling down for "
                f"~{wait}s before asking again."
            )
        if not _per_second.check("xon", limit=self._per_second, window_seconds=1).allowed:
            return (
                "XposedOrNot free-tier limit reached (2 lookups/second). "
                "Retry in a moment."
            )
        if not _per_hour.check("xon", limit=self._per_hour, window_seconds=3600).allowed:
            return (
                "XposedOrNot free-tier budget exhausted "
                f"({self._per_hour} lookups/hour per IP). Retry later."
            )
        return None

    def _interpret(self, response: httpx.Response) -> XonLookup:
        code = response.status_code

        if code == 429:
            self._enter_cooldown(response.headers.get("Retry-After"))
            return XonLookup(
                UNAVAILABLE,
                rate_limited=True,
                reason=(
                    "XposedOrNot rate limit reached (HTTP 429). The free tier allows "
                    f"{self._per_hour} email lookups/hour per IP."
                ),
            )
        if code >= 500:
            return XonLookup(
                UNAVAILABLE,
                reason=f"XposedOrNot is reporting a server-side problem (HTTP {code}).",
            )
        if code in (400, 401, 403, 422):
            return XonLookup(
                UNAVAILABLE,
                reason=f"XposedOrNot rejected the request (HTTP {code}).",
            )
        if code == 404:
            # The docs imply 404 means "no data found"; accept it only when the
            # body actually says so. Any other 404 is an error we must not launder
            # into a clean result.
            body = _json_or_none(response)
            if _is_not_found(body):
                return XonLookup(CHECKED_SAFE, reason=NOT_FOUND_REASON)
            return XonLookup(
                UNAVAILABLE,
                reason="XposedOrNot returned HTTP 404 without a recognised not-found body.",
            )
        if code != 200:
            return XonLookup(
                UNAVAILABLE,
                reason=f"XposedOrNot returned an unexpected HTTP {code}.",
            )

        body = _json_or_none(response)
        if body is None:
            return XonLookup(
                UNAVAILABLE, reason="XposedOrNot returned a response that was not JSON."
            )
        if not isinstance(body, dict):
            return XonLookup(
                UNAVAILABLE, reason="XposedOrNot returned an unrecognised response shape."
            )

        if "breaches" in body:
            names = _flatten_breach_names(body["breaches"])
            if names:
                return XonLookup(FINDING, breaches=names)
            # A "hit" envelope with no usable names is ambiguous, not good news.
            return XonLookup(
                UNAVAILABLE,
                reason=(
                    "XposedOrNot returned an empty breach list; CRIX treats that as "
                    "unverified rather than safe."
                ),
            )

        if _is_not_found(body):
            return XonLookup(CHECKED_SAFE, reason=NOT_FOUND_REASON)

        detail = _error_text(body)
        if detail:
            return XonLookup(
                UNAVAILABLE, reason=f"XposedOrNot returned an error response: {detail}"
            )
        return XonLookup(
            UNAVAILABLE, reason="XposedOrNot returned an unrecognised response body."
        )

    def _enter_cooldown(self, retry_after: str | None) -> None:
        seconds = 60.0
        if retry_after:
            try:
                seconds = float(int(str(retry_after).strip()))
            except (TypeError, ValueError):
                seconds = 60.0
        seconds = min(max(seconds, 1.0), 3600.0)
        _state["cooldown_until"] = self._clock() + seconds


# --------------------------------------------------------------------------- #
# Response helpers
# --------------------------------------------------------------------------- #
def _json_or_none(response: httpx.Response):
    try:
        return response.json()
    except ValueError:
        return None


def _is_not_found(body: object) -> bool:
    """True only for the provider's documented negative response."""
    if not isinstance(body, dict):
        return False
    for key in ("Error", "error"):
        value = body.get(key)
        if isinstance(value, str) and value.strip().lower() in {"not found", "notfound"}:
            return True
    return False


def _error_text(body: dict) -> str:
    for key in ("Error", "error", "detail", "message"):
        value = body.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:200]
    return ""


def _flatten_breach_names(value: object) -> list[str]:
    """XON returns ``[["Name", ...]]`` (list of lists); tolerate a flat list too."""
    names: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, str):
            if node.strip():
                names.append(node.strip())
        elif isinstance(node, (list, tuple)):
            for child in node:
                walk(child)

    walk(value)
    return names