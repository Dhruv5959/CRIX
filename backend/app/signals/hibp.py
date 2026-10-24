"""Have I Been Pwned (HIBP) client — REAL external data source (§3.A, §0.4).

Two capabilities:
1. ``breached_account`` — email breach lookup (requires HIBP_API_KEY).
2. ``pwned_password_range`` — Pwned Passwords range query. The password is
   hashed CLIENT-SIDE; the server only ever sees (or proxies) a 5-character
   SHA-1 prefix and the suffixes come back from HIBP. We never see plaintext.

When the API key is absent the email lookup returns UNAVAILABLE (never "safe").
"""
from __future__ import annotations

import httpx

BREACH_API = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
PWNED_PASSWORDS_RANGE = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "CRIX-Capstone/0.1 (security-signal-correlator)"


class HIBPUnavailable(RuntimeError):
    """Raised when HIBP cannot be consulted (no key / network / rate limited)."""


class HIBPClient:
    def __init__(self, api_key: str, *, timeout: float = 10.0) -> None:
        self._api_key = api_key
        self._timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    def breached_account(self, email: str) -> list[dict]:
        """Return breach records for an email. Raises HIBPUnavailable if we
        cannot consult the API (missing key, network error, rate limit)."""
        if not self._api_key:
            raise HIBPUnavailable("HIBP_API_KEY not configured.")
        headers = {"hibp-api-key": self._api_key, "user-agent": USER_AGENT}
        url = BREACH_API.format(account=email)
        try:
            response = httpx.get(
                url, headers=headers, params={"truncateResponse": "false"},
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise HIBPUnavailable(f"HIBP request failed: {exc}") from exc
        if response.status_code == 404:
            return []  # Not found in any breach — a genuine CHECKED_SAFE.
        if response.status_code == 429:
            raise HIBPUnavailable("HIBP rate limit reached.")
        if response.status_code == 401:
            raise HIBPUnavailable("HIBP API key rejected.")
        if response.status_code >= 400:
            raise HIBPUnavailable(f"HIBP returned HTTP {response.status_code}.")
        return response.json()

    def pwned_password_range(self, prefix: str) -> str:
        """Proxy a Pwned Passwords range query. ``prefix`` is 5 hex chars."""
        if len(prefix) != 5 or any(c not in "0123456789ABCDEFabcdef" for c in prefix):
            raise ValueError("Range prefix must be 5 hex characters.")
        url = PWNED_PASSWORDS_RANGE.format(prefix=prefix.upper())
        try:
            response = httpx.get(
                url, timeout=self._timeout,
                headers={"user-agent": USER_AGENT, "Add-Padding": "true"},
            )
        except httpx.HTTPError as exc:
            raise HIBPUnavailable(f"Pwned Passwords request failed: {exc}") from exc
        if response.status_code >= 400:
            raise HIBPUnavailable(f"Pwned Passwords returned HTTP {response.status_code}.")
        return response.text


def classify_session_capability(breach: dict) -> bool:
    """Heuristic: does a breach plausibly include session-cookie / MFA-bypassing
    data? HIBP's ``DataClasses`` used to include 'Auth tokens'/'Session' for some
    breaches. When absent we assume False (conservative, documented)."""
    classes = {c.lower() for c in breach.get("DataClasses", [])}
    session_markers = {"auth tokens", "session", "sessions", "security questions"}
    return bool(classes & session_markers)


def pwned_password_count(password: str, *, timeout: float = 10.0) -> int:
    """How many times a password appears in the Pwned Passwords corpus.

    Feature B, server side: the plaintext exists in CRIX memory only at the
    moment the user submitted it (registration / login). We hash it to SHA-1
    transiently, send ONLY the 5-character prefix to HIBP (k-anonymity; the
    full hash and the plaintext never leave CRIX), and compare suffixes here.

    Raises ``HIBPUnavailable`` so callers can follow the policy fallback: the
    result is recorded as UNAVAILABLE, never as "safe".
    """
    import hashlib

    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    text = HIBPClient("", timeout=timeout).pwned_password_range(digest[:5])
    suffix = digest[5:]
    for line in text.splitlines():
        candidate, _, count = line.partition(":")
        if candidate.strip().upper() == suffix:
            try:
                return int(count or 0)
            except ValueError:
                return 0
    return 0