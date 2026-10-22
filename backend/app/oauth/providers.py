"""Live account connections via official OAuth 2.0 / OIDC (scope change).

Hard rules enforced across every provider implementation:

* Authorization-code flow with PKCE (S256) and a cryptographically random
  ``state``. We never request, transmit, or store a provider password.
* Raw tokens are encrypted at rest (``app.token_crypto``) and are NEVER sent to
  the frontend and NEVER logged.
* Only official endpoints. No scraping, no unofficial APIs.
* Only request the minimum scopes; each provider documents why.
* Capabilities the provider API does not expose are reported
  ``UNAVAILABLE_THROUGH_PROVIDER`` — never ``SAFE``.

The OAuth client id/secret must be registered by the project team in the
provider's developer console. When credentials are absent the provider reports
``NOT_CONFIGURED`` and the UI shows the connector as unavailable — it never
pretends to be connected.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ProviderInfo:
    key: str
    label: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scopes: tuple[str, ...]
    # Endpoint that lists which redirect URIs the app must register.
    docs_url: str
    extra_authorize_params: dict[str, str] = field(default_factory=dict)
    # A provider whose API is restricted to a particular account class says so.
    account_requirement: str = ""
    # What official API data CRIX may actually read (surfaced in the UI).
    exposes: tuple[str, ...] = ()
    does_not_expose: tuple[str, ...] = ()


PROVIDERS: dict[str, ProviderInfo] = {
    "google": ProviderInfo(
        key="google",
        label="Google / Gmail",
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
        # Minimum scopes: identity via OIDC. gmail.metadata is enough for the
        # phishing-analysis feature (headers/labels); gmail.readonly is requested
        # only when message content is genuinely required.
        scopes=(
            "openid",
            "email",
            "profile",
            "https://www.googleapis.com/auth/gmail.metadata",
        ),
        docs_url="https://developers.google.com/identity/protocols/oauth2/web-server",
        extra_authorize_params={"access_type": "offline", "prompt": "consent"},
        account_requirement="Any Google account",
        exposes=(
            "Basic profile / email",
            "Gmail message metadata (headers & labels, no body)",
        ),
        does_not_expose=(
            "Google Security Checkup status",
            "MFA / 2-Step Verification status",
            "Breach exposure status",
            "Password reuse / credential state",
        ),
    ),
    "linkedin": ProviderInfo(
        key="linkedin",
        label="LinkedIn",
        authorize_url="https://www.linkedin.com/oauth/v2/authorization",
        token_url="https://www.linkedin.com/oauth/v2/accessToken",
        userinfo_url="https://api.linkedin.com/v2/userinfo",
        scopes=("openid", "profile", "email"),
        docs_url="https://learn.microsoft.com/linkedin/shared/authentication/authentication",
        account_requirement="Any LinkedIn member",
        exposes=(
            "Authenticated member basic profile",
            "Primary email (where permitted)",
        ),
        does_not_expose=(
            "MFA status",
            "Security-checkup status",
            "Connected-applications list",
            "Breach / compromise status",
            "Password reuse",
        ),
    ),
}


def get_provider(key: str) -> ProviderInfo | None:
    return PROVIDERS.get(key)


def is_configured(key: str, settings) -> bool:
    """A provider is configured only when BOTH id and secret are present."""
    return bool(settings.oauth_client_id(key) and settings.oauth_client_secret(key))


def configuration_state(settings) -> dict[str, dict]:
    """Per-provider configuration/connection capability for the UI (§12)."""
    return {
        key: {
            "key": info.key,
            "label": info.label,
            "configured": is_configured(key, settings),
            "account_requirement": info.account_requirement,
            "exposes": list(info.exposes),
            "does_not_expose": list(info.does_not_expose),
            "docs_url": info.docs_url,
            "scopes": list(info.scopes),
        }
        for key, info in PROVIDERS.items()
    }
