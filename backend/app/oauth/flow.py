"""Authorization-code exchange and provider profile retrieval.

Only official token/userinfo endpoints are called (via httpx). Raw tokens are
returned to the caller for immediate encryption and are never logged.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

from app.config import Settings
from app.oauth.pkce import code_challenge
from app.oauth.providers import PROVIDERS, get_provider

logger = logging.getLogger(__name__)

_TIMEOUT = 20.0


class OAuthError(Exception):
    """Raised when the provider rejects an OAuth step."""


@dataclass
class TokenSet:
    access_token: str
    refresh_token: str | None
    expires_in: int | None
    scope: str | None
    token_type: str | None


@dataclass
class Profile:
    provider_account_id: str
    identifier: str | None
    display_name: str | None
    extra: dict[str, Any]


def redirect_uri(settings: Settings, provider: str) -> str:
    return f"{settings.oauth_redirect_base}/{provider}/callback"


def build_authorize_url(provider: str, settings: Settings, *, state: str, code_verifier: str) -> str:
    info = get_provider(provider)
    if info is None:
        raise OAuthError(f"Unknown provider: {provider}")
    params = {
        "client_id": settings.oauth_client_id(provider),
        "redirect_uri": redirect_uri(settings, provider),
        "response_type": "code",
        "scope": " ".join(info.scopes),
        "state": state,
        "code_challenge": code_challenge(code_verifier),
        "code_challenge_method": "S256",
    }
    params.update(info.extra_authorize_params)
    from urllib.parse import urlencode

    return f"{info.authorize_url}?{urlencode(params)}"


def exchange_code(provider: str, settings: Settings, *, code: str, code_verifier: str) -> TokenSet:
    info = get_provider(provider)
    if info is None:
        raise OAuthError(f"Unknown provider: {provider}")
    data = {
        "grant_type": "authorization_code",
        "client_id": settings.oauth_client_id(provider),
        "client_secret": settings.oauth_client_secret(provider),
        "code": code,
        "redirect_uri": redirect_uri(settings, provider),
        "code_verifier": code_verifier,
    }
    try:
        response = httpx.post(
            info.token_url, data=data, timeout=_TIMEOUT, headers={"Accept": "application/json"}
        )
    except httpx.HTTPError as exc:
        logger.warning("oauth token exchange transport error: %s", type(exc).__name__)
        raise OAuthError("Could not reach the provider token endpoint.") from exc

    if response.status_code >= 400:
        # Log status only — never the response body (it can echo tokens).
        logger.warning("oauth token exchange rejected: HTTP %s", response.status_code)
        raise OAuthError("Provider rejected the authorization code.")

    payload = response.json()
    access_token = payload.get("access_token")
    if not access_token:
        raise OAuthError("Provider returned no access token.")
    return TokenSet(
        access_token=access_token,
        refresh_token=payload.get("refresh_token"),
        expires_in=payload.get("expires_in"),
        scope=payload.get("scope"),
        token_type=payload.get("token_type"),
    )


def fetch_profile(provider: str, settings: Settings, access_token: str) -> Profile:
    info = get_provider(provider)
    if info is None:
        raise OAuthError(f"Unknown provider: {provider}")
    params = {"access_token": access_token}
    # Google returns identity via standard OIDC claims; Instagram needs fields.
    if provider == "instagram":
        params["fields"] = "id,username,account_type,name"
    try:
        response = httpx.get(
            info.userinfo_url, params=params, timeout=_TIMEOUT, headers={"Accept": "application/json"}
        )
    except httpx.HTTPError as exc:
        logger.warning("oauth userinfo transport error: %s", type(exc).__name__)
        raise OAuthError("Could not reach the provider profile endpoint.") from exc

    if response.status_code >= 400:
        logger.warning("oauth userinfo rejected: HTTP %s", response.status_code)
        raise OAuthError("Provider rejected the profile request.")

    payload = response.json()
    return _normalize_profile(provider, payload)


def _normalize_profile(provider: str, payload: dict[str, Any]) -> Profile:
    if provider == "google":
        return Profile(
            provider_account_id=str(payload.get("sub") or payload.get("id") or ""),
            identifier=payload.get("email"),
            display_name=payload.get("name"),
            extra={"picture": payload.get("picture"), "hd": payload.get("hd")},
        )
    if provider == "linkedin":
        return Profile(
            provider_account_id=str(payload.get("sub") or ""),
            identifier=payload.get("email"),
            display_name=payload.get("name"),
            extra={
                "given_name": payload.get("given_name"),
                "family_name": payload.get("family_name"),
                "picture": payload.get("picture"),
            },
        )
    if provider == "instagram":
        return Profile(
            provider_account_id=str(payload.get("id") or ""),
            identifier=payload.get("username"),
            display_name=payload.get("name") or payload.get("username"),
            extra={"username": payload.get("username"), "account_type": payload.get("account_type")},
        )
    return Profile(provider_account_id="", identifier=None, display_name=None, extra={})


def providers_payload(settings: Settings) -> dict:
    """Configuration snapshot for the UI (never includes secrets)."""
    from app.oauth.providers import configuration_state

    return configuration_state(settings)


__all__ = [
    "OAuthError",
    "TokenSet",
    "Profile",
    "redirect_uri",
    "build_authorize_url",
    "exchange_code",
    "fetch_profile",
    "providers_payload",
    "PROVIDERS",
]
