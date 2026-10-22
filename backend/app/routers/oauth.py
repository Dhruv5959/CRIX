"""Live account connection endpoints (official OAuth only, scope change).

Security invariants enforced here:
- The OAuth ``state`` is single-use and bound to the initiating user (CSRF).
- PKCE code_verifier never leaves the backend.
- Tokens are encrypted at rest and are NEVER returned to the frontend.
- Only official endpoints; no provider password is ever requested.
- A connection proves authorization only — capability availability comes from
  the curated matrix, never from the connection itself (§12).
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.config import Settings, get_settings
from app.data.loader import seed_all
from app.db import get_db
from app.deps import get_current_user
from app.models import ConnectedSignal, ProviderCapability, ProviderConnection, User
from app.oauth import flow
from app.oauth.flow import OAuthError, build_authorize_url, exchange_code, fetch_profile
from app.oauth.pkce import new_code_verifier, new_state, put_pending, take_pending
from app.oauth.providers import PROVIDERS, is_configured
from app.rate_limit import client_ip
from app import token_crypto

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/oauth", tags=["oauth"])


def _ensure_capability_seed(db: Session) -> None:
    count = db.scalar(
        select(ProviderCapability).limit(1)
    )
    if count is None:
        seed_all(db)


@router.get("/providers")
def providers(settings: Annotated[Settings, Depends(get_settings)]) -> dict:
    """What is configured, what the official APIs expose, and what they do not.

    Never includes client secrets.
    """
    payload = {}
    for key, info in PROVIDERS.items():
        payload[key] = {
            "key": info.key,
            "label": info.label,
            "configured": is_configured(key, settings),
            "status": "AVAILABLE" if is_configured(key, settings) else "NOT_CONFIGURED",
            "account_requirement": info.account_requirement,
            "scopes": list(info.scopes),
            "exposes": list(info.exposes),
            "does_not_expose": list(info.does_not_expose),
            "docs_url": info.docs_url,
        }
    return {"providers": payload}


@router.get("/capabilities")
def capabilities(
    db: Session = Depends(get_db),
) -> dict:
    """Curated capability matrix: can the official API actually return this?"""
    _ensure_capability_seed(db)
    rows = db.scalars(select(ProviderCapability)).all()
    return {
        "capabilities": [
            {
                "provider": row.provider,
                "capability": row.capability,
                "available": row.available,
                "source": row.source,
                "last_verified": row.last_verified.isoformat() if row.last_verified else None,
                "note": row.note,
                "status": "AVAILABLE" if row.available else "UNAVAILABLE_THROUGH_PROVIDER",
            }
            for row in sorted(rows, key=lambda r: (r.provider, r.capability))
        ],
        "note": (
            "A connected account proves an authorized relationship only. "
            "Capability availability comes from this curated matrix, not from "
            "the connection. Unavailable capabilities are marked "
            "UNAVAILABLE_THROUGH_PROVIDER — never SAFE."
        ),
    }


@router.get("/{provider}/authorize")
def authorize(
    provider: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Start the authorization-code + PKCE flow. Returns the URL to open."""
    if provider not in PROVIDERS:
        raise HTTPException(status_code=404, detail="Unknown provider.")
    if not is_configured(provider, settings):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"{PROVIDERS[provider].label} OAuth is NOT_CONFIGURED. Register an app "
                f"and set the client id/secret. See {PROVIDERS[provider].docs_url}."
            ),
        )

    state = new_state()
    verifier = new_code_verifier()
    put_pending(state, provider, current_user.id, verifier)
    url = build_authorize_url(provider, settings, state=state, code_verifier=verifier)
    return {"authorize_url": url, "provider": provider, "state": state}


@router.get("/{provider}/callback")
def callback(
    provider: str,
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Handle the provider redirect. Exchanges the code, stores tokens
    encrypted, and redirects back to the frontend."""
    frontend = settings.oauth_frontend_redirect

    def _bounce(extra: str) -> RedirectResponse:
        sep = "&" if "?" in frontend else "?"
        return RedirectResponse(f"{frontend}{sep}{extra}")

    if error:
        logger.warning("oauth provider returned error: %s", error)
        return _bounce("oauth_error=provider_denied")
    if not code or not state:
        return _bounce("oauth_error=missing_code")

    pending = take_pending(state)
    if pending is None or pending.provider != provider:
        return _bounce("oauth_error=invalid_state")

    try:
        tokens = exchange_code(provider, settings, code=code, code_verifier=pending.code_verifier)
        profile = fetch_profile(provider, settings, tokens.access_token)
    except OAuthError as exc:
        logger.warning("oauth exchange failed for %s: %s", provider, type(exc).__name__)
        return _bounce("oauth_error=exchange_failed")

    _store_connection(
        db=db,
        user_id=pending.user_id,
        provider=provider,
        tokens=tokens,
        profile=profile,
        settings=settings,
        ip_address=client_ip(request),
    )
    return _bounce(f"oauth_success={provider}")


def _store_connection(
    *, db: Session, user_id: str, provider: str, tokens, profile, settings,
    ip_address: str | None = None,
) -> None:
    """Persist the connection + encrypted tokens + a linked CRIX asset."""
    if not profile.provider_account_id:
        raise OAuthError("Provider returned no stable account id.")

    existing = db.scalar(
        select(ProviderConnection).where(
            ProviderConnection.user_id == user_id, ProviderConnection.provider == provider
        )
    )
    expires_at = None
    if tokens.expires_in:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(tokens.expires_in))

    # CRIX asset id: provider-scoped, e.g. "google_123".
    account_id = f"{provider}_{profile.provider_account_id}"[:64]

    now = datetime.now(timezone.utc)
    if existing is None:
        existing = ProviderConnection(
            user_id=user_id,
            provider=provider,
            provider_account_id=profile.provider_account_id,
            identifier=profile.identifier,
            display_name=profile.display_name,
            connected_at=now,
            scopes=tokens.scope or "",
            account_id=account_id,
        )
        db.add(existing)
    existing.connection_status = "CONNECTED"
    existing.source_mode = "REAL"
    existing.access_token_enc = token_crypto.encrypt_token(tokens.access_token)
    existing.refresh_token_enc = token_crypto.encrypt_token(tokens.refresh_token)
    existing.token_expires_at = expires_at
    existing.scopes = tokens.scope or ""
    existing.last_synced_at = now
    existing.identifier = profile.identifier
    existing.display_name = profile.display_name
    existing.account_id = account_id

    # Register the linked asset so it appears in the dependency graph.
    _ensure_asset(
        db=db, user_id=user_id, provider=provider, profile=profile,
        account_id=account_id, settings=settings,
    )

    db.commit()

    # Audit trail records the event, never the token (redacted detail).
    audit.record(
        db,
        action="oauth.connection_established",
        user_id=user_id,
        ip_address=ip_address,
        detail={
            "provider": provider,
            "account_id": account_id,
            "scopes": tokens.scope or "",
        },
    )


def _ensure_asset(*, db, user_id, provider, profile, account_id, settings, source_mode="REAL") -> None:
    label = profile.display_name or profile.identifier or account_id
    service = PROVIDERS[provider].label
    existing = db.scalar(
        select(ConnectedSignal).where(
            ConnectedSignal.user_id == user_id, ConnectedSignal.account_id == account_id
        )
    )
    if existing is None:
        db.add(
            ConnectedSignal(
                user_id=user_id,
                account_id=account_id,
                label=label,
                service_name=service,
                platform=provider,
                email=profile.identifier,
                source="oauth" if source_mode == "REAL" else "fixture",
                metadata_json={
                    "service_name": service,
                    "source_mode": source_mode,
                    "provider": provider,
                    "oauth": source_mode == "REAL",
                    "fixture": source_mode == "FIXTURE",
                },
            )
        )
    else:
        existing.label = label
        existing.email = profile.identifier
        existing.source = "oauth" if source_mode == "REAL" else "fixture"
        existing.metadata_json = {
            **(existing.metadata_json or {}),
            "service_name": service,
            "source_mode": source_mode,
            "provider": provider,
            "oauth": source_mode == "REAL",
            "fixture": source_mode == "FIXTURE",
        }


@router.get("/connections")
def list_connections(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> dict:
    rows = db.scalars(
        select(ProviderConnection).where(ProviderConnection.user_id == current_user.id)
    ).all()
    return {
        "connections": [
            {
                "id": row.id,
                "provider": row.provider,
                "provider_label": PROVIDERS[row.provider].label if row.provider in PROVIDERS else row.provider,
                "provider_account_id": row.provider_account_id,
                "identifier": row.identifier,
                "display_name": row.display_name,
                "connection_status": row.connection_status,
                "source_mode": row.source_mode,
                "scopes": row.scopes,
                "connected_at": row.connected_at.isoformat() if row.connected_at else None,
                "last_synced_at": row.last_synced_at.isoformat() if row.last_synced_at else None,
                "account_id": row.account_id,
                # Tokens are NEVER included here (§: never exposed to frontend).
                "token_available": bool(row.access_token_enc),
            }
            for row in rows
        ]
    }


@router.delete("/connections/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
def disconnect(
    connection_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> None:
    row = db.scalar(
        select(ProviderConnection).where(
            ProviderConnection.user_id == current_user.id,
            ProviderConnection.id == connection_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Connection not found.")
    provider, account_id = row.provider, row.account_id
    db.delete(row)
    db.commit()
    audit.record(
        db,
        action="oauth.connection_removed",
        user_id=current_user.id,
        detail={"provider": provider, "account_id": account_id},
    )


# --------------------------------------------------------------------------- #
# FIXTURE connector (§13 safe demo strategy)
# --------------------------------------------------------------------------- #
# Clearly labeled source_mode=FIXTURE. This is NOT real OAuth and never claims
# to be: no provider API is called, no tokens exist, and the UI labels it
# FIXTURE. It exists so the propagation demo works before real credentials are
# registered. Disabled in production.
_FIXTURE_ACCOUNTS = {
    "google": ("Gmail", "gmail-demo@example.com"),
    "linkedin": ("LinkedIn", "linkedin-demo-profile"),
    "instagram": ("Instagram", "instagram_professional_demo"),
}


@router.post("/fixtures/{provider}")
def connect_fixture(
    provider: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Create a clearly-labeled FIXTURE connection for local demos.

    source_mode = FIXTURE (never REAL). Used only when the provider has no real
    credentials configured, or when explicitly requested for a demo.
    """
    if provider not in PROVIDERS:
        raise HTTPException(status_code=404, detail="Unknown provider.")
    if not settings.allow_fixture_connectors or settings.is_production:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Fixture connectors are disabled in this environment.",
        )

    label, identifier = _FIXTURE_ACCOUNTS.get(provider, (provider, f"{provider}-fixture"))
    account_id = f"{provider}_fixture_{current_user.id[:8]}"
    now = datetime.now(timezone.utc)

    row = db.scalar(
        select(ProviderConnection).where(
            ProviderConnection.user_id == current_user.id,
            ProviderConnection.provider == provider,
        )
    )
    if row is None:
        row = ProviderConnection(
            user_id=current_user.id,
            provider=provider,
            provider_account_id=account_id,
            connected_at=now,
            scopes="fixture",
            account_id=account_id,
        )
        db.add(row)
    row.provider_account_id = account_id
    row.identifier = identifier
    row.display_name = label
    row.connection_status = "CONNECTED"
    row.source_mode = "FIXTURE"
    row.access_token_enc = None
    row.refresh_token_enc = None
    row.scopes = "fixture"
    row.last_synced_at = now
    row.account_id = account_id

    _ensure_asset(
        db=db,
        user_id=current_user.id,
        provider=provider,
        profile=flow.Profile(
            provider_account_id=account_id,
            identifier=identifier,
            display_name=label,
            extra={"fixture": True},
        ),
        account_id=account_id,
        settings=settings,
        source_mode="FIXTURE",
    )

    db.commit()
    audit.record(
        db,
        action="oauth.fixture_connected",
        user_id=current_user.id,
        detail={"provider": provider, "account_id": account_id, "source_mode": "FIXTURE"},
    )
    return {
        "provider": provider,
        "source_mode": "FIXTURE",
        "connection_status": "CONNECTED",
        "account_id": account_id,
        "identifier": identifier,
        "notice": (
            "FIXTURE connection — local demo data only. No provider API was "
            "called and no real account is involved."
        ),
    }
