"""Stable company-asset identity and organization-scoped resolution (Phase 2, §3).

Rules enforced here:

* Identity is **canonical, not fuzzy**. Only trimming, lower-casing of the
  host/local part, and scheme/slash/``.git`` normalisation are applied. Anything
  else is left byte-identical.
* Two identifiers are the same asset only when their canonical forms are
  **exactly equal**. Similar names never merge assets.
* A Gmail account (``alice@gmail.com``) and a Google domain (``gmail.com``) are
  different identifiers, so they are never the same asset; a relationship between
  them exists only if an administrator registers one explicitly
  (``org_assets``/``asset_dependencies``, ``edge_source=ADMIN_DECLARED``).
* Resolution is scoped to a single organization. The query filters on ``org_id``,
  so a candidate that lives in another tenant can never be returned — it resolves
  to "no match" instead of a cross-tenant binding.
* Labels and service names are deliberately **not** used as candidates: they are
  display names, and matching on them would be exactly the name-similarity
  merging this rule forbids.
"""
from __future__ import annotations

import re
from typing import Iterable, NamedTuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import OrgAsset

# Entirely local-part@domain.tld, no internal whitespace.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# A registrable-looking host (must contain at least one dot).
_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?$", re.IGNORECASE
)
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)


class Identity(NamedTuple):
    """A canonical identifier and the kind of thing it refers to."""

    kind: str  # "email" | "url" | "domain" | "id"
    value: str


def identity_of(value: str | None) -> Identity | None:
    """Canonicalise one candidate identifier.

    Returns ``None`` when the value is not an identifier at all (blank, a label
    containing spaces, an unsupported scheme) — an explicit "unknown", never a
    guess.
    """
    text = (value or "").strip()
    if not text:
        return None
    # Anything with internal whitespace is a human label, not an identifier.
    if any(ch.isspace() for ch in text):
        return None

    if "@" in text:
        if not _EMAIL_RE.match(text):
            return None
        local, _, domain = text.rpartition("@")
        return Identity("email", f"{local.lower()}@{domain.lower()}")

    had_scheme = bool(_SCHEME_RE.match(text))
    body = _SCHEME_RE.sub("", text)
    if not body:
        return None

    if "/" in body:
        host, _, path = body.partition("/")
        host = host.lower()
        # Drop trailing slashes and an optional .git suffix so the same
        # repository URL always yields the same identity.
        while path.endswith("/"):
            path = path[:-1]
        if path.lower().endswith(".git"):
            path = path[:-4]
        value = f"{host}/{path}" if path else host
        return Identity("url", value)

    host = body.rstrip(".")
    if not host or not _DOMAIN_RE.match(host):
        # Opaque but stable user-chosen identifier (e.g. "github-acme-app").
        return Identity("id", text.rstrip("/"))
    if had_scheme:
        # "https://example.com" and "example.com" are the same host only after
        # the scheme is dropped; that is a normalisation, not a merge.
        return Identity("domain", host.lower())
    return Identity("domain", host.lower())


def canonical_asset_id(value: str | None) -> str:
    """Canonical form used for BOTH registration and lookup.

    Non-identifier values (opaque ids chosen by the admin) are only trimmed, so a
    registered id is never silently rewritten into a different resource.
    """
    if value is None:
        return ""
    ident = identity_of(value)
    if ident is not None:
        return ident.value
    return value.strip()


def resolve_asset(
    db: Session, org_id: str, candidates: Iterable[str | None]
) -> OrgAsset | None:
    """Return the organization's asset whose canonical id equals a candidate.

    * ``org_id`` filters the query, so nothing outside the tenant can match.
    * Candidates are tried in the order given (deterministic).
    * No match means ``None``: an unknown asset stays unknown.
    """
    if not org_id:
        return None
    wanted: list[str] = []
    for candidate in candidates:
        ident = identity_of(candidate)
        if ident is None:
            continue
        if ident.value not in wanted:
            wanted.append(ident.value)
    if not wanted:
        return None

    assets = list(
        db.scalars(select(OrgAsset).where(OrgAsset.org_id == org_id)).all()
    )
    lookup = {canonical_asset_id(asset.asset_id): asset for asset in assets}
    for candidate in wanted:
        asset = lookup.get(candidate)
        if asset is not None:
            return asset
    return None


def assert_asset_in_org(db: Session, org_id: str, asset_id: str) -> OrgAsset | None:
    """Fetch an asset by its stable id, only within ``org_id``.

    Raises nothing: a cross-organization or unknown id simply resolves to
    ``None``, so callers cannot accidentally treat "belongs to someone else" as
    "found".
    """
    if not org_id:
        return None
    wanted = canonical_asset_id(asset_id)
    for asset in db.scalars(select(OrgAsset).where(OrgAsset.org_id == org_id)).all():
        if canonical_asset_id(asset.asset_id) == wanted:
            return asset
    return None
