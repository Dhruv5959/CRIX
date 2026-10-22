"""Seed a demo account with a realistic scenario, run the real pipeline, and print
the measured output. Useful for portfolio demos and manual verification.

Usage (from repo root):
    .venv\\Scripts\\python.exe backend\\scripts\\seed_demo.py
    .venv\\Scripts\\python.exe backend\\scripts\\seed_demo.py --email you@example.com --password "your-password"
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from sqlalchemy import select  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.data.loader import seed_all  # noqa: E402
from app.db import SessionLocal, init_db  # noqa: E402
from app.engine import normalizer, pipeline  # noqa: E402
from app.models import (  # noqa: E402
    AccountRelationship,
    ConnectedSignal,
    Membership,
    Organization,
    User,
)
from app.routers.org import unique_slug  # noqa: E402
from app.security import hash_password  # noqa: E402
from app.schemas import ExposureType, OrgRole, PasswordHygieneRequest, PasswordReuseItem, PermissionAuditRequest, PermissionEntry  # noqa: E402
from app.signals.password import build_hygiene_events  # noqa: E402
from app.signals.permissions import build_permission_events  # noqa: E402


def _validate_will_be_accepted(email: str, password: str) -> None:
    """Fail loudly if the seed would create a user the API would reject.

    The API validates with Pydantic's ``EmailStr``, which rejects RFC 6761
    special-use domains (``.local``, ``.test``, ``.invalid``, ``.localhost``).
    A seeded account that cannot pass registration/login validation is a broken
    demo, so the seed refuses to create one. Checked against the *real*
    ``RegisterRequest`` schema the API uses.
    """
    from app.schemas import RegisterRequest

    try:
        RegisterRequest(email=email, password=password)
    except Exception as exc:  # pragma: no cover - defensive guard
        raise SystemExit(
            f"Refusing to seed {email!r}: the API would reject it "
            f"({type(exc).__name__}).\n"
            "Use a routable-looking address such as demo@example.com "
            "(RFC 2606 reserves example.com for documentation)."
        ) from exc


def _ensure_user(db, email: str, password: str) -> User:
    _validate_will_be_accepted(email, password)
    user = db.scalar(select(User).where(User.email == email))
    if user:
        return user
    settings = get_settings()
    user = User(email=email, password_hash=hash_password(password, settings), email_verified=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _ensure_account(db, user_id: str, account_id: str, label: str, service: str, source: str) -> None:
    existing = db.scalar(
        select(ConnectedSignal).where(
            ConnectedSignal.user_id == user_id, ConnectedSignal.account_id == account_id
        )
    )
    if existing:
        return
    db.add(
        ConnectedSignal(
            user_id=user_id,
            account_id=account_id,
            label=label,
            service_name=service,
            platform="web",
            source=source,
            metadata_json={"service_name": service},
        )
    )
    db.commit()


def _ensure_org(db, user: User, name: str) -> Membership:
    """Create the demo organization and make the demo user its ORG_ADMIN (§4).

    Real registration does exactly this; the seed mirrors it so the demo user has
    a tenant and the Admin/Member/Viewer surface is reachable. There is no
    personal or default organization.
    """
    membership = db.scalar(select(Membership).where(Membership.user_id == user.id))
    if membership is not None:
        return membership
    org = Organization(name=name, slug=unique_slug(db, name), created_by_user_id=user.id)
    db.add(org)
    db.flush()
    membership = Membership(
        org_id=org.id, user_id=user.id, role=OrgRole.ORG_ADMIN.value, is_active=True
    )
    db.add(membership)
    db.commit()
    db.refresh(membership)
    return membership


def _ensure_demo_accounts(db, user_id: str) -> None:
    """Three COMPANY work accounts for the demo, all USER_REPORTED.

    OAuth connectors are frozen (§1.4): nothing here creates a
    ``ProviderConnection`` or contacts a provider API. The accounts are labeled
    ``user_reported`` so they are never presented as live provider data.
    """
    for account_id, label, service in (
        ("google-main", "Primary Gmail", "Google"),
        ("github-main", "Work GitHub", "GitHub"),
        ("slack-main", "Company Slack", "Slack"),
    ):
        _ensure_account(db, user_id, account_id, label, service, "user_reported")


def _ensure_demo_relationships(db, user_id: str) -> None:
    """USER_CONFIRMED edges for the propagation demo. CRIX never invents these."""
    weights = {"recovery_email": 1.0, "sso": 0.85}
    edges = [
        ("google-main", "github-main", "recovery_email"),
        ("google-main", "slack-main", "sso"),
    ]

    known = {
        row.account_id
        for row in db.scalars(
            select(ConnectedSignal).where(ConnectedSignal.user_id == user_id)
        ).all()
    }
    for src, dst, rel_type in edges:
        if src not in known or dst not in known:
            continue
        existing = db.scalar(
            select(AccountRelationship).where(
                AccountRelationship.user_id == user_id,
                AccountRelationship.from_account_id == src,
                AccountRelationship.to_account_id == dst,
                AccountRelationship.relationship_type == rel_type,
            )
        )
        if existing is None:
            db.add(
                AccountRelationship(
                    user_id=user_id,
                    from_account_id=src,
                    to_account_id=dst,
                    relationship_type=rel_type,
                    source="USER_CONFIRMED",
                    source_mode="USER_PROVIDED",
                    confidence=1.0,
                    weight=weights.get(rel_type, 0.5),
                )
            )
    db.commit()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--email", default="demo@example.com")
    parser.add_argument("--password", default="demo-password-123")
    parser.add_argument("--org-name", default="Demo Company")
    args = parser.parse_args()

    init_db()
    db = SessionLocal()
    try:
        seed_all(db)
        user = _ensure_user(db, args.email, args.password)
        membership = _ensure_org(db, user, args.org_name)

        # Three COMPANY work accounts plus USER_CONFIRMED dependency edges, so the
        # Compromise Propagation demo works with no OAuth and no provider API.
        # A Google account that is a recovery hub for the other services, with a
        # breach + reused password + no MFA + SMS recovery + risky app.
        _ensure_demo_accounts(db, user.id)
        _ensure_demo_relationships(db, user.id)

        # Breach finding on Google (SIMULATED scenario, clearly labeled).
        from app.signals.breach import check_breach
        from app.signals.hibp import HIBPClient

        settings = get_settings()
        # Deliberately offline & deterministic: an UNCONFIGURED HIBP client can
        # never open a socket, so seeding does not depend on a live provider and
        # does not spend any of the free tier's quota. The demo's breach story
        # stays the SIMULATED session scenario below.
        sim = check_breach(
            user_id=user.id,
            account_id="google-main",
            email=args.email,
            settings=settings,
            client=HIBPClient(""),
            simulated_exposure_type=ExposureType.SESSION_ONLY,
            simulated_mfa_bypass_capable=True,
        )
        normalizer.replace_module_events(
            db, user.id, "google-main",
            ["BREACH_EXPOSURE", "IDENTITY_EXPOSED", "SESSION_EXPOSURE"], sim,
        )

        hygiene = build_hygiene_events(
            user_id=user.id,
            payload=PasswordHygieneRequest(
                account_id="google-main",
                provider="Google",
                mfa_enabled=False,
                passkey_enabled=False,
                sms_otp_recovery=True,
                push_bombing_reported=True,
                reused_credentials=[PasswordReuseItem(label="reused-cross-site", reused=True)],
            ),
            passkey_supported_by_provider=True,
            provider_source="Google Account Help",
        )
        normalizer.replace_module_events(
            db, user.id, "google-main",
            ["PASSWORD_REUSE", "MFA_MISSING", "PASSKEY_READY_NOT_ENABLED",
             "SIM_SWAP_VULNERABLE", "PUSH_BOMBING_REPORTED"], hygiene,
        )

        perm_events, _ = build_permission_events(
            user_id=user.id,
            payload=PermissionAuditRequest(
                account_id="google-main",
                entries=[PermissionEntry(app_name="Photo Editor Pro", platform="android",
                                         permissions=["contacts", "location", "files"])],
            ),
        )
        normalizer.replace_module_events(
            db, user.id, "google-main",
            ["RISKY_PERMISSION_GRANTED", "STALE_PERMISSION_GRANTED"], perm_events,
        )

        result = pipeline.run_analysis(db, user.id, persist=True)
        print("=" * 60)
        print(f"Demo user: {args.email}  (password: {args.password})")
        print(f"Role:      ORG_ADMIN of organization {membership.org_id}")
        print("=" * 60)
        print(f"Events:        {len(result['events'])}")
        print(f"Correlations:  {len(result['correlations'])}")
        for c in result["correlations"]:
            print(f"   - {c.rule_id}  severity={c.severity:.2f}")
        print(f"Risk score:    {result['risk'].score:.1f} ({result['risk'].band})")
        print(f"  base={result['risk'].base_risk:.1f} interaction={result['risk'].interaction_risk:.1f} "
              f"mitigation={result['risk'].mitigation_credit:.1f}")
        print(f"  range={result['risk'].range_low:.0f}-{result['risk'].range_high:.0f} "
              f"confidence={result['risk'].confidence}")
        print(f"Shapley:       sum={result['attribution']['sum_of_contributions']:.4f} "
              f"vs total={result['attribution']['total_risk']:.4f} "
              f"(err {result['attribution']['efficiency_error']:.1e}, {result['attribution']['compute_ms']:.1f} ms)")
        print(f"Planner:       greedy risk_after={result['planner']['greedy']['risk_after']:.1f} "
              f"exact risk_after={result['planner']['exact']['risk_after']:.1f} "
              f"gap={result['planner']['optimality_gap']:.2%}")
        print("=" * 60)
        print("Log in at http://localhost:5173 with the demo credentials above.")
    finally:
        db.close()


if __name__ == "__main__":
    main()