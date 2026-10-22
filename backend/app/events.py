"""Canonical event-type names and helpers for building normalized events.

Event types are the vocabulary the declarative correlation rules match on
(§5). Keeping them central prevents typos that would silently break rules.
"""
from __future__ import annotations

import uuid

# --- breach / exposure (§3.A) ---
BREACH_EXPOSURE = "BREACH_EXPOSURE"
SESSION_EXPOSURE = "SESSION_EXPOSURE"
IDENTITY_EXPOSED = "IDENTITY_EXPOSED"

# --- password / auth hygiene (§3.B) ---
PASSWORD_REUSE = "PASSWORD_REUSE"
MFA_MISSING = "MFA_MISSING"
PASSKEY_READY_NOT_ENABLED = "PASSKEY_READY_NOT_ENABLED"
SIM_SWAP_VULNERABLE = "SIM_SWAP_VULNERABLE"
PUSH_BOMBING_REPORTED = "PUSH_BOMBING_REPORTED"

# --- phishing (§3.C) ---
PHISHING_MESSAGE_DETECTED = "PHISHING_MESSAGE_DETECTED"
AI_GENERATED_MESSAGE_DETECTED = "AI_GENERATED_MESSAGE_DETECTED"

# --- permissions (§3.D) ---
RISKY_PERMISSION_GRANTED = "RISKY_PERMISSION_GRANTED"
STALE_PERMISSION_GRANTED = "STALE_PERMISSION_GRANTED"

# --- graph-derived (Phase 7) ---
ACCOUNT_DEPENDENCY = "ACCOUNT_DEPENDENCY"
COMPROMISED_RECOVERY_ACCOUNT = "COMPROMISED_RECOVERY_ACCOUNT"


def new_event_id() -> str:
    return f"evt_{uuid.uuid4().hex}"