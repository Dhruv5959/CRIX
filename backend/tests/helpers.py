"""Helpers to construct normalized security events in tests."""
from __future__ import annotations

from app.schemas import SecurityEventSchema


def ev(event_type: str, *, severity: float = 0.6, confidence: float = 0.8,
       exposure_type=None, status: str = "FINDING", account_id: str = "acct",
       metadata: dict | None = None, source: str = "test", event_id: str | None = None):
    return SecurityEventSchema(
        event_id=event_id or f"evt_{event_type}_{account_id}_{severity}_{exposure_type}",
        user_id="user-1",
        account_id=account_id,
        event_type=event_type,
        exposure_type=exposure_type,
        severity=severity,
        confidence=confidence,
        source=source,
        status=status,
        metadata=metadata or {},
        provenance="test",
    )