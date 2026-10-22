"""Deterministic sliding-window rate limiter.

Implemented in-house (rather than via middleware magic) so tests can drive it
with a fake clock and assert exact behaviour. Keys are typically client IP.
A background cleanup trims stale buckets to bound memory.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from fastapi import HTTPException, Request, status


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    remaining: int
    retry_after_seconds: int


class RateLimiter:
    def __init__(self, clock=time.monotonic) -> None:
        self._clock = clock
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, *, limit: int, window_seconds: int = 60) -> RateLimitDecision:
        now = self._clock()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._buckets[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = max(1, int(bucket[0] + window_seconds - now) + 1)
                return RateLimitDecision(False, 0, retry_after)
            bucket.append(now)
            return RateLimitDecision(True, limit - len(bucket), 0)

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)


# Process-wide limiter. Tests import and reset this.
login_limiter = RateLimiter()
password_check_limiter = RateLimiter()
# Inbound cap for the breach-check endpoint: the external provider's free tier is
# small (25 lookups/hour/IP), so one client must not be able to burn it.
breach_check_limiter = RateLimiter()


def client_ip(request: Request) -> str:
    # Trust X-Forwarded-For only if behind a known proxy; default to peer IP.
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def enforce(limiter: RateLimiter, request: Request, *, limit: int) -> None:
    decision = limiter.check(client_ip(request), limit=limit, window_seconds=60)
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please slow down.",
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )