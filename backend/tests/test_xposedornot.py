"""XposedOrNot provider-client tests (§3.A, integration spec §6–§8).

Every test replaces ``httpx.get`` with a stub, so nothing here touches the real
provider or spends any of its free-tier quota.

The two cases marked "live behaviour" encode what the real endpoint actually did
when probed, which differs from the published documentation — they are the
regression tests that keep CRIX honest if the provider drifts again.
"""
from __future__ import annotations

import httpx
import pytest

from app.signals import xposedornot as xon
from app.signals.xposedornot import (
    CHECKED_SAFE,
    FINDING,
    UNAVAILABLE,
    XposedOrNotClient,
    is_well_formed_email,
    reset_provider_state,
)
from tests.xon_stubs import FakeResponse, patch_transport

ADDRESS = "person@example.com"


@pytest.fixture(autouse=True)
def _clean_provider_state():
    """The outbound throttle is process-wide, so isolate every test."""
    reset_provider_state()
    yield
    reset_provider_state()


# --------------------------------------------------------------------------- #
# Success paths
# --------------------------------------------------------------------------- #
def test_hit_flattens_the_nested_breach_list(monkeypatch):
    calls = patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe", "Chegg"]]}))
    result = XposedOrNotClient().check_email(ADDRESS)

    assert result.outcome == FINDING
    assert result.breaches == ["Adobe", "Chegg"]
    # The address is URL-encoded into the path, per the documented endpoint.
    assert calls == ["https://api.xposedornot.com/v1/check-email/person%40example.com"]


def test_hit_tolerates_a_flat_breach_list(monkeypatch):
    patch_transport(monkeypatch, FakeResponse(200, {"breaches": ["Adobe"]}))
    assert XposedOrNotClient().check_email(ADDRESS).breaches == ["Adobe"]


def test_live_not_found_body_is_checked_safe(monkeypatch):
    """Live behaviour: "no record" arrives as HTTP 200, not the documented 404."""
    patch_transport(monkeypatch, FakeResponse(200, {"Error": "Not found", "email": None}))
    assert XposedOrNotClient().check_email(ADDRESS).outcome == CHECKED_SAFE


def test_documented_404_not_found_is_also_checked_safe(monkeypatch):
    patch_transport(monkeypatch, FakeResponse(404, {"Error": "Not found", "email": None}))
    assert XposedOrNotClient().check_email(ADDRESS).outcome == CHECKED_SAFE


# --------------------------------------------------------------------------- #
# Failure paths never become "safe" (§7)
# --------------------------------------------------------------------------- #
def test_other_error_body_is_unavailable(monkeypatch):
    patch_transport(monkeypatch, FakeResponse(200, {"Error": "Service degraded"}))
    result = XposedOrNotClient().check_email(ADDRESS)

    assert result.outcome == UNAVAILABLE
    assert "degraded" in result.reason


def test_unrecognised_body_is_unavailable(monkeypatch):
    patch_transport(monkeypatch, FakeResponse(200, {"unexpected": "shape"}))
    assert XposedOrNotClient().check_email(ADDRESS).outcome == UNAVAILABLE


def test_404_without_a_not_found_body_is_unavailable(monkeypatch):
    patch_transport(monkeypatch, FakeResponse(404, {"Error": "Bad request"}))
    assert XposedOrNotClient().check_email(ADDRESS).outcome == UNAVAILABLE


@pytest.mark.parametrize("payload", [[], [[]], ["", "  "]])
def test_empty_breach_list_is_unverified_not_safe(monkeypatch, payload):
    patch_transport(monkeypatch, FakeResponse(200, {"breaches": payload}))
    result = XposedOrNotClient().check_email(ADDRESS)

    assert result.outcome == UNAVAILABLE
    assert "empty breach list" in result.reason


def test_provider_outage_is_unavailable(monkeypatch):
    patch_transport(monkeypatch, FakeResponse(503, {}))
    result = XposedOrNotClient().check_email(ADDRESS)

    assert result.outcome == UNAVAILABLE
    assert "server-side" in result.reason


@pytest.mark.parametrize("code", [400, 401, 403, 422])
def test_rejected_request_is_unavailable(monkeypatch, code):
    patch_transport(monkeypatch, FakeResponse(code, {}))
    assert XposedOrNotClient().check_email(ADDRESS).outcome == UNAVAILABLE


def test_non_json_body_is_unavailable(monkeypatch):
    patch_transport(monkeypatch, FakeResponse(200, None, json_error=True, text="<html>"))
    assert XposedOrNotClient().check_email(ADDRESS).outcome == UNAVAILABLE


@pytest.mark.parametrize(
    "exc",
    [
        httpx.ConnectTimeout("timed out"),
        httpx.ConnectError("dns failure"),
        httpx.ReadError("connection reset"),
    ],
)
def test_transport_failure_is_unavailable_and_hides_the_address(monkeypatch, exc):
    patch_transport(monkeypatch, exc=exc)
    sensitive = "very.sensitive.person@example.com"
    result = XposedOrNotClient().check_email(sensitive)

    assert result.outcome == UNAVAILABLE
    assert type(exc).__name__ in result.reason
    # The address must never leak into a reason string (it is logged and rendered).
    assert "very.sensitive.person" not in result.reason
    assert sensitive not in result.reason


# --------------------------------------------------------------------------- #
# Rate limiting (§6)
# --------------------------------------------------------------------------- #
def test_rate_limited_response_is_unavailable_and_starts_a_cooldown(monkeypatch):
    now = [1_000.0]
    patch_transport(monkeypatch, FakeResponse(429, {}, headers={"Retry-After": "30"}))
    client = XposedOrNotClient(clock=lambda: now[0])

    first = client.check_email(ADDRESS)
    assert first.outcome == UNAVAILABLE
    assert first.rate_limited

    # While cooling down we must not touch the provider again.
    calls = patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    second = client.check_email(ADDRESS)
    assert second.outcome == UNAVAILABLE
    assert calls == []

    # Once the cooldown expires the client resumes.
    now[0] += 31
    third = client.check_email(ADDRESS)
    assert third.outcome == FINDING
    assert len(calls) == 1


def test_cooldown_defaults_when_retry_after_is_missing(monkeypatch):
    patch_transport(monkeypatch, FakeResponse(429, {}))
    client = XposedOrNotClient()
    assert client.check_email(ADDRESS).rate_limited


def test_outbound_throttle_enforces_the_per_second_limit(monkeypatch):
    patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    client = XposedOrNotClient(per_second=1)

    assert client.check_email(ADDRESS).outcome == FINDING
    blocked = client.check_email(ADDRESS)
    assert blocked.outcome == UNAVAILABLE
    assert blocked.rate_limited
    assert "2 lookups/second" in blocked.reason


def test_outbound_throttle_enforces_the_hourly_budget(monkeypatch):
    patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    client = XposedOrNotClient(per_second=10, per_hour=1)

    assert client.check_email(ADDRESS).outcome == FINDING
    blocked = client.check_email(ADDRESS)
    assert blocked.outcome == UNAVAILABLE
    assert "budget exhausted" in blocked.reason


# --------------------------------------------------------------------------- #
# Input validation (§7)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "bad",
    ["", "   ", "not-an-email", "no-at-sign.example.com", "a@b", "two@@example.com", None, 42],
)
def test_malformed_input_is_unavailable_and_never_queried(monkeypatch, bad):
    calls = patch_transport(monkeypatch, FakeResponse(200, {"breaches": [["Adobe"]]}))
    result = XposedOrNotClient().check_email(bad)  # type: ignore[arg-type]

    assert result.outcome == UNAVAILABLE
    # Crucially: a malformed address must not consume quota or be "confirmed safe".
    assert calls == []


@pytest.mark.parametrize(
    "good",
    ["person@example.com", "first.last@sub.example.co.uk", "a+tag@example.io", " x@example.com "],
)
def test_valid_addresses_pass_validation(good):
    assert is_well_formed_email(good) is True