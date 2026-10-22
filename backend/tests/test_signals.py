"""Signal module tests (§3.A-D): breach, hygiene, permissions, phishing."""
from __future__ import annotations

from app.config import Settings
from app.engine.risk import extract_features
from app.schemas import (
    ExposureType,
    PasswordHygieneRequest,
    PasswordReuseItem,
    PermissionAuditRequest,
    PermissionEntry,
    SourceMode,
)
from app.signals.breach import (
    check_breach,
    lookup_email_breaches,
    provider_label,
    resolve_email_provider,
)
from app.signals.hibp import HIBPClient, HIBPUnavailable, classify_session_capability
from app.signals.password import build_hygiene_events
from app.signals.permissions import build_permission_events, classify_permission
from app.signals.xposedornot import (
    CHECKED_SAFE as XON_CHECKED_SAFE,
    FINDING as XON_FINDING,
    UNAVAILABLE as XON_UNAVAILABLE,
    XonLookup,
    XposedOrNotClient,
)


# --------------------------------------------------------------------------- #
# Breach (§3.A)
# --------------------------------------------------------------------------- #
class FakeHIBP(HIBPClient):
    def __init__(self, breaches=None, raises=None):
        super().__init__("fake-key")
        self._breaches = breaches
        self._raises = raises

    def breached_account(self, email):
        if self._raises:
            raise self._raises
        return self._breaches


def test_breach_unavailable_never_becomes_safe(settings):
    events = check_breach(
        user_id="u", account_id="a", email="x@example.com", settings=settings,
        client=FakeHIBP(raises=HIBPUnavailable("no key")),
    )
    assert len(events) == 1
    assert events[0].status == "UNAVAILABLE"
    assert events[0].severity == 0.0


def test_breach_checked_safe_when_404(settings):
    events = check_breach(
        user_id="u", account_id="a", email="x@example.com", settings=settings,
        client=FakeHIBP(breaches=[]),
    )
    assert events[0].status == "CHECKED_SAFE"


def test_breach_finding_with_records(settings):
    breaches = [{"Name": "Adobe", "DataClasses": ["Email addresses", "Passwords"]}]
    events = check_breach(
        user_id="u", account_id="a", email="x@example.com", settings=settings,
        client=FakeHIBP(breaches=breaches),
    )
    types = {e.event_type for e in events}
    assert "BREACH_EXPOSURE" in types
    assert "IDENTITY_EXPOSED" in types
    exposure = next(e for e in events if e.event_type == "BREACH_EXPOSURE")
    assert exposure.status == "FINDING"
    assert exposure.exposure_type == ExposureType.PASSWORD_ONLY


def test_simulated_session_exposure_is_labeled_simulated(settings):
    events = check_breach(
        user_id="u", account_id="a", email="x@example.com", settings=settings,
        client=FakeHIBP(breaches=[]),
        simulated_exposure_type=ExposureType.SESSION_ONLY,
        simulated_mfa_bypass_capable=True,
    )
    session = next(e for e in events if e.event_type == "SESSION_EXPOSURE")
    assert session.source == "simulated"
    assert "SIMULATED" in session.provenance
    assert session.metadata["mfa_bypass_capable"] is True


def test_classify_session_capability():
    assert classify_session_capability({"DataClasses": ["Auth tokens"]}) is True
    assert classify_session_capability({"DataClasses": ["Email addresses"]}) is False


# --------------------------------------------------------------------------- #
# Password hygiene (§3.B)
# --------------------------------------------------------------------------- #
def test_reuse_event_emitted():
    payload = PasswordHygieneRequest(
        account_id="a",
        reused_credentials=[PasswordReuseItem(label="old-gmail", reused=True)],
    )
    events = build_hygiene_events(user_id="u", payload=payload, passkey_supported_by_provider=False)
    assert any(e.event_type == "PASSWORD_REUSE" for e in events)


def test_missing_mfa_flag():
    payload = PasswordHygieneRequest(account_id="a", mfa_enabled=False)
    events = build_hygiene_events(user_id="u", payload=payload, passkey_supported_by_provider=False)
    assert any(e.event_type == "MFA_MISSING" for e in events)


def test_mfa_enabled_no_flag():
    payload = PasswordHygieneRequest(account_id="a", mfa_enabled=True, mfa_method="passkey")
    events = build_hygiene_events(user_id="u", payload=payload, passkey_supported_by_provider=True)
    assert not any(e.event_type == "MFA_MISSING" for e in events)


def test_passkey_ready_not_enabled_from_curated_table():
    payload = PasswordHygieneRequest(account_id="a", mfa_enabled=True, provider="Google",
                                     passkey_enabled=False)
    events = build_hygiene_events(
        user_id="u", payload=payload, passkey_supported_by_provider=True, provider_source="doc"
    )
    assert any(e.event_type == "PASSKEY_READY_NOT_ENABLED" for e in events)


def test_sms_recovery_flags_sim_swap():
    payload = PasswordHygieneRequest(account_id="a", sms_otp_recovery=True)
    events = build_hygiene_events(user_id="u", payload=payload, passkey_supported_by_provider=False)
    assert any(e.event_type == "SIM_SWAP_VULNERABLE" for e in events)


def test_push_bombing_flags():
    payload = PasswordHygieneRequest(account_id="a", push_bombing_reported=True)
    events = build_hygiene_events(user_id="u", payload=payload, passkey_supported_by_provider=False)
    assert any(e.event_type == "PUSH_BOMBING_REPORTED" for e in events)


# --------------------------------------------------------------------------- #
# Permissions (§3.D)
# --------------------------------------------------------------------------- #
def test_permission_taxonomy_is_explainable():
    result = classify_permission("sms")
    assert result["sensitivity"] == "high"
    assert result["rationale"]


def test_unknown_permission_reported_unknown_not_guessed():
    result = classify_permission("some_vendor_weird_scope_xyz")
    assert result["matched"] is False
    assert result["category"] == "unknown"


def test_permission_audit_emits_event_and_report():
    payload = PermissionAuditRequest(
        account_id="a",
        entries=[PermissionEntry(app_name="Sketchy", platform="android",
                                 permissions=["contacts", "location"])],
    )
    events, report = build_permission_events(user_id="u", payload=payload)
    assert any(e.event_type == "RISKY_PERMISSION_GRANTED" for e in events)
    assert report[0]["permissions"][0]["sensitivity"] == "high"
    assert all("rationale" in c for c in report[0]["permissions"])


# --------------------------------------------------------------------------- #
# Breach provider orchestration (§3.A — XposedOrNot integration)
# --------------------------------------------------------------------------- #
class FakeXon(XposedOrNotClient):
    """Duck-typed stand-in so orchestration can be tested without a socket."""

    def __init__(self, outcome=XON_FINDING, breaches=None, reason=""):
        super().__init__()
        self._outcome = outcome
        self._breaches = list(breaches or [])
        self._reason = reason

    def check_email(self, email):  # noqa: ARG002 - signature parity with the real client
        return XonLookup(self._outcome, self._breaches, self._reason)


def _check_with(outcome, settings, breaches=None, reason=""):
    return check_breach(
        user_id="u",
        account_id="a",
        email="x@example.com",
        settings=settings,
        xon_client=FakeXon(outcome, breaches, reason),
    )


def _exposure(events):
    return next(e for e in events if e.event_type == "BREACH_EXPOSURE")


def _settings(**overrides) -> Settings:
    base = dict(
        env="test",
        database_url="sqlite://",
        jwt_secret="t" * 40,
        hibp_api_key="",
    )
    base.update(overrides)
    return Settings(**base)


def test_provider_resolution_uses_the_free_api_when_no_hibp_key_exists():
    assert resolve_email_provider(_settings()) == "xposedornot"


def test_provider_resolution_prefers_hibp_only_when_a_key_is_configured():
    assert resolve_email_provider(_settings(hibp_api_key="real-key")) == "hibp"


def test_provider_resolution_honours_an_explicit_preference():
    assert resolve_email_provider(_settings(breach_email_provider="hibp")) == "hibp"
    assert (
        resolve_email_provider(
            _settings(breach_email_provider="xposedornot", hibp_api_key="real-key")
        )
        == "xposedornot"
    )


def test_xon_finding_carries_provider_and_checked_at(settings):
    events = _check_with(XON_FINDING, settings, ["Adobe", "Chegg"])
    exposure = _exposure(events)

    assert exposure.status == "FINDING"
    assert exposure.source == "xposedornot"
    assert exposure.source_mode == SourceMode.REAL
    assert exposure.metadata["provider"] == "xposedornot"
    assert exposure.metadata["provider_label"] == provider_label("xposedornot")
    assert exposure.metadata["breaches"] == ["Adobe", "Chegg"]
    assert exposure.metadata["breach_count"] == 2
    # "last checked" is recorded and persisted with the event.
    assert exposure.metadata["checked_at"] == exposure.detected_at.isoformat()


def test_xon_finding_does_not_claim_which_data_classes_leaked(settings):
    exposure = _exposure(_check_with(XON_FINDING, settings, ["Adobe"]))

    # Claiming PASSWORD_ONLY would assert a password leaked. XON does not know.
    assert exposure.exposure_type is None
    assert exposure.metadata["exposed_data_classes"] == "UNAVAILABLE_THROUGH_PROVIDER"
    assert exposure.metadata["session_capable_breach"] is False


def test_xon_unavailable_is_never_safe(settings):
    events = _check_with(XON_UNAVAILABLE, settings, reason="free-tier budget exhausted")
    exposure = events[0]

    assert exposure.status == "UNAVAILABLE"
    assert exposure.status != "CHECKED_SAFE"
    assert exposure.severity == 0.0
    assert exposure.confidence == 0.0
    assert exposure.source_mode == SourceMode.UNAVAILABLE
    assert "budget" in exposure.metadata["reason"]
    assert len(events) == 1  # no identity claim either


def test_xon_checked_safe_is_a_negative_not_a_finding(settings):
    events = _check_with(XON_CHECKED_SAFE, settings)
    exposure = events[0]

    assert exposure.status == "CHECKED_SAFE"
    assert exposure.severity == 0.0
    assert exposure.metadata["breach_count"] == 0
    assert "not proof" in exposure.provenance


def test_unknown_provider_name_queries_nothing(settings):
    lookup = lookup_email_breaches("x@example.com", settings=settings, provider="nonsense")

    assert lookup.outcome == XON_UNAVAILABLE
    assert "nonsense" in lookup.reason
    assert lookup.breach_names == []


def test_injected_client_pins_its_own_provider(settings):
    lookup = lookup_email_breaches(
        "x@example.com", settings=settings, hibp_client=FakeHIBP(breaches=[])
    )
    assert lookup.provider == "hibp"


def test_explicit_provider_overrides_an_injected_client(settings):
    lookup = lookup_email_breaches(
        "x@example.com",
        settings=settings,
        provider="xposedornot",
        xon_client=FakeXon(XON_FINDING, ["Adobe"]),
    )
    assert lookup.provider == "xposedornot"
    assert lookup.breach_names == ["Adobe"]


# --------------------------------------------------------------------------- #
# §8: the provider observes, the engine scores
# --------------------------------------------------------------------------- #
def test_unavailable_and_checked_safe_lookups_add_no_breach_risk(settings):
    for outcome in (XON_UNAVAILABLE, XON_CHECKED_SAFE):
        events = _check_with(outcome, settings)
        assert extract_features(events)["breach"] == 0.0


def test_provider_cannot_set_the_authoritative_score(settings):
    """A provider answer becomes ONE observation, never a score."""
    events = _check_with(XON_FINDING, settings, ["Adobe"])
    features = extract_features(events)
    exposure = _exposure(events)

    assert features["breach"] == exposure.severity
    # The provider's payload touched nothing else in the feature vector.
    assert {name for name, value in features.items() if value > 0} == {"breach", "identity"}