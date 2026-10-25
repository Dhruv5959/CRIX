"""HTTPS transactional-email transport tests without contacting the provider."""
from __future__ import annotations

import httpx
import pytest

from app.config import Settings
from app.services.email import EmailDeliveryError, send_email


def _settings() -> Settings:
    return Settings(
        env="production",
        email_provider="resend",
        resend_api_key="test-secret-key",
        email_from="CRIX <no-reply@example.com>",
    )


def test_resend_sends_transactional_email_over_https(monkeypatch):
    requests = []

    class Response:
        status_code = 200

    def post(url, **kwargs):
        requests.append((url, kwargs))
        return Response()

    monkeypatch.setattr("app.services.email.httpx.post", post)
    result = send_email(
        to="employee@example.com",
        subject="Verify your CRIX account",
        body="A one-time verification link",
        settings=_settings(),
    )

    assert result == "resend"
    url, request = requests[0]
    assert url == "https://api.resend.com/emails"
    assert request["headers"]["Authorization"] == "Bearer test-secret-key"
    assert request["json"] == {
        "from": "CRIX <no-reply@example.com>",
        "to": ["employee@example.com"],
        "subject": "Verify your CRIX account",
        "text": "A one-time verification link",
    }
    assert request["timeout"] == 15.0


@pytest.mark.parametrize("status_code", [401, 429, 503])
def test_resend_http_failures_are_safe_delivery_errors(monkeypatch, status_code):
    class Response:
        pass

    response = Response()
    response.status_code = status_code
    monkeypatch.setattr("app.services.email.httpx.post", lambda *_args, **_kwargs: response)

    with pytest.raises(EmailDeliveryError, match="temporarily unavailable"):
        send_email(
            to="employee@example.com", subject="Subject", body="Body", settings=_settings()
        )


def test_resend_network_failure_is_safe_delivery_error(monkeypatch):
    def fail(*_args, **_kwargs):
        raise httpx.TimeoutException("sensitive provider diagnostic")

    monkeypatch.setattr("app.services.email.httpx.post", fail)
    with pytest.raises(EmailDeliveryError, match="temporarily unavailable") as error:
        send_email(to="employee@example.com", subject="Subject", body="Body", settings=_settings())
    assert "sensitive provider diagnostic" not in str(error.value)
