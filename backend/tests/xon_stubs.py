"""Shared stubs for the XposedOrNot integration tests.

The provider is never contacted: ``httpx.get`` is replaced with a stub whose
response can be shaped to anything, including the two shapes where the live API
differs from its own documentation.
"""
from __future__ import annotations

from app.signals import xposedornot as xon


class FakeResponse:
    """Minimal stand-in for ``httpx.Response`` (only what the client reads)."""

    def __init__(
        self,
        status_code: int = 200,
        body=None,
        *,
        headers: dict | None = None,
        json_error: bool = False,
        text: str = "",
    ) -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body
        self._json_error = json_error
        self.text = text

    def json(self):
        if self._json_error:
            raise ValueError("body is not JSON")
        return self._body


def patch_transport(monkeypatch, response=None, *, exc: Exception | None = None) -> list[str]:
    """Replace ``httpx.get`` for the provider module; return the captured URLs."""
    calls: list[str] = []

    def fake_get(url, **_kwargs):
        calls.append(url)
        if exc is not None:
            raise exc
        return response

    monkeypatch.setattr(xon.httpx, "get", fake_get)
    return calls