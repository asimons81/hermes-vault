from __future__ import annotations

import socket
import os
import urllib.error

from hermes_vault.models import VerificationCategory
from hermes_vault.verifier import Verifier


def test_verifier_classifies_invalid() -> None:
    verifier = Verifier()
    result = verifier._classify_http_error("openai", 401, "{}")
    assert result.category is VerificationCategory.invalid_or_expired


def test_verifier_classifies_rate_limit() -> None:
    verifier = Verifier()
    result = verifier._classify_http_error("github", 403, '{"message":"rate limit exceeded"}')
    assert result.category is VerificationCategory.rate_limit


def test_verifier_classifies_permission_scope_issue() -> None:
    verifier = Verifier()
    result = verifier._classify_http_error(
        "github",
        403,
        '{"message":"Resource not accessible by integration"}',
    )
    assert result.category is VerificationCategory.permission_scope_issue


def test_verifier_classifies_network_failure() -> None:
    verifier = Verifier()
    result = verifier._classify_transport_error("openai", urllib.error.URLError(socket.timeout()))
    assert result.category is VerificationCategory.network_failure


def test_verifier_minimax_uses_configured_endpoint(monkeypatch) -> None:
    monkeypatch.setenv("HERMES_VAULT_MINIMAX_VERIFY_URL", "https://api.minimax.io/v1/models")
    verifier = Verifier()

    captured: dict[str, str] = {}

    def fake_http_verify(config):
        captured["service"] = config.service
        captured["url"] = config.url
        captured["authorization"] = config.headers["Authorization"]
        return verifier._classify_transport_error("minimax", urllib.error.URLError(os.strerror(0)))

    monkeypatch.setattr(verifier, "_http_verify", fake_http_verify)

    verifier._verify_minimax("secret-value")

    assert captured["service"] == "minimax"
    assert captured["url"] == "https://api.minimax.io/v1/models"
    assert captured["authorization"] == "Bearer secret-value"
