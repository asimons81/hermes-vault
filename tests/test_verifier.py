from __future__ import annotations

import os
import socket
import urllib.error

from hermes_vault.models import VerificationCategory, VerificationResult
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


def test_verifier_unknown_service_keeps_unsupported_result() -> None:
    verifier = Verifier(load_file_plugins=False, load_entry_points=False)

    result = verifier.verify("internal-tool", "secret-value")

    assert result.service == "internal-tool"
    assert result.category is VerificationCategory.unknown
    assert result.success is False
    assert result.reason == "No provider-specific verifier is configured for this service."


def test_register_custom_verifier_and_manual_override() -> None:
    verifier = Verifier(load_file_plugins=False, load_entry_points=False)

    def first(secret: str) -> VerificationResult:
        return VerificationResult(
            service="custom-service",
            category=VerificationCategory.valid,
            success=True,
            reason=f"first:{secret}",
        )

    def second(secret: str) -> VerificationResult:
        return VerificationResult(
            service="custom-service",
            category=VerificationCategory.unknown,
            success=False,
            reason=f"second:{secret}",
        )

    verifier.register("custom-service", first)
    verifier.register("custom-service", second)
    assert verifier.verify("custom-service", "secret-value").reason == "first:secret-value"
    assert verifier.diagnostics()[-1].level == "warning"

    verifier.register("custom-service", second, override=True)
    assert verifier.verify("custom-service", "secret-value").reason == "second:secret-value"
    assert verifier.diagnostics()[-1].level == "info"


def test_file_plugin_registers_http_verifier_and_renders_secret_at_verify_time(monkeypatch, tmp_path) -> None:
    plugin_dir = tmp_path / "verifiers"
    plugin_dir.mkdir()
    (plugin_dir / "acme.yaml").write_text(
        """
verifiers:
  acme_custom:
    type: http
    method: POST
    url: https://api.acme.example/v1/me
    headers:
      Authorization: "Bearer {secret}"
      Accept: application/json
    success_statuses: [204]
    timeout_seconds: 3
""",
        encoding="utf-8",
    )
    verifier = Verifier(plugin_dir=plugin_dir, load_entry_points=False)
    captured: dict[str, object] = {}

    def fake_http_verify(config):
        captured["service"] = config.service
        captured["method"] = config.method
        captured["url"] = config.url
        captured["authorization"] = config.headers["Authorization"]
        captured["success_statuses"] = config.success_statuses
        captured["timeout_seconds"] = config.timeout_seconds
        return VerificationResult(
            service=config.service,
            category=VerificationCategory.valid,
            success=True,
            reason="ok",
        )

    monkeypatch.setattr(verifier, "_http_verify", fake_http_verify)

    result = verifier.verify("acme_custom", "secret-value")

    assert result.success is True
    assert captured == {
        "service": "acme_custom",
        "method": "POST",
        "url": "https://api.acme.example/v1/me",
        "authorization": "Bearer secret-value",
        "success_statuses": (204,),
        "timeout_seconds": 3,
    }
    assert verifier.diagnostics() == []


def test_file_plugin_errors_are_diagnostics_not_constructor_failures(tmp_path) -> None:
    plugin_dir = tmp_path / "verifiers"
    plugin_dir.mkdir()
    (plugin_dir / "bad.yaml").write_text("verifiers: [not-a-mapping", encoding="utf-8")
    (plugin_dir / "unknown-type.yaml").write_text(
        """
verifiers:
  acme:
    type: shell
    url: https://api.acme.example/v1/me
    headers:
      Authorization: "Bearer {secret}"
""",
        encoding="utf-8",
    )

    verifier = Verifier(plugin_dir=plugin_dir, load_entry_points=False)

    diagnostics = verifier.diagnostics()
    assert [diagnostic.level for diagnostic in diagnostics] == ["error", "error"]
    assert "Invalid verifier plugin YAML" in diagnostics[0].message
    assert "Invalid verifier plugin schema" in diagnostics[1].message


def test_file_plugin_does_not_override_builtin_without_global_opt_in(monkeypatch, tmp_path) -> None:
    plugin_dir = tmp_path / "verifiers"
    plugin_dir.mkdir()
    (plugin_dir / "openai.yaml").write_text(
        """
verifiers:
  openai:
    type: http
    url: https://example.invalid/plugin
    headers:
      Authorization: "Bearer {secret}"
    allow_override: true
""",
        encoding="utf-8",
    )
    verifier = Verifier(plugin_dir=plugin_dir, load_entry_points=False)
    captured: dict[str, str] = {}

    def fake_http_verify(config):
        captured["url"] = config.url
        return VerificationResult(
            service=config.service,
            category=VerificationCategory.valid,
            success=True,
            reason="ok",
        )

    monkeypatch.setattr(verifier, "_http_verify", fake_http_verify)

    verifier.verify("openai", "secret-value")

    assert captured["url"] == "https://api.openai.com/v1/models"
    assert verifier.diagnostics()[-1].level == "warning"


def test_file_plugin_can_override_builtin_with_global_and_plugin_opt_in(monkeypatch, tmp_path) -> None:
    plugin_dir = tmp_path / "verifiers"
    plugin_dir.mkdir()
    (plugin_dir / "openai.yaml").write_text(
        """
verifiers:
  openai:
    type: http
    url: https://example.invalid/plugin
    headers:
      Authorization: "Bearer {secret}"
    allow_override: true
""",
        encoding="utf-8",
    )
    verifier = Verifier(
        plugin_dir=plugin_dir,
        load_entry_points=False,
        allow_plugin_overrides=True,
    )
    captured: dict[str, str] = {}

    def fake_http_verify(config):
        captured["url"] = config.url
        return VerificationResult(
            service=config.service,
            category=VerificationCategory.valid,
            success=True,
            reason="ok",
        )

    monkeypatch.setattr(verifier, "_http_verify", fake_http_verify)

    verifier.verify("openai", "secret-value")

    assert captured["url"] == "https://example.invalid/plugin"
    assert verifier.diagnostics()[-1].level == "info"


def test_entry_point_plugin_registers_service(monkeypatch, tmp_path) -> None:
    class EntryPlugin:
        service_ids = ("entry-custom",)

        def verify(self, service, secret, context):
            return VerificationResult(
                service=service,
                category=VerificationCategory.valid,
                success=True,
                reason=f"entry:{secret}:{context.timeout_seconds}",
            )

    class FakeEntryPoint:
        name = "entry_custom"

        def load(self):
            return EntryPlugin

    monkeypatch.setattr(
        "hermes_vault.verifier.metadata.entry_points",
        lambda group: [FakeEntryPoint()],
    )

    verifier = Verifier(plugin_dir=tmp_path / "missing", load_file_plugins=False, timeout_seconds=7)

    result = verifier.verify("entry-custom", "secret-value")

    assert result.success is True
    assert result.reason == "entry:secret-value:7"


def test_registered_plugin_exception_is_sanitized() -> None:
    verifier = Verifier(load_file_plugins=False, load_entry_points=False)

    def raises(secret: str) -> VerificationResult:
        raise RuntimeError(f"secret leaked: {secret}")

    verifier.register("boom", raises)

    result = verifier.verify("boom", "secret-value")

    assert result.category is VerificationCategory.unknown
    assert result.reason == "Verifier plugin failed: RuntimeError"
    assert "secret-value" not in result.reason


def test_plugin_protocol_exports_remain_available() -> None:
    from hermes_vault.verifiers import CredentialVerifierPlugin, VerifierContext
    from hermes_vault.verifiers.base import ProviderVerifierConfig

    assert CredentialVerifierPlugin is not None
    assert VerifierContext is not None
    assert ProviderVerifierConfig is not None
