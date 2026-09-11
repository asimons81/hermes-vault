"""P3 CLI truth pack: verify exit codes + JSON encoding.

Live probes at v0.25.1:
- `verify nonexistent-svc` printed allowed:false "credential not found in
  vault" and exited 0 — real failures looked successful to cron pipelines.
- `verify x --format json` printed a JSON *string containing* JSON (rich
  print_json(data=<pre-encoded str>) re-encodes strings).
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from hermes_vault.cli import _hermes_group
from hermes_vault.models import BrokerDecision


def _build(broker):
    def _inner(prompt: bool = False):
        return object(), object(), broker, object()
    return _inner


def _decision(*, allowed: bool, reason: str, metadata: dict | None = None) -> BrokerDecision:
    return BrokerDecision(
        allowed=allowed,
        service="svc",
        agent_id="hermes-vault",
        reason=reason,
        metadata=metadata or {},
    )


# ── exit codes ─────────────────────────────────────────────────────────────


def test_verify_not_found_exits_nonzero(monkeypatch) -> None:
    class B:
        def verify_credential(self, service, alias=None):
            return _decision(
                allowed=False,
                reason="credential not found in vault",
            )

    monkeypatch.setattr("hermes_vault.cli.build_services", _build(B()))
    result = CliRunner().invoke(_hermes_group, ["--no-banner", "verify", "nonexistent-svc"])
    assert result.exit_code == 1, result.output


def test_verify_invalid_credential_exits_nonzero(monkeypatch) -> None:
    class B:
        def verify_credential(self, service, alias=None):
            return _decision(
                allowed=False,
                reason="invalid credential",
                metadata={
                    "verification_result": {
                        "success": False,
                        "category": "invalid_or_expired",
                        "reason": "invalid credential",
                        "checked_at": "2026-09-10T00:00:00+00:00",
                    }
                },
            )

    monkeypatch.setattr("hermes_vault.cli.build_services", _build(B()))
    result = CliRunner().invoke(_hermes_group, ["--no-banner", "verify", "openai"])
    assert result.exit_code == 1, result.output


def test_verify_denied_by_policy_exits_nonzero(monkeypatch) -> None:
    class B:
        def verify_credential(self, service, alias=None):
            return _decision(allowed=False, reason="agent not allowed")

    monkeypatch.setattr("hermes_vault.cli.build_services", _build(B()))
    result = CliRunner().invoke(_hermes_group, ["--no-banner", "verify", "openai"])
    assert result.exit_code == 1, result.output


def test_verify_valid_credential_exits_zero(monkeypatch) -> None:
    class B:
        def verify_credential(self, service, alias=None):
            return _decision(
                allowed=True,
                reason="ok",
                metadata={
                    "verification_result": {
                        "success": True,
                        "category": "valid",
                        "reason": "ok",
                        "checked_at": "2026-09-10T00:00:00+00:00",
                    }
                },
            )

    monkeypatch.setattr("hermes_vault.cli.build_services", _build(B()))
    result = CliRunner().invoke(_hermes_group, ["--no-banner", "verify", "openai"])
    assert result.exit_code == 0, result.output


def test_verify_unsupported_verifier_is_not_a_failure(monkeypatch) -> None:
    """No provider-specific verifier = configured no-op, exit 0.

    Prevents --all batches from failing on every service without a verifier
    (the common case for custom/internal services)."""
    class B:
        def verify_credential(self, service, alias=None):
            return _decision(
                allowed=False,
                reason="No provider-specific verifier is configured for this service.",
                metadata={
                    "verification_result": {
                        "success": False,
                        "category": "unknown",
                        "reason": "No provider-specific verifier is configured for this service.",
                        "checked_at": "2026-09-10T00:00:00+00:00",
                    }
                },
            )

    monkeypatch.setattr("hermes_vault.cli.build_services", _build(B()))
    result = CliRunner().invoke(_hermes_group, ["--no-banner", "verify", "custom-svc"])
    assert result.exit_code == 0, result.output


def test_verify_mixed_batch_fails_if_any_target_failed(monkeypatch) -> None:
    class FakeVault:
        def list_credentials(self):
            from hermes_vault.models import CredentialRecord
            return [
                CredentialRecord(id="1", service="good", alias="default",
                                 credential_type="api_key", encrypted_payload="x"),
                CredentialRecord(id="2", service="bad", alias="default",
                                 credential_type="api_key", encrypted_payload="x"),
            ]

    class B:
        def __init__(self):
            self.seen = []

        def verify_credential(self, service, alias=None):
            good = service == "good"
            return _decision(
                allowed=good,
                reason="ok" if good else "invalid credential",
                metadata={"verification_result": {
                    "success": good,
                    "category": "valid" if good else "invalid_or_expired",
                    "reason": "ok" if good else "invalid credential",
                    "checked_at": "2026-09-10T00:00:00+00:00",
                }},
            )

    broker = B()

    def _inner(prompt: bool = False):
        return FakeVault(), object(), broker, object()

    monkeypatch.setattr("hermes_vault.cli.build_services", _inner)
    result = CliRunner().invoke(_hermes_group, ["--no-banner", "verify", "--all"])
    assert result.exit_code == 1, result.output


def test_verify_all_unsupported_exits_zero(monkeypatch) -> None:
    """--all over only-unsupported services must still succeed (no-op batch)."""
    class FakeVault:
        def list_credentials(self):
            from hermes_vault.models import CredentialRecord
            return [CredentialRecord(id="1", service="internal", alias="default",
                                     credential_type="api_key", encrypted_payload="x")]

    unsupported_reason = "No provider-specific verifier is configured for this service."

    class B:
        def verify_credential(self, service, alias=None):
            return _decision(
                allowed=False,
                reason=unsupported_reason,
                metadata={"verification_result": {
                    "success": False,
                    "category": "unknown",
                    "reason": unsupported_reason,
                    "checked_at": "2026-09-10T00:00:00+00:00",
                }},
            )

    def _inner(prompt: bool = False):
        return FakeVault(), object(), B(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", _inner)
    result = CliRunner().invoke(_hermes_group, ["--no-banner", "verify", "--all"])
    assert result.exit_code == 0, result.output


# ── JSON encoding ──────────────────────────────────────────────────────────


def test_verify_json_output_is_not_double_encoded(monkeypatch) -> None:
    class B:
        def verify_credential(self, service, alias=None):
            return _decision(allowed=True, reason="ok")

    monkeypatch.setattr("hermes_vault.cli.build_services", _build(B()))
    result = CliRunner().invoke(_hermes_group, ["--no-banner", "verify", "openai", "--format", "json"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert isinstance(parsed, list), f"expected a JSON array, got {type(parsed).__name__}: {result.output[:120]}"
    assert parsed[0]["allowed"] is True


def test_verify_json_report_file_is_plain_json(monkeypatch, tmp_path) -> None:
    class B:
        def verify_credential(self, service, alias=None):
            return _decision(allowed=False, reason="credential not found in vault")

    monkeypatch.setattr("hermes_vault.cli.build_services", _build(B()))
    report = tmp_path / "verify-report.json"
    result = CliRunner().invoke(
        _hermes_group,
        ["--no-banner", "verify", "ghost", "--format", "json", "--report", str(report)],
    )
    # Report written, failure still truthful:
    assert result.exit_code == 1, result.output
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert isinstance(payload, list)
    assert payload[0]["allowed"] is False
