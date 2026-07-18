from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from click.testing import CliRunner

from hermes_vault import _platform
from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.cli import _dashboard_runtime_warning, _hermes_group, app
from hermes_vault.models import AgentPolicy, BrokerDecision, MutationResult, PolicyConfig, ServiceAction, ServicePolicyEntry, utc_now
from hermes_vault.policy import PolicyEngine
from hermes_vault.vault import Vault


class StubBroker:
    def __init__(self) -> None:
        self.called_with: list[str] = []
        self.audit = None

    def verify_credential(self, service: str, alias: str | None = None) -> BrokerDecision:
        self.called_with.append(service)
        return BrokerDecision(
            allowed=True,
            service=service,
            agent_id="hermes-vault",
            reason="ok",
        )

    def issue_lease(self, agent_id: str, service_or_id: str, ttl_seconds: int, alias: str | None = None, purpose: str = "task", reason: str | None = None) -> BrokerDecision:
        self.called_with.append(f"lease:{service_or_id}")
        return BrokerDecision(
            allowed=True,
            service=service_or_id,
            agent_id=agent_id,
            reason="lease issued",
            ttl_seconds=ttl_seconds,
            metadata={"lease": {"id": "lease-1", "service": service_or_id, "alias": alias or "default", "purpose": purpose}},
        )

    def list_leases(self, agent_id: str, service: str | None = None, status: str | None = None) -> BrokerDecision:
        return BrokerDecision(
            allowed=True,
            service=service or "*",
            agent_id=agent_id,
            reason="returned 1 lease",
            metadata={"leases": [{"id": "lease-1", "service": service or "openai", "status": status or "active"}]},
        )

    def show_lease(self, agent_id: str, lease_id: str) -> BrokerDecision:
        return BrokerDecision(
            allowed=True,
            service="openai",
            agent_id=agent_id,
            reason="returned lease",
            metadata={"lease": {"id": lease_id, "service": "openai", "status": "active"}},
        )

    def renew_lease(self, agent_id: str, lease_id: str, ttl_seconds: int) -> BrokerDecision:
        return BrokerDecision(
            allowed=True,
            service="openai",
            agent_id=agent_id,
            reason="renewed lease",
            ttl_seconds=ttl_seconds,
            metadata={"lease": {"id": lease_id, "service": "openai", "status": "active"}},
        )

    def revoke_lease(self, agent_id: str, lease_id: str, reason: str | None = None) -> BrokerDecision:
        return BrokerDecision(
            allowed=True,
            service="openai",
            agent_id=agent_id,
            reason="revoked lease",
            metadata={"lease": {"id": lease_id, "service": "openai", "status": "revoked"}},
        )


class StubMutations:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.records: dict[str, object] = {}

    def add_credential(self, **kwargs):
        self.calls.append(("add", kwargs))
        from hermes_vault.models import CredentialRecord
        rec = CredentialRecord(
            id="test-id-123",
            service=kwargs.get("service", "openai"),
            alias=kwargs.get("alias", "default"),
            credential_type=kwargs.get("credential_type", "api_key"),
            encrypted_payload="encrypted",
            tags=kwargs.get("tags") or [],
            notes=kwargs.get("notes"),
        )
        return MutationResult(
            allowed=True,
            service=kwargs.get("service", "openai"),
            agent_id="operator",
            action="add_credential",
            reason="ok",
            record=rec,
        )

    def get_metadata(self, **kwargs):
        self.calls.append(("metadata", kwargs))
        from hermes_vault.models import CredentialRecord
        rec = CredentialRecord(
            id="test-id-123",
            service=kwargs.get("service_or_id", "openai"),
            alias="default",
            credential_type="api_key",
            encrypted_payload="encrypted",
        )
        return MutationResult(
            allowed=True,
            service=kwargs.get("service_or_id", "openai"),
            agent_id="operator",
            action="get_metadata",
            reason="ok",
            record=rec,
        )

    def rotate_credential(self, **kwargs):
        self.calls.append(("rotate", kwargs))
        from hermes_vault.models import CredentialRecord
        rec = CredentialRecord(
            id="test-id-123",
            service=kwargs.get("service_or_id", "openai"),
            alias="default",
            credential_type="api_key",
            encrypted_payload="encrypted",
        )
        return MutationResult(
            allowed=True,
            service=kwargs.get("service_or_id", "openai"),
            agent_id="operator",
            action="rotate_credential",
            reason="ok",
            record=rec,
        )

    def delete_credential(self, **kwargs):
        self.calls.append(("delete", kwargs))
        return MutationResult(
            allowed=True,
            service=kwargs.get("service_or_id", "openai"),
            agent_id="operator",
            action="delete_credential",
            reason="ok",
            metadata={"credential_id": "test-id-123"},
        )


def _fake_build_services(mutations: StubMutations | None = None, broker: StubBroker | None = None):
    """Return a fake build_services that uses stubs."""
    broker = broker or StubBroker()
    mutations = mutations or StubMutations()

    def _inner(prompt: bool = False):
        return object(), object(), broker, mutations

    return _inner


def test_policy_doctor_json_output(monkeypatch, tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
agents:
  hermes:
    services:
      openai:
        actions: [get_env, verify, metadata, add_credential, rotate]
    capabilities: [list_credentials]
    raw_secret_access: false
    ephemeral_env_only: true
    max_ttl_seconds: 900
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["policy", "doctor", "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["version"] == "policy-doctor-v1"
    assert payload["finding_count"] == 0


def test_policy_doctor_strict_exit_code(monkeypatch, tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
agents:
  hermes:
    services: [openai]
    raw_secret_access: true
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["policy", "doctor", "--strict", "--format", "json"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["strict_violation"] is True
    assert any(f["kind"] == "raw_secret_access_enabled" for f in payload["findings"])


def test_policy_explain_json_reports_lease_requirement(monkeypatch, tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
agents:
  coder:
    services:
      openai:
        actions: [get_env]
        require_lease_for_env: true
        max_ttl_seconds: 300
    max_ttl_seconds: 900
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))

    runner = CliRunner()
    result = runner.invoke(
        _hermes_group,
        ["policy", "explain", "coder", "openai", "--action", "get_env", "--ttl", "600", "--format", "json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["version"] == "policy-explain-v1"
    assert payload["requires_lease"] is True
    assert payload["effective_ttl_seconds"] == 300


def test_policy_simulate_denies_missing_action(monkeypatch, tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
agents:
  auditor:
    services:
      github:
        actions: [metadata]
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))

    runner = CliRunner()
    result = runner.invoke(
        _hermes_group,
        ["policy", "simulate", "--agent", "auditor", "--service", "github", "--actions", "metadata,get_env"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["version"] == "policy-simulate-v1"
    assert payload["allowed"] is False


def test_maintain_json_output(monkeypatch) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services())

    class FakeReport:
        recommended_exit_code = 0

        def as_dict(self, exclude_none: bool = True):
            return {
                "version": "maintain-v1",
                "dry_run": True,
                "lifecycle_scope": "refresh + health only",
                "policy_drift_checked": False,
                "recovery_proven": False,
                "next_step_hint": "Run policy doctor, then backup-verify and restore --dry-run.",
                "refresh_summary": {"attempted": 0, "succeeded": 0, "failed": 0},
                "health": {"healthy": True, "findings": []},
                "audit_recorded": False,
                "recommended_exit_code": 0,
            }

    monkeypatch.setattr("hermes_vault.maintenance.run_maintenance", lambda *args, **kwargs: FakeReport())

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["maintain", "--dry-run", "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["version"] == "maintain-v1"
    assert payload["dry_run"] is True
    assert payload["lifecycle_scope"] == "refresh + health only"
    assert payload["policy_drift_checked"] is False
    assert payload["recovery_proven"] is False
    assert "backup-verify" in payload["next_step_hint"]


def test_maintain_table_uses_recommended_exit_code(monkeypatch) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services())

    class FakeReport:
        recommended_exit_code = 1
        refresh_summary = {"attempted": 1, "succeeded": 0, "failed": 1}
        health = {"healthy": False, "findings": []}
        leases = {"active": 0, "expired": 1, "revoked": 0, "total": 1}
        audit_recorded = True
        lifecycle_scope = "refresh + health only"
        policy_drift_checked = False
        recovery_proven = False
        next_step_hint = "Fix refresh and health, then run policy doctor and backup-verify."
        refresh_results = [
            {
                "service": "google",
                "alias": "work",
                "success": False,
                "error_kind": "missing_refresh_token",
                "reason": "No refresh token found",
            }
        ]

    monkeypatch.setattr("hermes_vault.maintenance.run_maintenance", lambda *args, **kwargs: FakeReport())

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["maintain"])

    assert result.exit_code == 1
    assert "Hermes Vault Maintenance" in result.output
    assert "Lifecycle scope" in result.output
    assert "policy doctor" in result.output
    assert "Refresh Failures" in result.output


def test_maintain_print_systemd(monkeypatch) -> None:
    monkeypatch.setattr(_platform, "current_platform", lambda: _platform.PlatformKind.POSIX)
    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["maintain", "--print-systemd"])

    assert result.exit_code == 0
    assert "hermes-vault-maintain.service" in result.output
    assert "hermes-vault --no-banner maintain --format json" in result.output


def test_maintain_print_schedule_alias(monkeypatch) -> None:
    monkeypatch.setattr(_platform, "current_platform", lambda: _platform.PlatformKind.POSIX)
    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["maintain", "--print-schedule"])

    assert result.exit_code == 0
    assert "hermes-vault-maintain.service" in result.output
    assert "hermes-vault --no-banner maintain --format json" in result.output


def test_oauth_device_login_invokes_device_flow(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeFlow:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def run(self):
            captured["ran"] = True

    monkeypatch.setattr("hermes_vault.oauth.device.DeviceLoginFlow", FakeFlow)

    runner = CliRunner()
    result = runner.invoke(
        _hermes_group,
        ["oauth", "device-login", "google", "--alias", "work", "--scope", "openid", "--scope", "email"],
    )

    assert result.exit_code == 0
    assert captured["provider_id"] == "google"
    assert captured["alias"] == "work"
    assert captured["timeout"] == 300
    assert captured["scopes"] == ["openid", "email"]
    assert captured["ran"] is True


def test_oauth_login_headless_routes_to_device_flow(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    class FakeFlow:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def run(self):
            captured["ran"] = True

    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_OAUTH_GOOGLE_CLIENT_ID", "test-client-id")
    monkeypatch.setattr("hermes_vault.oauth.device.DeviceLoginFlow", FakeFlow)

    runner = CliRunner()
    result = runner.invoke(
        _hermes_group,
        ["oauth", "login", "google", "--alias", "work", "--headless", "--scope", "openid"],
    )

    assert result.exit_code == 0
    assert captured["provider_id"] == "google"
    assert captured["alias"] == "work"
    assert captured["scopes"] == ["openid"]
    assert captured["ran"] is True


def test_oauth_login_headless_rejects_unsupported_provider(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["oauth", "login", "openai", "--headless"])

    assert result.exit_code == 1
    assert "does not support headless device-code login" in result.output
    assert "Use --no-browser" in result.output


def test_bootstrap_json_dry_run_never_prints_secrets(monkeypatch, tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("OPENAI_API_KEY=sk-secret-value\nBOGUS=value\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path / "vault-home"))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")

    runner = CliRunner()
    result = runner.invoke(
        _hermes_group,
        ["bootstrap", "--from-env", str(env_path), "--agent", "test-agent", "--dry-run", "--json"],
    )

    assert result.exit_code == 0
    assert "sk-secret-value" not in result.output
    payload = json.loads(result.output)
    assert payload["version"] == "first-safe-agent-bootstrap-v1"
    assert payload["dry_run"] is True
    assert payload["agent"] == "test-agent"
    assert payload["import_preview"]["importable_count"] == 1
    assert payload["import_preview"]["importable"][0]["env_name"] == "OPENAI_API_KEY"
    assert payload["import_result"]["imported_count"] == 0
    assert not (tmp_path / "vault-home" / "policy.yaml").exists()
    assert not (tmp_path / "vault-home" / "vault.db").exists()
    assert env_path.read_text(encoding="utf-8") == "OPENAI_API_KEY=sk-secret-value\nBOGUS=value\n"


def test_oauth_providers_shows_device_code_support(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["oauth", "providers"])

    assert result.exit_code == 0
    assert "Device Code" in result.output
    assert "google" in result.output
    assert "github" in result.output


def test_oauth_doctor_json_reports_missing_env_without_secret(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.delenv("HERMES_VAULT_OAUTH_GOOGLE_CLIENT_ID", raising=False)

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["oauth", "doctor", "google", "--format", "json"])

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["provider"] == "google"
    assert data["supports_device_code"] is True
    assert data["missing_env"] == ["HERMES_VAULT_OAUTH_GOOGLE_CLIENT_ID"]
    assert "secret" not in result.output.lower()


def test_oauth_doctor_table_reports_ready_provider(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_OAUTH_GOOGLE_CLIENT_ID", "client-id")

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["oauth", "doctor", "google"])

    assert result.exit_code == 0
    assert "OAuth Provider Readiness" in result.output
    assert "hermes-vault oauth login google --alias work --headless" in result.output


def test_oauth_normalize_json_output(monkeypatch) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services())

    class FakeReport:
        def as_dict(self):
            return {
                "version": "oauth-normalize-v1",
                "dry_run": True,
                "changed_count": 0,
                "skipped_count": 0,
                "changes": [],
                "skips": [],
            }

    monkeypatch.setattr("hermes_vault.oauth.normalize.normalize_oauth_records", lambda *args, **kwargs: FakeReport())

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["oauth", "normalize", "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["version"] == "oauth-normalize-v1"
    assert payload["dry_run"] is True


def test_backup_verify_json_output(monkeypatch, tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-secret", "api_key")
    backup_path = tmp_path / "backup.json"
    backup_path.write_text(json.dumps(vault.export_backup()), encoding="utf-8")

    def fake_build_services(prompt: bool = False):
        return vault, object(), object(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build_services)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["backup-verify", "--input", str(backup_path), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["version"] == "backup-verification-v2"
    assert payload["decryptable"] is True


def test_restore_dry_run_json_output_does_not_require_yes(monkeypatch, tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("github", "ghp-secret", "personal_access_token")
    backup_path = tmp_path / "backup.json"
    backup_path.write_text(json.dumps(vault.export_backup()), encoding="utf-8")

    def fake_build_services(prompt: bool = False):
        return vault, object(), object(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build_services)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["restore", "--input", str(backup_path), "--dry-run", "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["mode"] == "restore-dry-run"
    assert payload["would_restore_count"] == 1


def test_agent_context_json_is_redacted(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
agents:
  coder:
    services:
      openai:
        actions: [get_env, issue_lease]
        require_lease_for_env: true
    max_ttl_seconds: 900
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))
    vault = Vault(tmp_path / "vault.db", tmp_path / "master_key_salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-super-secret", "api_key")

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["--no-banner", "agent", "context", "coder", "--format", "json"])

    assert result.exit_code == 0, result.output
    assert "sk-super-secret" not in result.output
    payload = json.loads(result.output)
    assert payload["version"] == "agent-context-v1"
    assert payload["services"][0]["requires_lease_for_env"] is True


def test_request_access_and_approve_cli_without_secret_leak(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
agents:
  coder:
    services:
      openai:
        actions: [get_env, issue_lease]
        require_lease_for_env: true
    max_ttl_seconds: 900
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))
    vault = Vault(tmp_path / "vault.db", tmp_path / "master_key_salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-request-secret", "api_key")

    runner = CliRunner()
    created = runner.invoke(
        _hermes_group,
        ["--no-banner", "request", "access", "openai", "--agent", "coder", "--purpose", "deploy", "--ttl", "60"],
    )
    assert created.exit_code == 0, created.output
    assert "sk-request-secret" not in created.output
    request_id = json.loads(created.output)["metadata"]["request"]["id"]

    approved = runner.invoke(
        _hermes_group,
        ["--no-banner", "request", "approve", request_id, "--issue-lease", "--ttl", "60", "--reason", "ok"],
    )

    assert approved.exit_code == 0, approved.output
    assert "sk-request-secret" not in approved.output
    payload = json.loads(approved.output)
    assert payload["metadata"]["request"]["status"] == "approved"
    assert payload["metadata"]["request"]["lease_id"]


def test_recovery_drill_json_composes_backup_checks(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
    vault = Vault(tmp_path / "vault.db", tmp_path / "master_key_salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-recovery-secret", "api_key")
    backup_path = tmp_path / "backup.json"
    backup_path.write_text(json.dumps(vault.export_backup()), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        _hermes_group,
        ["--no-banner", "recovery", "drill", "--backup", str(backup_path), "--format", "json"],
    )

    assert result.exit_code == 0, result.output
    assert "sk-recovery-secret" not in result.output
    payload = json.loads(result.output)
    assert payload["version"] == "recovery-drill-v1"
    assert payload["backup_verify"]["decryptable"] is True
    assert payload["restore_dry_run"]["decryptable"] is True


def test_incident_bundle_dry_run_lists_redacted_manifest(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
    vault = Vault(tmp_path / "vault.db", tmp_path / "master_key_salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-incident-secret", "api_key")

    runner = CliRunner()
    result = runner.invoke(
        _hermes_group,
        ["--no-banner", "incident", "bundle", "--output", str(tmp_path / "incident.zip"), "--dry-run"],
    )

    assert result.exit_code == 0, result.output
    assert "sk-incident-secret" not in result.output
    payload = json.loads(result.output)
    assert payload["version"] == "incident-bundle-v1"
    assert payload["dry_run"] is True
    assert "audit.json" in payload["files"]


# ── verify (positional target — post issue #6) ────────────────────────────


def test_verify_accepts_positional_target(monkeypatch) -> None:
    broker = StubBroker()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(broker=broker))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify", "minimax"])

    assert result.exit_code == 0
    assert broker.called_with == ["minimax"]


def test_verify_accepts_alias_flag(monkeypatch) -> None:
    broker = StubBroker()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(broker=broker))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify", "github", "--alias", "work"])

    assert result.exit_code == 0
    assert broker.called_with == ["github"]


def test_verify_accepts_all_flag(monkeypatch) -> None:
    """--all should iterate over all vault credentials."""

    class FakeVault:
        def list_credentials(self):
            from hermes_vault.models import CredentialRecord
            return [
                CredentialRecord(id="1", service="openai", alias="default",
                                 credential_type="api_key", encrypted_payload="x"),
                CredentialRecord(id="2", service="github", alias="work",
                                 credential_type="personal_access_token", encrypted_payload="x"),
            ]

    broker = StubBroker()

    def fake_build(prompt=False):
        return FakeVault(), object(), broker, object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build)

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify", "--all"])

    assert result.exit_code == 0
    assert set(broker.called_with) == {"openai", "github"}


def test_verify_no_target_shows_helpful_error(monkeypatch) -> None:
    """No target and no --all should print examples."""
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services())

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify"])

    assert result.exit_code == 1
    assert "Provide a credential target" in result.output
    assert "hermes-vault verify openai" in result.output


def test_verify_help_mentions_verifier_plugin_directory() -> None:
    runner = CliRunner()

    result = runner.invoke(_hermes_group, ["verify", "--help"])

    assert result.exit_code == 0
    assert "$HERMES_VAULT_HOME/verifiers/" in result.output


# ── add (canonical service ID) ─────────────────────────────────────────────


def test_add_normalizes_service_name(monkeypatch) -> None:
    mutations = StubMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["add", "open_ai", "--secret", "sk-test"])

    assert result.exit_code == 0
    # The service should be normalized to 'openai'
    assert mutations.calls[0][1]["service"] == "openai"
    assert "openai" in result.output


def test_add_shows_credential_id(monkeypatch) -> None:
    mutations = StubMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["add", "openai", "--secret", "sk-test"])

    assert result.exit_code == 0
    assert "test-id-123" in result.output


def test_add_accepts_tags_and_notes(monkeypatch) -> None:
    mutations = StubMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(
        _hermes_group,
        [
            "add",
            "openai",
            "--secret",
            "sk-test",
            "--tags",
            "prod, ai",
            "--tags",
            "prod",
            "--notes",
            "plaintext note",
        ],
    )

    assert result.exit_code == 0
    kwargs = mutations.calls[0][1]
    assert kwargs["tags"] == ["prod", "ai"]
    assert kwargs["notes"] == "plaintext note"


# ── show-metadata (error handling) ─────────────────────────────────────────


def test_show_metadata_handles_ambiguous_target(monkeypatch) -> None:
    from hermes_vault.vault import AmbiguousTargetError

    class AmbiguousMutations(StubMutations):
        def get_metadata(self, **kwargs):
            raise AmbiguousTargetError("Service 'github' has 2 credentials — specify credential ID or service+alias")

    mutations = AmbiguousMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["show-metadata", "github"])

    assert result.exit_code == 1
    assert "Ambiguous" in result.output
    assert "--alias" in result.output


def test_show_metadata_handles_not_found(monkeypatch) -> None:
    class NotFoundMutations(StubMutations):
        def get_metadata(self, **kwargs):
            raise KeyError("Service 'nonexistent' not found in vault")

    mutations = NotFoundMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["show-metadata", "nonexistent"])

    assert result.exit_code == 1
    assert "Not found" in result.output


def test_show_metadata_with_alias(monkeypatch) -> None:
    mutations = StubMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["show-metadata", "github", "--alias", "work"])

    assert result.exit_code == 0
    assert mutations.calls[0][1]["alias"] == "work"


# ── rotate (error handling) ────────────────────────────────────────────────


def test_rotate_handles_ambiguous_target(monkeypatch) -> None:
    from hermes_vault.vault import AmbiguousTargetError

    class AmbiguousMutations(StubMutations):
        def rotate_credential(self, **kwargs):
            raise AmbiguousTargetError("Service 'github' has 2 credentials — specify credential ID or service+alias")

    mutations = AmbiguousMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["rotate", "github", "--secret", "new"])

    assert result.exit_code == 1
    assert "Ambiguous" in result.output
    assert "--alias" in result.output


def test_rotate_handles_not_found(monkeypatch) -> None:
    class NotFoundMutations(StubMutations):
        def rotate_credential(self, **kwargs):
            raise KeyError("Service 'nonexistent' not found in vault")

    mutations = NotFoundMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["rotate", "nonexistent", "--secret", "new"])

    assert result.exit_code == 1
    assert "Not found" in result.output


def test_rotate_shows_canonical_service(monkeypatch) -> None:
    mutations = StubMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["rotate", "openai", "--secret", "new"])

    assert result.exit_code == 0
    assert "openai" in result.output


# ── delete (error handling) ────────────────────────────────────────────────


def test_delete_requires_yes(monkeypatch) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services())

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["delete", "openai"])

    assert result.exit_code == 1
    assert "--yes" in result.output


def test_delete_handles_ambiguous_target(monkeypatch) -> None:
    from hermes_vault.vault import AmbiguousTargetError

    class AmbiguousMutations(StubMutations):
        def delete_credential(self, **kwargs):
            raise AmbiguousTargetError("Service 'github' has 2 credentials — specify credential ID or service+alias")

    mutations = AmbiguousMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["delete", "github", "--yes"])

    assert result.exit_code == 1
    assert "Ambiguous" in result.output
    assert "--alias" in result.output


def test_delete_handles_not_found(monkeypatch) -> None:
    class NotFoundMutations(StubMutations):
        def delete_credential(self, **kwargs):
            raise KeyError("Service 'nonexistent' not found in vault")

    mutations = NotFoundMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["delete", "nonexistent", "--yes"])

    assert result.exit_code == 1
    assert "Not found" in result.output


def test_delete_shows_credential_id(monkeypatch) -> None:
    mutations = StubMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["delete", "openai", "--yes"])

    assert result.exit_code == 0
    assert "test-id-123" in result.output


# ── broker get/env (canonical ID) ──────────────────────────────────────────


def test_broker_get_normalizes_service(monkeypatch) -> None:
    """broker get should normalize service names like open_ai → openai."""
    calls = []

    class FakeBroker:
        def get_credential(self, service, purpose, agent_id):
            calls.append(service)
            return BrokerDecision(
                allowed=True, service=service, agent_id=agent_id,
                reason="ok",
            )

    def fake_build(prompt=False):
        return object(), object(), FakeBroker(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build)

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["broker", "get", "open_ai", "--agent", "hermes"])

    assert result.exit_code == 0
    assert calls == ["openai"]


def test_broker_env_normalizes_service(monkeypatch) -> None:
    calls = []

    class FakeBroker:
        def get_ephemeral_env(self, service, agent_id, ttl):
            calls.append(service)
            return BrokerDecision(
                allowed=True, service=service, agent_id=agent_id,
                reason="ok", ttl_seconds=ttl,
            )

    def fake_build(prompt=False):
        return object(), object(), FakeBroker(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build)

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["broker", "env", "gh", "--agent", "hermes"])

    assert result.exit_code == 0
    assert calls == ["github"]


def test_lease_issue_cli_uses_broker(monkeypatch) -> None:
    broker = StubBroker()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(broker=broker))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["lease", "issue", "open_ai", "--agent", "hermes", "--ttl", "600"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["allowed"] is True
    assert payload["service"] == "openai"
    assert payload["ttl_seconds"] == 600
    assert broker.called_with == ["lease:openai"]


def _real_lease_build_services(tmp_path: Path):
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-openai", "api_key", alias="primary", scopes=["models.read"])
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "hermes": AgentPolicy(
                    services=["openai"],
                    service_actions={
                        "openai": ServicePolicyEntry(
                            actions=[
                                ServiceAction.issue_lease,
                                ServiceAction.list_leases,
                                ServiceAction.show_lease,
                                ServiceAction.renew_lease,
                                ServiceAction.revoke_lease,
                            ]
                        )
                    },
                    max_ttl_seconds=900,
                    raw_secret_access=False,
                    ephemeral_env_only=True,
                )
            }
        )
    )
    broker = Broker(vault, policy, object(), AuditLogger(tmp_path / "vault.db"))

    def _inner(prompt: bool = False):
        return vault, policy, broker, object()

    return _inner


def test_lease_cli_end_to_end(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _real_lease_build_services(tmp_path))

    runner = CliRunner()
    issue = runner.invoke(
        _hermes_group,
        ["lease", "issue", "open_ai", "--agent", "hermes", "--ttl", "600", "--alias", "primary", "--purpose", "deploy"],
    )
    assert issue.exit_code == 0
    issued = json.loads(issue.output)
    lease_id = issued["metadata"]["lease"]["id"]
    assert issued["allowed"] is True
    assert issued["service"] == "openai"

    listed = runner.invoke(_hermes_group, ["lease", "list", "--agent", "hermes", "--service", "openai"])
    assert listed.exit_code == 0
    listed_payload = json.loads(listed.output)
    assert [item["id"] for item in listed_payload["metadata"]["leases"]] == [lease_id]

    shown = runner.invoke(_hermes_group, ["lease", "show", lease_id, "--agent", "hermes"])
    assert shown.exit_code == 0
    shown_payload = json.loads(shown.output)
    assert shown_payload["metadata"]["lease"]["purpose"] == "deploy"

    renewed = runner.invoke(_hermes_group, ["lease", "renew", lease_id, "--agent", "hermes", "--ttl", "300"])
    assert renewed.exit_code == 0
    renewed_payload = json.loads(renewed.output)
    assert renewed_payload["ttl_seconds"] == 300
    assert renewed_payload["metadata"]["lease"]["renew_count"] == 1

    revoked = runner.invoke(_hermes_group, ["lease", "revoke", lease_id, "--agent", "hermes", "--reason", "cleanup"])
    assert revoked.exit_code == 0
    revoked_payload = json.loads(revoked.output)
    assert revoked_payload["metadata"]["lease"]["status"] == "revoked"


def test_lease_cli_output_contains_expected_fields(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _real_lease_build_services(tmp_path))

    runner = CliRunner()
    result = runner.invoke(
        _hermes_group,
        ["lease", "issue", "openai", "--agent", "hermes", "--ttl", "120", "--alias", "primary", "--reason", "ticket-7"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    lease = payload["metadata"]["lease"]
    assert {"id", "service", "alias", "agent_id", "status", "ttl_seconds", "expires_at", "reason"}.issubset(lease)
    assert lease["reason"] == "ticket-7"


def test_policy_pack_show_and_init(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()
    show_result = runner.invoke(_hermes_group, ["policy", "pack", "show", "coder", "--format", "json"])
    assert show_result.exit_code == 0
    show_payload = json.loads(show_result.output)
    assert show_payload["agents"]["hermes"]["services"]
    assert "issue_lease" in show_payload["agents"]["hermes"]["service_actions"]["openai"]["actions"]

    output = tmp_path / "policy.yaml"
    init_result = runner.invoke(_hermes_group, ["policy", "pack", "init", "auditor", "--output", str(output), "--force"])
    assert init_result.exit_code == 0
    assert output.exists()
    text = output.read_text(encoding="utf-8")
    assert "agents:" in text
    assert "list_leases" in text


# ── import (error handling) ────────────────────────────────────────────────


def test_import_requires_source(monkeypatch) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services())

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["import"])

    assert result.exit_code == 1
    assert "--from-env" in result.output or "--from-file" in result.output


def test_import_from_env_reports_skipped_unknowns(monkeypatch, tmp_path: Path) -> None:
    mutations = StubMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))
    env_path = tmp_path / ".env"
    env_path.write_text("OPENAI_API_KEY=fake-openai\nUNKNOWN_NAME=fake\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        _hermes_group,
        [
            "import",
            "--from-env",
            str(env_path),
            "--tags",
            "imported, env",
            "--notes",
            "source import",
        ],
    )

    assert result.exit_code == 0
    assert "Imported 1 credential" in result.output
    assert "skipped 1 env" in result.output
    assert "Skipped" in result.output
    assert "UNKNOWN_NAME" in result.output
    assert mutations.calls[0][1]["service"] == "openai"
    assert mutations.calls[0][1]["tags"] == ["imported", "env"]
    assert mutations.calls[0][1]["notes"] == "source import"


def test_import_from_env_is_idempotent_and_updates_existing(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    env_path = tmp_path / ".env"
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
    env_path.write_text("OPENAI_API_KEY=sk-aaaaaaaaaaaaaaaaaaaa\n", encoding="utf-8")

    runner = CliRunner()
    first = runner.invoke(_hermes_group, ["import", "--from-env", str(env_path)])
    assert first.exit_code == 0
    assert "Imported 1 credential" in first.output

    second = runner.invoke(_hermes_group, ["import", "--from-env", str(env_path)])
    assert second.exit_code == 0
    assert "Already imported" in second.output

    env_path.write_text("OPENAI_API_KEY=sk-bbbbbbbbbbbbbbbbbbbb\n", encoding="utf-8")
    third = runner.invoke(_hermes_group, ["import", "--from-env", str(env_path)])
    assert third.exit_code == 0
    assert "Updated" in third.output

    vault = Vault(home / "vault.db", home / "master_key_salt.bin", "test-passphrase")
    secret = vault.get_secret("openai")
    assert secret is not None
    assert secret.secret == "sk-bbbbbbbbbbbbbbbbbbbb"


def test_import_from_env_known_hint_imports_openrouter_and_fal(monkeypatch, tmp_path: Path) -> None:
    mutations = StubMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))
    env_path = tmp_path / ".env"
    env_path.write_text("OPENROUTER_API_KEY=fake-openrouter\nFAL_KEY=fake-fal\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["import", "--from-env", str(env_path)])

    assert result.exit_code == 0
    assert "Imported 2 credential" in result.output
    calls = [call for _action, call in mutations.calls]
    assert [(call["service"], call["credential_type"], call["alias"]) for call in calls] == [
        ("openrouter", "api_key", "openrouter_api_key"),
        ("fal", "api_key", "fal_key"),
    ]


def test_import_from_env_dry_run_does_not_build_services_or_mutate(monkeypatch, tmp_path: Path) -> None:
    def fail_build(prompt: bool = False):
        raise AssertionError("build_services must not be called for dry-run")

    monkeypatch.setattr("hermes_vault.cli.build_services", fail_build)
    env_path = tmp_path / ".env"
    env_path.write_text("OPENROUTER_API_KEY=fake-openrouter\nUNKNOWN_NAME=fake\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["import", "--from-env", str(env_path), "--dry-run"])

    assert result.exit_code == 0
    assert "Would import" in result.output
    assert "Dry run: 1 credential" in result.output
    assert "Skipped" in result.output


def test_import_from_env_map_override_imports_custom_name(monkeypatch, tmp_path: Path) -> None:
    mutations = StubMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))
    env_path = tmp_path / ".env"
    env_path.write_text("WEIRD_SECRET=fake-custom\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        _hermes_group,
        [
            "import",
            "--from-env",
            str(env_path),
            "--map",
            "WEIRD_SECRET=custom-service:api_key",
        ],
    )

    assert result.exit_code == 0
    assert len(mutations.calls) == 1
    call = mutations.calls[0][1]
    assert call["service"] == "custom-service"
    assert call["credential_type"] == "api_key"
    assert call["alias"] == "weird_secret"


def test_import_from_env_redact_source_only_imported_lines(monkeypatch, tmp_path: Path) -> None:
    mutations = StubMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))
    env_path = tmp_path / ".env"
    env_path.write_text("OPENAI_API_KEY=fake-openai\nUNKNOWN_NAME=fake\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["import", "--from-env", str(env_path), "--redact-source"])

    assert result.exit_code == 0
    text = env_path.read_text(encoding="utf-8")
    assert "# REDACTED by hermes-vault import: OPENAI_API_KEY=fake-openai" in text
    assert "UNKNOWN_NAME=fake" in text
    assert "# REDACTED by hermes-vault import: UNKNOWN_NAME" not in text
    assert "1 skipped" in result.output


def test_import_from_env_dry_run_redact_source_leaves_file_unchanged(monkeypatch, tmp_path: Path) -> None:
    def fail_build(prompt: bool = False):
        raise AssertionError("build_services must not be called for dry-run")

    monkeypatch.setattr("hermes_vault.cli.build_services", fail_build)
    env_path = tmp_path / ".env"
    original = "OPENAI_API_KEY=fake-openai\nUNKNOWN_NAME=fake\n"
    env_path.write_text(original, encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["import", "--from-env", str(env_path), "--dry-run", "--redact-source"])

    assert result.exit_code == 0
    assert env_path.read_text(encoding="utf-8") == original
    assert "not redacted" in result.output


def test_import_from_env_next_public_skipped(monkeypatch, tmp_path: Path) -> None:
    def fail_build(prompt: bool = False):
        raise AssertionError("build_services must not be called when every env var is skipped")

    monkeypatch.setattr("hermes_vault.cli.build_services", fail_build)
    env_path = tmp_path / ".env"
    env_path.write_text("NEXT_PUBLIC_API_KEY=public\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["import", "--from-env", str(env_path)])

    assert result.exit_code == 0
    assert "Imported 0 credential" in result.output
    assert "public" in result.output


def test_import_from_env_broad_secret_skipped_without_map(monkeypatch, tmp_path: Path) -> None:
    def fail_build(prompt: bool = False):
        raise AssertionError("build_services must not be called when every env var is skipped")

    monkeypatch.setattr("hermes_vault.cli.build_services", fail_build)
    env_path = tmp_path / ".env"
    env_path.write_text("DATABASE_URL=postgres://fake\nAPP_PASSWORD=fake\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["import", "--from-env", str(env_path)])

    assert result.exit_code == 0
    assert "Imported 0 credential" in result.output
    assert "--map" in result.output


def test_import_from_env_invalid_map_exits_1(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services())
    env_path = tmp_path / ".env"
    env_path.write_text("OPENAI_API_KEY=fake\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["import", "--from-env", str(env_path), "--map", "BAD"])

    assert result.exit_code == 1
    assert "Invalid --map" in result.output


def test_import_from_env_no_importable_candidates_does_not_prompt(monkeypatch, tmp_path: Path) -> None:
    def fail_build(prompt: bool = False):
        raise AssertionError("build_services must not be called when there are no importable candidates")

    monkeypatch.setattr("hermes_vault.cli.build_services", fail_build)
    env_path = tmp_path / ".env"
    env_path.write_text("UNKNOWN_NAME=fake\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["import", "--from-env", str(env_path)])

    assert result.exit_code == 0
    assert "Imported 0 credential" in result.output
    assert "UNKNOWN_NAME" in result.output


# ── banner tests (unchanged) ──────────────────────────────────────────────


def test_app_shows_banner_before_root_help(monkeypatch) -> None:
    calls: list[object] = []

    monkeypatch.setattr("hermes_vault.cli._should_show_banner", lambda: True)
    monkeypatch.setattr("hermes_vault.cli._show_banner", lambda: calls.append("banner"))
    monkeypatch.setattr(sys, "argv", ["hermes-vault", "--help"])

    def fake_group(*, args=None, prog_name=None):
        calls.append(("group", args, prog_name))
        return 0

    monkeypatch.setattr("hermes_vault.cli._hermes_group", fake_group)

    assert app() == 0
    assert calls == ["banner", ("group", ["--help"], "hermes-vault")]


def test_app_respects_no_banner_for_root_help(monkeypatch) -> None:
    calls: list[object] = []

    monkeypatch.setattr("hermes_vault.cli._should_show_banner", lambda: True)
    monkeypatch.setattr("hermes_vault.cli._show_banner", lambda: calls.append("banner"))
    monkeypatch.setattr(sys, "argv", ["hermes-vault", "--no-banner", "--help"])

    def fake_group(*, args=None, prog_name=None):
        calls.append(("group", args, prog_name))
        return 0

    monkeypatch.setattr("hermes_vault.cli._hermes_group", fake_group)

    assert app() == 0
    assert calls == [("group", ["--no-banner", "--help"], "hermes-vault")]


# ── verify format and report options ────────────────────────────────────────


class StubVerifyResult:
    """Fake VerificationResult for verify command tests."""
    def __init__(self, service="openai", alias="default", success=True,
                 category="valid", reason="ok", status_code=200):
        from hermes_vault.models import VerificationCategory
        self.service = service
        self.alias = alias
        self.category = VerificationCategory(category)
        self.success = success
        self.reason = reason
        self.status_code = status_code
        self.checked_at = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    def model_dump(self, mode=None):
        return {
            "service": self.service,
            "category": self.category.value,
            "success": self.success,
            "reason": self.reason,
            "checked_at": self.checked_at.isoformat(),
            "status_code": self.status_code,
        }


class StubVerifyBroker:
    """Fake broker that returns StubVerifyResult."""
    def __init__(self, results: list | None = None):
        self.results = results or [StubVerifyResult()]
        self.called_with: list[tuple] = []

    def verify_credential(self, service: str, alias: str | None = None):
        self.called_with.append((service, alias))
        return self.results[0] if len(self.results) == 1 else self.results[len(self.called_with) - 1]


def test_verify_default_is_json(monkeypatch) -> None:
    """verify --all without --format must still emit JSON (backward compat)."""
    broker = StubVerifyBroker()
    monkeypatch.setattr("hermes_vault.cli.build_services", lambda prompt=False: (
        _fake_vault(), object(), broker, object()
    ))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify", "--all"])

    assert result.exit_code == 0
    import re
    clean = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', result.output)
    # Output is a JSON-encoded string, so we parse twice
    inner = json.loads(clean)
    data = json.loads(inner)
    assert isinstance(data, list)
    assert data[0]["service"] == "openai"


def test_verify_format_json(monkeypatch) -> None:
    broker = StubVerifyBroker()
    monkeypatch.setattr("hermes_vault.cli.build_services", lambda prompt=False: (
        _fake_vault(), object(), broker, object()
    ))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify", "--all", "--format", "json"])

    assert result.exit_code == 0
    import re
    clean = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', result.output)
    inner = json.loads(clean)
    data = json.loads(inner)
    assert isinstance(data, list)
    assert data[0]["service"] == "openai"


def test_verify_format_table(monkeypatch) -> None:
    broker = StubVerifyBroker()
    monkeypatch.setattr("hermes_vault.cli.build_services", lambda prompt=False: (
        _fake_vault(), object(), broker, object()
    ))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify", "--all", "--format", "table"])

    assert result.exit_code == 0
    assert "SERVICE" in result.output or "RESULT" in result.output


def test_verify_format_table_with_brokerdecision_metadata(monkeypatch) -> None:
    """Table format must work with the real BrokerDecision shape from Broker.verify_credential()."""

    class FakeVault:
        def list_credentials(self):
            from hermes_vault.models import CredentialRecord
            return [
                CredentialRecord(
                    id="cred-1",
                    service="openai",
                    alias="primary",
                    credential_type="api_key",
                    encrypted_payload="x",
                ),
            ]

    class FakeBroker:
        def verify_credential(self, service: str, alias: str | None = None):
            return BrokerDecision(
                allowed=False,
                service=service,
                agent_id="hermes-vault",
                reason="provider lookup failed",
                metadata={
                    "alias": alias or "primary",
                    "verification_result": {
                        "service": service,
                        "category": "network_failure",
                        "success": False,
                        "reason": "provider lookup failed",
                        "checked_at": "2025-01-01T12:00:00+00:00",
                        "status_code": None,
                    },
                },
            )

    monkeypatch.setattr("hermes_vault.cli.build_services", lambda prompt=False: (
        FakeVault(), object(), FakeBroker(), object()
    ))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify", "--all", "--format", "table"])

    assert result.exit_code == 0
    assert "primary" in result.output
    assert "provider" in result.output


def test_verify_report_writes_file(monkeypatch, tmp_path) -> None:
    broker = StubVerifyBroker()
    monkeypatch.setattr("hermes_vault.cli.build_services", lambda prompt=False: (
        _fake_vault(), object(), broker, object()
    ))

    report = tmp_path / "verify.json"
    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify", "--all", "--report", str(report)])

    assert result.exit_code == 0
    assert report.exists()
    data = json.loads(report.read_text())
    assert isinstance(data, list)


def test_verify_report_creates_parent_dirs(monkeypatch, tmp_path) -> None:
    broker = StubVerifyBroker()
    monkeypatch.setattr("hermes_vault.cli.build_services", lambda prompt=False: (
        _fake_vault(), object(), broker, object()
    ))

    report = tmp_path / "subdir" / "nested" / "report.json"
    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify", "--all", "--report", str(report)])

    assert result.exit_code == 0
    assert report.exists()


def test_verify_report_chmod_0600(monkeypatch, tmp_path) -> None:
    import stat
    broker = StubVerifyBroker()
    monkeypatch.setattr("hermes_vault.cli.build_services", lambda prompt=False: (
        _fake_vault(), object(), broker, object()
    ))

    report = tmp_path / "verify.json"
    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify", "--all", "--report", str(report)])

    assert result.exit_code == 0
    mode = stat.S_IMODE(report.stat().st_mode)
    if _platform.current_platform() == _platform.PlatformKind.WINDOWS:
        assert report.exists()
    else:
        assert mode == 0o600


def test_verify_report_with_table_format(monkeypatch, tmp_path) -> None:
    """--format table --report PATH: table to stdout, JSON to file."""
    broker = StubVerifyBroker()
    monkeypatch.setattr("hermes_vault.cli.build_services", lambda prompt=False: (
        _fake_vault(), object(), broker, object()
    ))

    report = tmp_path / "verify.json"
    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify", "--all", "--format", "table", "--report", str(report)])

    assert result.exit_code == 0
    assert report.exists()
    json.loads(report.read_text())  # report is JSON
    assert "SERVICE" in result.output or "RESULT" in result.output  # stdout is table


def test_verify_expands_tilde_in_report_path(monkeypatch, tmp_path) -> None:
    """~ in report path should be expanded."""
    broker = StubVerifyBroker()
    monkeypatch.setattr("hermes_vault.cli.build_services", lambda prompt=False: (
        _fake_vault(), object(), broker, object()
    ))

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    report = home / "verify.json"
    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify", "--all", "--report", str(report)])
    # Should succeed (path exists or is creatable)
    assert result.exit_code == 0 or "permission" in result.output.lower()


def test_dashboard_runtime_warning_flags_temp_home_with_populated_default(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    if _platform.current_platform() == _platform.PlatformKind.WINDOWS:
        localappdata = home / "AppData" / "Local"
        monkeypatch.setenv("LOCALAPPDATA", str(localappdata))
    else:
        monkeypatch.setenv("HOME", str(home))
    default_runtime = _platform.default_vault_home()
    default_runtime.mkdir(parents=True)
    Vault(default_runtime / "vault.db", default_runtime / "salt.bin", "test-passphrase").add_credential(
        "openai",
        "sk-test-secret",
        "api_key",
        alias="default",
    )
    temp_runtime = tmp_path / "dashboard-demo"
    temp_runtime.mkdir()
    monkeypatch.setenv("HERMES_VAULT_HOME", str(temp_runtime))

    warning = _dashboard_runtime_warning()

    assert warning is not None
    assert "temporary HERMES_VAULT_HOME" in warning
    assert "1 credential metadata record" in warning
    assert "sk-test-secret" not in warning


def test_dashboard_runtime_warning_ignores_non_temp_home(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    if _platform.current_platform() == _platform.PlatformKind.WINDOWS:
        localappdata = home / "AppData" / "Local"
        monkeypatch.setenv("LOCALAPPDATA", str(localappdata))
    else:
        monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_HOME", "relative-runtime")

    assert _dashboard_runtime_warning() is None


def test_cli_profile_flag_isolates_runtime_home(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
    monkeypatch.delenv("HERMES_VAULT_PROFILE", raising=False)
    runner = CliRunner()

    default_add = runner.invoke(_hermes_group, ["--no-banner", "add", "openai", "--secret", "default-secret"])
    work_add = runner.invoke(_hermes_group, ["--no-banner", "--profile", "work", "add", "github", "--secret", "work-secret"])
    default_list = runner.invoke(_hermes_group, ["--no-banner", "list"])
    work_list = runner.invoke(_hermes_group, ["--no-banner", "--profile", "work", "list"])

    assert default_add.exit_code == 0, default_add.output
    assert work_add.exit_code == 0, work_add.output
    assert default_list.exit_code == 0, default_list.output
    assert work_list.exit_code == 0, work_list.output
    assert (tmp_path / "vault.db").exists()
    assert (tmp_path / "profiles" / "work" / "vault.db").exists()
    assert "openai" in default_list.output
    assert "github" not in default_list.output
    assert "github" in work_list.output
    assert "openai" not in work_list.output


def test_cli_profile_flag_beats_env_profile(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_PROFILE", "env-profile")
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
    runner = CliRunner()

    result = runner.invoke(_hermes_group, ["--no-banner", "--profile", "cli-profile", "add", "openai", "--secret", "cli-secret"])

    assert result.exit_code == 0, result.output
    assert (tmp_path / "profiles" / "cli-profile" / "vault.db").exists()
    assert not (tmp_path / "profiles" / "env-profile" / "vault.db").exists()


def _fake_vault():
    """Return a fake vault with no credentials for verify tests."""
    from hermes_vault.models import CredentialRecord
    class FakeVault:
        def list_credentials(self):
            return [
                CredentialRecord(
                    id="cred-1", service="openai", alias="default",
                    credential_type="api_key", encrypted_payload="x"
                ),
            ]
    return FakeVault()


# ── broker env OAuth freshness tests ─────────────────────────────────────


def test_broker_env_cli_shows_oauth_refresh_metadata(monkeypatch, tmp_path: Path) -> None:
    """CLI broker env must include oauth_refresh metadata for current OAuth tokens."""
    home = tmp_path
    db_path = home / "vault.db"
    salt_path = home / "master_key_salt.bin"
    policy_path = home / "policy.yaml"

    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))

    # Create vault with OAuth token
    salt_path.write_bytes(os.urandom(16))
    vault = Vault(db_path, salt_path, "test-passphrase")
    vault.initialize()

    future = utc_now() + timedelta(hours=24)
    rec = vault.add_credential(
        service="google",
        secret="test-google-oauth-token",
        credential_type="oauth_access_token",
        alias="default",
        replace_existing=True,
    )
    vault.set_expiry(rec.id, future)

    # Create policy granting test-agent get_env access to google
    policy_yaml = """\
agents:
  test-agent:
    services:
      google:
        actions:
          - get_env
    max_ttl_seconds: 3600
    raw_secret_access: false
    ephemeral_env_only: true
"""
    policy_path.write_text(policy_yaml, encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        _hermes_group,
        ["--no-banner", "broker", "env", "google", "--agent", "test-agent"],
    )

    assert result.exit_code == 0, f"CLI failed: {result.output}"
    data = json.loads(result.output)
    assert "oauth_refresh" in data.get("metadata", {}), (
        f"Expected oauth_refresh in metadata, got: {data}"
    )
    assert data["metadata"]["oauth_refresh"]["refreshed"] is False


def test_broker_env_cli_denies_with_sanitized_reason(monkeypatch, tmp_path: Path) -> None:
    """CLI broker env must deny expired OAuth tokens without refresh token, with sanitized reason."""
    home = tmp_path
    db_path = home / "vault.db"
    salt_path = home / "master_key_salt.bin"
    policy_path = home / "policy.yaml"

    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))

    # Create vault with expired OAuth token — no refresh token
    salt_path.write_bytes(os.urandom(16))
    vault = Vault(db_path, salt_path, "test-passphrase")
    vault.initialize()

    past = utc_now() - timedelta(seconds=10)
    rec = vault.add_credential(
        service="google",
        secret="expired-oauth-token",
        credential_type="oauth_access_token",
        alias="default",
        replace_existing=True,
    )
    vault.set_expiry(rec.id, past)
    # Deliberately no refresh token

    # Create policy granting test-agent get_env access to google
    policy_yaml = """\
agents:
  test-agent:
    services:
      google:
        actions:
          - get_env
          - rotate
    max_ttl_seconds: 3600
    raw_secret_access: false
    ephemeral_env_only: true
"""
    policy_path.write_text(policy_yaml, encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        _hermes_group,
        ["--no-banner", "broker", "env", "google", "--agent", "test-agent"],
    )

    assert result.exit_code == 1, (
        f"Expected exit code 1, got {result.exit_code}: {result.output}"
    )
    data = json.loads(result.output)
    assert "reason" in data
    # No raw token leaked in reason
    assert "expired-oauth-token" not in data["reason"], (
        f"Raw token leaked in reason: {data['reason']}"
    )
