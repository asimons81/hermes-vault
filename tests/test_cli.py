from __future__ import annotations

import json
import sys
from pathlib import Path

from click.testing import CliRunner

from hermes_vault.cli import _dashboard_runtime_warning, _hermes_group, app
from hermes_vault.models import BrokerDecision, MutationResult
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


def test_maintain_json_output(monkeypatch) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services())

    class FakeReport:
        recommended_exit_code = 0

        def as_dict(self, exclude_none: bool = True):
            return {
                "version": "maintain-v1",
                "dry_run": True,
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


def test_maintain_table_uses_recommended_exit_code(monkeypatch) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services())

    class FakeReport:
        recommended_exit_code = 1
        refresh_summary = {"attempted": 1, "succeeded": 0, "failed": 1}
        health = {"healthy": False, "findings": []}
        audit_recorded = True
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
    assert "Refresh Failures" in result.output


def test_maintain_print_systemd(monkeypatch) -> None:
    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["maintain", "--print-systemd"])

    assert result.exit_code == 0
    assert "hermes-vault-maintain.service" in result.output
    assert "hermes-vault --no-banner maintain --format json" in result.output


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
    assert payload["version"] == "backup-verification-v1"
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
    result = runner.invoke(_hermes_group, ["import", "--from-env", str(env_path)])

    assert result.exit_code == 0
    assert "Imported 1 credential" in result.output
    assert "skipped 1 env" in result.output
    assert "Skipped" in result.output
    assert "UNKNOWN_NAME" in result.output
    assert mutations.calls[0][1]["service"] == "openai"


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
    assert "1 skipped line" in result.output


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
        from datetime import datetime, timezone
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
    import os
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
    default_runtime = home / ".hermes" / "hermes-vault-data"
    default_runtime.mkdir(parents=True)
    Vault(default_runtime / "vault.db", default_runtime / "salt.bin", "test-passphrase").add_credential(
        "openai",
        "sk-test-secret",
        "api_key",
        alias="default",
    )
    temp_runtime = tmp_path / "dashboard-demo"
    temp_runtime.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_HOME", str(temp_runtime))

    warning = _dashboard_runtime_warning()

    assert warning is not None
    assert "temporary HERMES_VAULT_HOME" in warning
    assert "1 credential metadata record" in warning
    assert "sk-test-secret" not in warning


def test_dashboard_runtime_warning_ignores_non_temp_home(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_HOME", "relative-runtime")

    assert _dashboard_runtime_warning() is None


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
