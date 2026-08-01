"""Regression tests for the 0.23.2 audit chain wedge fix.

Six CLI write paths (set-expiry, clear-expiry, backup-verify,
restore --dry-run, rotate-master-key pre-rotation, recovery drill) used to
construct AuditLogger WITHOUT a master key. Their audit.record() calls took
the legacy unprotected INSERT branch, and the next protected append raised
AuditIntegrityError, wedging the whole chain (delete/add/lease/request all
crashed). These tests reproduce the smoke-test repro sequence: initialize
the chain with a protected row via `hermes-vault add`, run the vulnerable
command, then assert audit-verify stays healthy and a subsequent mutation
still succeeds.

Also covers the export --with-secrets fail-closed fix: a wrong passphrase
must raise instead of silently emitting "secret": null.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from hermes_vault.cli import _hermes_group
from hermes_vault.vault import Vault


PASSPHRASE = "test-passphrase"
NEW_PASSPHRASE = "new-passphrase"


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _set_env(tmp_path: Path, passphrase: str = PASSPHRASE) -> None:
    os.environ["HERMES_VAULT_PASSPHRASE"] = passphrase
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)


def _init_vault(tmp_path: Path, runner: CliRunner) -> Vault:
    """Create a vault and seed the audit chain via the real `add` CLI path.

    The `add` command writes a *protected* audit row through
    build_services' AuditLogger (master_key present), which is what the
    smoke-test repro uses to initialize the integrity chain.
    """
    _set_env(tmp_path)
    result = runner.invoke(
        _hermes_group, ["add", "openai", "--secret", "sk-test-123"], catch_exceptions=False
    )
    assert result.exit_code == 0, result.output
    return Vault(tmp_path / "vault.db", tmp_path / "master_key_salt.bin", PASSPHRASE)


def _backup(tmp_path: Path, vault: Vault) -> Path:
    backup_path = tmp_path / "backup.json"
    backup_path.write_text(json.dumps(vault.export_backup(), indent=2, sort_keys=True), encoding="utf-8")
    return backup_path


def _assert_chain_healthy(runner: CliRunner) -> None:
    result = runner.invoke(_hermes_group, ["audit-verify", "--format", "json"], catch_exceptions=False)
    assert result.exit_code == 0, f"audit-verify failed:\n{result.output}"
    payload = json.loads(result.output)
    assert payload["status"] == "healthy", f"audit chain not healthy:\n{payload}"


def _assert_mutation_succeeds(runner: CliRunner) -> None:
    result = runner.invoke(_hermes_group, ["delete", "openai", "--yes"], catch_exceptions=False)
    assert result.exit_code == 0, f"delete crashed after wedge:\n{result.output}"


def test_set_expiry_keeps_chain_healthy(tmp_path: Path, runner: CliRunner) -> None:
    _init_vault(tmp_path, runner)
    result = runner.invoke(_hermes_group, ["set-expiry", "openai", "--days", "30"], catch_exceptions=False)
    assert result.exit_code == 0, result.output

    _assert_chain_healthy(runner)
    _assert_mutation_succeeds(runner)


def test_clear_expiry_keeps_chain_healthy(tmp_path: Path, runner: CliRunner) -> None:
    vault = _init_vault(tmp_path, runner)
    vault.set_expiry("openai", datetime.now(timezone.utc) + timedelta(days=30))
    result = runner.invoke(_hermes_group, ["clear-expiry", "openai"], catch_exceptions=False)
    assert result.exit_code == 0, result.output

    _assert_chain_healthy(runner)
    _assert_mutation_succeeds(runner)


def test_backup_verify_keeps_chain_healthy(tmp_path: Path, runner: CliRunner) -> None:
    vault = _init_vault(tmp_path, runner)
    backup_path = _backup(tmp_path, vault)
    result = runner.invoke(_hermes_group, ["backup-verify", "--input", str(backup_path)], catch_exceptions=False)
    assert result.exit_code == 0, result.output

    _assert_chain_healthy(runner)
    _assert_mutation_succeeds(runner)


def test_restore_dry_run_keeps_chain_healthy(tmp_path: Path, runner: CliRunner) -> None:
    vault = _init_vault(tmp_path, runner)
    backup_path = _backup(tmp_path, vault)
    result = runner.invoke(_hermes_group, ["restore", "--input", str(backup_path), "--dry-run"], catch_exceptions=False)
    assert result.exit_code == 0, result.output

    _assert_chain_healthy(runner)
    _assert_mutation_succeeds(runner)


def test_rotate_master_key_keeps_chain_healthy(tmp_path: Path, runner: CliRunner, monkeypatch) -> None:
    _init_vault(tmp_path, runner)

    answers = iter([PASSPHRASE, NEW_PASSPHRASE, NEW_PASSPHRASE])

    def fake_getpass(prompt: str = "") -> str:
        return next(answers)

    monkeypatch.setattr("getpass.getpass", fake_getpass)
    result = runner.invoke(_hermes_group, ["rotate-master-key"], catch_exceptions=False)
    assert result.exit_code == 0, result.output

    # Rotation re-derives the master key; subsequent commands need the new passphrase.
    os.environ["HERMES_VAULT_PASSPHRASE"] = NEW_PASSPHRASE

    _assert_chain_healthy(runner)
    _assert_mutation_succeeds(runner)


def test_recovery_drill_keeps_chain_healthy(tmp_path: Path, runner: CliRunner) -> None:
    vault = _init_vault(tmp_path, runner)
    backup_path = _backup(tmp_path, vault)
    result = runner.invoke(_hermes_group, ["recovery", "drill", "--backup", str(backup_path)], catch_exceptions=False)
    assert result.exit_code == 0, result.output

    _assert_chain_healthy(runner)
    _assert_mutation_succeeds(runner)


def test_export_with_secrets_wrong_passphrase_fails_closed(tmp_path: Path) -> None:
    """Wrong passphrase must abort export instead of emitting secret:null."""
    from hermes_vault.import_export import export_credentials

    _set_env(tmp_path)
    vault = Vault(tmp_path / "vault.db", tmp_path / "master_key_salt.bin", PASSPHRASE)
    vault.add_credential("openai", "sk-test-123", "api_key")
    rec = vault.list_credentials()[0]
    wrong_vault = Vault(vault.db_path, vault.salt_path, "wrong-passphrase")

    with pytest.raises(ValueError, match="Failed to decrypt"):
        export_credentials([rec], fmt="json", include_secrets=True, vault=wrong_vault)

    with pytest.raises(ValueError, match="Failed to decrypt"):
        export_credentials([rec], fmt="env", include_secrets=True, vault=wrong_vault)

    # Sanity: correct passphrase still exports the real secret.
    out = export_credentials([rec], fmt="json", include_secrets=True, vault=vault)
    parsed = json.loads(out)
    assert parsed[0]["secret"] == "sk-test-123"
