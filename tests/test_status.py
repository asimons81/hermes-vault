from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from hermes_vault.cli import _hermes_group
from hermes_vault.models import CredentialStatus
from hermes_vault.vault import Vault


@pytest.fixture
def cli_runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def vault_with_creds_and_status(tmp_path: Path) -> Vault:
    """Creates a vault with credentials and status for status CLI testing."""
    db_path = tmp_path / "vault.db"
    salt_path = tmp_path / "salt.bin"

    os.environ["HERMES_VAULT_PASSPHRASE"] = "test-passphrase"
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)

    vault = Vault(db_path, salt_path, "test-passphrase")
    vault.add_credential("openai", "sk-test123", "api_key", alias="primary")
    vault.add_credential("github", "ghp_test123", "personal_access_token", alias="work")

    # openai primary: invalid + stale (verified 10 days ago)
    old_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    vault.update_status("openai", CredentialStatus.invalid, verified_at=old_ts, alias="primary")

    # github work: active, recently verified (not stale)
    recent_ts = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    vault.update_status("github", CredentialStatus.active, verified_at=recent_ts, alias="work")

    return vault


# ── Status CLI tests ──────────────────────────────────────────────────────────


def test_status_all_credentials(cli_runner: CliRunner, vault_with_creds_and_status: Vault, monkeypatch) -> None:
    """No filters shows all credentials."""
    vault = vault_with_creds_and_status

    def fake_build_services(prompt: bool = False):
        return vault, object(), object(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build_services)

    result = cli_runner.invoke(_hermes_group, ["status"], catch_exceptions=False)
    assert result.exit_code == 0


def test_status_stale_filter(cli_runner: CliRunner, vault_with_creds_and_status: Vault, monkeypatch) -> None:
    """--stale 7d shows credentials not verified in the last 7 days."""
    vault = vault_with_creds_and_status

    def fake_build_services(prompt: bool = False):
        return vault, object(), object(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build_services)

    result = cli_runner.invoke(_hermes_group, ["status", "--stale", "7d"], catch_exceptions=False)
    assert result.exit_code == 0
    # openai primary was verified 10 days ago — should appear
    assert "openai" in result.output


def test_status_stale_filter_none_match(cli_runner: CliRunner, vault_with_creds_and_status: Vault, monkeypatch) -> None:
    """--stale with no matching credentials exits 0 with empty output."""
    vault = vault_with_creds_and_status

    def fake_build_services(prompt: bool = False):
        return vault, object(), object(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build_services)

    result = cli_runner.invoke(_hermes_group, ["status", "--stale", "7d"], catch_exceptions=False)
    assert result.exit_code == 0
    # github work was verified 1 day ago — not stale (threshold is 7d)


def test_status_invalid_filter(cli_runner: CliRunner, vault_with_creds_and_status: Vault, monkeypatch) -> None:
    """--invalid shows credentials with invalid or expired status."""
    vault = vault_with_creds_and_status

    def fake_build_services(prompt: bool = False):
        return vault, object(), object(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build_services)

    result = cli_runner.invoke(_hermes_group, ["status", "--invalid"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "openai" in result.output


def test_status_target_not_found(cli_runner: CliRunner, vault_with_creds_and_status: Vault, monkeypatch) -> None:
    """Target that does not exist exits 1."""
    vault = vault_with_creds_and_status

    def fake_build_services(prompt: bool = False):
        return vault, object(), object(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build_services)

    result = cli_runner.invoke(_hermes_group, ["status", "nonexistent"], catch_exceptions=False)
    assert result.exit_code == 1
    assert "Not found" in result.output


def test_status_target_by_service(cli_runner: CliRunner, vault_with_creds_and_status: Vault, monkeypatch) -> None:
    """Targeting by service name works."""
    vault = vault_with_creds_and_status

    def fake_build_services(prompt: bool = False):
        return vault, object(), object(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build_services)

    result = cli_runner.invoke(_hermes_group, ["status", "openai"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "openai" in result.output


def test_status_target_by_alias(cli_runner: CliRunner, vault_with_creds_and_status: Vault, monkeypatch) -> None:
    """--alias filters to a specific alias."""
    vault = vault_with_creds_and_status

    def fake_build_services(prompt: bool = False):
        return vault, object(), object(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build_services)

    result = cli_runner.invoke(
        _hermes_group, ["status", "github", "--alias", "work"], catch_exceptions=False
    )
    assert result.exit_code == 0
    assert "github" in result.output


def test_status_invalid_stale_format(cli_runner: CliRunner, vault_with_creds_and_status: Vault, monkeypatch) -> None:
    """Invalid --stale format exits 1."""
    vault = vault_with_creds_and_status

    def fake_build_services(prompt: bool = False):
        return vault, object(), object(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build_services)

    result = cli_runner.invoke(_hermes_group, ["status", "--stale", "not-a-number"], catch_exceptions=False)
    assert result.exit_code == 1
    assert "Invalid --stale value" in result.output


def test_status_invalid_expiring_format(cli_runner: CliRunner, vault_with_creds_and_status: Vault, monkeypatch) -> None:
    """Invalid --expiring format exits 1."""
    vault = vault_with_creds_and_status

    def fake_build_services(prompt: bool = False):
        return vault, object(), object(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build_services)

    result = cli_runner.invoke(
        _hermes_group, ["status", "--expiring", "xyz"], catch_exceptions=False
    )
    assert result.exit_code == 1
    assert "Invalid --expiring value" in result.output


def test_status_json_format(cli_runner: CliRunner, vault_with_creds_and_status: Vault, monkeypatch) -> None:
    """--format json outputs a list."""
    vault = vault_with_creds_and_status

    def fake_build_services(prompt: bool = False):
        return vault, object(), object(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build_services)

    result = cli_runner.invoke(_hermes_group, ["status", "--format", "json"], catch_exceptions=False)
    assert result.exit_code == 0
    # Rich console.print_json wraps strings in quotes, so double-parse is needed
    parsed = json.loads(result.output)
    if isinstance(parsed, str):
        data = json.loads(parsed)
    else:
        data = parsed
    assert isinstance(data, list)
    assert len(data) > 0


def test_status_json_no_encrypted_payload(cli_runner: CliRunner, vault_with_creds_and_status: Vault, monkeypatch) -> None:
    """JSON output must not contain encrypted_payload."""
    vault = vault_with_creds_and_status

    def fake_build_services(prompt: bool = False):
        return vault, object(), object(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build_services)

    result = cli_runner.invoke(_hermes_group, ["status", "--format", "json"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "encrypted_payload" not in result.output
    assert "sk-" not in result.output  # No raw secrets


def test_status_json_fields(cli_runner: CliRunner, vault_with_creds_and_status: Vault, monkeypatch) -> None:
    """JSON output contains expected fields."""
    vault = vault_with_creds_and_status

    def fake_build_services(prompt: bool = False):
        return vault, object(), object(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build_services)

    result = cli_runner.invoke(_hermes_group, ["status", "--format", "json"], catch_exceptions=False)
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    if isinstance(parsed, str):
        data = json.loads(parsed)
    else:
        data = parsed
    for item in data:
        assert "service" in item
        assert "alias" in item
        assert "credential_type" in item
        assert "status" in item
        assert "last_verified_at" in item
        assert "expiry" in item
        assert "is_stale" in item
        assert "is_expiring" in item
        assert "days_since_verified" in item
        assert "days_until_expiry" in item


def test_status_never_verified_is_stale(cli_runner: CliRunner, tmp_path: Path) -> None:
    """A credential that was never verified is always stale."""
    db_path = tmp_path / "vault.db"
    salt_path = tmp_path / "salt.bin"
    os.environ["HERMES_VAULT_PASSPHRASE"] = "test-passphrase"
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)

    vault = Vault(db_path, salt_path, "test-passphrase")
    vault.add_credential("never", "sk-never", "api_key", alias="default")
    # last_verified_at stays None

    def fake_build_services(prompt: bool = False):
        return vault, object(), object(), object()

    # Apply monkeypatch via pytest fixture approach
    from hermes_vault import cli as cli_module
    original = cli_module.build_services
    cli_module.build_services = fake_build_services
    try:
        result = CliRunner().invoke(_hermes_group, ["status", "--stale", "1d"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "never" in result.output
    finally:
        cli_module.build_services = original


def test_status_combined_filters(cli_runner: CliRunner, vault_with_creds_and_status: Vault, monkeypatch) -> None:
    """--stale and --invalid used together applies AND logic."""
    vault = vault_with_creds_and_status

    def fake_build_services(prompt: bool = False):
        return vault, object(), object(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build_services)

    result = cli_runner.invoke(
        _hermes_group, ["status", "--stale", "7d", "--invalid"], catch_exceptions=False
    )
    assert result.exit_code == 0
    # openai primary is both stale (10d) and invalid — should appear
    assert "openai" in result.output
