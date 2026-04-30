from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from hermes_vault.audit import AuditLogger
from hermes_vault.cli import _hermes_group, build_services as real_build_services
from hermes_vault.health import HealthReport, run_health
from hermes_vault.models import AccessLogRecord, CredentialStatus, Decision
from hermes_vault.vault import Vault


@pytest.fixture
def cli_runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def empty_vault(tmp_path: Path) -> Vault:
    db_path = tmp_path / "vault.db"
    salt_path = tmp_path / "salt.bin"
    os.environ["HERMES_VAULT_PASSPHRASE"] = "test-passphrase"
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    return Vault(db_path, salt_path, "test-passphrase")


@pytest.fixture
def vault_with_fresh_creds(tmp_path: Path) -> Vault:
    db_path = tmp_path / "vault.db"
    salt_path = tmp_path / "salt.bin"
    os.environ["HERMES_VAULT_PASSPHRASE"] = "test-passphrase"
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)

    vault = Vault(db_path, salt_path, "test-passphrase")
    vault.add_credential("openai", "sk-test-1234", "api_key", alias="primary")
    vault.add_credential("github", "ghp-test-5678", "personal_access_token", alias="work")
    now = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    vault.update_status("openai", CredentialStatus.active, verified_at=now, alias="primary")
    vault.update_status("github", CredentialStatus.active, verified_at=now, alias="work")
    return vault


@pytest.fixture
def vault_with_problems(tmp_path: Path) -> Vault:
    db_path = tmp_path / "vault.db"
    salt_path = tmp_path / "salt.bin"
    os.environ["HERMES_VAULT_PASSPHRASE"] = "test-passphrase"
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)

    vault = Vault(db_path, salt_path, "test-passphrase")
    vault.add_credential("openai", "sk-test-1", "api_key", alias="primary")
    vault.add_credential("github", "ghp-test-2", "personal_access_token", alias="work")
    vault.add_credential("netlify", "nft-test-3", "personal_access_token", alias="default")

    ten_days = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    one_day = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

    vault.update_status("openai", CredentialStatus.invalid, verified_at=ten_days, alias="primary")
    vault.update_status("github", CredentialStatus.active, verified_at=ten_days, alias="work")
    vault.update_status("netlify", CredentialStatus.active, verified_at=one_day, alias="default")

    expiry_soon = datetime.now(timezone.utc) + timedelta(days=3)
    vault.set_expiry("openai", expiry_soon, alias="primary")

    expiry_past = datetime.now(timezone.utc) - timedelta(days=2)
    vault.set_expiry("github", expiry_past, alias="work")

    return vault


# ── Unit tests for run_health ────────────────────────────────────────────

def test_health_empty_vault(empty_vault: Vault) -> None:
    report = run_health(empty_vault)
    assert report.healthy is True
    assert report.total_credentials == 0
    assert report.healthy_count == 0
    assert len(report.findings) == 0


def test_health_all_fresh(vault_with_fresh_creds: Vault) -> None:
    report = run_health(vault_with_fresh_creds)
    assert report.healthy is True
    assert report.total_credentials == 2
    assert report.healthy_count == 2
    assert report.stale_count == 0
    assert report.invalid_count == 0
    assert report.expired_count == 0
    assert report.expiring_count == 0
    assert len(report.findings) == 0


def test_health_detects_stale(vault_with_problems: Vault) -> None:
    report = run_health(vault_with_problems, stale_days=5)
    assert report.healthy is False
    assert report.stale_count > 0
    stale_findings = [f for f in report.findings if f.kind == "stale"]
    assert len(stale_findings) > 0


def test_health_detects_invalid(vault_with_problems: Vault) -> None:
    report = run_health(vault_with_problems)
    invalid_findings = [f for f in report.findings if f.kind == "invalid"]
    assert len(invalid_findings) > 0
    assert any(f.service == "openai" for f in invalid_findings)


def test_health_detects_expired(vault_with_problems: Vault) -> None:
    report = run_health(vault_with_problems)
    expired_findings = [f for f in report.findings if f.kind == "expired"]
    assert len(expired_findings) > 0
    assert any(f.service == "github" for f in expired_findings)


def test_health_detects_expiring(vault_with_problems: Vault) -> None:
    report = run_health(vault_with_problems)
    expiring_findings = [f for f in report.findings if f.kind == "expiring"]
    assert len(expiring_findings) > 0
    assert any(f.service == "openai" for f in expiring_findings)


def test_health_detects_never_verified(empty_vault: Vault) -> None:
    empty_vault.add_credential("openai", "sk-never", "api_key", alias="fresh")
    report = run_health(empty_vault)
    nv_findings = [f for f in report.findings if f.kind == "never_verified"]
    assert len(nv_findings) == 1
    assert nv_findings[0].service == "openai"


def test_health_no_secrets_in_report(vault_with_problems: Vault) -> None:
    report = run_health(vault_with_problems)
    d = report.as_dict(exclude_none=False)
    payload = json.dumps(d, sort_keys=True)
    assert "encrypted_payload" not in payload
    assert "sk-" not in payload
    assert "ghp_" not in payload
    assert "nft-" not in payload


def test_health_report_version_builtin(vault_with_fresh_creds: Vault) -> None:
    report = run_health(vault_with_fresh_creds)
    d = report.as_dict(exclude_none=False)
    assert d["version"] == "health-v1"


def test_health_backup_warning_when_no_backup(empty_vault: Vault, tmp_path: Path) -> None:
    audit = AuditLogger(empty_vault.db_path)
    report = run_health(empty_vault, audit=audit)
    backup_findings = [f for f in report.findings if f.kind == "backup"]
    assert len(backup_findings) == 1
    assert "no backup has been recorded" in backup_findings[0].detail.lower()


def test_health_backup_warning_when_stale(empty_vault: Vault, tmp_path: Path) -> None:
    audit = AuditLogger(empty_vault.db_path)
    old_ts = datetime.now(timezone.utc) - timedelta(days=60)
    audit.record(AccessLogRecord(
        agent_id="hermes-vault",
        service="*",
        action="export_backup",
        decision=Decision.allow,
        reason="backup exported",
        ttl_seconds=None,
        timestamp=old_ts,
    ))
    report = run_health(empty_vault, audit=audit)
    backup_findings = [f for f in report.findings if f.kind == "backup"]
    assert len(backup_findings) >= 1
    assert "day(s) ago" in backup_findings[0].detail


# ── CLI integration tests ───────────────────────────────────────────────

def _fake_build_services(vault: Vault):
    def _inner(prompt: bool = False):
        return vault, object(), object(), object()
    return _inner


def _record_recent_backup(audit: AuditLogger) -> None:
    """Record a recent backup audit entry so health doesn't flag it."""
    recent_ts = datetime.now(timezone.utc) - timedelta(hours=1)
    audit.record(AccessLogRecord(
        agent_id="hermes-vault",
        service="*",
        action="export_backup",
        decision=Decision.allow,
        reason="backup exported",
        ttl_seconds=None,
        timestamp=recent_ts,
    ))


def test_cli_health_healthy_exit_0(
    cli_runner: CliRunner, vault_with_fresh_creds: Vault, monkeypatch
) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(vault_with_fresh_creds))
    _record_recent_backup(AuditLogger(vault_with_fresh_creds.db_path))
    result = cli_runner.invoke(_hermes_group, ["health"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "ALL HEALTHY" in result.output


def test_cli_health_warnings_exit_1(
    cli_runner: CliRunner, vault_with_problems: Vault, monkeypatch
) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(vault_with_problems))
    result = cli_runner.invoke(_hermes_group, ["health"], catch_exceptions=False)
    assert result.exit_code == 1
    assert "WARNINGS FOUND" in result.output


def test_cli_health_json_format(
    cli_runner: CliRunner, vault_with_fresh_creds: Vault, monkeypatch
) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(vault_with_fresh_creds))
    _record_recent_backup(AuditLogger(vault_with_fresh_creds.db_path))
    result = cli_runner.invoke(_hermes_group, ["health", "--format", "json"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "health-v1" in result.output
    assert "generated_at" in result.output


def test_cli_health_json_no_secrets(
    cli_runner: CliRunner, vault_with_problems: Vault, monkeypatch
) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(vault_with_problems))
    result = cli_runner.invoke(_hermes_group, ["health", "--format", "json"], catch_exceptions=False)
    assert "encrypted_payload" not in result.output
    assert "sk-" not in result.output


def test_cli_health_preserves_status_command(
    cli_runner: CliRunner, vault_with_fresh_creds: Vault, monkeypatch
) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(vault_with_fresh_creds))
    status_result = cli_runner.invoke(_hermes_group, ["status"], catch_exceptions=False)
    assert status_result.exit_code == 0


def test_cli_health_invalid_format_exit_2(
    cli_runner: CliRunner, vault_with_fresh_creds: Vault, monkeypatch
) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(vault_with_fresh_creds))
    result = cli_runner.invoke(_hermes_group, ["health", "--format", "xml"], catch_exceptions=False)
    assert result.exit_code == 2


def test_cli_health_negative_threshold_exit_2(
    cli_runner: CliRunner, vault_with_fresh_creds: Vault, monkeypatch
) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(vault_with_fresh_creds))
    result = cli_runner.invoke(_hermes_group, ["health", "--stale-days", "0"], catch_exceptions=False)
    assert result.exit_code == 2
