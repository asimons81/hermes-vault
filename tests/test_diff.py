from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from hermes_vault.cli import _hermes_group
from hermes_vault.diff import DiffEntry, diff_backups
from hermes_vault.models import CredentialStatus, AccessLogRecord, Decision
from hermes_vault.vault import Vault


@pytest.fixture
def cli_runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def vault_with_two_creds(tmp_path: Path) -> Vault:
    db_path = tmp_path / "vault.db"
    salt_path = tmp_path / "salt.bin"
    os.environ["HERMES_VAULT_PASSPHRASE"] = "test-passphrase"
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    vault = Vault(db_path, salt_path, "test-passphrase")
    vault.add_credential("openai", "sk-test-1", "api_key", alias="primary")
    vault.add_credential("github", "ghp-test-2", "personal_access_token", alias="work")
    now = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    vault.update_status("openai", CredentialStatus.active, verified_at=now, alias="primary")
    vault.update_status("github", CredentialStatus.active, verified_at=now, alias="work")
    return vault


# ── metadata-only backup tests ────────────────────────────────────────

def test_metadata_only_excludes_payload(vault_with_two_creds: Vault) -> None:
    backup = vault_with_two_creds.export_backup(metadata_only=True)
    assert backup["version"] == "hvbackup-v1"
    for cred in backup["credentials"]:
        assert "encrypted_payload" not in cred
        assert "service" in cred
        assert "alias" in cred
        assert "status" in cred


def test_normal_backup_includes_payload(vault_with_two_creds: Vault) -> None:
    backup = vault_with_two_creds.export_backup(metadata_only=False)
    for cred in backup["credentials"]:
        assert "encrypted_payload" in cred
        assert cred["encrypted_payload"]


def test_restore_rejects_metadata_only(vault_with_two_creds: Vault, tmp_path: Path) -> None:
    backup = vault_with_two_creds.export_backup(metadata_only=True)
    db2 = tmp_path / "vault2.db"
    salt2 = tmp_path / "salt2.bin"
    vault2 = Vault(db2, salt2, "test-passphrase")
    with pytest.raises(ValueError, match="metadata-only"):
        vault2.import_backup(backup)


# ── diff engine tests ─────────────────────────────────────────────────

def test_diff_identical_backups(vault_with_two_creds: Vault) -> None:
    b1 = vault_with_two_creds.export_backup(metadata_only=True)
    b2 = vault_with_two_creds.export_backup(metadata_only=True)
    entries = diff_backups(b1, b2)
    assert len(entries) == 0


def test_diff_added_credential(vault_with_two_creds: Vault, tmp_path: Path) -> None:
    b1 = vault_with_two_creds.export_backup(metadata_only=True)
    vault_with_two_creds.add_credential("netlify", "nft-test-3", "personal_access_token", alias="main")
    b2 = vault_with_two_creds.export_backup(metadata_only=True)
    entries = diff_backups(b2, b1)
    added = [e for e in entries if e.kind == "added"]
    assert len(added) == 1
    assert added[0].service == "netlify"


def test_diff_removed_credential(vault_with_two_creds: Vault) -> None:
    b1 = vault_with_two_creds.export_backup(metadata_only=True)
    vault_with_two_creds.delete("github", alias="work")
    b2 = vault_with_two_creds.export_backup(metadata_only=True)
    entries = diff_backups(b2, b1)
    removed = [e for e in entries if e.kind == "removed"]
    assert len(removed) == 1
    assert removed[0].service == "github"


def test_diff_changed_credential(vault_with_two_creds: Vault) -> None:
    b1 = vault_with_two_creds.export_backup(metadata_only=True)
    vault_with_two_creds.update_status("openai", CredentialStatus.invalid, alias="primary")
    b2 = vault_with_two_creds.export_backup(metadata_only=True)
    entries = diff_backups(b2, b1)
    changed = [e for e in entries if e.kind == "changed"]
    assert len(changed) >= 1
    assert any(e.service == "openai" for e in changed)


def test_diff_accepts_metadata_only(vault_with_two_creds: Vault, tmp_path: Path) -> None:
    b1 = vault_with_two_creds.export_backup(metadata_only=True)
    db2 = tmp_path / "vault2.db"
    salt2 = tmp_path / "salt2.bin"
    vault2 = Vault(db2, salt2, "test-passphrase")
    vault2.add_credential("openai", "sk-other", "api_key", alias="primary")
    vault2.add_credential("supabase", "sb-test", "api_key", alias="main")
    b2 = vault2.export_backup(metadata_only=True)
    entries = diff_backups(b2, b1)
    assert any(e.service == "supabase" for e in entries)


def test_diff_no_encrypted_payload_in_output(vault_with_two_creds: Vault) -> None:
    b1 = vault_with_two_creds.export_backup(metadata_only=True)
    b2 = vault_with_two_creds.export_backup(metadata_only=True)
    entries = diff_backups(b2, b1)
    for e in entries:
        d = e.as_dict()
        payload = json.dumps(d)
        assert "encrypted_payload" not in payload
        assert "sk-" not in payload
        assert "ghp_" not in payload


def test_diff_version_is_preserved(vault_with_two_creds: Vault) -> None:
    b1 = vault_with_two_creds.export_backup(metadata_only=True)
    b2 = vault_with_two_creds.export_backup(metadata_only=True)
    entries = diff_backups(b2, b1)
    assert isinstance(entries, list)


# ── CLI integration: backup --metadata-only ────────────────────────────

def _fake_build(vault: Vault):
    def _inner(prompt: bool = False):
        return vault, object(), object(), object()
    return _inner


def test_cli_backup_metadata_only(
    cli_runner: CliRunner, vault_with_two_creds: Vault, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build(vault_with_two_creds))
    out = tmp_path / "backup-meta.json"
    result = cli_runner.invoke(
        _hermes_group, ["backup", "--metadata-only", "--output", str(out)], catch_exceptions=False
    )
    assert result.exit_code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["version"] == "hvbackup-v1"
    for c in data["credentials"]:
        assert "encrypted_payload" not in c


def test_cli_restore_rejects_metadata_only(
    cli_runner: CliRunner, vault_with_two_creds: Vault, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build(vault_with_two_creds))
    meta_backup = vault_with_two_creds.export_backup(metadata_only=True)
    meta_backup.pop("encrypted_payload", None)
    out = tmp_path / "meta.json"
    out.write_text(json.dumps(meta_backup, indent=2))
    result = cli_runner.invoke(
        _hermes_group, ["restore", "--input", str(out), "--yes"], catch_exceptions=False
    )
    assert result.exit_code == 1


def test_cli_diff_new_credential(
    cli_runner: CliRunner, vault_with_two_creds: Vault, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build(vault_with_two_creds))
    against_path = tmp_path / "against.json"
    against_path.write_text(json.dumps(vault_with_two_creds.export_backup(metadata_only=True), indent=2))
    vault_with_two_creds.add_credential("supabase", "sb-test-new", "api_key", alias="main")
    result = cli_runner.invoke(
        _hermes_group, ["diff", "--against", str(against_path)], catch_exceptions=False
    )
    assert result.exit_code == 0
    assert "supabase" in result.output


def test_cli_diff_missing_file(
    cli_runner: CliRunner, vault_with_two_creds: Vault, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build(vault_with_two_creds))
    result = cli_runner.invoke(
        _hermes_group, ["diff", "--against", str(tmp_path / "nope.json")], catch_exceptions=False
    )
    assert result.exit_code == 2
