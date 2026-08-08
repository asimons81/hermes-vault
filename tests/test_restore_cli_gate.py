"""E2 CLI gate tests for Issue #62 — v2 restore gate and audit integration.

These tests exercise the `restore` CLI command end-to-end (CliRunner with a
monkeypatched build_services, mirroring test_diff.py) against the E1 atomic
restore core. They cover:

- successful restore of hvbackup-v1 and hvbackup-v2 backups
- each E1 preflight rejection class surfaced as a distinct, non-zero exit:
  partial-commit risk (metadata-only), foreign credential linkage, broker
  mismatch, missing v2 evidence, audit failure
- audit failure atomicity from the CLI: when the protected restore audit
  event cannot be written, the restore rolls back and the CLI exits non-zero
- the forged-active-lease class: E1 force-revokes active leases (never mints
  them active), and the CLI surfaces a distinct notice while restoring
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from datetime import timedelta
from pathlib import Path

from click.testing import CliRunner, Result

from hermes_vault.audit import AuditLogger
from hermes_vault.cli import _hermes_group
from hermes_vault.models import AccessLogRecord, Decision, utc_now
from hermes_vault.vault import Vault

PASSPHRASE = "test-passphrase"


def _make_vault(tmp_path: Path, name: str = "vault.db", salt: str = "salt.bin") -> Vault:
    return Vault(tmp_path / name, tmp_path / salt, PASSPHRASE)


def _fake_build(vault: Vault):
    def _inner(prompt: bool = False):
        return vault, object(), object(), object()

    return _inner


def _write_backup(path: Path, backup: dict) -> Path:
    path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _restore(
    runner: CliRunner,
    backup_path: Path,
    target_vault: Vault,
    monkeypatch,
) -> Result:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build(target_vault))
    return runner.invoke(
        _hermes_group,
        ["restore", "--input", str(backup_path), "--yes"],
        catch_exceptions=False,
    )


def _target_with_shared_key(tmp_path: Path, source: Vault) -> Vault:
    """Target vault sharing the source master key (same salt bytes)."""
    shutil.copy(source.salt_path, tmp_path / "tgt_salt.bin")
    return _make_vault(tmp_path, name="target.db", salt="tgt_salt.bin")


# ── Successful restores ────────────────────────────────────────────────


def test_cli_restore_v1_success(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "sk-secret", "api_key", alias="primary")
    backup_path = _write_backup(tmp_path / "backup.json", source.export_backup())

    target = _target_with_shared_key(tmp_path, source)
    result = _restore(runner, backup_path, target, monkeypatch)

    assert result.exit_code == 0, result.output
    assert "Restored 1 credential(s)" in result.output
    services = sorted(c.service for c in target.list_credentials())
    assert services == ["openai"]


def test_cli_restore_v2_success(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("github", "ghp-secret", "personal_access_token", alias="primary")
    backup_path = _write_backup(
        tmp_path / "backup.json",
        source.export_backup(include_audit=True),
    )
    assert json.loads(backup_path.read_text(encoding="utf-8"))["version"] == "hvbackup-v2"

    target = _target_with_shared_key(tmp_path, source)
    result = _restore(runner, backup_path, target, monkeypatch)

    assert result.exit_code == 0, result.output
    services = sorted(c.service for c in target.list_credentials())
    assert services == ["github"]

    # The protected restore audit event was routed through the E1 seam and
    # committed with the restore (action=restore, operator agent).
    with sqlite3.connect(target.db_path) as conn:
        rows = conn.execute("SELECT action, agent_id FROM access_logs WHERE action = 'restore'").fetchall()
    assert rows, "no protected restore audit event written"
    assert all(action == "restore" and agent_id == "operator" for action, agent_id in rows)


# ── Preflight rejection classes ────────────────────────────────────────


def test_cli_restore_metadata_only_blocked(monkeypatch, tmp_path: Path) -> None:
    """Partial-commit risk: metadata-only backups must be blocked, not half-restored."""
    runner = CliRunner()
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "sk-secret", "api_key", alias="primary")
    backup = source.export_backup(metadata_only=True)
    backup_path = _write_backup(tmp_path / "backup.json", backup)

    target = _target_with_shared_key(tmp_path, source)
    result = _restore(runner, backup_path, target, monkeypatch)

    assert result.exit_code == 1, result.output
    assert "metadata-only" in result.output.lower(), result.output
    assert target.list_credentials() == []


def test_cli_restore_foreign_linkage_blocked(monkeypatch, tmp_path: Path) -> None:
    """Foreign credential linkage: lease pointing outside the backup/vault is blocked."""
    runner = CliRunner()
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "sk-secret", "api_key", alias="primary")
    forged_lease = {
        "id": "foreign-link-lease",
        "service": "openai",
        "alias": "primary",
        "credential_id": "no-such-credential-id",
        "credential_type": "api_key",
        "agent_id": "attacker-agent",
        "issued_by": "attacker-agent",
        "purpose": "task",
        "status": "active",
        "ttl_seconds": 3600,
        "issued_at": utc_now().isoformat(),
        "expires_at": (utc_now() + timedelta(hours=1)).isoformat(),
    }
    backup = source.export_backup()
    backup["leases"] = [forged_lease]
    backup_path = _write_backup(tmp_path / "backup.json", backup)

    target = _target_with_shared_key(tmp_path, source)
    result = _restore(runner, backup_path, target, monkeypatch)

    assert result.exit_code == 1, result.output
    assert "foreign" in result.output.lower(), result.output
    assert target.get_lease("foreign-link-lease") is None
    assert target.list_credentials() == []


def test_cli_restore_broker_mismatch_blocked(monkeypatch, tmp_path: Path) -> None:
    """Broker mismatch: lease identity not matching the referenced credential is blocked."""
    runner = CliRunner()
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    record = source.add_credential("openai", "sk-secret", "api_key", alias="primary")
    mismatched_lease = {
        "id": "mismatch-lease",
        "service": "openai",
        "alias": "different-alias",  # does not match the referenced credential's alias
        "credential_id": record.id,
        "credential_type": "api_key",
        "agent_id": "attacker-agent",
        "issued_by": "attacker-agent",
        "purpose": "task",
        "status": "active",
        "ttl_seconds": 3600,
        "issued_at": utc_now().isoformat(),
        "expires_at": (utc_now() + timedelta(hours=1)).isoformat(),
    }
    backup = source.export_backup()
    backup["leases"] = [mismatched_lease]
    backup_path = _write_backup(tmp_path / "backup.json", backup)

    target = _target_with_shared_key(tmp_path, source)
    result = _restore(runner, backup_path, target, monkeypatch)

    assert result.exit_code == 1, result.output
    assert "broker mismatch" in result.output.lower(), result.output
    assert target.get_lease("mismatch-lease") is None
    assert target.list_credentials() == []


def test_cli_restore_v2_missing_evidence_blocked(monkeypatch, tmp_path: Path) -> None:
    """v2 evidence contract: a v2 backup without audit evidence cannot be restored."""
    runner = CliRunner()
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "sk-secret", "api_key", alias="primary")
    backup = source.export_backup(include_audit=True)
    backup.pop("audit_integrity", None)
    backup_path = _write_backup(tmp_path / "backup.json", backup)

    target = _target_with_shared_key(tmp_path, source)
    result = _restore(runner, backup_path, target, monkeypatch)

    assert result.exit_code == 1, result.output
    assert "audit integrity evidence" in result.output.lower(), result.output
    assert target.list_credentials() == []


def test_cli_restore_v2_marker_only_evidence_blocked(monkeypatch, tmp_path: Path) -> None:
    """F3: marker-only v2 evidence fails closed at the CLI (no write, exit 1).

    Review F3: the live restore path accepted a v2 backup whose
    audit_integrity carried only ``integrity_available: true``. The CLI must
    reject it with a non-zero exit exactly like backup-verify does, and the
    target vault must remain unchanged.
    """
    runner = CliRunner()
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "sk-secret", "api_key", alias="primary")
    backup = source.export_backup(include_audit=True)
    backup["audit_integrity"] = {
        "integrity_available": True,
        "state": [],
        "segments": [],
        "records": [],
    }
    backup_path = _write_backup(tmp_path / "backup.json", backup)

    target = _target_with_shared_key(tmp_path, source)
    result = _restore(runner, backup_path, target, monkeypatch)

    assert result.exit_code == 1, result.output
    assert "audit integrity evidence" in result.output.lower(), result.output
    assert target.list_credentials() == []


def test_cli_restore_transaction_failure_surface(monkeypatch, tmp_path: Path) -> None:
    """Transaction failure (sqlite3.Error) is surfaced as a distinct class."""
    runner = CliRunner()
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "sk-secret", "api_key", alias="primary")
    backup_path = _write_backup(tmp_path / "backup.json", source.export_backup())

    target = _target_with_shared_key(tmp_path, source)

    def boom(_backup, _replace: bool = True, agent_id: str = "operator"):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(target, "import_backup", boom)
    result = _restore(runner, backup_path, target, monkeypatch)

    assert result.exit_code == 1, result.output
    assert "transaction failure" in result.output.lower(), result.output


# ── Audit failure atomicity from the CLI ───────────────────────────────


def test_cli_restore_audit_failure_rolls_back(monkeypatch, tmp_path: Path) -> None:
    """When the protected restore audit event cannot be written, the CLI restore rolls back.

    Mirrors test_restore_atomicity.py::test_restore_appends_protected_audit_event
    but driven through the CLI: the chain is staled so append_in_transaction
    raises AuditIntegrityError, and no restore changes may commit.
    """
    runner = CliRunner()
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "sk-secret", "api_key", alias="primary")
    backup_path = _write_backup(tmp_path / "backup.json", source.export_backup())

    target = _target_with_shared_key(tmp_path, source)

    # Seed a healthy protected chain, advance past the checkpoint, then revert
    # the checkpoint so the next protected append fails (stale checkpoint).
    audit = AuditLogger(target.db_path, master_key=target.key)
    audit.record(
        AccessLogRecord(
            agent_id="operator",
            service="*",
            action="seed",
            decision=Decision.allow,
            reason="seed protected chain",
        )
    )
    checkpoint_path = target.db_path.with_name("audit.checkpoint.json")
    original_checkpoint = checkpoint_path.read_bytes()
    audit.record(
        AccessLogRecord(
            agent_id="operator",
            service="*",
            action="seed-2",
            decision=Decision.allow,
            reason="advance chain past checkpoint",
        )
    )
    checkpoint_path.write_bytes(original_checkpoint)

    result = _restore(runner, backup_path, target, monkeypatch)

    assert result.exit_code == 1, result.output
    assert "audit" in result.output.lower(), result.output
    assert target.list_credentials() == [], "restore committed rows despite audit failure"


# ── Forged active lease class ──────────────────────────────────────────


def test_cli_restore_forged_active_lease_force_revoked(monkeypatch, tmp_path: Path) -> None:
    """Active leases in a backup are never restored as active (E1 policy).

    The CLI gate surfaces a distinct notice about the force-revoke while the
    restore itself succeeds — active lease identities are never minted (#62).
    """
    runner = CliRunner()
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    record = source.add_credential("openai", "sk-secret", "api_key", alias="primary")
    active_lease = {
        "id": "forged-active-lease",
        "service": "openai",
        "alias": "primary",
        "credential_id": record.id,
        "credential_type": "api_key",
        "agent_id": "attacker-agent",
        "issued_by": "attacker-agent",
        "purpose": "task",
        "status": "active",
        "ttl_seconds": 3600,
        "issued_at": utc_now().isoformat(),
        "expires_at": (utc_now() + timedelta(hours=1)).isoformat(),
    }
    backup = source.export_backup()
    backup["leases"] = [active_lease]
    backup_path = _write_backup(tmp_path / "backup.json", backup)

    target = _target_with_shared_key(tmp_path, source)
    result = _restore(runner, backup_path, target, monkeypatch)

    assert result.exit_code == 0, result.output
    assert "force" in result.output.lower() and "revok" in result.output.lower(), result.output
    active = target.find_active_lease(agent_id="attacker-agent", service="openai", alias="primary")
    assert active is None, "restore minted an active lease from backup data"
    restored = target.get_lease("forged-active-lease")
    if restored is not None:
        from hermes_vault.models import LeaseStatus

        assert restored.status is not LeaseStatus.active
