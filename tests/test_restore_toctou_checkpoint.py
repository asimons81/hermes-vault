"""Red tests for Issue #62B — restore TOCTOU and checkpoint atomicity seams (F5/F6).

These tests encode the failure modes the F5/F6 repair must handle and are
intentionally RED against the pre-repair codebase:

F5 — preflight-to-transaction TOCTOU:
- A writer that deletes a referenced credential AFTER the preflight
  validation but BEFORE ``BEGIN IMMEDIATE`` must not produce a dangling
  restored lease or a silently skipped credential replace. The lease
  linkage and broker identity are re-verified inside the write
  transaction, so the restore fails closed and commits nothing.

F6 — checkpoint-after-commit atomicity:
- When the protected restore audit event commits but the checkpoint file
  write fails afterward, the restore must NOT be reported as blocked /
  rolled back: the data is committed, so the failure surfaces as a
  distinct ``RestoreCommittedCheckpointError`` and the chain verifies as
  ``checkpoint_stale`` until the checkpoint is re-published.
- A retry of the same restore by the same acting agent must not append a duplicate protected
  restore event: the event id is deterministic and the retry re-publishes the
  checkpoint idempotently.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner

from hermes_vault.audit import AuditLogger
from hermes_vault.audit_integrity.models import AuditIntegrityStatus
from hermes_vault.audit_integrity.service import AuditIntegrityService
from hermes_vault.cli import _hermes_group
from hermes_vault.models import AccessLogRecord, Decision
from hermes_vault.vault import RestoreCommittedCheckpointError, Vault

PASSPHRASE = "test-passphrase"


def _make_vault(tmp_path: Path, name: str = "vault.db", salt: str = "salt.bin") -> Vault:
    return Vault(tmp_path / name, tmp_path / salt, PASSPHRASE)


def _target_with_shared_key(tmp_path: Path, source: Vault) -> Vault:
    shutil.copy(source.salt_path, tmp_path / "tgt_salt.bin")
    return _make_vault(tmp_path, name="target.db", salt="tgt_salt.bin")


def _write_backup(path: Path, backup: dict) -> Path:
    path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _seed_healthy_chain(target: Vault) -> None:
    """Seed one protected audit event so the restore path runs a protected chain."""
    AuditLogger(target.db_path, master_key=target.key).record(
        AccessLogRecord(
            agent_id="operator",
            service="*",
            action="seed",
            decision=Decision.allow,
            reason="seed protected chain",
        )
    )


def _restore_event_count(target: Vault) -> int:
    with sqlite3.connect(target.db_path) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM access_logs WHERE action = 'restore'").fetchone()[0])


def _fake_build(vault: Vault):
    def _inner(prompt: bool = False):
        return vault, object(), object(), object()

    return _inner


# ── F5: preflight-to-transaction TOCTOU ───────────────────────────────


def test_restore_reverifies_lease_linkage_inside_transaction(tmp_path: Path, monkeypatch) -> None:
    """A credential deleted after preflight must not yield a dangling restored lease.

    The preflight validates the lease linkage against the pre-lock snapshot;
    a concurrent writer deleting the referenced credential between the
    preflight reads and BEGIN IMMEDIATE must be caught by the in-transaction
    re-verification, which fails closed and commits nothing.
    """
    target = _make_vault(tmp_path, name="target.db", salt="tgt_salt.bin")
    record = target.add_credential("openai", "sk-target", "api_key", alias="primary")
    target.issue_lease(record.id, agent_id="agent-a", ttl_seconds=600)
    _seed_healthy_chain(target)

    # Backup carries the lease but no credentials: the lease references a
    # credential that already exists in the target vault (preflight accepts it).
    backup = target.export_backup()
    backup["credentials"] = []
    backup_path = _write_backup(tmp_path / "backup.json", backup)

    real_verify = AuditIntegrityService.verify

    def concurrent_delete(self, *args, **kwargs):
        # Simulate a writer that removes the referenced credential after the
        # preflight reads but before the restore transaction.
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM credentials WHERE id = ?", (record.id,))
            conn.commit()
        return real_verify(self, *args, **kwargs)

    monkeypatch.setattr(AuditIntegrityService, "verify", concurrent_delete)

    with pytest.raises(ValueError, match="foreign credential linkage"):
        target.import_backup(json.loads(backup_path.read_text(encoding="utf-8")))

    # Nothing committed: no dangling lease row and no protected restore event.
    assert _restore_event_count(target) == 0, "restore committed a protected event for a dangling lease"
    assert target.list_credentials() == []


def test_restore_reverifies_existing_credential_still_present(tmp_path: Path, monkeypatch) -> None:
    """A credential being replaced that vanishes after preflight must block the restore.

    The preflight captured an existing row to UPDATE; if a concurrent writer
    removes it before the transaction, the in-transaction re-verification must
    reject the restore instead of silently applying a zero-row UPDATE.
    """
    target = _make_vault(tmp_path, name="target.db", salt="tgt_salt.bin")
    record = target.add_credential("openai", "sk-target", "api_key", alias="primary")
    _seed_healthy_chain(target)

    backup = target.export_backup()
    backup_path = _write_backup(tmp_path / "backup.json", backup)

    real_verify = AuditIntegrityService.verify

    def concurrent_delete(self, *args, **kwargs):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM credentials WHERE id = ?", (record.id,))
            conn.commit()
        return real_verify(self, *args, **kwargs)

    monkeypatch.setattr(AuditIntegrityService, "verify", concurrent_delete)

    with pytest.raises(ValueError, match="removed while the restore was being prepared"):
        target.import_backup(json.loads(backup_path.read_text(encoding="utf-8")))

    assert _restore_event_count(target) == 0, "restore committed despite the referenced credential vanishing"
    assert target.list_credentials() == []


# ── F6: checkpoint-after-commit atomicity ─────────────────────────────


def test_restore_checkpoint_failure_reports_committed_not_blocked(tmp_path: Path, monkeypatch) -> None:
    """A checkpoint write failure after commit must not look like a rolled-back restore.

    The restore data and its protected audit event are already committed when
    the checkpoint publication runs; the failure surfaces as
    ``RestoreCommittedCheckpointError`` (not a generic audit failure) and the
    chain verifies ``checkpoint_stale`` until the checkpoint is re-published.
    """
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "sk-secret", "api_key", alias="primary")
    backup_path = _write_backup(tmp_path / "backup.json", source.export_backup())

    target = _target_with_shared_key(tmp_path, source)
    _seed_healthy_chain(target)

    def failing_write(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("hermes_vault.audit_integrity.service.write_checkpoint", failing_write)

    with pytest.raises(RestoreCommittedCheckpointError):
        target.import_backup(json.loads(backup_path.read_text(encoding="utf-8")))

    # Data committed despite the checkpoint publication failure.
    services = sorted(c.service for c in target.list_credentials())
    assert services == ["openai"], "restore data did not commit"
    assert _restore_event_count(target) == 1, "protected restore event did not commit"

    # Fail closed: the chain is verifiable only as checkpoint_stale (incomplete).
    result = AuditIntegrityService(target.db_path, target.key).verify()
    assert result.status == AuditIntegrityStatus.incomplete, f"expected incomplete, got {result.status}"
    assert result.reason_code == "checkpoint_stale"


def test_restore_retry_after_checkpoint_failure_is_idempotent(tmp_path: Path, monkeypatch) -> None:
    """Retrying a restore whose checkpoint publication failed must not duplicate events.

    Attempt 1 commits the restore and its protected event but fails to publish
    the checkpoint. Attempt 2 re-runs the same backup: the deterministic event
    id is already committed, so the retry skips the append, re-publishes the
    checkpoint, and leaves exactly one protected restore event.
    """
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "sk-secret", "api_key", alias="primary")
    backup_path = _write_backup(tmp_path / "backup.json", source.export_backup())
    backup = json.loads(backup_path.read_text(encoding="utf-8"))

    target = _target_with_shared_key(tmp_path, source)
    _seed_healthy_chain(target)

    import hermes_vault.audit_integrity.service as audit_service_module

    real_write_checkpoint = audit_service_module.write_checkpoint

    def failing_write(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(audit_service_module, "write_checkpoint", failing_write)
    with pytest.raises(RestoreCommittedCheckpointError):
        target.import_backup(backup)
    assert _restore_event_count(target) == 1

    # Second attempt: checkpoint publication works again.
    monkeypatch.setattr(audit_service_module, "write_checkpoint", real_write_checkpoint)
    imported = target.import_backup(backup)

    assert [c.service for c in imported] == ["openai"]
    assert _restore_event_count(target) == 1, "retry appended a duplicate protected restore event"

    # The retry re-published the checkpoint, so the chain is healthy again.
    result = AuditIntegrityService(target.db_path, target.key).verify()
    assert result.status == AuditIntegrityStatus.healthy, (
        f"expected healthy, got {result.status} ({result.reason_code})"
    )


def test_identical_backup_restores_keep_distinct_protected_actor_attribution(tmp_path: Path) -> None:
    """Different actors restoring identical content get distinct protected restore events.

    F6 retries remain idempotent for the same acting agent, but the event identity
    must not collapse a real second actor into the first actor's restore record
    (F4/F6 interaction).
    """
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "sk-secret", "api_key", alias="primary")
    backup = source.export_backup()

    target = _target_with_shared_key(tmp_path, source)
    _seed_healthy_chain(target)

    target.import_backup(backup, agent_id="pam")
    target.import_backup(backup, agent_id="bob")

    with sqlite3.connect(target.db_path) as conn:
        rows = conn.execute(
            "SELECT agent_id FROM access_logs WHERE action = 'restore' ORDER BY timestamp"
        ).fetchall()
    assert [row[0] for row in rows] == ["pam", "bob"]
    assert _restore_event_count(target) == 2
    assert AuditIntegrityService(target.db_path, target.key).verify().status == AuditIntegrityStatus.healthy



def test_cli_restore_checkpoint_failure_reports_committed_not_blocked(monkeypatch, tmp_path: Path) -> None:
    """The CLI must never report a committed restore as blocked/rolled back.

    A checkpoint publication failure after commit exits non-zero (fail closed
    — the degraded audit state needs attention) but the message states the
    restore committed and points at the checkpoint, not at a rolled-back
    restore (issue #62B / F6).
    """
    runner = CliRunner()
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "sk-secret", "api_key", alias="primary")
    backup_path = _write_backup(tmp_path / "backup.json", source.export_backup())

    target = _target_with_shared_key(tmp_path, source)
    _seed_healthy_chain(target)

    def failing_write(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("hermes_vault.audit_integrity.service.write_checkpoint", failing_write)
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build(target))

    result = runner.invoke(
        _hermes_group,
        ["restore", "--input", str(backup_path), "--yes"],
        catch_exceptions=False,
    )

    assert result.exit_code == 1, result.output
    assert "Restore committed" in result.output, result.output
    assert "blocked" not in result.output.lower(), result.output
    assert "checkpoint_stale" in result.output, result.output
    # The restore data committed despite the checkpoint failure.
    assert sorted(c.service for c in target.list_credentials()) == ["openai"]
    assert _restore_event_count(target) == 1
