from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from hermes_vault.audit import AuditLogger
from hermes_vault.audit_integrity.models import AuditIntegrityStatus
from hermes_vault.audit_integrity.service import AuditIntegrityService
from hermes_vault.config import AppSettings
from hermes_vault.crypto import CorruptKeyMaterialError, MissingKeyMaterialError, derive_key
from hermes_vault.models import AccessLogRecord, Decision
from hermes_vault.rotation_journal import (
    DurableKind,
    DurableMaterial,
    JournalPhase,
    RotationJournalEntry,
    encrypt_old_key_recovery,
)
from hermes_vault.vault import RotationRecoveryError, Vault


def test_missing_salt_after_restore_raises(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "test-passphrase")
    vault.add_credential("openai", "sk-secret-1234567890", "api_key")
    salt.unlink()

    with pytest.raises(MissingKeyMaterialError):
        Vault(db, salt, "test-passphrase")


def test_corrupt_salt_raises(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    Vault(db, salt, "test-passphrase")
    salt.write_bytes(b"short")

    with pytest.raises(CorruptKeyMaterialError):
        Vault(db, salt, "test-passphrase")


def test_ensure_runtime_layout_ignores_chmod_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "runtime"
    settings = AppSettings(runtime_home=runtime)

    def raise_oserror(*args: object, **kwargs: object) -> None:
        raise OSError("read-only file system")

    monkeypatch.setattr("hermes_vault.config.os.chmod", raise_oserror)

    settings.ensure_runtime_layout()

    assert runtime.exists()
    assert settings.generated_skills_dir.exists()


# ── Master-key rotation tests ──────────────────────────────────────


def test_rotate_master_key_preserves_secrets(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "old-pass")
    vault.add_credential("openai", "sk-test-1234", "api_key", alias="primary")

    result = vault.rotate_master_key("old-pass", "new-pass")
    assert result["re_encrypted"] == 1
    assert result["failed"] == 0

    vault2 = Vault(db, salt, "new-pass")
    secret = vault2.get_secret("openai")
    assert secret is not None
    assert secret.secret == "sk-test-1234"


def test_rotate_master_key_wrong_old_passphrase(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "old-pass")
    vault.add_credential("openai", "sk-test", "api_key")

    with pytest.raises(ValueError, match="Old passphrase"):
        vault.rotate_master_key("wrong-pass", "new-pass")


def test_rotate_master_key_empty_vault(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "old-pass")

    result = vault.rotate_master_key("old-pass", "new-pass")
    assert result["re_encrypted"] == 0


def test_rotate_master_key_with_backup(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    os.environ["HERMES_VAULT_PASSPHRASE"] = "old-pass"
    vault = Vault(db, salt, "old-pass")
    vault.add_credential("openai", "sk-test-1", "api_key", alias="primary")
    vault.add_credential("github", "ghp-test-2", "personal_access_token", alias="work")

    backup_path = tmp_path / "pre-rotate.json"
    result = vault.rotate_master_key(
        "old-pass", "new-pass", backup_path=backup_path
    )
    assert result["re_encrypted"] == 2
    assert backup_path.exists()


def test_rotate_master_key_recovers_after_salt_finalization_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "old-pass")
    vault.add_credential("openai", "sk-test-1234", "api_key", alias="primary")
    original_replace = Vault._replace_salt_durable

    def fail_replace(self: Vault, new_salt: bytes) -> None:
        raise OSError("simulated salt write failure")

    monkeypatch.setattr(Vault, "_replace_salt_durable", fail_replace)
    with pytest.raises(OSError, match="simulated salt write failure"):
        vault.rotate_master_key("old-pass", "new-pass")

    assert vault.rotation_journal_path.exists()
    monkeypatch.setattr(Vault, "_replace_salt_durable", original_replace)

    recovered = Vault(db, salt, "new-pass")
    secret = recovered.get_secret("openai")

    assert secret is not None
    assert secret.secret == "sk-test-1234"
    assert not recovered.rotation_journal_path.exists()


def test_corrupt_rotation_journal_raises(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    Vault(db, salt, "old-pass")
    journal = salt.with_name(f"{salt.name}.rotation.json")
    journal.write_text("{not-json", encoding="utf-8")

    with pytest.raises(RotationRecoveryError, match="journal"):
        Vault(db, salt, "old-pass")


def test_rotate_master_key_no_secrets_in_audit(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    os.environ["HERMES_VAULT_PASSPHRASE"] = "old-pass"
    vault = Vault(db, salt, "old-pass")
    vault.add_credential("openai", "sk-test", "api_key")
    vault.rotate_master_key("old-pass", "new-pass")

    from hermes_vault.audit import AuditLogger
    audit = AuditLogger(db)
    entries = audit.list_recent(limit=10, action="rotate_master_key")
    for entry in entries:
        assert "sk-test" not in str(entry)


# ── Issue #66: live v2 rotation-journal recovery regressions ──────────────


def _seed_vault(tmp_path: Path, passphrase: str = "old-pass") -> tuple[Vault, Path, Path]:
    """Create a vault with one credential and one protected audit record."""
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, passphrase)
    vault.add_credential("openai", "sk-test-1234", "api_key", alias="primary")
    logger = AuditLogger(vault.db_path, master_key=vault.key)
    logger.record(
        AccessLogRecord(
            agent_id="agent-1",
            service="openai",
            action="get_env",
            decision=Decision.allow,
            reason="seed",
        )
    )
    return vault, db, salt


def _segment_rows(db: Path) -> list[sqlite3.Row]:
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT * FROM audit_integrity_segments ORDER BY segment_number"
        ).fetchall()


def test_crash_before_audit_rotation_recovers_on_reopen_with_new_passphrase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Crash immediately before audit rotation; reopen with the new passphrase.

    The credential DB is already committed under the new key, but the audit
    chain is still under the old key. Recovery must decrypt the old-key
    recovery material, reconcile the audit transition, finalize the durable
    material, and only then delete the journal — leaving credentials readable
    and the audit chain healthy.
    """
    vault, db, salt = _seed_vault(tmp_path)

    def _crash_rotate_segment(self: AuditIntegrityService, new_master_key: bytes) -> None:
        raise RuntimeError("simulated crash before audit rotation")

    with monkeypatch.context() as m:
        m.setattr(AuditIntegrityService, "rotate_segment", _crash_rotate_segment)
        with pytest.raises(RuntimeError, match="simulated crash before audit rotation"):
            vault.rotate_master_key("old-pass", "new-pass")

    journal = salt.with_name(f"{salt.name}.rotation.json")
    assert journal.exists()
    entry = RotationJournalEntry.from_json(journal.read_text(encoding="utf-8"))
    assert entry.phase() == JournalPhase.db_committed_pending
    assert entry.old_key_recovery is not None

    # Reopen with the NEW passphrase: recovery reconciles the audit chain.
    recovered = Vault(db, salt, "new-pass")
    secret = recovered.get_secret("openai")
    assert secret is not None
    assert secret.secret == "sk-test-1234"
    assert not recovered.rotation_journal_path.exists()

    svc = AuditIntegrityService(db, recovered.key)
    result = svc.verify()
    assert result.status is AuditIntegrityStatus.healthy
    assert result.active_segment_number == 2
    assert result.verified_count == 1


def test_crash_after_audit_commit_before_checkpoint_reconciles_on_reopen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Successor committed but checkpoint publication interrupted.

    Recovery must detect that the active segment is already the journaled
    old segment's successor, rewrite only the checkpoint, and leave the exact
    predecessor/successor relationship intact — no duplicate segment and no
    unrelated registry authentication.
    """
    vault, db, salt = _seed_vault(tmp_path)
    old_segment_id = AuditIntegrityService(db, vault.key).verify().active_segment_id
    assert old_segment_id is not None

    def _crash_checkpoint(
        self: AuditIntegrityService, conn: sqlite3.Connection, segment: sqlite3.Row, **kwargs: object
    ) -> None:
        raise RuntimeError("simulated crash before checkpoint publication")

    with monkeypatch.context() as m:
        m.setattr(AuditIntegrityService, "_write_current_checkpoint", _crash_checkpoint)
        with pytest.raises(RuntimeError, match="simulated crash before checkpoint publication"):
            vault.rotate_master_key("old-pass", "new-pass")

    journal = salt.with_name(f"{salt.name}.rotation.json")
    assert journal.exists()

    # Reopen with the NEW passphrase: recovery rewrites the checkpoint only.
    recovered = Vault(db, salt, "new-pass")
    secret = recovered.get_secret("openai")
    assert secret is not None
    assert secret.secret == "sk-test-1234"
    assert not recovered.rotation_journal_path.exists()

    svc = AuditIntegrityService(db, recovered.key)
    result = svc.verify()
    assert result.status is AuditIntegrityStatus.healthy
    assert result.active_segment_number == 2

    segments = _segment_rows(db)
    assert len(segments) == 2
    assert segments[0]["segment_id"] == old_segment_id
    assert segments[1]["predecessor_segment_id"] == old_segment_id
    # The successor's predecessor tip must equal the old segment's last digest.
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        old_tip = conn.execute(
            "SELECT entry_digest FROM audit_integrity_records WHERE segment_id = ? ORDER BY sequence DESC LIMIT 1",
            (old_segment_id,),
        ).fetchone()
    assert segments[1]["predecessor_tip_digest"] == old_tip["entry_digest"]


def test_pre_commit_crash_rolls_back_with_old_passphrase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Crash before the credential DB commit; reopen with the OLD passphrase.

    The started journal is a safe pre-commit rollback: restore the old
    durable material, delete the journal, and leave credentials readable
    under the old key with a healthy (untouched) audit chain.
    """
    vault, db, salt = _seed_vault(tmp_path)
    original_salt = salt.read_bytes()

    def _boom(secret: str, key: bytes, version: str, aad: dict) -> str:
        raise RuntimeError("simulated crash before DB commit")

    with monkeypatch.context() as m:
        m.setattr("hermes_vault.vault.encrypt_secret_versioned", _boom)
        with pytest.raises(RuntimeError, match="simulated crash before DB commit"):
            vault.rotate_master_key("old-pass", "new-pass")

    journal = salt.with_name(f"{salt.name}.rotation.json")
    assert journal.exists()
    entry = RotationJournalEntry.from_json(journal.read_text(encoding="utf-8"))
    assert entry.phase() == JournalPhase.started

    # Reopen with the OLD passphrase: safe pre-commit rollback.
    recovered = Vault(db, salt, "old-pass")
    secret = recovered.get_secret("openai")
    assert secret is not None
    assert secret.secret == "sk-test-1234"
    assert not recovered.rotation_journal_path.exists()
    assert salt.read_bytes() == original_salt

    svc = AuditIntegrityService(db, recovered.key)
    result = svc.verify()
    assert result.status is AuditIntegrityStatus.healthy
    assert result.active_segment_number == 1


def test_contradictory_v2_journal_retained_on_reopen(tmp_path: Path) -> None:
    """A db_committed journal whose old segment id contradicts the audit
    registry fails closed: journal and durable material are retained."""
    vault, db, salt = _seed_vault(tmp_path)
    journal = salt.with_name(f"{salt.name}.rotation.json")

    new_salt = os.urandom(16)
    new_key = derive_key("new-pass", new_salt)
    entry = RotationJournalEntry.start(
        old_durable=DurableMaterial(kind=DurableKind.pbkdf_salt, salt=salt.read_bytes()),
        new_durable=DurableMaterial(kind=DurableKind.pbkdf_salt, salt=new_salt),
        journal_id="contradict-journal",
    )
    recovery = encrypt_old_key_recovery(vault.key, new_key, entry.journal_id)
    committed = entry.mark_db_committed(
        old_segment_id="seg-does-not-exist",
        old_key_recovery=recovery,
    )
    journal.write_text(committed.to_json(), encoding="utf-8")
    original_salt = salt.read_bytes()

    with pytest.raises(RotationRecoveryError, match="rotation journal"):
        Vault(db, salt, "new-pass")

    # Journal and durable key material are retained — never silently deleted.
    assert journal.exists()
    assert salt.read_bytes() == original_salt


def test_legacy_v1_pending_journal_without_recovery_retained(tmp_path: Path) -> None:
    """A legacy v1 pending journal lacks protected old-key recovery: retain it
    and surface a clear recovery error rather than claiming success."""
    vault, db, salt = _seed_vault(tmp_path)
    journal = salt.with_name(f"{salt.name}.rotation.json")
    v1 = {
        "version": "rotation-journal-v1",
        "status": "db_committed",
        "old_salt": salt.read_bytes().hex(),
        "new_salt": os.urandom(16).hex(),
        "created_at": "2026-07-30T10:15:30+00:00",
        "committed_at": "2026-07-30T10:15:45+00:00",
        "audit_transition_state": "pending",
        "old_segment_id": "seg-7f3a9c2e",
    }
    journal.write_text(json.dumps(v1, sort_keys=True), encoding="utf-8")
    original_salt = salt.read_bytes()

    with pytest.raises(RotationRecoveryError, match="old-key recovery|recovery"):
        Vault(db, salt, "new-pass")

    assert journal.exists()
    assert salt.read_bytes() == original_salt


def test_malformed_journal_retained_on_reopen(tmp_path: Path) -> None:
    """Malformed JSON journal fails closed and is retained."""
    vault, db, salt = _seed_vault(tmp_path)
    journal = salt.with_name(f"{salt.name}.rotation.json")
    journal.write_text("{not-json", encoding="utf-8")

    with pytest.raises(RotationRecoveryError, match="journal"):
        Vault(db, salt, "old-pass")

    assert journal.exists()


def test_rotation_journal_contains_no_plaintext_key_or_passphrase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The v2 journal never stores a plaintext passphrase or master key."""
    vault, db, salt = _seed_vault(tmp_path)

    def _crash_rotate_segment(self: AuditIntegrityService, new_master_key: bytes) -> None:
        raise RuntimeError("simulated crash")

    with monkeypatch.context() as m:
        m.setattr(AuditIntegrityService, "rotate_segment", _crash_rotate_segment)
        with pytest.raises(RuntimeError, match="simulated crash"):
            vault.rotate_master_key("old-pass", "new-pass")

    journal = salt.with_name(f"{salt.name}.rotation.json")
    raw = journal.read_text(encoding="utf-8")
    assert "old-pass" not in raw
    assert "new-pass" not in raw
    assert vault.key.hex() not in raw  # old master key never appears in plaintext
    entry = RotationJournalEntry.from_json(raw)
    assert entry.old_key_recovery is not None
    assert entry.new_durable.salt is not None
    new_key = derive_key("new-pass", entry.new_durable.salt)
    assert new_key.hex() not in raw  # new master key never appears in plaintext


def test_journal_deleted_only_after_healthy_audit_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Journal deletion is gated on healthy audit verification.

    A recovery that cannot reach a healthy audit state keeps the journal and
    the durable material; a healthy recovery deletes both only afterwards.
    """
    vault, db, salt = _seed_vault(tmp_path)
    journal = salt.with_name(f"{salt.name}.rotation.json")

    # Fault: reconcile the DB commit but make the audit transition fail.
    def _crash_rotate_segment(self: AuditIntegrityService, new_master_key: bytes) -> None:
        raise RuntimeError("simulated crash before audit rotation")

    with monkeypatch.context() as m:
        m.setattr(AuditIntegrityService, "rotate_segment", _crash_rotate_segment)
        with pytest.raises(RuntimeError, match="simulated crash"):
            vault.rotate_master_key("old-pass", "new-pass")

    # Break the recovery material so reconciliation cannot produce health:
    # replace the journal with a contradictory old segment id.
    entry = RotationJournalEntry.from_json(journal.read_text(encoding="utf-8"))
    broken = entry.model_copy(update={"old_segment_id": "seg-gone"})
    journal.write_text(broken.to_json(), encoding="utf-8")

    with pytest.raises(RotationRecoveryError, match="rotation journal"):
        Vault(db, salt, "new-pass")

    # The journal survived the failed recovery — deletion is health-gated.
    assert journal.exists()

