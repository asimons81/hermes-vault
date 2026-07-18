from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from hermes_vault.audit import AuditLogger
from hermes_vault.audit_integrity.models import AuditIntegrityStatus
from hermes_vault.audit_integrity.service import AuditIntegrityError
from hermes_vault.models import AccessLogRecord, Decision
from hermes_vault.vault import Vault


def make_logger(tmp_path: Path) -> AuditLogger:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    return AuditLogger(vault.db_path, master_key=vault.key)


def record(logger: AuditLogger, reason: str = "allowed") -> None:
    logger.record(AccessLogRecord(agent_id="test-agent", service="openai", action="get_env", decision=Decision.allow, reason=reason, metadata={"ticket": "fake"}))


def test_fresh_audit_history_is_signed_and_verified(tmp_path: Path) -> None:
    logger = make_logger(tmp_path)
    record(logger)

    result = logger.integrity.verify()  # type: ignore[union-attr]

    assert result.status is AuditIntegrityStatus.healthy
    assert result.verified_count == 1
    assert (tmp_path / "audit.checkpoint.json").exists()


def test_mutated_audit_row_fails_verification(tmp_path: Path) -> None:
    logger = make_logger(tmp_path)
    record(logger)
    with sqlite3.connect(logger.db_path) as conn:
        conn.execute("UPDATE access_logs SET reason = 'changed' ")
        conn.commit()

    result = logger.integrity.verify()  # type: ignore[union-attr]

    assert result.status is AuditIntegrityStatus.failed
    assert result.reason_code == "entry_digest_mismatch"


def test_stale_checkpoint_blocks_append_until_operator_advances_it(tmp_path: Path) -> None:
    logger = make_logger(tmp_path)
    record(logger)
    checkpoint = tmp_path / "audit.checkpoint.json"
    original = checkpoint.read_bytes()
    record(logger)
    checkpoint.write_bytes(original)

    result = logger.integrity.verify()  # type: ignore[union-attr]
    assert result.status is AuditIntegrityStatus.incomplete
    assert result.reason_code == "checkpoint_stale"
    with pytest.raises(AuditIntegrityError):
        record(logger)

    advanced = logger.integrity.advance_checkpoint()  # type: ignore[union-attr]
    assert advanced.status is AuditIntegrityStatus.healthy
    record(logger)


def test_legacy_history_is_anchored_without_rewriting_rows(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "audit.db", tmp_path / "salt.bin", "test-passphrase")
    logger = AuditLogger(vault.db_path)
    record(logger, reason="legacy")
    before = (tmp_path / "audit.db").read_bytes()
    protected = AuditLogger(vault.db_path, master_key=vault.key)
    protected.integrity.ensure_initialized()  # type: ignore[union-attr]

    result = protected.integrity.verify()  # type: ignore[union-attr]

    assert result.status is AuditIntegrityStatus.healthy
    assert result.legacy_count == 1
    assert before != b""

def test_rotation_creates_a_new_segment_and_retains_history(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "old-passphrase")
    logger = AuditLogger(vault.db_path, master_key=vault.key)
    record(logger)

    vault.rotate_master_key("old-passphrase", "new-passphrase")
    reopened = Vault(vault.db_path, vault.salt_path, "new-passphrase")
    result = AuditLogger(reopened.db_path, master_key=reopened.key).integrity.verify()  # type: ignore[union-attr]

    assert result.status is AuditIntegrityStatus.healthy
    assert result.active_segment_number == 2
    assert result.verified_count == 1