"""Tests for idempotent audit transition reconciliation (Slice C, #66).

Covers the ``AuditIntegrityService.recover_pending_rotation`` seam from
INTEGRITY_RECOVERY_PLAN.md lines 341-345: given the typed v2 rotation
journal (which records the *old* audit segment id and phase
``db_committed_pending``), reconcile the audit chain under the new master
key:

* repeated replay of the same journal converges to the same state
  (idempotent transition application);
* an interrupted audit (segment rotation committed but checkpoint rewrite
  lost, or rotation never committed) resumes to the same state as a clean
  rotation;
* contradictions fail closed and the destructive
  ``recover_checkpoint`` / ``_rebuild_integrity_for_key_mismatch``
  semantics are never expanded or invoked.

These tests exercise the real ``AuditIntegrityService`` against a real
sqlite audit DB (same fixture pattern as ``test_audit_integrity_core.py``).
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from hermes_vault.audit import AuditLogger
from hermes_vault.audit_integrity.models import AuditIntegrityStatus
from hermes_vault.audit_integrity.service import AuditIntegrityError, AuditIntegrityService
from hermes_vault.models import AccessLogRecord, Decision
from hermes_vault.rotation_journal import (
    DurableKind,
    DurableMaterial,
    JournalPhase,
    RotationJournalEntry,
    encrypt_old_key_recovery,
)
from hermes_vault.vault import Vault


def make_logger(tmp_path: Path, passphrase: str = "test-passphrase") -> tuple[AuditLogger, Vault]:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", passphrase)
    return AuditLogger(vault.db_path, master_key=vault.key), vault


def record(logger: AuditLogger, reason: str = "allowed") -> None:
    logger.record(
        AccessLogRecord(
            agent_id="test-agent",
            service="openai",
            action="get_env",
            decision=Decision.allow,
            reason=reason,
            metadata={"ticket": "fake"},
        )
    )


def _pbkdf_material() -> DurableMaterial:
    return DurableMaterial(kind=DurableKind.pbkdf_salt, salt=os.urandom(16))


def _pending_journal(
    old_segment_id: str | None,
    old_key: bytes,
    new_key: bytes,
    journal_id: str = "reconcile-journal-1",
) -> RotationJournalEntry:
    """Typed v2 journal in the exact state a rotation leaves at interruption."""
    assert old_segment_id is not None  # verify() always yields an active segment
    entry = RotationJournalEntry.start(
        old_durable=_pbkdf_material(),
        new_durable=_pbkdf_material(),
        journal_id=journal_id,
    )
    recovery = encrypt_old_key_recovery(old_key, new_key, entry.journal_id)
    return entry.mark_db_committed(old_segment_id=old_segment_id, old_key_recovery=recovery)


def _segment_rows(tmp_path: Path) -> list[sqlite3.Row]:
    with sqlite3.connect(tmp_path / "vault.db") as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT * FROM audit_integrity_segments ORDER BY segment_number"
        ).fetchall()


# ── L2/L4: completes a rotation that never reached the audit chain ────────


def test_reconcile_completes_pending_rotation(tmp_path: Path) -> None:
    logger, vault = make_logger(tmp_path)
    record(logger)
    record(logger)
    old_segment_id = logger.integrity.verify().active_segment_id  # type: ignore[union-attr]
    assert old_segment_id is not None

    new_key = os.urandom(32)
    journal = _pending_journal(old_segment_id, vault.key, new_key)

    # Reopen with the new key: the chain is still under the old key.
    service = AuditIntegrityService(vault.db_path, new_key)
    before = service.verify()
    assert before.status is AuditIntegrityStatus.failed
    assert before.reason_code == "active_key_mismatch"

    result = service.recover_pending_rotation(journal, old_master_key=vault.key)

    assert result.status is AuditIntegrityStatus.healthy
    assert result.active_segment_number == 2
    assert result.verified_count == 2
    # The successor must be linked to the journaled old segment.
    segments = _segment_rows(tmp_path)
    assert len(segments) == 2
    assert segments[0]["segment_id"] == old_segment_id
    assert segments[0]["sequence_end"] is not None
    assert segments[1]["predecessor_segment_id"] == old_segment_id
    # predecessor_tip_digest must equal the old segment's last record digest.
    with sqlite3.connect(vault.db_path) as conn:
        conn.row_factory = sqlite3.Row
        old_tip = conn.execute(
            "SELECT entry_digest FROM audit_integrity_records WHERE segment_id = ? ORDER BY sequence DESC LIMIT 1",
            (old_segment_id,),
        ).fetchone()
    assert segments[1]["predecessor_tip_digest"] == old_tip["entry_digest"]


def test_reconcile_replay_converges(tmp_path: Path) -> None:
    logger, vault = make_logger(tmp_path)
    record(logger)
    old_segment_id = logger.integrity.verify().active_segment_id  # type: ignore[union-attr]
    new_key = os.urandom(32)
    journal = _pending_journal(old_segment_id, vault.key, new_key)

    first = AuditIntegrityService(vault.db_path, new_key)
    result1 = first.recover_pending_rotation(journal, old_master_key=vault.key)
    assert result1.status is AuditIntegrityStatus.healthy
    active_after_first = result1.active_segment_id

    # Replaying the same journal must converge — no duplicate segment, same
    # active segment, still healthy.
    again = AuditIntegrityService(vault.db_path, new_key)
    result2 = again.recover_pending_rotation(journal, old_master_key=vault.key)
    assert result2.status is AuditIntegrityStatus.healthy
    assert result2.active_segment_id == active_after_first
    assert result2.active_segment_number == 2
    assert result2.verified_count == 1
    assert len(_segment_rows(tmp_path)) == 2


def test_reconcile_thrice_replay_keeps_same_state(tmp_path: Path) -> None:
    logger, vault = make_logger(tmp_path)
    record(logger)
    record(logger)
    record(logger)
    old_segment_id = logger.integrity.verify().active_segment_id  # type: ignore[union-attr]
    new_key = os.urandom(32)
    journal = _pending_journal(old_segment_id, vault.key, new_key)

    results = [
        AuditIntegrityService(vault.db_path, new_key)
        .recover_pending_rotation(journal, old_master_key=vault.key)
        .active_segment_id
        for _ in range(3)
    ]
    assert results[0] == results[1] == results[2]
    assert len(_segment_rows(tmp_path)) == 2


# ── L2/L4: interrupted audit resume (rotation committed, checkpoint lost) ──


def test_reconcile_resumes_interrupted_audit_same_state(tmp_path: Path) -> None:
    """A lost checkpoint after the segment commit resumes to the clean state."""
    logger, vault = make_logger(tmp_path)
    record(logger)
    record(logger)
    old_segment_id = logger.integrity.verify().active_segment_id  # type: ignore[union-attr]

    # Clean rotation creates the successor and writes the checkpoint.
    new_key = os.urandom(32)
    clean_service = AuditIntegrityService(vault.db_path, vault.key)
    clean_service.rotate_segment(new_key)
    clean_active = clean_service.verify().active_segment_id
    assert len(_segment_rows(tmp_path)) == 2

    # Simulate an interruption: the segment commit happened but the
    # checkpoint write was lost.  Rewind by removing the checkpoint.
    checkpoint = vault.db_path.with_name("audit.checkpoint.json")
    checkpoint.unlink()
    interrupted = AuditIntegrityService(vault.db_path, new_key)
    before = interrupted.verify()
    assert before.status is AuditIntegrityStatus.incomplete  # checkpoint_missing

    journal = _pending_journal(old_segment_id, vault.key, new_key)
    result = interrupted.recover_pending_rotation(journal, old_master_key=vault.key)

    assert result.status is AuditIntegrityStatus.healthy
    # Same state as the clean rotation: same active segment, no third segment.
    assert result.active_segment_id == clean_active
    assert result.active_segment_number == 2
    assert result.verified_count == 2
    assert len(_segment_rows(tmp_path)) == 2


def test_reconcile_rewrites_only_checkpoint_when_rotation_committed(tmp_path: Path) -> None:
    """If the successor already exists, reconciliation must not create another."""
    logger, vault = make_logger(tmp_path)
    record(logger)
    old_segment_id = logger.integrity.verify().active_segment_id  # type: ignore[union-attr]
    new_key = os.urandom(32)

    clean = AuditIntegrityService(vault.db_path, vault.key)
    clean.rotate_segment(new_key)
    segments_after_rotation = _segment_rows(tmp_path)
    assert len(segments_after_rotation) == 2

    checkpoint = vault.db_path.with_name("audit.checkpoint.json")
    checkpoint.unlink()
    journal = _pending_journal(old_segment_id, vault.key, new_key)
    service = AuditIntegrityService(vault.db_path, new_key)
    result = service.recover_pending_rotation(journal, old_master_key=vault.key)

    assert result.status is AuditIntegrityStatus.healthy
    segments = _segment_rows(tmp_path)
    assert len(segments) == 2  # no duplicate successor
    assert [s["segment_id"] for s in segments] == [
        s["segment_id"] for s in segments_after_rotation
    ]


# ── L2/L4: fail-closed contradictions ─────────────────────────────────────


def test_reconcile_contradictory_journal_fails_closed(tmp_path: Path) -> None:
    logger, vault = make_logger(tmp_path)
    record(logger)
    new_key = os.urandom(32)

    # Journal claims an old segment id that is neither active nor a predecessor.
    journal = _pending_journal("seg-does-not-exist", vault.key, new_key)
    service = AuditIntegrityService(vault.db_path, new_key)
    before = service.verify()

    with pytest.raises(AuditIntegrityError, match="contradictory"):
        service.recover_pending_rotation(journal, old_master_key=vault.key)

    # Nothing was mutated: same segments, same verify result.
    assert len(_segment_rows(tmp_path)) == 1
    after = service.verify()
    assert after.status is before.status
    assert after.reason_code == before.reason_code


def test_reconcile_wrong_old_key_fails_closed(tmp_path: Path) -> None:
    logger, vault = make_logger(tmp_path)
    record(logger)
    old_segment_id = logger.integrity.verify().active_segment_id  # type: ignore[union-attr]
    new_key = os.urandom(32)
    journal = _pending_journal(old_segment_id, vault.key, new_key)

    service = AuditIntegrityService(vault.db_path, new_key)
    with pytest.raises(AuditIntegrityError, match="contradictory|old key"):
        # The journaled old key does not match the segment's recorded key.
        service.recover_pending_rotation(
            journal, old_master_key=os.urandom(32)
        )


def test_reconcile_started_journal_fails_closed(tmp_path: Path) -> None:
    logger, vault = make_logger(tmp_path)
    record(logger)
    new_key = os.urandom(32)

    entry = RotationJournalEntry.start(
        old_durable=_pbkdf_material(),
        new_durable=_pbkdf_material(),
        journal_id="reconcile-started",
    )
    service = AuditIntegrityService(vault.db_path, new_key)
    with pytest.raises(AuditIntegrityError, match="started"):
        service.recover_pending_rotation(entry, old_master_key=vault.key)


def test_reconcile_checkpoint_committed_journal_is_noop(tmp_path: Path) -> None:
    logger, vault = make_logger(tmp_path)
    record(logger)
    old_segment_id = logger.integrity.verify().active_segment_id  # type: ignore[union-attr]
    new_key = os.urandom(32)

    # Fully completed rotation.
    clean = AuditIntegrityService(vault.db_path, vault.key)
    clean.rotate_segment(new_key)
    segments_before = _segment_rows(tmp_path)

    # A checkpoint_committed journal replay is a no-op.
    entry = _pending_journal(old_segment_id, vault.key, new_key)
    done = entry.mark_audit_checkpoint_committed()
    assert done.phase() == JournalPhase.checkpoint_committed

    service = AuditIntegrityService(vault.db_path, new_key)
    result = service.recover_pending_rotation(done, old_master_key=vault.key)
    assert result.status is AuditIntegrityStatus.healthy
    assert len(_segment_rows(tmp_path)) == len(segments_before)


# ── L3/L4: no destructive operations are added or invoked ─────────────────


def test_reconcile_never_invokes_destructive_rebuild(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    logger, vault = make_logger(tmp_path)
    record(logger)
    old_segment_id = logger.integrity.verify().active_segment_id  # type: ignore[union-attr]
    new_key = os.urandom(32)
    journal = _pending_journal(old_segment_id, vault.key, new_key)

    service = AuditIntegrityService(vault.db_path, new_key)

    def _boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("destructive rebuild must not be invoked")

    monkeypatch.setattr(service, "_rebuild_integrity_for_key_mismatch", _boom)
    monkeypatch.setattr(service, "recover_checkpoint", _boom)

    result = service.recover_pending_rotation(journal, old_master_key=vault.key)
    assert result.status is AuditIntegrityStatus.healthy
    assert len(_segment_rows(tmp_path)) == 2


def test_reconcile_preserves_all_records_and_tables(tmp_path: Path) -> None:
    logger, vault = make_logger(tmp_path)
    for i in range(5):
        record(logger, reason=f"r{i}")
    old_segment_id = logger.integrity.verify().active_segment_id  # type: ignore[union-attr]
    new_key = os.urandom(32)
    journal = _pending_journal(old_segment_id, vault.key, new_key)

    service = AuditIntegrityService(vault.db_path, new_key)
    result = service.recover_pending_rotation(journal, old_master_key=vault.key)
    assert result.status is AuditIntegrityStatus.healthy
    assert result.verified_count == 5
    assert result.legacy_count == 0

    with sqlite3.connect(vault.db_path) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    for required in (
        "access_logs",
        "audit_integrity_state",
        "audit_integrity_segments",
        "audit_integrity_records",
    ):
        assert required in tables
