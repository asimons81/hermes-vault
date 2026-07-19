"""Regression tests for the audit-integrity TOCTOU race that lets
unprotected access_logs rows be written between the legacy snapshot
capture and the chain's first protected append.

The bug (pre-fix): `_legacy_snapshot()` ran BEFORE the BEGIN IMMEDIATE
in `ensure_initialized`, so any rows committed by other processes (or by
the same process reentering the append path during `initialize_schema`)
between snapshot capture and segment activation ended up outside the
prefix AND outside the protected chain. `verify()` then permanently
returned `missing_integrity_record`, and `AuditLogger.record()` raised
on every subsequent append — but `VaultMutations.add_credential` had
already committed the credential to `credentials`, leaving the vault
in a desynced state (credential exists, audit row missing).

The fix: capture the legacy snapshot INSIDE the same BEGIN IMMEDIATE
transaction as the segment insert, after `initialize_schema()` and
before the INSERTs. This makes snapshot capture and segment creation
atomic from the perspective of any concurrent writer.
"""
from __future__ import annotations

import sqlite3
import threading
import uuid
from pathlib import Path

import pytest

from hermes_vault.audit import AuditLogger
from hermes_vault.audit_integrity.models import AuditIntegrityStatus
from hermes_vault.models import AccessLogRecord, Decision
from hermes_vault.vault import Vault


def make_vault_and_logger(tmp_path: Path) -> tuple[Vault, AuditLogger]:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    logger = AuditLogger(vault.db_path, master_key=vault.key)
    return vault, logger


def _legacy_record(logger: AuditLogger, reason: str = "legacy") -> None:
    """Write a single legacy audit row, bypassing the integrity append path.

    Simulates a pre-v0.21 vault that has unanchored audit history.
    """
    logger.initialize()  # ensure access_logs schema exists
    record = AccessLogRecord(
        agent_id="legacy-agent",
        service="openai",
        action="add_credential",
        decision=Decision.allow,
        reason=reason,
        metadata={"ticket": "fake"},
    )
    with sqlite3.connect(logger.db_path) as conn:
        conn.execute(
            """INSERT INTO access_logs (id, timestamp, agent_id, service, action, decision, reason, ttl_seconds, verification_result, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (record.id, record.timestamp.isoformat(), record.agent_id, record.service,
             record.action, record.decision.value, record.reason, record.ttl_seconds,
             None, "{}"),
        )
        conn.commit()


def test_legacy_migration_with_concurrent_writer_does_not_leave_gap(tmp_path: Path) -> None:
    """Reproduces the TOCTOU race that bit production on 2026-07-18.

    Pre-fix: a writer thread that calls `audit.record()` while
    `ensure_initialized()` is mid-flight could enter `integrity.append()`
    BEFORE the migration commits its segment row, and the row would land
    in `access_logs` without a corresponding `audit_integrity_records`
    row. After the migration commits, verify() permanently returned
    `missing_integrity_record` because legacy_count + protected < total.

    Post-fix: `ensure_initialized` holds the audit-write lock across the
    snapshot capture AND the segment INSERT, serializing any concurrent
    `audit.record()` call. The writer either commits BEFORE the snapshot
    (and is included in legacy_count) or AFTER (and is the first protected
    row). No gap is possible.
    """
    vault, logger = make_vault_and_logger(tmp_path)
    # Write 50 legacy rows
    for i in range(50):
        _legacy_record(logger, reason=f"legacy-{i}")

    # Spawn a writer thread that races against ensure_initialized using
    # the same audit-record path production code uses.
    barrier = threading.Barrier(2)
    stop_event = threading.Event()
    errors: list[Exception] = []
    rows_added: list[str] = []

    def writer():
        try:
            barrier.wait(timeout=5)
            while not stop_event.is_set():
                # Simulate a production-style concurrent audit write.
                # audit.record -> integrity.append -> ensure_initialized
                # (all serialised through audit_write_lock file).
                logger.record(AccessLogRecord(
                    agent_id="racing-agent",
                    service="openai",
                    action="get_env",
                    decision=Decision.allow,
                    reason="racing-write",
                    metadata={"ticket": "fake"},
                ))
                rows_added.append("x")
        except Exception as exc:
            errors.append(exc)

    t = threading.Thread(target=writer, daemon=True)
    t.start()
    try:
        barrier.wait(timeout=5)
        # Trigger initialization under contention
        assert logger.integrity is not None
        logger.integrity.ensure_initialized()
        result = logger.integrity.verify()
    finally:
        stop_event.set()
        t.join(timeout=5)

    assert result.status is AuditIntegrityStatus.healthy, (
        f"Chain should be healthy after migration under contention; "
        f"got status={result.status} reason={result.reason_code}. "
        f"Errors in writer: {errors}"
    )
    # Every legacy row must be accounted for: prefix + protected
    with sqlite3.connect(logger.db_path) as conn:
        total = conn.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0]
        protected = conn.execute("SELECT COUNT(*) FROM audit_integrity_records").fetchone()[0]
    assert result.legacy_count + protected == total, (
        f"Integrity math broken: legacy({result.legacy_count}) + "
        f"protected({protected}) != total({total})"
    )


def test_ensure_initialized_is_idempotent_under_repeat_calls(tmp_path: Path) -> None:
    """Calling ensure_initialized multiple times must not change legacy_count
    or reseal the chain with new rows after the migration window closes."""
    vault, logger = make_vault_and_logger(tmp_path)
    _legacy_record(logger, reason="legacy-1")
    _legacy_record(logger, reason="legacy-2")

    assert logger.integrity is not None
    logger.integrity.ensure_initialized()
    first = logger.integrity.verify()
    assert first.status is AuditIntegrityStatus.healthy
    assert first.legacy_count == 2

    # Subsequent ensure_initialized calls must not extend the prefix
    logger.integrity.ensure_initialized()
    second = logger.integrity.verify()
    assert second.legacy_count == first.legacy_count
    assert second.active_segment_id == first.active_segment_id


def test_add_credential_failure_rolls_back_credential_when_chain_fails(tmp_path: Path) -> None:
    """When the integrity chain refuses to seal an audit append, the
    credential write MUST also roll back. Pre-fix: credential committed,
    audit row missing — vault desync. Post-fix: no credential, clean error.
    """
    from hermes_vault.mutations import VaultMutations
    from hermes_vault.policy import PolicyEngine
    vault, logger = make_vault_and_logger(tmp_path)
    policy = PolicyEngine()
    mutations = VaultMutations(vault=vault, policy=policy, audit=logger)

    # Write some legacy rows so the chain has a prefix
    for i in range(3):
        _legacy_record(logger, reason=f"setup-{i}")
    assert logger.integrity is not None
    logger.integrity.ensure_initialized()

    # Now break the chain: corrupt the checkpoint so verify() returns failed
    # (which simulates the post-TOCTOU state where protected chain is unhealthy)
    checkpoint_path = logger.db_path.with_name("audit.checkpoint.json")
    checkpoint_path.write_bytes(b'{"format": "hermes-vault-audit-checkpoint", "version": "audit-checkpoint-v1", "signature": "bogus"}')

    # Attempt an add — should fail cleanly with NO credential persisted
    result = mutations.add_credential(
        agent_id="operator",
        service="test-service",
        secret="super-secret-value",
        credential_type="api_key",
        alias="rollback-test",
    )

    assert result.allowed is False, "add must be denied when integrity chain is broken"
    assert "integrity" in result.reason.lower() or "audit" in result.reason.lower(), (
        f"reason should mention audit/integrity; got: {result.reason!r}"
    )

    # Confirm the credential was NOT written
    credentials = vault.list_credentials()
    assert all(c.alias != "rollback-test" for c in credentials), (
        "Credential was persisted despite integrity failure — rollback is broken"
    )