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
import time
from pathlib import Path

from hermes_vault.audit import AuditLogger
from hermes_vault.audit_integrity.checkpoint import AuditLockError, audit_write_lock
from hermes_vault.audit_integrity.models import AuditIntegrityStatus, AuditVerificationResult
from hermes_vault.audit_integrity.service import AuditIntegrityError, AuditIntegrityService
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
            (
                record.id,
                record.timestamp.isoformat(),
                record.agent_id,
                record.service,
                record.action,
                record.decision.value,
                record.reason,
                record.ttl_seconds,
                None,
                "{}",
            ),
        )
        conn.commit()


# The audit-write lock is an O_EXCL file lock with a 5-second acquire timeout
# (checkpoint.audit_write_lock). Under Windows CI (slow secure_file / durable
# replace, antivirus scanning), a racing thread can legitimately time out while
# the migration holds the lock — that is lock coordination doing its job, not a
# TOCTOU gap. Production callers retry (vault.py catches AuditLockError); the
# test mirrors that with a bounded retry so a slow lock holder doesn't turn a
# healthy race into a flaky failure.
_LOCK_CONTENTION_MESSAGE = "Audit write coordination is unavailable"


def _is_lock_contention(exc: Exception) -> bool:
    """Return True when *exc* is transient audit-write lock contention."""
    if isinstance(exc, AuditLockError):
        return True
    # append() wraps the second lock acquisition's AuditLockError in
    # AuditIntegrityError with the same message.
    if isinstance(exc, AuditIntegrityError) and _LOCK_CONTENTION_MESSAGE in str(exc):
        return True
    # The writer's record() runs access_logs DDL (AuditLogger.initialize)
    # outside the audit lock. While the migration holds BEGIN IMMEDIATE, that
    # DDL can hit sqlite's busy timeout on a slow box — same transient
    # contention class, retry it too.
    return isinstance(exc, sqlite3.OperationalError) and "locked" in str(exc).lower()


def _ensure_initialized_with_retry(service: AuditIntegrityService, *, attempts: int = 5, delay: float = 0.25) -> None:
    """Run ensure_initialized(), tolerating transient audit-write lock contention.

    The racing writer may hold the O_EXCL lock past the 5s acquire timeout on a
    slow CI box; that is the lock serializing writers, so we retry instead of
    failing. The TOCTOU guarantee is unaffected: the migration itself still runs
    under the lock, and once it returns the prefix is sealed.
    """
    last_error: Exception | None = None
    for _ in range(attempts):
        try:
            service.ensure_initialized()
            return
        except Exception as exc:  # retry only known transient contention
            if not _is_lock_contention(exc):
                raise
            last_error = exc
            time.sleep(delay)
    assert last_error is not None
    raise last_error


def _verify_with_lock_retry(
    service: AuditIntegrityService, *, attempts: int = 5, delay: float = 0.25
) -> AuditVerificationResult:
    """Verify from a single-writer vantage point (same pattern as restore_backup).

    Holding the audit-write lock across verify makes the multi-query chain walk
    quiescent with respect to the racing writer, so a concurrent append cannot
    land between verify's COUNT(access_logs) and COUNT(audit_integrity_records)
    reads and produce a false missing_integrity_record (the #82 race class).
    Retries tolerate the same Windows lock-acquire flake as
    _ensure_initialized_with_retry.
    """
    last_error: Exception | None = None
    for _ in range(attempts):
        try:
            with audit_write_lock(service.lock_path):
                return service.verify()
        except Exception as exc:  # retry only known transient contention
            if not _is_lock_contention(exc):
                raise
            last_error = exc
            time.sleep(delay)
    assert last_error is not None
    raise last_error


def _record_with_lock_retry(
    logger: AuditLogger, rows_added: list[str], *, attempts: int = 5, delay: float = 0.05
) -> None:
    """Record one audit row, retrying transient audit-write lock contention.

    While the main thread migrates (or verifies) under the lock, a writer that
    happens to call record() may see AuditLockError / AuditIntegrityError after
    the 5s acquire timeout. That is expected serialization, not corruption:
    retry a bounded number of times (mirroring production's retry behavior)
    instead of dying mid-race.
    """
    last_error: Exception | None = None
    for _ in range(attempts):
        try:
            logger.record(
                AccessLogRecord(
                    agent_id="racing-agent",
                    service="openai",
                    action="get_env",
                    decision=Decision.allow,
                    reason="racing-write",
                    metadata={"ticket": "fake"},
                )
            )
            rows_added.append("x")
            return
        except Exception as exc:  # noqa: BLE001 - retry only known transient contention
            if not _is_lock_contention(exc):
                raise
            last_error = exc
            time.sleep(delay)
    assert last_error is not None
    raise last_error


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

    Windows note: the audit-write lock is an O_EXCL file lock with a 5s
    acquire timeout. A racing writer that hits the lock while the migration
    holds it will see AuditLockError after 5s on a slow CI box — that is
    serialization working, not a TOCTOU gap. The test retries bounded times
    (mirroring production's retry behavior) so a slow lock holder doesn't
    surface as a flake. Verify runs under the lock so a concurrent append
    cannot land between verify's COUNT reads and produce a false
    missing_integrity_record (the #82 race class).
    """
    vault, logger = make_vault_and_logger(tmp_path)
    # Write 50 legacy rows
    for i in range(50):
        _legacy_record(logger, reason=f"legacy-{i}")

    # A start latch (not a Barrier): Event.wait can never break, so a worker
    # delayed past the timeout just starts late instead of raising
    # BrokenBarrierError in both workers (PR #82 pattern; the 2026-08-10
    # Windows Py3.12 CI flake class).
    start_latch = threading.Event()
    writer_started = threading.Event()
    first_write_done = threading.Event()
    stop_event = threading.Event()
    errors: list[Exception] = []
    rows_added: list[str] = []

    def writer() -> None:
        try:
            start_latch.wait(timeout=30)
            writer_started.set()
            while not stop_event.is_set():
                # Simulate a production-style concurrent audit write.
                # audit.record -> integrity.append -> ensure_initialized
                # (all serialised through audit_write_lock file).
                _record_with_lock_retry(logger, rows_added)
                first_write_done.set()
        except Exception as exc:
            errors.append(exc)

    t = threading.Thread(target=writer, daemon=True)
    t.start()
    start_latch.set()
    try:
        # Guarantee the writer is live and contending before we migrate, so the
        # race is actually exercised (and rows_added can't be 0 by scheduling).
        assert writer_started.wait(timeout=30), "writer thread never started"
        # Trigger initialization under contention
        assert logger.integrity is not None
        _ensure_initialized_with_retry(logger.integrity)
        # Wait for at least one racing write to land before verifying, so the
        # post-condition covers a genuinely concurrent append.
        assert first_write_done.wait(timeout=30), "writer never completed a racing write"
        result = _verify_with_lock_retry(logger.integrity)
    finally:
        stop_event.set()
        t.join(timeout=60)

    # Surface the real exception instead of a bare assertion if a worker
    # fails (the PR #82 assert-errors-empty pattern).
    assert errors == [], f"writer exception(s): {errors}"
    assert rows_added, "writer thread never completed a racing write; race not exercised"
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
        f"Integrity math broken: legacy({result.legacy_count}) + protected({protected}) != total({total})"
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
    checkpoint_path.write_bytes(
        b'{"format": "hermes-vault-audit-checkpoint", "version": "audit-checkpoint-v1", "signature": "bogus"}'
    )

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
