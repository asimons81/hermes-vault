"""P1 safe-recovery: non-destructive audit-chain repair.

Ships the ops skill's documented purge-and-re-establish recipe as product
behavior — with two safety reversals the manual recipe lacked:

1. Old integrity tables are QUARANTINED (``quarantine_<table>_<ts>`` copies
   plus an ``audit_quarantine_manifest`` row), never dropped: the evidence
   survives for forensics (F-06).
2. Repair is refused — loudly — for tamper-evidence failures and for the
   ``active_key_mismatch`` salt-migration signature. Rebuilding integrity
   tables over mismatched key material covers up trap #2 (the
   backup-rebuild brick); rebuilding over tamper evidence destroys the
   record of alteration.

All functions here are importable, CLI-independent primitives (P7 ``doctor``
wraps them as-is).
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path

from hermes_vault.audit_integrity.models import (
    AuditCheckpointStatus,
    AuditIntegrityStatus,
    AuditVerificationResult,
)
from hermes_vault.audit_integrity.service import AuditIntegrityService
from hermes_vault.crypto import credential_aad_metadata, decrypt_secret_versioned
from hermes_vault.vault import Vault, _salt_mismatch_message, _salt_fingerprint_or_none


# The 6 tables the documented incident recipe purges. Order matters:
# audit_integrity_records references access_logs(id), so records must be
# deleted before access_logs; within the integrity tables, records reference
# segments/state only logically (no FK), but we keep the ops recipe's order.
QUARANTINE_TABLES: tuple[str, ...] = (
    "access_logs",
    "access_requests",
    "audit_integrity_records",
    "audit_integrity_segments",
    "audit_integrity_state",
    "audit_verification_runs",
)

# FK-correct delete order (children before parents).
DELETE_ORDER: tuple[str, ...] = (
    "audit_integrity_records",
    "audit_integrity_segments",
    "audit_integrity_state",
    "audit_verification_runs",
    "access_requests",
    "access_logs",
)

REPAIRABLE_REASONS = frozenset({
    "missing_integrity_record",
    "migration_interrupted",
    "checkpoint_missing",
    "checkpoint_stale",
    "checkpoint_ahead",
    "checkpoint_invalid_format",
    "checkpoint_segment_mismatch",
    "checkpoint_registry_mismatch",
})

REFUSE_TAMPER_REASONS = frozenset({
    "entry_digest_mismatch",
    "entry_signature_mismatch",
    "previous_digest_mismatch",
    "sequence_gap",
    "missing_access_log",
    "legacy_anchor_mismatch",
    "segment_registry_mismatch",
    "checkpoint_invalid_signature",
})

REFUSE_KEY_MATERIAL_REASONS = frozenset({"active_key_mismatch"})

REFUSE_UNSUPPORTED_REASONS = frozenset({
    "unsupported_chain_version",
    "unsupported_serialization_version",
    "unsupported_signature_version",
    "database_unreadable",
})

MANIFEST_TABLE = "audit_quarantine_manifest"


class RepairClass(StrEnum):
    healthy_noop = "healthy_noop"
    repairable = "repairable"
    refuse_tamper = "refuse_tamper"
    refuse_key_material = "refuse_key_material"
    refuse_unsupported = "refuse_unsupported"


class RepairRefusedError(RuntimeError):
    """Repair refused by an interlock (tamper / key material / unsupported)."""

    def __init__(self, message: str, *, repair_class: RepairClass, reason_code: str) -> None:
        super().__init__(message)
        self.repair_class = repair_class
        self.reason_code = reason_code


@dataclass(frozen=True)
class StoreDecryptability:
    """P1 self-check: does every live credential decrypt under the current key?"""

    credential_count: int
    decryptable_count: int
    ok: bool

    def summary_line(self, *, salt_fingerprint: str | None) -> str:
        if self.ok:
            return (
                f"Store decryptability: {self.decryptable_count}/{self.credential_count} "
                "credentials decrypt under the current master key"
            )
        fp = f", salt fingerprint {salt_fingerprint}" if salt_fingerprint else ""
        return (
            f"Store decryptability: {self.decryptable_count}/{self.credential_count} "
            f"— KEY-MATERIAL MISMATCH{fp}"
        )


@dataclass
class RepairReport:
    """Outcome of an executed repair (``--yes``)."""

    executed: bool = False
    quarantine_id: str | None = None
    quarantined_tables: dict[str, int] = field(default_factory=dict)
    safety_copy_path: str | None = None
    prior_verify_reason: str | None = None
    reason: str = ""
    verify_result: dict[str, object] | None = None
    deferred_events: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "executed": self.executed,
            "quarantine_id": self.quarantine_id,
            "quarantined_tables": dict(self.quarantined_tables),
            "safety_copy_path": self.safety_copy_path,
            "prior_verify_reason": self.prior_verify_reason,
            "reason": self.reason,
            "verify_result": self.verify_result,
            "deferred_events": list(self.deferred_events),
        }


def _now_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _checkpoint_reason(result: AuditVerificationResult) -> str | None:
    """The checkpoint-derived reason code when the chain walk itself passed."""
    mapping = {
        AuditCheckpointStatus.missing: "checkpoint_missing",
        AuditCheckpointStatus.stale: "checkpoint_stale",
        AuditCheckpointStatus.ahead: "checkpoint_ahead",
        AuditCheckpointStatus.invalid_signature: "checkpoint_invalid_signature",
        AuditCheckpointStatus.invalid_format: "checkpoint_invalid_format",
        AuditCheckpointStatus.segment_mismatch: "checkpoint_segment_mismatch",
        AuditCheckpointStatus.registry_mismatch: "checkpoint_registry_mismatch",
    }
    return mapping.get(result.checkpoint_status)


def classify_repairability(result: AuditVerificationResult) -> RepairClass:
    """Map a verify() result to the repair verdict (design §3.4)."""
    if result.status == AuditIntegrityStatus.healthy:
        return RepairClass.healthy_noop
    reason = result.reason_code
    if reason in REFUSE_KEY_MATERIAL_REASONS:
        return RepairClass.refuse_key_material
    if reason in REFUSE_TAMPER_REASONS:
        return RepairClass.refuse_tamper
    if reason in REPAIRABLE_REASONS:
        return RepairClass.repairable
    # A chain-healthy result with a checkpoint-derived reason code (e.g.
    # status incomplete "none" + checkpoint_stale) is re-anchorable via
    # establish, which is what repair's re-establish step performs.
    cp_reason = _checkpoint_reason(result)
    if cp_reason and cp_reason in REPAIRABLE_REASONS:
        return RepairClass.repairable
    if cp_reason and cp_reason in REFUSE_TAMPER_REASONS:
        return RepairClass.refuse_tamper
    return RepairClass.refuse_unsupported


def store_decryptability(vault: Vault) -> StoreDecryptability:
    """Prove every live ``credentials`` row decrypts under the current key."""
    count = 0
    decryptable = 0
    import json as _json

    conn = sqlite3.connect(vault.db_path)
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, service, alias, credential_type, scopes, encrypted_payload, crypto_version FROM credentials"
        ).fetchall()
    finally:
        conn.close()
    for row in rows:
        count += 1
        try:
            scopes = row["scopes"]
            if isinstance(scopes, str):
                scopes = _json.loads(scopes) if scopes else []
            decrypt_secret_versioned(
                row["encrypted_payload"],
                vault.key,
                row["crypto_version"],
                credential_aad_metadata(
                    row["id"], row["service"], row["alias"], row["credential_type"], scopes or []
                ),
            )
        except Exception:
            continue
        decryptable += 1
    return StoreDecryptability(
        credential_count=count,
        decryptable_count=decryptable,
        ok=(count == decryptable),
    )


def quarantine_row_counts(conn: sqlite3.Connection) -> dict[str, int]:
    """Row counts per quarantine-table that WOULD be captured (pre-delete)."""
    counts: dict[str, int] = {}
    for table in QUARANTINE_TABLES:
        exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()
        counts[table] = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) if exists else 0
    return counts


def _copy_file(src: Path, dst: Path) -> None:
    data = src.read_bytes()
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def run_repair(
    service: AuditIntegrityService,
    vault: Vault,
    *,
    reason: str,
    safety_copy: bool = True,
    command: str = "cli",
    deferred_events: list[str] | None = None,
) -> RepairReport:
    """Execute the quarantine + re-establish repair (design §3.3 interlocks).

    Interlocks (in order): verify-classification refusal, decryptability
    gate, safety copy, single-transaction quarantine+purge, ensure_initialized
    + establish, post-verify, protected ``audit_repair`` event on the new
    chain. Any failure before the transaction leaves the vault
    byte-identical; a transaction failure rolls back.
    """
    report = RepairReport(reason=reason)

    result = service.verify()
    report.prior_verify_reason = result.reason_code

    if result.status == AuditIntegrityStatus.healthy:
        report.executed = False
        return report

    repair_class = classify_repairability(result)
    if repair_class is RepairClass.refuse_tamper:
        raise RepairRefusedError(
            "Repair refused: the audit chain shows evidence of tampering "
            f"({result.reason_code}). Repairing would destroy the record of "
            "alteration. Inspect 'hermes-vault audit-export --with-integrity', "
            "preserve the evidence, and restore from a verified backup instead.",
            repair_class=repair_class,
            reason_code=result.reason_code,
        )
    if repair_class is RepairClass.refuse_key_material:
        raise RepairRefusedError(
            "Repair refused: active_key_mismatch is the salt-migration signature — "
            "the audit tables are signed under different key material than this "
            "vault's current master key. Repairing the audit tables would hide the "
            "real failure. Fix the key material instead:\n\n"
            + _salt_mismatch_message(
                decryptable_count=0,
                credential_count=store_decryptability(vault).credential_count,
                salt_fingerprint=_salt_fingerprint_or_none(vault.salt_path),
                subject="store",
            ),
            repair_class=repair_class,
            reason_code=result.reason_code,
        )
    if repair_class is RepairClass.refuse_unsupported:
        raise RepairRefusedError(
            "Repair refused: unsupported or unreadable audit chain state "
            f"({result.reason_code}). This is an upgrade-path or database-level "
            "diagnosis, not a repair target.",
            repair_class=repair_class,
            reason_code=result.reason_code,
        )

    # Interlock 4: decryptability self-check must pass — repairing audit
    # tables over a key-mismatched store hides the real brick.
    decrypt = store_decryptability(vault)
    if not decrypt.ok:
        message = _salt_mismatch_message(
            decryptable_count=decrypt.decryptable_count,
            credential_count=decrypt.credential_count,
            salt_fingerprint=_salt_fingerprint_or_none(vault.salt_path),
            subject="store",
        )
        raise RepairRefusedError(
            "Repair blocked: the store itself does not decrypt under the current "
            "master key; repairing the audit tables would hide the real failure.\n" + message,
            repair_class=RepairClass.refuse_key_material,
            reason_code="store_decryptability_failed",
        )

    db_path = Path(vault.db_path)
    quarantine_id = _now_compact()

    # Interlock 5: safety copy (before the transaction).
    safety_copy_path: Path | None = None
    if safety_copy:
        safety_copy_path = db_path.with_name(f"{db_path.name}.pre-repair-{quarantine_id}")
        _copy_file(db_path, safety_copy_path)
    report.safety_copy_path = str(safety_copy_path) if safety_copy_path else None

    # Interlock 6: single transaction — manifest + quarantine copies +
    # ordered deletes. ANY failure rolls back and leaves the db intact.
    conn = sqlite3.connect(db_path, timeout=30)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN IMMEDIATE")
        try:
            counts = quarantine_row_counts(conn)
            conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {MANIFEST_TABLE} (
                    quarantine_id TEXT NOT NULL,
                    quarantined_at TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    source_command TEXT NOT NULL,
                    table_name TEXT NOT NULL,
                    row_count INTEGER NOT NULL,
                    safety_copy_path TEXT,
                    prior_verify_reason TEXT,
                    PRIMARY KEY (quarantine_id, table_name)
                )
                """
            )
            now_iso = datetime.now(timezone.utc).isoformat()
            for table in QUARANTINE_TABLES:
                exists = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
                ).fetchone()
                if exists:
                    # Identifier-quoted: the <ts> suffix contains '-' which is
                    # not a bare-SQL identifier character.
                    conn.execute(
                        f'CREATE TABLE "quarantine_{table}_{quarantine_id}" AS SELECT * FROM {table}'
                    )
                conn.execute(
                    f"INSERT INTO {MANIFEST_TABLE} (quarantine_id, quarantined_at, reason, source_command, table_name, row_count, safety_copy_path, prior_verify_reason) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        quarantine_id,
                        now_iso,
                        reason,
                        command,
                        table,
                        counts[table],
                        report.safety_copy_path,
                        report.prior_verify_reason,
                    ),
                )
            for table in DELETE_ORDER:
                exists = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
                ).fetchone()
                if exists:
                    conn.execute(f"DELETE FROM {table}")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    finally:
        conn.close()
    report.quarantine_id = quarantine_id
    report.quarantined_tables = counts

    # Sidecar: rename the stale checkpoint so `establish` publishes fresh.
    checkpoint_path = Path(service.checkpoint_path)
    if checkpoint_path.exists():
        os.replace(
            checkpoint_path,
            checkpoint_path.with_name(f"{checkpoint_path.name}.quarantine-{quarantine_id}"),
        )

    # Interlock 7: re-initialize + establish over the purged state.
    service.ensure_initialized()
    establish_result = service.establish_checkpoint()

    # Interlock 8: post-verify must be healthy.
    post = service.verify()
    if post.status != AuditIntegrityStatus.healthy:
        report.verify_result = post.to_dict()
        raise RuntimeError(
            "Repair transaction committed but post-repair verification is not healthy "
            f"({post.reason_code}). The pre-repair safety copy is at {report.safety_copy_path}; "
            f"quarantine id {quarantine_id}."
        )

    report.executed = True
    report.verify_result = establish_result.to_dict()

    # Interlock 9: protected audit_repair event on the NEW chain, folding in
    # any deferred recovery facts recorded while the old chain was broken.
    from hermes_vault.audit import AuditLogger
    from hermes_vault.models import AccessLogRecord, Decision

    deferred = list(deferred_events or [])
    metadata: dict[str, object] = {
        "quarantine_id": quarantine_id,
        "quarantined_tables": counts,
        "safety_copy_path": report.safety_copy_path,
        "prior_verify_reason": report.prior_verify_reason,
        "reason": reason,
        "command": command,
    }
    if deferred:
        metadata["deferred_recovery_events"] = deferred
    audit = AuditLogger(Path(service.db_path), master_key=service.master_key)
    audit.record(
        AccessLogRecord(
            agent_id="operator",
            service="*",
            action="audit_repair",
            decision=Decision.allow,
            reason=f"audit chain repaired (quarantine {quarantine_id}): {reason}",
            metadata=metadata,
        )
    )
    report.deferred_events = deferred
    return report
