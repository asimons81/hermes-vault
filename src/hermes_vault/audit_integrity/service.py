from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from hermes_vault.audit_integrity.canonical import CANONICAL_JSON_VERSION, canonical_bytes, framed
from hermes_vault.audit_integrity.checkpoint import (
    CHECKPOINT_VERSION, AuditLockError, audit_write_lock, checkpoint_signature_valid, read_checkpoint, write_checkpoint,
)
from hermes_vault.audit_integrity.crypto import (
    CHECKPOINT_SIGNATURE_VERSION, CHECKPOINT_SIGNING_CONTEXT, ENTRY_SIGNATURE_VERSION, ENTRY_SIGNING_CONTEXT,
    KEY_DERIVATION_VERSION, digest_hex, public_key_b64, sign, verify,
)
from hermes_vault.audit_integrity.models import AuditCheckpointStatus, AuditIntegrityStatus, AuditVerificationResult
from hermes_vault.audit_integrity.repository import access_log_payload, registry_digest, registry_rows
from hermes_vault.audit_integrity.schema import SCHEMA_VERSION, initialize_schema

CHAIN_VERSION = "sha256-chain-v1"


class AuditIntegrityError(RuntimeError):
    pass


class AuditIntegrityService:
    """Owns the protected audit append protocol and read-only verification."""

    def __init__(self, db_path: Path, master_key: bytes, checkpoint_path: Path | None = None) -> None:
        self.db_path = db_path
        self.master_key = master_key
        self.checkpoint_path = checkpoint_path or db_path.with_name("audit.checkpoint.json")
        self.lock_path = self.checkpoint_path.with_suffix(".lock")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _failure(
        self, reason: str, checkpoint: AuditCheckpointStatus = AuditCheckpointStatus.valid, *, sequence: int | None = None,
        segment_id: str | None = None, verified: int = 0, legacy: int = 0,
    ) -> AuditVerificationResult:
        message = {
            "checkpoint_missing": "The authenticated checkpoint is missing.",
            "checkpoint_stale": "The checkpoint does not cover the database tip.",
            "checkpoint_ahead": "The checkpoint refers to evidence not present in the database.",
            "checkpoint_invalid_signature": "The checkpoint signature is invalid.",
            "checkpoint_invalid_format": "The checkpoint format is invalid.",
            "segment_registry_mismatch": "The checkpoint does not authenticate the current segment registry.",
            "entry_digest_mismatch": "An audit entry no longer matches its protected digest.",
            "entry_signature_mismatch": "An audit entry signature is invalid.",
            "previous_digest_mismatch": "The protected audit chain is discontinuous.",
            "sequence_gap": "The protected audit sequence is incomplete.",
            "missing_access_log": "A protected audit record has no corresponding audit row.",
            "missing_integrity_record": "An audit row is not protected by an integrity record.",
            "active_key_mismatch": "The active audit public key does not match the unlocked vault.",
            "legacy_anchor_mismatch": "The recorded legacy snapshot no longer matches its original rows.",
            "unsupported_chain_version": "This audit chain version is not supported by this Hermes Vault version.",
            "unsupported_serialization_version": "This audit serialization version is not supported by this Hermes Vault version.",
            "unsupported_signature_version": "This audit signature version is not supported by this Hermes Vault version.",
            "database_unreadable": "The audit database could not be verified.",
        }.get(reason, "Audit evidence could not be verified.")
        return AuditVerificationResult(
            status=AuditIntegrityStatus.incomplete if checkpoint in {AuditCheckpointStatus.missing, AuditCheckpointStatus.stale, AuditCheckpointStatus.ahead} else AuditIntegrityStatus.failed,
            reason_code=reason, chain_version=CHAIN_VERSION, serialization_version=CANONICAL_JSON_VERSION,
            active_segment_id=segment_id, active_segment_number=None, verified_count=verified, legacy_count=legacy,
            first_verified_sequence=1 if verified else None, last_verified_sequence=sequence if verified else None,
            checkpoint_status=checkpoint, failure_sequence=sequence, failure_segment_id=segment_id,
            sanitized_reason=message,
            recommended_next_step="Run `hermes-vault audit checkpoint advance` only after reviewing the evidence." if checkpoint == AuditCheckpointStatus.stale else "Do not append audit records; inspect the integrity result and restore from a verified backup if needed.",
            verified_at=datetime.now(timezone.utc),
        )

    def _legacy_snapshot(self, conn: sqlite3.Connection) -> tuple[int, str | None, str | None, str | None, str | None]:
        table = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'access_logs'").fetchone()
        if table is None:
            return 0, None, None, None, None
        rows = conn.execute("SELECT id, timestamp, agent_id, service, action, decision, reason, ttl_seconds, verification_result, metadata_json FROM access_logs ORDER BY timestamp ASC, id ASC").fetchall()
        if not rows:
            return 0, None, None, None, None
        frames = []
        for row in rows:
            frames.append(framed([(b"" if value is None else str(value).encode("utf-8")) for value in row]))
        return len(rows), rows[0]["id"], rows[-1]["id"], digest_hex(b"".join(frames)), rows[-1]["timestamp"]

    def _create_segment(
        self, conn: sqlite3.Connection, *, master_key: bytes, transition_reason: str, sequence_start: int,
        predecessor_segment_id: str | None = None, predecessor_tip_digest: str | None = None,
        legacy: tuple[int, str | None, str | None, str | None, str | None] | None = None,
    ) -> sqlite3.Row:
        number = int(conn.execute("SELECT COALESCE(MAX(segment_number), 0) + 1 FROM audit_integrity_segments").fetchone()[0])
        segment_id = str(uuid4())
        now = self._now()
        legacy_count, first, last, snapshot, _ = legacy or (0, None, None, None, None)
        conn.execute(
            """INSERT INTO audit_integrity_segments (
                segment_id, segment_number, chain_version, serialization_version, key_derivation_version, entry_signature_version,
                checkpoint_signature_version, entry_public_key, checkpoint_public_key, sequence_start, predecessor_segment_id,
                predecessor_tip_digest, transition_reason, legacy_count, legacy_snapshot_digest, legacy_first_id, legacy_last_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (segment_id, number, CHAIN_VERSION, CANONICAL_JSON_VERSION, KEY_DERIVATION_VERSION, ENTRY_SIGNATURE_VERSION,
             CHECKPOINT_SIGNATURE_VERSION, public_key_b64(master_key, ENTRY_SIGNING_CONTEXT), public_key_b64(master_key, CHECKPOINT_SIGNING_CONTEXT),
             sequence_start, predecessor_segment_id, predecessor_tip_digest, transition_reason, legacy_count, snapshot, first, last, now),
        )
        return conn.execute("SELECT * FROM audit_integrity_segments WHERE segment_id = ?", (segment_id,)).fetchone()

    def ensure_initialized(self) -> None:
        with audit_write_lock(self.lock_path):
            with self._connection() as conn:
                initialize_schema(conn)
                state = conn.execute("SELECT * FROM audit_integrity_state WHERE id = 1").fetchone()
                if state is not None:
                    return
                legacy = self._legacy_snapshot(conn)
                reason = "legacy_migration" if legacy[0] else "fresh_vault"
                segment = self._create_segment(conn, master_key=self.master_key, transition_reason=reason, sequence_start=1, legacy=legacy)
                now = self._now()
                conn.execute(
                    "INSERT INTO audit_integrity_state (id, schema_version, migration_state, active_segment_id, legacy_cutoff_timestamp, legacy_cutoff_id, created_at, updated_at) VALUES (1, ?, 'active', ?, ?, ?, ?, ?)",
                    (SCHEMA_VERSION, segment["segment_id"], legacy[4], legacy[2], now, now),
                )
                conn.commit()
                self._write_current_checkpoint(conn, segment, latest_sequence=0, latest_digest="")

    def _active(self, conn: sqlite3.Connection) -> sqlite3.Row:
        state = conn.execute("SELECT * FROM audit_integrity_state WHERE id = 1").fetchone()
        if state is None or state["active_segment_id"] is None:
            raise AuditIntegrityError("Audit integrity state is not initialized.")
        row = conn.execute("SELECT * FROM audit_integrity_segments WHERE segment_id = ?", (state["active_segment_id"],)).fetchone()
        if row is None:
            raise AuditIntegrityError("Audit integrity state references an unavailable segment.")
        return row

    def _tip(self, conn: sqlite3.Connection) -> tuple[int, str]:
        row = conn.execute("SELECT sequence, entry_digest FROM audit_integrity_records ORDER BY sequence DESC LIMIT 1").fetchone()
        return (int(row["sequence"]), str(row["entry_digest"])) if row else (0, "")

    def _write_current_checkpoint(self, conn: sqlite3.Connection, segment: sqlite3.Row, *, latest_sequence: int, latest_digest: str) -> None:
        legacy = registry_rows(conn)[0]
        payload: dict[str, object] = {
            "active_segment_id": segment["segment_id"], "active_segment_number": segment["segment_number"],
            "latest_sequence": latest_sequence, "latest_entry_digest": latest_digest, "segment_registry_digest": registry_digest(conn),
            "legacy_anchor_digest": legacy["legacy_snapshot_digest"] or "", "entry_public_key": segment["entry_public_key"],
            "checkpoint_public_key": segment["checkpoint_public_key"], "updated_at": self._now(),
        }
        write_checkpoint(self.checkpoint_path, payload, self.master_key)

    def append(self, record: object) -> None:
        self.ensure_initialized()
        current = self.verify()
        if current.status != AuditIntegrityStatus.healthy:
            raise AuditIntegrityError(current.sanitized_reason)
        try:
            with audit_write_lock(self.lock_path):
                with self._connection() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    active = self._active(conn)
                    sequence, previous_digest = self._tip(conn)
                    next_sequence = sequence + 1
                    metadata_json = canonical_bytes(getattr(record, "metadata")).decode("utf-8") if getattr(record, "metadata") else "{}"
                    values = (
                        getattr(record, "id"), getattr(record, "timestamp").isoformat(), getattr(record, "agent_id"),
                        getattr(record, "service"), getattr(record, "action"), getattr(record, "decision").value,
                        getattr(record, "reason"), getattr(record, "ttl_seconds"),
                        getattr(record, "verification_result").value if getattr(record, "verification_result") else None, metadata_json,
                    )
                    conn.execute("INSERT INTO access_logs (id, timestamp, agent_id, service, action, decision, reason, ttl_seconds, verification_result, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", values)
                    row = conn.execute("SELECT * FROM access_logs WHERE id = ?", (getattr(record, "id"),)).fetchone()
                    entry_digest = digest_hex(canonical_bytes(access_log_payload(row)))
                    envelope = {"chain_version": CHAIN_VERSION, "serialization_version": CANONICAL_JSON_VERSION, "segment_id": active["segment_id"], "sequence": next_sequence, "previous_digest": previous_digest, "entry_digest": entry_digest}
                    signature = sign(self.master_key, ENTRY_SIGNING_CONTEXT, canonical_bytes(envelope))
                    conn.execute("INSERT INTO audit_integrity_records (sequence, segment_id, access_log_id, previous_digest, entry_digest, signature, chain_version, serialization_version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (next_sequence, active["segment_id"], getattr(record, "id"), previous_digest, entry_digest, signature, CHAIN_VERSION, CANONICAL_JSON_VERSION, self._now()))
                    conn.execute("UPDATE audit_integrity_state SET updated_at = ? WHERE id = 1", (self._now(),))
                    conn.commit()
                    self._write_current_checkpoint(conn, active, latest_sequence=next_sequence, latest_digest=entry_digest)
        except AuditLockError as exc:
            raise AuditIntegrityError(str(exc)) from exc

    def _verify_checkpoint(self, conn: sqlite3.Connection, active: sqlite3.Row, sequence: int, tip: str) -> tuple[AuditCheckpointStatus, str | None]:
        checkpoint = read_checkpoint(self.checkpoint_path)
        if checkpoint is None:
            return AuditCheckpointStatus.missing, "checkpoint_missing"
        if checkpoint.get("format") != "hermes-vault-audit-checkpoint" or checkpoint.get("version") != CHECKPOINT_VERSION:
            return AuditCheckpointStatus.invalid_format, "checkpoint_invalid_format"
        if not checkpoint_signature_valid(checkpoint, str(active["checkpoint_public_key"])):
            return AuditCheckpointStatus.invalid_signature, "checkpoint_invalid_signature"
        if checkpoint.get("active_segment_id") != active["segment_id"]:
            return AuditCheckpointStatus.segment_mismatch, "checkpoint_segment_mismatch"
        if checkpoint.get("segment_registry_digest") != registry_digest(conn):
            return AuditCheckpointStatus.registry_mismatch, "segment_registry_mismatch"
        checkpoint_sequence = checkpoint.get("latest_sequence")
        if not isinstance(checkpoint_sequence, int):
            return AuditCheckpointStatus.invalid_format, "checkpoint_invalid_format"
        if checkpoint_sequence < sequence or checkpoint.get("latest_entry_digest") != tip:
            return AuditCheckpointStatus.stale, "checkpoint_stale"
        if checkpoint_sequence > sequence:
            return AuditCheckpointStatus.ahead, "checkpoint_ahead"
        return AuditCheckpointStatus.valid, None

    def verify(self, *, require_checkpoint: bool = True) -> AuditVerificationResult:
        try:
            with self._connection() as conn:
                existing = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'audit_integrity_state'").fetchone()
                legacy_count = int(conn.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0]) if conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'access_logs'").fetchone() else 0
                if existing is None:
                    return AuditVerificationResult(AuditIntegrityStatus.legacy, "legacy_only", None, None, None, None, 0, legacy_count, None, None, AuditCheckpointStatus.missing, None, None, "Legacy history remains readable but was not retrospectively protected.", "Create a verified backup before initializing Audit Assurance.", datetime.now(timezone.utc))
                state = conn.execute("SELECT * FROM audit_integrity_state WHERE id = 1").fetchone()
                if state is None or state["migration_state"] != "active":
                    return self._failure("migration_interrupted", AuditCheckpointStatus.missing, legacy=legacy_count)
                active = self._active(conn)
                if active["chain_version"] != CHAIN_VERSION:
                    return self._failure("unsupported_chain_version", segment_id=active["segment_id"], legacy=legacy_count)
                if active["serialization_version"] != CANONICAL_JSON_VERSION:
                    return self._failure("unsupported_serialization_version", segment_id=active["segment_id"], legacy=legacy_count)
                if active["entry_signature_version"] != ENTRY_SIGNATURE_VERSION:
                    return self._failure("unsupported_signature_version", segment_id=active["segment_id"], legacy=legacy_count)
                if active["entry_public_key"] != public_key_b64(self.master_key, ENTRY_SIGNING_CONTEXT) or active["checkpoint_public_key"] != public_key_b64(self.master_key, CHECKPOINT_SIGNING_CONTEXT):
                    return self._failure("active_key_mismatch", segment_id=active["segment_id"], legacy=legacy_count)
                first = registry_rows(conn)[0]
                if first["legacy_count"]:
                    cutoff_count = int(first["legacy_count"])
                    # A migration snapshot covers the original prefix, not later protected entries.
                    rows = conn.execute("SELECT id, timestamp, agent_id, service, action, decision, reason, ttl_seconds, verification_result, metadata_json FROM access_logs ORDER BY timestamp ASC, id ASC LIMIT ?", (cutoff_count,)).fetchall()
                    frames = [framed([(b"" if value is None else str(value).encode("utf-8")) for value in row]) for row in rows]
                    if len(rows) != cutoff_count or digest_hex(b"".join(frames)) != first["legacy_snapshot_digest"]:
                        return self._failure("legacy_anchor_mismatch", segment_id=active["segment_id"], legacy=cutoff_count)
                rows = conn.execute("SELECT r.*, a.id AS aid, a.timestamp, a.agent_id, a.service, a.action, a.decision, a.reason, a.ttl_seconds, a.verification_result, a.metadata_json FROM audit_integrity_records r LEFT JOIN access_logs a ON a.id = r.access_log_id ORDER BY r.sequence").fetchall()
                previous = ""
                expected_sequence = 1
                for row in rows:
                    if row["aid"] is None:
                        return self._failure("missing_access_log", sequence=row["sequence"], segment_id=row["segment_id"], verified=len(rows), legacy=legacy_count)
                    if int(row["sequence"]) != expected_sequence:
                        return self._failure("sequence_gap", sequence=row["sequence"], segment_id=row["segment_id"], verified=expected_sequence - 1, legacy=legacy_count)
                    if row["previous_digest"] != previous:
                        return self._failure("previous_digest_mismatch", sequence=row["sequence"], segment_id=row["segment_id"], verified=expected_sequence - 1, legacy=legacy_count)
                    payload = {key: row[key] for key in ("aid", "timestamp", "agent_id", "service", "action", "decision", "reason", "ttl_seconds", "verification_result", "metadata_json")}
                    payload["id"] = payload.pop("aid")
                    if digest_hex(canonical_bytes(payload)) != row["entry_digest"]:
                        return self._failure("entry_digest_mismatch", sequence=row["sequence"], segment_id=row["segment_id"], verified=expected_sequence - 1, legacy=legacy_count)
                    segment = conn.execute("SELECT * FROM audit_integrity_segments WHERE segment_id = ?", (row["segment_id"],)).fetchone()
                    if segment is None:
                        return self._failure("segment_registry_mismatch", sequence=row["sequence"], segment_id=row["segment_id"], verified=expected_sequence - 1, legacy=legacy_count)
                    envelope = {"chain_version": row["chain_version"], "serialization_version": row["serialization_version"], "segment_id": row["segment_id"], "sequence": row["sequence"], "previous_digest": row["previous_digest"], "entry_digest": row["entry_digest"]}
                    if not verify(segment["entry_public_key"], row["signature"], canonical_bytes(envelope)):
                        return self._failure("entry_signature_mismatch", sequence=row["sequence"], segment_id=row["segment_id"], verified=expected_sequence - 1, legacy=legacy_count)
                    previous = str(row["entry_digest"])
                    expected_sequence += 1
                # No unprotected rows may appear after the preserved migration prefix.
                protected = int(conn.execute("SELECT COUNT(*) FROM audit_integrity_records").fetchone()[0])
                if legacy_count != int(first["legacy_count"]) + protected:
                    return self._failure("missing_integrity_record", segment_id=active["segment_id"], verified=protected, legacy=int(first["legacy_count"]))
                sequence, tip = self._tip(conn)
                checkpoint_status, reason = self._verify_checkpoint(conn, active, sequence, tip) if require_checkpoint else (AuditCheckpointStatus.valid, None)
                if reason:
                    return self._failure(reason, checkpoint_status, sequence=sequence, segment_id=active["segment_id"], verified=protected, legacy=int(first["legacy_count"]))
                result = AuditVerificationResult(AuditIntegrityStatus.healthy, "none", CHAIN_VERSION, CANONICAL_JSON_VERSION, active["segment_id"], int(active["segment_number"]), protected, int(first["legacy_count"]), 1 if protected else None, sequence if protected else None, checkpoint_status, None, None, "Protected audit history verified from the migration anchor forward.", "Continue normal operation; retain verified backups.", datetime.now(timezone.utc))
                self._record_run(conn, result)
                conn.commit()
                return result
        except sqlite3.Error:
            return self._failure("database_unreadable")

    def _record_run(self, conn: sqlite3.Connection, result: AuditVerificationResult) -> None:
        conn.execute("INSERT INTO audit_verification_runs (verification_id, verified_at, status, reason_code, segment_id, chain_version, verified_count, legacy_count, first_sequence, last_sequence, checkpoint_status, failure_sequence, registry_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid4()), result.verified_at.isoformat(), result.status.value, result.reason_code, result.active_segment_id, result.chain_version, result.verified_count, result.legacy_count, result.first_verified_sequence, result.last_verified_sequence, result.checkpoint_status.value, result.failure_sequence, registry_digest(conn)))

    def advance_checkpoint(self) -> AuditVerificationResult:
        self.ensure_initialized()
        result = self.verify(require_checkpoint=False)
        if result.status != AuditIntegrityStatus.healthy:
            return result
        with audit_write_lock(self.lock_path):
            with self._connection() as conn:
                active = self._active(conn)
                sequence, tip = self._tip(conn)
                self._write_current_checkpoint(conn, active, latest_sequence=sequence, latest_digest=tip)
        return self.verify()

    def establish_checkpoint(self) -> AuditVerificationResult:
        return self.advance_checkpoint()

    def rotate_segment(self, new_master_key: bytes) -> None:
        self.ensure_initialized()
        result = self.verify()
        if result.status != AuditIntegrityStatus.healthy:
            raise AuditIntegrityError(result.sanitized_reason)
        with audit_write_lock(self.lock_path):
            with self._connection() as conn:
                conn.execute("BEGIN IMMEDIATE")
                old = self._active(conn)
                sequence, tip = self._tip(conn)
                now = self._now()
                conn.execute("UPDATE audit_integrity_segments SET sequence_end = ?, closed_at = ? WHERE segment_id = ?", (sequence, now, old["segment_id"]))
                new = self._create_segment(conn, master_key=new_master_key, transition_reason="master_key_rotation", sequence_start=sequence + 1, predecessor_segment_id=old["segment_id"], predecessor_tip_digest=tip)
                conn.execute("UPDATE audit_integrity_state SET active_segment_id = ?, updated_at = ? WHERE id = 1", (new["segment_id"], now))
                conn.commit()
                old_key = self.master_key
                self.master_key = new_master_key
                try:
                    self._write_current_checkpoint(conn, new, latest_sequence=sequence, latest_digest=tip)
                except Exception:
                    self.master_key = old_key
                    raise

    def recover_checkpoint(self) -> AuditVerificationResult:
        """Start a new explicit segment; never rewrites a failed segment or prior evidence."""
        self.ensure_initialized()
        result = self.verify()
        if result.status == AuditIntegrityStatus.healthy:
            return result
        if result.status == AuditIntegrityStatus.failed:
            return result
        with audit_write_lock(self.lock_path):
            with self._connection() as conn:
                conn.execute("BEGIN IMMEDIATE")
                old = self._active(conn)
                sequence, tip = self._tip(conn)
                now = self._now()
                conn.execute("UPDATE audit_integrity_segments SET sequence_end = ?, closed_at = ? WHERE segment_id = ?", (sequence, now, old["segment_id"]))
                new = self._create_segment(conn, master_key=self.master_key, transition_reason="checkpoint_recovery", sequence_start=sequence + 1, predecessor_segment_id=old["segment_id"], predecessor_tip_digest=tip)
                conn.execute("UPDATE audit_integrity_state SET active_segment_id = ?, updated_at = ? WHERE id = 1", (new["segment_id"], now))
                conn.commit()
                self._write_current_checkpoint(conn, new, latest_sequence=sequence, latest_digest=tip)
        return self.verify()
    def export_evidence(self) -> dict[str, object]:
        """Return backup-safe integrity evidence: public keys, signed rows, and checkpoint only."""
        with self._connection() as conn:
            available = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'audit_integrity_state'").fetchone()
            if available is None:
                return {"version": "audit-backup-evidence-v1", "integrity_available": False}
            def rows(table: str) -> list[dict[str, object]]:
                return [dict(row) for row in conn.execute(f"SELECT * FROM {table}").fetchall()]
            return {
                "version": "audit-backup-evidence-v1",
                "integrity_available": True,
                "state": rows("audit_integrity_state"),
                "segments": rows("audit_integrity_segments"),
                "records": rows("audit_integrity_records"),
                "access_logs": rows("access_logs"),
                "checkpoint": read_checkpoint(self.checkpoint_path),
            }