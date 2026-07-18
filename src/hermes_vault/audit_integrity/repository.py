from __future__ import annotations

import sqlite3
from typing import Any

from hermes_vault.audit_integrity.canonical import canonical_bytes
from hermes_vault.audit_integrity.crypto import digest_hex


def registry_rows(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    return conn.execute("SELECT * FROM audit_integrity_segments ORDER BY segment_number").fetchall()


def registry_digest(conn: sqlite3.Connection) -> str:
    rows = registry_rows(conn)
    public = []
    for row in rows:
        public.append({key: row[key] for key in (
            "segment_id", "segment_number", "chain_version", "serialization_version", "key_derivation_version",
            "entry_signature_version", "checkpoint_signature_version", "entry_public_key", "checkpoint_public_key",
            "sequence_start", "sequence_end", "predecessor_segment_id", "predecessor_tip_digest", "transition_reason",
            "legacy_count", "legacy_snapshot_digest", "legacy_first_id", "legacy_last_id", "created_at", "closed_at"
        )})
    return digest_hex(canonical_bytes(public))


def access_log_payload(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"], "timestamp": row["timestamp"], "agent_id": row["agent_id"], "service": row["service"],
        "action": row["action"], "decision": row["decision"], "reason": row["reason"],
        "ttl_seconds": row["ttl_seconds"], "verification_result": row["verification_result"], "metadata_json": row["metadata_json"],
    }