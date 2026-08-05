"""Detached cryptographic verification of exported audit evidence (Slice D, #59).

Verifies the hvbackup-v2 ``audit_integrity`` evidence exported by
``AuditIntegrityService.export_evidence`` with NO live database reads:
registry/checkpoint, record signatures/digests/continuity, checkpoint tip,
access-log bindings, and segment key material. Used to make backup
verification and recovery drills fail closed on tampered evidence.
"""

from __future__ import annotations

from typing import Any

from hermes_vault.audit_integrity.canonical import CANONICAL_JSON_VERSION, canonical_bytes, framed
from hermes_vault.audit_integrity.checkpoint import checkpoint_signature_valid
from hermes_vault.audit_integrity.crypto import (
    CHECKPOINT_SIGNING_CONTEXT,
    ENTRY_SIGNING_CONTEXT,
    ENTRY_SIGNATURE_VERSION,
    digest_hex,
    public_key_b64,
    verify,
)
from hermes_vault.audit_integrity.service import CHAIN_VERSION

# Status strings mirror backup.BACKUP_INTEGRITY_* without importing backup
# (backup imports this module, so a shared constant would be circular).
DETACHED_HEALTHY = "healthy"
DETACHED_LEGACY = "legacy"
DETACHED_INCOMPLETE = "incomplete"
DETACHED_FAILED = "failed"

# Public registry fields authenticated by the checkpoint (mirror repository.registry_digest).
_REGISTRY_KEYS = (
    "segment_id",
    "segment_number",
    "chain_version",
    "serialization_version",
    "key_derivation_version",
    "entry_signature_version",
    "checkpoint_signature_version",
    "entry_public_key",
    "checkpoint_public_key",
    "sequence_start",
    "sequence_end",
    "predecessor_segment_id",
    "predecessor_tip_digest",
    "transition_reason",
    "legacy_count",
    "legacy_snapshot_digest",
    "legacy_first_id",
    "legacy_last_id",
    "created_at",
    "closed_at",
)

# Column order used by the legacy snapshot framing (mirror service._legacy_snapshot).
_ACCESS_LOG_COLUMNS = (
    "id",
    "timestamp",
    "agent_id",
    "service",
    "action",
    "decision",
    "reason",
    "ttl_seconds",
    "verification_result",
    "metadata_json",
)


def _registry_digest(segments: list[dict[str, Any]]) -> str:
    ordered = sorted(segments, key=lambda seg: seg.get("segment_number", 0))
    public = [{key: seg.get(key) for key in _REGISTRY_KEYS} for seg in ordered]
    return digest_hex(canonical_bytes(public))


def _access_log_payload(row: dict[str, Any]) -> dict[str, Any]:
    return {key: row.get(key) for key in _ACCESS_LOG_COLUMNS}


def _legacy_anchor_digest(access_logs: list[dict[str, Any]], cutoff: int) -> str:
    ordered = sorted(access_logs, key=lambda row: (str(row.get("timestamp", "")), str(row.get("id", ""))))
    frames = []
    for row in ordered[:cutoff]:
        frames.append(
            framed(
                [(b"" if row.get(key) is None else str(row.get(key)).encode("utf-8")) for key in _ACCESS_LOG_COLUMNS]
            )
        )
    return digest_hex(b"".join(frames))


def verify_detached_evidence(evidence: dict[str, Any], master_key: bytes) -> tuple[str, str | None]:
    """Verify exported audit evidence using only *evidence* and the vault master key.

    Returns ``(status, reason)`` where status is one of ``healthy``, ``failed``,
    ``incomplete``, or ``legacy`` and reason is the failure code (``None`` when
    healthy). Mirrors ``AuditIntegrityService.verify`` over the exported dicts
    instead of the live database.
    """
    if not evidence.get("integrity_available", False):
        return DETACHED_LEGACY, "integrity_evidence_not_available"

    state_rows = evidence.get("state")
    if not state_rows:
        return DETACHED_INCOMPLETE, "integrity_state_missing"
    segments = evidence.get("segments")
    if not segments:
        return DETACHED_INCOMPLETE, "integrity_segments_missing"

    records = evidence.get("records") or []
    access_logs = evidence.get("access_logs") or []
    checkpoint = evidence.get("checkpoint")

    state = state_rows[0]
    if state.get("migration_state") != "active":
        return DETACHED_LEGACY, "migration_not_active"

    active_segment_id = state.get("active_segment_id")
    active = next((seg for seg in segments if seg.get("segment_id") == active_segment_id), None)
    if active is None:
        return DETACHED_FAILED, "segment_registry_mismatch"
    if active.get("chain_version") != CHAIN_VERSION:
        return DETACHED_FAILED, "unsupported_chain_version"
    if active.get("serialization_version") != CANONICAL_JSON_VERSION:
        return DETACHED_FAILED, "unsupported_serialization_version"
    if active.get("entry_signature_version") != ENTRY_SIGNATURE_VERSION:
        return DETACHED_FAILED, "unsupported_signature_version"
    if active.get("entry_public_key") != public_key_b64(master_key, ENTRY_SIGNING_CONTEXT) or active.get(
        "checkpoint_public_key"
    ) != public_key_b64(master_key, CHECKPOINT_SIGNING_CONTEXT):
        return DETACHED_FAILED, "key_mismatch"

    # Legacy anchor: the migration prefix must still match its recorded snapshot.
    first = min(segments, key=lambda seg: seg.get("segment_number", 0))
    legacy_count = int(first.get("legacy_count") or 0)
    if legacy_count:
        if len(access_logs) < legacy_count or _legacy_anchor_digest(access_logs, legacy_count) != first.get(
            "legacy_snapshot_digest"
        ):
            return DETACHED_FAILED, "legacy_anchor_mismatch"

    access_logs_by_id = {row.get("id"): row for row in access_logs}
    segments_by_id = {seg.get("segment_id"): seg for seg in segments}
    ordered_records = sorted(records, key=lambda rec: rec.get("sequence", 0))
    previous = ""
    expected_sequence = 1
    last_sequence = 0
    last_digest = ""
    for rec in ordered_records:
        sequence = rec.get("sequence")
        if sequence != expected_sequence:
            return DETACHED_FAILED, "sequence_gap"
        if rec.get("previous_digest") != previous:
            return DETACHED_FAILED, "previous_digest_mismatch"
        log_row = access_logs_by_id.get(rec.get("access_log_id"))
        if log_row is None:
            return DETACHED_FAILED, "missing_access_log"
        if digest_hex(canonical_bytes(_access_log_payload(log_row))) != rec.get("entry_digest"):
            return DETACHED_FAILED, "entry_digest_mismatch"
        segment = segments_by_id.get(rec.get("segment_id"))
        if segment is None:
            return DETACHED_FAILED, "segment_registry_mismatch"
        envelope = {
            "chain_version": rec.get("chain_version"),
            "serialization_version": rec.get("serialization_version"),
            "segment_id": rec.get("segment_id"),
            "sequence": rec.get("sequence"),
            "previous_digest": rec.get("previous_digest"),
            "entry_digest": rec.get("entry_digest"),
        }
        if not verify(segment.get("entry_public_key", ""), rec.get("signature", ""), canonical_bytes(envelope)):
            return DETACHED_FAILED, "entry_signature_mismatch"
        previous = str(rec.get("entry_digest"))
        expected_sequence += 1
        last_sequence = int(sequence)
        last_digest = str(rec.get("entry_digest"))

    # Every exported access-log row must be either legacy-prefix or protected.
    if len(access_logs) != legacy_count + len(records):
        return DETACHED_FAILED, "missing_integrity_record"

    # Checkpoint: format, signature, active segment, registry digest, tip.
    if checkpoint is None:
        return DETACHED_INCOMPLETE, "checkpoint_missing"
    if (
        checkpoint.get("format") != "hermes-vault-audit-checkpoint"
        or checkpoint.get("version") != "audit-checkpoint-v1"
    ):
        return DETACHED_INCOMPLETE, "checkpoint_invalid_format"
    if not checkpoint_signature_valid(checkpoint, str(active.get("checkpoint_public_key", ""))):
        return DETACHED_FAILED, "checkpoint_invalid_signature"
    if checkpoint.get("active_segment_id") != active_segment_id:
        return DETACHED_FAILED, "checkpoint_segment_mismatch"
    if checkpoint.get("segment_registry_digest") != _registry_digest(segments):
        return DETACHED_FAILED, "segment_registry_mismatch"
    cp_sequence = checkpoint.get("latest_sequence")
    if not isinstance(cp_sequence, int):
        return DETACHED_INCOMPLETE, "checkpoint_invalid_format"
    if cp_sequence < last_sequence or checkpoint.get("latest_entry_digest") != last_digest:
        return DETACHED_INCOMPLETE, "checkpoint_stale"
    if cp_sequence > last_sequence:
        return DETACHED_INCOMPLETE, "checkpoint_ahead"

    return DETACHED_HEALTHY, None
