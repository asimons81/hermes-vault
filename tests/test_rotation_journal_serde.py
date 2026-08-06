"""Focused unit tests for journal-level serialize/deserialize and validation.

Covers the S1 shared seam from INTEGRITY_RECOVERY_PLAN.md, Slice C
(issues #58 / #66), as scoped to this card: the journal-level
serialize/deserialize for the typed v2 rotation journal record
(:class:`RotationJournalEntry`) and its validation.

Acceptance covered here:

* Serialization round-trips every field exactly — the dict produced by
  ``to_dict`` parses back (``from_dict``) to an identical entry, and the
  serialized shape keeps the v1-compatible ``old_salt`` / ``new_salt`` hex
  fields so pre-v2 readers keep working on the common fields.
* Validation rejects entries that mix envelope kinds: a DPAPI envelope kind
  carrying PBKDF-only salt bytes, or a PBKDF entry missing its required
  16-byte salt, are both rejected with :class:`RotationJournalError`.
* v1 backward read: ``rotation-journal-v1`` payloads are accepted and their
  durable kind is inferred from the bytes (``HVDP`` magic + length gate);
  ambiguous bytes fail closed.

The destructive ``recover_checkpoint`` /
``_rebuild_integrity_for_key_mismatch`` semantics in
:mod:`hermes_vault.audit_integrity.service` are intentionally not touched by
this workstream and no test here depends on them.
"""

from __future__ import annotations

import os

import pytest

from hermes_vault.dpapi import DPAPI_ENVELOPE_VERSION, DPAPI_HEADER
from hermes_vault.rotation_journal import (
    JOURNAL_VERSION_V1,
    JOURNAL_VERSION_V2,
    AuditTransitionState,
    DurableKind,
    DurableMaterial,
    JournalStatus,
    RotationJournalEntry,
    RotationJournalError,
    encrypt_old_key_recovery,
)


def _pbkdf_material() -> DurableMaterial:
    return DurableMaterial(kind=DurableKind.pbkdf_salt, salt=os.urandom(16))


def _dpapi_material() -> DurableMaterial:
    return DurableMaterial(
        kind=DurableKind.dpapi_envelope,
        envelope=DPAPI_HEADER + os.urandom(24),
    )


def _started_entry() -> RotationJournalEntry:
    return RotationJournalEntry.start(
        old_durable=_pbkdf_material(),
        new_durable=_pbkdf_material(),
    )


def _db_committed_entry() -> RotationJournalEntry:
    old = _pbkdf_material()
    new = _dpapi_material()
    started = RotationJournalEntry.start(old_durable=old, new_durable=new)
    recovery = encrypt_old_key_recovery(os.urandom(32), os.urandom(32), started.journal_id)
    return started.mark_db_committed(
        old_segment_id="seg-1",
        old_key_recovery=recovery,
    )


def _checkpoint_committed_entry() -> RotationJournalEntry:
    return _db_committed_entry().mark_audit_checkpoint_committed()


def _v1_payload(*, old_hex: str, new_hex: str, status: str = "started") -> dict[str, str]:
    payload: dict[str, str] = {
        "version": JOURNAL_VERSION_V1,
        "status": status,
        "old_salt": old_hex,
        "new_salt": new_hex,
        "created_at": "2026-08-05T12:00:00+00:00",
    }
    if status == "db_committed":
        payload["committed_at"] = "2026-08-05T12:01:00+00:00"
        payload["audit_transition_state"] = "pending"
        payload["old_segment_id"] = "seg-1"
    return payload


# ── round trips: all fields preserved exactly ─────────────────────────


def test_started_pbkdf_journal_round_trip_preserves_all_fields() -> None:
    entry = _started_entry()
    payload = entry.to_dict()
    restored = RotationJournalEntry.from_dict(payload)
    assert restored == entry
    assert restored.journal_id == entry.journal_id
    assert restored.created_at == entry.created_at
    assert restored.status == JournalStatus.started
    assert restored.old_durable == entry.old_durable
    assert restored.new_durable == entry.new_durable
    assert restored.old_key_recovery is None
    assert restored.audit_transition_state is None
    assert restored.old_segment_id is None
    assert restored.committed_at is None


def test_db_committed_dpapi_journal_round_trip_preserves_all_fields() -> None:
    entry = _db_committed_entry()
    payload = entry.to_dict()
    restored = RotationJournalEntry.from_dict(payload)
    assert restored == entry
    assert restored.journal_id == entry.journal_id
    assert restored.created_at == entry.created_at
    assert restored.committed_at == entry.committed_at
    assert restored.status == JournalStatus.db_committed
    assert restored.audit_transition_state == AuditTransitionState.pending
    assert restored.old_segment_id == "seg-1"
    assert restored.old_key_recovery is not None
    assert entry.old_key_recovery is not None
    assert restored.old_key_recovery == entry.old_key_recovery
    assert restored.old_key_recovery.nonce == entry.old_key_recovery.nonce
    assert restored.old_key_recovery.ciphertext == entry.old_key_recovery.ciphertext


def test_mixed_kind_journal_round_trip_preserves_kinds_and_metadata() -> None:
    entry = RotationJournalEntry.start(
        old_durable=_pbkdf_material(),
        new_durable=_dpapi_material(),
    )
    payload = entry.to_dict()
    assert payload["old_durable_type"] == DurableKind.pbkdf_salt.value
    assert payload["new_durable_type"] == DurableKind.dpapi_envelope.value
    restored = RotationJournalEntry.from_dict(payload)
    assert restored == entry
    assert restored.old_durable.kind == DurableKind.pbkdf_salt
    assert restored.new_durable.kind == DurableKind.dpapi_envelope
    assert restored.new_durable.envelope_version == DPAPI_ENVELOPE_VERSION
    assert restored.new_durable.envelope == entry.new_durable.envelope


def test_serialized_dict_keeps_v1_compatible_hex_fields() -> None:
    entry = _started_entry()
    payload = entry.to_dict()
    assert payload["old_salt"] == entry.old_durable.to_hex()
    assert payload["new_salt"] == entry.new_durable.to_hex()
    # v1 readers read old_salt/new_salt directly as hex — unchanged shape.
    assert bytes.fromhex(payload["old_salt"]) == entry.old_durable.salt
    assert bytes.fromhex(payload["new_salt"]) == entry.new_durable.salt


def test_to_json_from_json_round_trip() -> None:
    entry = _db_committed_entry()
    restored = RotationJournalEntry.from_json(entry.to_json())
    assert restored == entry


def test_checkpoint_committed_round_trip_preserves_all_fields() -> None:
    # The terminal state carries the fullest field set (status, audit
    # transition state, segment id, committed_at, and the retained recovery
    # material); the round trip must preserve every one of them.
    entry = _checkpoint_committed_entry()
    assert entry.audit_transition_state == AuditTransitionState.checkpoint_committed
    assert entry.old_key_recovery is not None
    payload = entry.to_dict()
    restored = RotationJournalEntry.from_dict(payload)
    assert restored == entry
    assert restored.status == JournalStatus.db_committed
    assert restored.audit_transition_state == AuditTransitionState.checkpoint_committed
    assert restored.old_segment_id == entry.old_segment_id
    assert restored.committed_at == entry.committed_at
    assert restored.old_key_recovery == entry.old_key_recovery
    assert restored.old_durable == entry.old_durable
    assert restored.new_durable == entry.new_durable
    assert restored.journal_id == entry.journal_id
    assert RotationJournalEntry.from_json(entry.to_json()) == entry


def test_serialization_is_deterministic() -> None:
    entry = _db_committed_entry()
    assert entry.to_dict() == entry.to_dict()
    assert entry.to_json() == entry.to_json()


# ── validation: reject envelope-kind mixing ───────────────────────────


def test_from_dict_rejects_dpapi_kind_with_pbkdf_only_salt_bytes() -> None:
    # A DPAPI envelope kind declared over a plain 16-byte salt must fail:
    # the bytes are not an envelope, so the kind is mixed/unrepresentable.
    salt_hex = os.urandom(16).hex()
    payload = {
        "version": JOURNAL_VERSION_V2,
        "status": "started",
        "old_salt": salt_hex,
        "new_salt": salt_hex,
        "old_durable_type": DurableKind.dpapi_envelope.value,
        "new_durable_type": DurableKind.dpapi_envelope.value,
    }
    with pytest.raises(RotationJournalError, match="must start with the DPAPI header"):
        RotationJournalEntry.from_dict(payload)


def test_from_dict_rejects_pbkdf_missing_required_salt() -> None:
    payload = {
        "version": JOURNAL_VERSION_V2,
        "status": "started",
        "old_salt": "",
        "new_salt": os.urandom(16).hex(),
        "old_durable_type": DurableKind.pbkdf_salt.value,
        "new_durable_type": DurableKind.pbkdf_salt.value,
    }
    with pytest.raises(RotationJournalError, match="must be 16 bytes"):
        RotationJournalEntry.from_dict(payload)


def test_from_dict_rejects_pbkdf_kind_with_dpapi_envelope_bytes() -> None:
    # Reverse mixing direction: a pbkdf_salt kind declared over actual DPAPI
    # envelope bytes must fail closed at the journal level too — the bytes
    # are not a 16-byte salt, so the entry is mixed/unrepresentable.
    envelope_hex = (DPAPI_HEADER + os.urandom(24)).hex()
    payload = {
        "version": JOURNAL_VERSION_V2,
        "status": "started",
        "old_salt": envelope_hex,
        "new_salt": os.urandom(16).hex(),
        "old_durable_type": DurableKind.pbkdf_salt.value,
        "new_durable_type": DurableKind.pbkdf_salt.value,
    }
    with pytest.raises(RotationJournalError, match="must be 16 bytes"):
        RotationJournalEntry.from_dict(payload)


def test_pbkdf_material_rejects_dpapi_envelope_metadata() -> None:
    # A PBKDF salt entry carrying DPAPI-only envelope_version metadata is
    # kind mixing and must be rejected by the model itself.
    with pytest.raises(ValueError, match="must not carry DPAPI envelope metadata"):
        DurableMaterial(
            kind=DurableKind.pbkdf_salt,
            salt=os.urandom(16),
            envelope_version="dpapi-v1",
        )


def test_from_dict_rejects_pbkdf_kind_with_dpapi_envelope_metadata() -> None:
    # Journal-level: a PBKDF durable declaring DPAPI envelope metadata must
    # be rejected, not silently normalized (the metadata is dpapi-only).
    salt_hex = os.urandom(16).hex()
    payload = {
        "version": JOURNAL_VERSION_V2,
        "status": "started",
        "old_salt": salt_hex,
        "new_salt": salt_hex,
        "old_durable_type": DurableKind.pbkdf_salt.value,
        "new_durable_type": DurableKind.pbkdf_salt.value,
        "old_envelope_version": "dpapi-v1",
    }
    with pytest.raises(RotationJournalError, match="must not carry DPAPI envelope metadata"):
        RotationJournalEntry.from_dict(payload)


def test_from_dict_rejects_v2_without_typed_fields() -> None:
    payload = {
        "version": JOURNAL_VERSION_V2,
        "status": "started",
        "old_salt": os.urandom(16).hex(),
        "new_salt": os.urandom(16).hex(),
    }
    with pytest.raises(RotationJournalError):
        RotationJournalEntry.from_dict(payload)


def test_from_dict_rejects_unknown_version() -> None:
    payload = {
        "version": "rotation-journal-v3",
        "status": "started",
        "old_salt": os.urandom(16).hex(),
        "new_salt": os.urandom(16).hex(),
        "old_durable_type": DurableKind.pbkdf_salt.value,
        "new_durable_type": DurableKind.pbkdf_salt.value,
    }
    with pytest.raises(RotationJournalError, match="unsupported journal version"):
        RotationJournalEntry.from_dict(payload)


def test_from_dict_rejects_invalid_hex() -> None:
    payload = {
        "version": JOURNAL_VERSION_V2,
        "status": "started",
        "old_salt": "not-hex!!",
        "new_salt": os.urandom(16).hex(),
        "old_durable_type": DurableKind.pbkdf_salt.value,
        "new_durable_type": DurableKind.pbkdf_salt.value,
    }
    with pytest.raises(RotationJournalError):
        RotationJournalEntry.from_dict(payload)


def test_from_dict_rejects_extra_fields() -> None:
    payload = _started_entry().to_dict()
    payload["unexpected"] = "nope"
    with pytest.raises(RotationJournalError):
        RotationJournalEntry.from_dict(payload)


def test_from_dict_rejects_state_machine_contradiction() -> None:
    # db_committed without an old_segment_id is contradictory.
    payload = _db_committed_entry().to_dict()
    payload.pop("old_segment_id")
    with pytest.raises(RotationJournalError, match="requires an old segment id"):
        RotationJournalEntry.from_dict(payload)


# ── v1 backward read: infer kind from bytes, fail closed ──────────────


def test_v1_pbkdf_journal_backward_read_infers_kind() -> None:
    salt = os.urandom(16)
    payload = _v1_payload(old_hex=salt.hex(), new_hex=salt.hex())
    entry = RotationJournalEntry.from_dict(payload)
    assert entry.version == JOURNAL_VERSION_V2  # upgraded in memory
    assert entry.status == JournalStatus.started
    assert entry.old_durable.kind == DurableKind.pbkdf_salt
    assert entry.new_durable.kind == DurableKind.pbkdf_salt
    assert entry.old_durable.salt == salt
    assert entry.new_durable.salt == salt


def test_v1_dpapi_journal_backward_read_infers_kind() -> None:
    envelope = DPAPI_HEADER + os.urandom(24)
    salt = os.urandom(16)
    payload = _v1_payload(old_hex=envelope.hex(), new_hex=salt.hex())
    entry = RotationJournalEntry.from_dict(payload)
    assert entry.old_durable.kind == DurableKind.dpapi_envelope
    assert entry.old_durable.envelope == envelope
    assert entry.new_durable.kind == DurableKind.pbkdf_salt
    assert entry.new_durable.salt == salt


def test_v1_db_committed_backward_read_preserves_state() -> None:
    salt = os.urandom(16)
    payload = _v1_payload(
        old_hex=salt.hex(),
        new_hex=salt.hex(),
        status="db_committed",
    )
    entry = RotationJournalEntry.from_dict(payload)
    assert entry.status == JournalStatus.db_committed
    assert entry.audit_transition_state == AuditTransitionState.pending
    assert entry.old_segment_id == "seg-1"
    assert entry.committed_at is not None


def test_v1_ambiguous_bytes_fail_closed() -> None:
    # 12 random bytes that are neither a 16-byte salt nor an HVDP envelope.
    ambiguous = os.urandom(12)
    payload = _v1_payload(old_hex=ambiguous.hex(), new_hex=ambiguous.hex())
    with pytest.raises(RotationJournalError, match="must be 16 bytes"):
        RotationJournalEntry.from_dict(payload)


def test_v1_backward_read_keeps_hex_identical() -> None:
    salt = os.urandom(16)
    payload = _v1_payload(old_hex=salt.hex(), new_hex=salt.hex())
    entry = RotationJournalEntry.from_dict(payload)
    assert entry.to_dict()["old_salt"] == salt.hex()
    assert entry.to_dict()["new_salt"] == salt.hex()
