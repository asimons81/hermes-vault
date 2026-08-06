"""Unit tests for the v2 old-key recovery material and state transitions.

Covers the S1 shared seam from INTEGRITY_RECOVERY_PLAN.md, Slice C
(issues #58 / #66), as scoped to this card: the typed encrypted old-key
recovery material (:class:`OldKeyRecovery` plus the
:func:`encrypt_old_key_recovery` / :func:`decrypt_old_key_recovery`
helpers) and the explicit v2 state transition helpers
(:class:`RotationJournalEntry` ``start`` / ``mark_db_committed`` /
``mark_audit_checkpoint_committed`` / ``phase``, and the derived
:class:`JournalPhase`).

The typed durable entry types (:class:`DurableKind` /
:class:`DurableMaterial`) come from the prerequisite card; journal-level
serialize/deserialize lives on the sibling card.  The destructive
``recover_checkpoint`` semantics live in
:mod:`hermes_vault.audit_integrity.service` and are intentionally not
touched — no test here exercises or depends on them.
"""

from __future__ import annotations

import os

import pytest
from cryptography.exceptions import InvalidTag

from hermes_vault.crypto import AAD_DOMAIN, NONCE_SIZE
from hermes_vault.dpapi import DPAPI_ENVELOPE_VERSION, DPAPI_HEADER
from hermes_vault.models import utc_now
from hermes_vault.rotation_journal import (
    JOURNAL_VERSION_V1,
    JOURNAL_VERSION_V2,
    RECOVERY_AAD_KIND,
    RECOVERY_AAD_VERSION,
    RECOVERY_ENVELOPE_VERSION,
    AuditTransitionState,
    DurableKind,
    DurableMaterial,
    JournalPhase,
    JournalStatus,
    OldKeyRecovery,
    RotationJournalEntry,
    RotationJournalError,
    build_recovery_aad,
    decrypt_old_key_recovery,
    encrypt_old_key_recovery,
)


def _pbkdf_material() -> DurableMaterial:
    return DurableMaterial(kind=DurableKind.pbkdf_salt, salt=os.urandom(16))


def _dpapi_material() -> DurableMaterial:
    return DurableMaterial(
        kind=DurableKind.dpapi_envelope,
        envelope=DPAPI_HEADER + os.urandom(24),
    )


def _old_key() -> bytes:
    return os.urandom(32)


def _new_key() -> bytes:
    return os.urandom(32)


# ── OldKeyRecovery: typed encrypted recovery material ────────────────


def test_old_key_recovery_requires_nonce() -> None:
    with pytest.raises(ValueError, match="nonce"):
        OldKeyRecovery(nonce=b"", ciphertext=b"x")


def test_old_key_recovery_requires_12_byte_nonce() -> None:
    with pytest.raises(ValueError, match="must be 12 bytes"):
        OldKeyRecovery(nonce=os.urandom(8), ciphertext=b"x")


def test_old_key_recovery_rejects_empty_ciphertext() -> None:
    with pytest.raises(ValueError, match="ciphertext must not be empty"):
        OldKeyRecovery(nonce=os.urandom(NONCE_SIZE), ciphertext=b"")


def test_old_key_recovery_defaults_envelope_version() -> None:
    recovery = OldKeyRecovery(nonce=os.urandom(NONCE_SIZE), ciphertext=os.urandom(48))
    assert recovery.version == RECOVERY_ENVELOPE_VERSION


def test_old_key_recovery_extra_fields_forbidden() -> None:
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        OldKeyRecovery.model_validate(
            {
                "nonce": os.urandom(NONCE_SIZE),
                "ciphertext": os.urandom(48),
                "unexpected": "nope",
            }
        )


def test_old_key_recovery_dict_round_trip() -> None:
    recovery = OldKeyRecovery(nonce=os.urandom(NONCE_SIZE), ciphertext=os.urandom(48))
    payload = recovery.to_dict()
    assert set(payload) == {"version", "nonce", "ciphertext"}
    restored = OldKeyRecovery.from_dict(payload)
    assert restored.version == recovery.version
    assert restored.nonce == recovery.nonce
    assert restored.ciphertext == recovery.ciphertext


def test_old_key_recovery_from_dict_rejects_missing_ciphertext() -> None:
    with pytest.raises(RotationJournalError, match="invalid old_key_recovery payload"):
        OldKeyRecovery.from_dict({"nonce": os.urandom(NONCE_SIZE).hex()})


def test_old_key_recovery_from_dict_rejects_bad_hex() -> None:
    with pytest.raises(RotationJournalError, match="invalid old_key_recovery payload"):
        OldKeyRecovery.from_dict({"nonce": "zz", "ciphertext": "aa"})


# ── encrypt/decrypt helpers ──────────────────────────────────────────


def test_recovery_round_trip_returns_old_key() -> None:
    old_key = _old_key()
    new_key = _new_key()
    journal_id = "journal-123"
    recovery = encrypt_old_key_recovery(old_key, new_key, journal_id)
    assert decrypt_old_key_recovery(recovery, new_key, journal_id) == old_key


def test_recovery_never_stores_plaintext_or_passphrase() -> None:
    old_key = _old_key()
    recovery = encrypt_old_key_recovery(old_key, _new_key(), "journal-123")
    # The ciphertext must not equal or embed the plaintext key bytes.
    assert recovery.ciphertext != old_key
    assert old_key not in recovery.ciphertext
    payload = recovery.to_dict()
    assert payload["ciphertext"] != old_key.hex()
    # No human-readable key material in the serialized envelope.
    assert "passphrase" not in payload


def test_recovery_wrong_new_key_fails() -> None:
    old_key = _old_key()
    journal_id = "journal-123"
    recovery = encrypt_old_key_recovery(old_key, _new_key(), journal_id)
    with pytest.raises(InvalidTag):
        decrypt_old_key_recovery(recovery, _new_key(), journal_id)


def test_recovery_wrong_journal_id_fails() -> None:
    old_key = _old_key()
    new_key = _new_key()
    recovery = encrypt_old_key_recovery(old_key, new_key, "journal-123")
    with pytest.raises(InvalidTag):
        decrypt_old_key_recovery(recovery, new_key, "journal-456")


def test_recovery_tampered_ciphertext_fails() -> None:
    old_key = _old_key()
    new_key = _new_key()
    journal_id = "journal-123"
    recovery = encrypt_old_key_recovery(old_key, new_key, journal_id)
    tampered = OldKeyRecovery(
        nonce=recovery.nonce,
        ciphertext=recovery.ciphertext[:-1] + bytes([recovery.ciphertext[-1] ^ 0x01]),
    )
    with pytest.raises(InvalidTag):
        decrypt_old_key_recovery(tampered, new_key, journal_id)


def test_recovery_aad_binds_journal_id_deterministically() -> None:
    aad_1 = build_recovery_aad("journal-123")
    aad_2 = build_recovery_aad("journal-123")
    aad_other = build_recovery_aad("journal-456")
    assert aad_1 == aad_2
    assert aad_1 != aad_other
    marker = f"{AAD_DOMAIN}:{RECOVERY_AAD_KIND}:{RECOVERY_AAD_VERSION}"
    assert aad_1.startswith(marker.encode("utf-8"))


def test_recovery_aad_distinct_from_credential_aad() -> None:
    # The recovery marker kind must differ from the credential-aad marker so
    # ciphertexts can never be replayed across the two domains.
    aad = build_recovery_aad("journal-123").decode("utf-8")
    assert RECOVERY_AAD_KIND == "rotation-journal-old-key"
    assert RECOVERY_AAD_KIND != "credential-aad"
    assert "credential-aad" not in aad


# ── state machine enums / phase derivation ───────────────────────────


def test_phase_derivation() -> None:
    entry = RotationJournalEntry.start(
        old_durable=_pbkdf_material(),
        new_durable=_pbkdf_material(),
    )
    assert entry.phase() == JournalPhase.started
    committed = entry.mark_db_committed(
        old_segment_id="seg-1",
        old_key_recovery=encrypt_old_key_recovery(_old_key(), _new_key(), entry.journal_id),
    )
    assert committed.phase() == JournalPhase.db_committed_pending
    final = committed.mark_audit_checkpoint_committed()
    assert final.phase() == JournalPhase.checkpoint_committed


def test_journal_status_values() -> None:
    assert JournalStatus.started.value == "started"
    assert JournalStatus.db_committed.value == "db_committed"


def test_audit_transition_state_values() -> None:
    assert AuditTransitionState.pending.value == "pending"
    assert AuditTransitionState.checkpoint_committed.value == "checkpoint_committed"


def test_journal_phase_values() -> None:
    assert JournalPhase.started.value == "started"
    assert JournalPhase.db_committed_pending.value == "db_committed_pending"
    assert JournalPhase.checkpoint_committed.value == "checkpoint_committed"


# ── RotationJournalEntry: start / legal state validation ─────────────


def test_start_creates_started_entry_with_typed_materials() -> None:
    old_durable = _dpapi_material()
    new_durable = _pbkdf_material()
    entry = RotationJournalEntry.start(old_durable=old_durable, new_durable=new_durable)
    assert entry.version == JOURNAL_VERSION_V2
    assert entry.status == JournalStatus.started
    assert entry.audit_transition_state is None
    assert entry.old_segment_id is None
    assert entry.committed_at is None
    assert entry.old_durable.kind == DurableKind.dpapi_envelope
    assert entry.old_durable.to_hex() == old_durable.to_hex()
    assert entry.new_durable.kind == DurableKind.pbkdf_salt
    assert entry.old_key_recovery is None


def test_started_entry_rejects_audit_transition_state() -> None:
    with pytest.raises(ValueError, match="must not carry an audit transition state"):
        RotationJournalEntry(
            status=JournalStatus.started,
            audit_transition_state=AuditTransitionState.pending,
            old_durable=_pbkdf_material(),
            new_durable=_pbkdf_material(),
        )


def test_started_entry_rejects_old_segment_id() -> None:
    with pytest.raises(ValueError, match="must not carry an old segment id"):
        RotationJournalEntry(
            status=JournalStatus.started,
            old_segment_id="seg-1",
            old_durable=_pbkdf_material(),
            new_durable=_pbkdf_material(),
        )


def test_started_entry_rejects_committed_at() -> None:
    with pytest.raises(ValueError, match="must not carry a committed_at timestamp"):
        RotationJournalEntry(
            status=JournalStatus.started,
            committed_at=utc_now(),
            old_durable=_pbkdf_material(),
            new_durable=_pbkdf_material(),
        )


def test_entry_rejects_unknown_version() -> None:
    with pytest.raises(ValueError, match="unsupported journal version"):
        RotationJournalEntry(
            version="rotation-journal-v3",
            old_durable=_pbkdf_material(),
            new_durable=_pbkdf_material(),
        )


def test_v1_version_label_is_distinct() -> None:
    assert JOURNAL_VERSION_V1 == "rotation-journal-v1"
    assert JOURNAL_VERSION_V1 != JOURNAL_VERSION_V2


# ── mark_db_committed transition ─────────────────────────────────────


def test_mark_db_committed_requires_recovery_material() -> None:
    entry = RotationJournalEntry.start(
        old_durable=_pbkdf_material(),
        new_durable=_pbkdf_material(),
    )
    with pytest.raises(RotationJournalError, match="old_key_recovery is required"):
        entry.mark_db_committed(old_segment_id="seg-1")


def test_mark_db_committed_accepts_recovery_from_started_entry() -> None:
    recovery = encrypt_old_key_recovery(_old_key(), _new_key(), "journal-x")
    entry = RotationJournalEntry.start(
        old_durable=_pbkdf_material(),
        new_durable=_pbkdf_material(),
        old_key_recovery=recovery,
    )
    committed = entry.mark_db_committed(old_segment_id="seg-1")
    assert committed.status == JournalStatus.db_committed
    assert committed.audit_transition_state == AuditTransitionState.pending
    assert committed.old_segment_id == "seg-1"
    assert committed.committed_at is not None
    assert committed.old_key_recovery == recovery
    # journal id and durable materials are preserved.
    assert committed.journal_id == entry.journal_id
    assert committed.old_durable == entry.old_durable
    assert committed.new_durable == entry.new_durable


def test_mark_db_committed_accepts_recovery_passed_inline() -> None:
    entry = RotationJournalEntry.start(
        old_durable=_pbkdf_material(),
        new_durable=_pbkdf_material(),
    )
    recovery = encrypt_old_key_recovery(_old_key(), _new_key(), entry.journal_id)
    committed = entry.mark_db_committed(old_segment_id="seg-1", old_key_recovery=recovery)
    assert committed.old_key_recovery == recovery


def test_mark_db_committed_from_non_started_raises() -> None:
    recovery = encrypt_old_key_recovery(_old_key(), _new_key(), "journal-x")
    entry = RotationJournalEntry.start(
        old_durable=_pbkdf_material(),
        new_durable=_pbkdf_material(),
        old_key_recovery=recovery,
    ).mark_db_committed(old_segment_id="seg-1")
    with pytest.raises(RotationJournalError, match="cannot mark db_committed"):
        entry.mark_db_committed(old_segment_id="seg-2", old_key_recovery=recovery)


def test_db_committed_entry_requires_old_segment_id() -> None:
    recovery = encrypt_old_key_recovery(_old_key(), _new_key(), "journal-x")
    with pytest.raises(ValueError, match="requires an old segment id"):
        RotationJournalEntry(
            status=JournalStatus.db_committed,
            audit_transition_state=AuditTransitionState.pending,
            old_key_recovery=recovery,
            old_durable=_pbkdf_material(),
            new_durable=_pbkdf_material(),
            committed_at=utc_now(),
        )


def test_db_committed_pending_requires_recovery_material() -> None:
    with pytest.raises(ValueError, match="requires old_key_recovery"):
        RotationJournalEntry(
            status=JournalStatus.db_committed,
            audit_transition_state=AuditTransitionState.pending,
            old_segment_id="seg-1",
            old_durable=_pbkdf_material(),
            new_durable=_pbkdf_material(),
            committed_at=utc_now(),
        )


def test_db_committed_requires_committed_at() -> None:
    recovery = encrypt_old_key_recovery(_old_key(), _new_key(), "journal-x")
    with pytest.raises(ValueError, match="requires a committed_at timestamp"):
        RotationJournalEntry(
            status=JournalStatus.db_committed,
            audit_transition_state=AuditTransitionState.pending,
            old_segment_id="seg-1",
            old_key_recovery=recovery,
            old_durable=_pbkdf_material(),
            new_durable=_pbkdf_material(),
        )


# ── mark_audit_checkpoint_committed transition ───────────────────────


def test_mark_audit_checkpoint_committed_from_pending() -> None:
    recovery = encrypt_old_key_recovery(_old_key(), _new_key(), "journal-x")
    entry = RotationJournalEntry.start(
        old_durable=_dpapi_material(),
        new_durable=_dpapi_material(),
        old_key_recovery=recovery,
    ).mark_db_committed(old_segment_id="seg-1")
    final = entry.mark_audit_checkpoint_committed()
    assert final.status == JournalStatus.db_committed
    assert final.audit_transition_state == AuditTransitionState.checkpoint_committed
    assert final.phase() == JournalPhase.checkpoint_committed
    # Recovery material is retained through the final state.
    assert final.old_key_recovery == recovery
    assert final.old_segment_id == "seg-1"
    assert final.committed_at is not None


def test_mark_audit_checkpoint_committed_from_started_raises() -> None:
    entry = RotationJournalEntry.start(
        old_durable=_pbkdf_material(),
        new_durable=_pbkdf_material(),
    )
    with pytest.raises(RotationJournalError, match="cannot mark audit checkpoint committed"):
        entry.mark_audit_checkpoint_committed()


def test_mark_audit_checkpoint_committed_twice_raises() -> None:
    recovery = encrypt_old_key_recovery(_old_key(), _new_key(), "journal-x")
    entry = RotationJournalEntry.start(
        old_durable=_pbkdf_material(),
        new_durable=_pbkdf_material(),
        old_key_recovery=recovery,
    ).mark_db_committed(old_segment_id="seg-1")
    final = entry.mark_audit_checkpoint_committed()
    with pytest.raises(RotationJournalError, match="cannot mark audit checkpoint committed"):
        final.mark_audit_checkpoint_committed()


# ── coexistence with typed durable materials ─────────────────────────


def test_recovery_coexists_with_pbkdf_and_dpapi_materials() -> None:
    # A full v2 journal transition preserves every typed field: old and new
    # durable materials (both envelope kinds), journal id, and recovery.
    old_key = _old_key()
    new_key = _new_key()
    old_durable = _dpapi_material()
    new_durable = _pbkdf_material()
    entry = RotationJournalEntry.start(
        old_durable=old_durable,
        new_durable=new_durable,
        journal_id="journal-42",
    )
    recovery = encrypt_old_key_recovery(old_key, new_key, entry.journal_id)
    committed = entry.mark_db_committed(old_segment_id="seg-7", old_key_recovery=recovery)
    final = committed.mark_audit_checkpoint_committed()

    assert final.journal_id == "journal-42"
    assert final.old_durable.kind == DurableKind.dpapi_envelope
    assert final.old_durable.envelope_version == DPAPI_ENVELOPE_VERSION
    assert final.new_durable.kind == DurableKind.pbkdf_salt
    assert final.new_durable.salt is not None
    assert final.old_key_recovery is not None
    assert decrypt_old_key_recovery(final.old_key_recovery, new_key, final.journal_id) == old_key


def test_recovery_round_trip_via_journal_field_preserves_key() -> None:
    old_key = _old_key()
    new_key = _new_key()
    entry = RotationJournalEntry.start(
        old_durable=_pbkdf_material(),
        new_durable=_pbkdf_material(),
    )
    committed = entry.mark_db_committed(
        old_segment_id="seg-1",
        old_key_recovery=encrypt_old_key_recovery(old_key, new_key, entry.journal_id),
    )
    # The recovery material stored on the journal state decrypts to the
    # original old key with the new key and the same journal id.
    assert committed.old_key_recovery is not None
    assert decrypt_old_key_recovery(
        committed.old_key_recovery, new_key, committed.journal_id
    ) == old_key


def test_durable_material_helpers_still_round_trip() -> None:
    # Regression guard: the parent card's DurableMaterial hex/dict round
    # trips must keep working with the new module contents present.
    salt = os.urandom(16)
    material = DurableMaterial(kind=DurableKind.pbkdf_salt, salt=salt)
    assert DurableMaterial.from_dict(material.to_dict()).salt == salt

    envelope = DPAPI_HEADER + os.urandom(24)
    dpapi_material = DurableMaterial(kind=DurableKind.dpapi_envelope, envelope=envelope)
    restored = DurableMaterial.from_dict(dpapi_material.to_dict())
    assert restored.kind == DurableKind.dpapi_envelope
    assert restored.envelope == envelope
