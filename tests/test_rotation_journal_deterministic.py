"""Deterministic rotation-journal-v2 tests (Slice C, issues #58 / #66).

This file is the deterministic-test lane for the typed journal-v2 state
machine: every input is a fixed byte constant or a fixed string — no
``os.urandom``, no wall-clock dependence, and no OS-specific behavior.
The DPAPI envelope entries are tested through an *injectable envelope*
strategy: the journal only validates the envelope *shape* (``HVDP`` magic
plus a length gate) and never calls the Windows-only ``win32crypt``, so
tests feed fixed synthetic envelopes and get byte-identical behavior on
every platform, every run.

Coverage mapped to the card:

* DPAPI envelope entries — typed ``DurableMaterial`` with fixed envelope
  bytes, hex/dict round trips, envelope-kind rejection.
* PBKDF salt entries — fixed 16-byte salts, hex/dict round trips, salt
  size/kind rejection.
* Encrypted old-key recovery material — fixed old/new keys and journal id,
  plus an injected fixed nonce so the ciphertext is byte-deterministic;
  tamper/wrong-journal failures.
* Legacy v1 read — the checked-in ``rotation_journal_v1.json`` fixture and
  fixed inline v1 payloads, including DPAPI-envelope inference from bytes.
* Contradiction retention — fixed contradictory payloads produce a typed
  ``ContradictionMarker``; retaining the marker never touches the journal.
* Interrupted-audit reconciliation — fixed master keys drive the real
  ``AuditIntegrityService``; the replay regression proves replaying the
  same journal converges to the same state (no duplicate successor), and a
  lost-checkpoint interrupted audit resumes to the clean-rotation state.

The destructive ``recover_checkpoint`` /
``_rebuild_integrity_for_key_mismatch`` semantics in
:mod:`hermes_vault.audit_integrity.service` are intentionally not touched.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from hermes_vault.audit import AuditLogger
from hermes_vault.audit_integrity.service import AuditIntegrityError, AuditIntegrityService
from hermes_vault.dpapi import DPAPI_ENVELOPE_VERSION, DPAPI_HEADER
from hermes_vault.models import AccessLogRecord, Decision
from hermes_vault.rotation_journal import (
    JOURNAL_VERSION_V1,
    JOURNAL_VERSION_V2,
    AuditTransitionState,
    ContradictionKind,
    DurableKind,
    DurableMaterial,
    JournalPhase,
    JournalStatus,
    RotationJournalEntry,
    RotationJournalError,
    decrypt_old_key_recovery,
    encrypt_old_key_recovery,
    load_contradiction_marker,
    retain_contradiction_marker,
)

TESTDATA = Path(__file__).resolve().parent / "testdata"
V1_FIXTURE = TESTDATA / "rotation_journal_v1.json"

# ── Fixed inputs (no os.urandom anywhere in this file) ──────────────────────

#: Fixed 16-byte PBKDF derivation salt.
SALT_A = bytes.fromhex("00112233445566778899aabbccddeeff")
#: A second fixed 16-byte PBKDF derivation salt.
SALT_B = bytes.fromhex("ffeeddccbbaa99887766554433221100")
#: Fixed DPAPI envelope: 4-byte ``HVDP`` magic + 24 fixed payload bytes.
ENVELOPE_A = DPAPI_HEADER + bytes(range(24))
#: A second fixed DPAPI envelope.
ENVELOPE_B = DPAPI_HEADER + bytes(range(24, 48))
#: Fixed 32-byte pre-rotation (old) master key.
OLD_KEY = bytes(range(32))
#: Fixed 32-byte post-rotation (new) master key.
NEW_KEY = bytes(range(32, 64))
#: Fixed 12-byte AES-GCM nonce injected via monkeypatch for ciphertext determinism.
FIXED_NONCE = bytes(range(12))
#: Fixed journal id used across deterministic entries.
JOURNAL_ID = "det-journal-0001"
#: Fixed audit segment id used by deterministic reconcile fixtures.
OLD_SEGMENT_ID = "seg-det-0001"
#: Fixed ISO timestamps so serialized journals are byte-stable.
CREATED_AT = "2026-08-06T00:00:00+00:00"
COMMITTED_AT = "2026-08-06T00:01:00+00:00"


def _pbkdf_material(salt: bytes = SALT_A) -> DurableMaterial:
    return DurableMaterial(kind=DurableKind.pbkdf_salt, salt=salt)


def _dpapi_material(envelope: bytes = ENVELOPE_A) -> DurableMaterial:
    return DurableMaterial(kind=DurableKind.dpapi_envelope, envelope=envelope)


def _started_entry() -> RotationJournalEntry:
    return RotationJournalEntry.start(
        old_durable=_pbkdf_material(),
        new_durable=_pbkdf_material(),
        journal_id=JOURNAL_ID,
        created_at=__import__("datetime").datetime.fromisoformat(CREATED_AT),
    )


def _recovery() -> object:
    return encrypt_old_key_recovery(OLD_KEY, NEW_KEY, JOURNAL_ID)


# ── DPAPI envelope entries (injectable envelope: fixed bytes, no win32crypt) ─


def test_dpapi_envelope_entry_dict_round_trip_deterministic() -> None:
    material = _dpapi_material(ENVELOPE_A)
    assert material.kind == DurableKind.dpapi_envelope
    assert material.envelope == ENVELOPE_A
    assert material.envelope_version == DPAPI_ENVELOPE_VERSION

    payload = material.to_dict()
    assert payload == {
        "kind": "dpapi_envelope",
        "hex": ENVELOPE_A.hex(),
        "envelope_version": DPAPI_ENVELOPE_VERSION,
    }
    restored = DurableMaterial.from_dict(payload)
    assert restored == material
    assert restored.envelope == ENVELOPE_A
    assert restored.envelope_version == DPAPI_ENVELOPE_VERSION


def test_dpapi_envelope_entry_hex_round_trip_deterministic() -> None:
    material = _dpapi_material(ENVELOPE_B)
    assert material.to_hex() == ENVELOPE_B.hex()
    restored = DurableMaterial.from_hex(
        DurableKind.dpapi_envelope,
        material.to_hex(),
        envelope_version=DPAPI_ENVELOPE_VERSION,
    )
    assert restored.envelope == ENVELOPE_B
    assert restored.envelope_version == DPAPI_ENVELOPE_VERSION


def test_dpapi_envelope_kind_rejects_pbkdf_salt_bytes() -> None:
    # A DPAPI envelope kind over a plain 16-byte salt is unrepresentable.
    with pytest.raises(ValueError, match="must start with the DPAPI header"):
        DurableMaterial(kind=DurableKind.dpapi_envelope, envelope=SALT_A)


def test_dpapi_envelope_kind_rejects_header_only() -> None:
    with pytest.raises(ValueError, match="longer than the header"):
        DurableMaterial(kind=DurableKind.dpapi_envelope, envelope=DPAPI_HEADER)


def test_dpapi_envelope_kind_rejects_salt_field() -> None:
    with pytest.raises(ValueError, match="must not carry a PBKDF salt"):
        DurableMaterial(kind=DurableKind.dpapi_envelope, envelope=ENVELOPE_A, salt=SALT_A)


def test_dpapi_envelope_journal_round_trip_preserves_bytes() -> None:
    entry = RotationJournalEntry.start(
        old_durable=_dpapi_material(ENVELOPE_A),
        new_durable=_dpapi_material(ENVELOPE_B),
        journal_id=JOURNAL_ID,
    )
    restored = RotationJournalEntry.from_dict(entry.to_dict())
    assert restored == entry
    assert restored.old_durable.envelope == ENVELOPE_A
    assert restored.new_durable.envelope == ENVELOPE_B
    assert restored.to_json() == entry.to_json()  # byte-stable serialization


# ── PBKDF salt entries ──────────────────────────────────────────────────────


def test_pbkdf_salt_entry_dict_round_trip_deterministic() -> None:
    material = _pbkdf_material(SALT_A)
    assert material.salt == SALT_A
    assert material.envelope is None
    assert material.envelope_version is None

    payload = material.to_dict()
    assert payload == {"kind": "pbkdf_salt", "hex": SALT_A.hex(), "envelope_version": None}
    restored = DurableMaterial.from_dict(payload)
    assert restored == material
    assert restored.salt == SALT_A


def test_pbkdf_salt_entry_hex_round_trip_deterministic() -> None:
    material = _pbkdf_material(SALT_B)
    assert material.to_hex() == SALT_B.hex()
    restored = DurableMaterial.from_hex(DurableKind.pbkdf_salt, material.to_hex())
    assert restored.salt == SALT_B


def test_pbkdf_salt_kind_rejects_envelope_bytes() -> None:
    # Reverse mixing direction: a PBKDF kind over DPAPI envelope bytes fails.
    with pytest.raises(ValueError, match="must be 16 bytes"):
        DurableMaterial(kind=DurableKind.pbkdf_salt, salt=ENVELOPE_A)


def test_pbkdf_salt_kind_rejects_wrong_size() -> None:
    with pytest.raises(ValueError, match="must be 16 bytes"):
        DurableMaterial(kind=DurableKind.pbkdf_salt, salt=SALT_A[:12])


def test_pbkdf_salt_kind_rejects_envelope_field() -> None:
    with pytest.raises(ValueError, match="must not carry a DPAPI envelope"):
        DurableMaterial(kind=DurableKind.pbkdf_salt, salt=SALT_A, envelope=ENVELOPE_A)


def test_pbkdf_salt_kind_rejects_envelope_metadata() -> None:
    with pytest.raises(ValueError, match="must not carry DPAPI envelope metadata"):
        DurableMaterial(kind=DurableKind.pbkdf_salt, salt=SALT_A, envelope_version="dpapi-v1")


def test_pbkdf_salt_journal_round_trip_preserves_salt() -> None:
    entry = RotationJournalEntry.start(
        old_durable=_pbkdf_material(SALT_A),
        new_durable=_pbkdf_material(SALT_B),
        journal_id=JOURNAL_ID,
    )
    restored = RotationJournalEntry.from_dict(entry.to_dict())
    assert restored == entry
    assert restored.old_durable.salt == SALT_A
    assert restored.new_durable.salt == SALT_B


# ── Encrypted old-key recovery material ─────────────────────────────────────


def test_recovery_encrypt_decrypt_round_trip_fixed_keys() -> None:
    recovery = encrypt_old_key_recovery(OLD_KEY, NEW_KEY, JOURNAL_ID)
    assert decrypt_old_key_recovery(recovery, NEW_KEY, JOURNAL_ID) == OLD_KEY


def test_recovery_never_stores_plaintext_key() -> None:
    recovery = encrypt_old_key_recovery(OLD_KEY, NEW_KEY, JOURNAL_ID)
    assert recovery.ciphertext != OLD_KEY
    assert OLD_KEY not in recovery.ciphertext
    payload = recovery.to_dict()
    assert payload["ciphertext"] != OLD_KEY.hex()
    assert "passphrase" not in payload
    assert "key" not in payload


def test_recovery_deterministic_with_injected_nonce(monkeypatch: pytest.MonkeyPatch) -> None:
    # Inject a fixed nonce so the AES-GCM output is byte-deterministic:
    # same keys + same journal id + same nonce -> identical ciphertext.
    monkeypatch.setattr("os.urandom", lambda n: FIXED_NONCE[:n])
    first = encrypt_old_key_recovery(OLD_KEY, NEW_KEY, JOURNAL_ID)
    second = encrypt_old_key_recovery(OLD_KEY, NEW_KEY, JOURNAL_ID)
    assert first.nonce == FIXED_NONCE
    assert first.ciphertext == second.ciphertext
    # And the deterministic envelope still decrypts to the old key.
    assert decrypt_old_key_recovery(first, NEW_KEY, JOURNAL_ID) == OLD_KEY


def test_recovery_wrong_key_fails_fixed() -> None:
    recovery = encrypt_old_key_recovery(OLD_KEY, NEW_KEY, JOURNAL_ID)
    with pytest.raises(InvalidTag):
        decrypt_old_key_recovery(recovery, OLD_KEY, JOURNAL_ID)


def test_recovery_wrong_journal_id_fails_fixed() -> None:
    recovery = encrypt_old_key_recovery(OLD_KEY, NEW_KEY, JOURNAL_ID)
    with pytest.raises(InvalidTag):
        decrypt_old_key_recovery(recovery, NEW_KEY, "det-journal-9999")


def test_recovery_tampered_ciphertext_fails_fixed() -> None:
    recovery = encrypt_old_key_recovery(OLD_KEY, NEW_KEY, JOURNAL_ID)
    tampered = recovery.model_copy(
        update={"ciphertext": recovery.ciphertext[:-1] + bytes([recovery.ciphertext[-1] ^ 0x01])}
    )
    with pytest.raises(InvalidTag):
        decrypt_old_key_recovery(tampered, NEW_KEY, JOURNAL_ID)


def test_recovery_round_trip_through_journal_state() -> None:
    entry = _started_entry()
    recovery = encrypt_old_key_recovery(OLD_KEY, NEW_KEY, entry.journal_id)
    committed = entry.mark_db_committed(
        old_segment_id=OLD_SEGMENT_ID,
        old_key_recovery=recovery,
        committed_at=__import__("datetime").datetime.fromisoformat(COMMITTED_AT),
    )
    assert committed.phase() == JournalPhase.db_committed_pending
    assert committed.old_key_recovery is not None
    assert decrypt_old_key_recovery(committed.old_key_recovery, NEW_KEY, committed.journal_id) == OLD_KEY
    restored = RotationJournalEntry.from_dict(committed.to_dict())
    assert restored.old_key_recovery is not None
    assert decrypt_old_key_recovery(restored.old_key_recovery, NEW_KEY, restored.journal_id) == OLD_KEY


# ── Legacy v1 read ──────────────────────────────────────────────────────────


def test_v1_fixture_reads_without_data_loss_deterministic() -> None:
    raw = V1_FIXTURE.read_text(encoding="utf-8")
    payload = json.loads(raw)
    entry = RotationJournalEntry.from_json(raw)

    assert entry.version == JOURNAL_VERSION_V2  # upgraded in memory
    assert entry.status == JournalStatus.db_committed
    assert entry.audit_transition_state == AuditTransitionState.pending
    assert entry.old_segment_id == payload["old_segment_id"]
    assert entry.to_dict()["old_salt"] == payload["old_salt"]
    assert entry.to_dict()["new_salt"] == payload["new_salt"]
    assert entry.created_at.isoformat() == payload["created_at"]
    assert entry.committed_at is not None
    assert entry.committed_at.isoformat() == payload["committed_at"]
    assert entry.old_durable.kind == DurableKind.pbkdf_salt
    assert entry.old_durable.salt == bytes.fromhex(payload["old_salt"])
    assert entry.new_durable.kind == DurableKind.pbkdf_salt


def _v1_payload(*, old_hex: str, new_hex: str, status: str = "started") -> dict[str, str]:
    payload: dict[str, str] = {
        "version": JOURNAL_VERSION_V1,
        "status": status,
        "old_salt": old_hex,
        "new_salt": new_hex,
        "created_at": CREATED_AT,
    }
    if status == "db_committed":
        payload["committed_at"] = COMMITTED_AT
        payload["audit_transition_state"] = "pending"
        payload["old_segment_id"] = OLD_SEGMENT_ID
    return payload


def test_v1_pbkdf_backward_read_fixed() -> None:
    payload = _v1_payload(old_hex=SALT_A.hex(), new_hex=SALT_B.hex())
    entry = RotationJournalEntry.from_dict(payload)
    assert entry.version == JOURNAL_VERSION_V2
    assert entry.status == JournalStatus.started
    assert entry.old_durable.kind == DurableKind.pbkdf_salt
    assert entry.old_durable.salt == SALT_A
    assert entry.new_durable.salt == SALT_B
    assert entry.to_dict()["old_salt"] == SALT_A.hex()  # hex preserved exactly


def test_v1_dpapi_envelope_backward_read_infers_kind_fixed() -> None:
    payload = _v1_payload(old_hex=ENVELOPE_A.hex(), new_hex=SALT_A.hex())
    entry = RotationJournalEntry.from_dict(payload)
    assert entry.old_durable.kind == DurableKind.dpapi_envelope
    assert entry.old_durable.envelope == ENVELOPE_A
    assert entry.new_durable.kind == DurableKind.pbkdf_salt
    assert entry.new_durable.salt == SALT_A


def test_v1_db_committed_backward_read_fixed() -> None:
    payload = _v1_payload(old_hex=SALT_A.hex(), new_hex=SALT_B.hex(), status="db_committed")
    entry = RotationJournalEntry.from_dict(payload)
    assert entry.status == JournalStatus.db_committed
    assert entry.audit_transition_state == AuditTransitionState.pending
    assert entry.old_segment_id == OLD_SEGMENT_ID
    assert entry.committed_at is not None
    assert entry.committed_at.isoformat() == COMMITTED_AT


def test_v1_ambiguous_bytes_fail_closed_fixed() -> None:
    # 12 bytes that are neither a 16-byte salt nor a valid HVDP envelope.
    ambiguous = bytes(range(12))
    payload = _v1_payload(old_hex=ambiguous.hex(), new_hex=ambiguous.hex())
    with pytest.raises(RotationJournalError):
        RotationJournalEntry.from_dict(payload)


# ── Contradiction retention ─────────────────────────────────────────────────


def test_contradiction_marker_attached_for_ambiguous_v1_fixed() -> None:
    ambiguous = bytes(range(12))
    payload = _v1_payload(old_hex=ambiguous.hex(), new_hex=ambiguous.hex())
    with pytest.raises(RotationJournalError) as excinfo:
        RotationJournalEntry.from_dict(payload)
    marker = excinfo.value.marker
    assert marker is not None
    assert marker.kind == ContradictionKind.ambiguous_durable
    assert marker.declared_version == JOURNAL_VERSION_V1
    assert marker.field == "old_salt"


def test_retain_contradiction_marker_keeps_journal_byte_identical(tmp_path: Path) -> None:
    journal_path = tmp_path / "rotation-journal.json"
    original = json.dumps(
        _v1_payload(old_hex=bytes(range(12)).hex(), new_hex=bytes(range(12)).hex()),
        sort_keys=True,
    )
    journal_path.write_text(original, encoding="utf-8")

    with pytest.raises(RotationJournalError) as excinfo:
        RotationJournalEntry.from_json(original)
    assert excinfo.value.marker is not None

    marker_path = retain_contradiction_marker(journal_path, excinfo.value.marker)

    # The original journal is never truncated or rewritten.
    assert journal_path.read_text(encoding="utf-8") == original
    assert marker_path.name == "rotation-journal.json.contradiction.json"
    marker_payload = json.loads(marker_path.read_text(encoding="utf-8"))
    assert marker_payload["journal_file"] == journal_path.name
    assert marker_payload["marker"]["kind"] == ContradictionKind.ambiguous_durable.value
    assert marker_payload["marker"]["declared_version"] == JOURNAL_VERSION_V1
    assert "detected_at" in marker_payload["marker"]


def test_retain_marker_idempotent_sidecar_only(tmp_path: Path) -> None:
    journal_path = tmp_path / "rotation-journal.json"
    original = json.dumps(
        _v1_payload(old_hex=bytes(range(12)).hex(), new_hex=bytes(range(12)).hex()),
        sort_keys=True,
    )
    journal_path.write_text(original, encoding="utf-8")

    marker = __import__("hermes_vault.rotation_journal", fromlist=["ContradictionMarker"]).ContradictionMarker(
        kind=ContradictionKind.kind_conflict,
        message="first detection",
        field="old_salt",
        declared_version=JOURNAL_VERSION_V2,
    )
    retain_contradiction_marker(journal_path, marker)

    loaded = load_contradiction_marker(journal_path.with_name("rotation-journal.json.contradiction.json"))
    assert loaded.kind == ContradictionKind.kind_conflict
    # The journal is untouched.
    assert journal_path.read_text(encoding="utf-8") == original


# ── Interrupted-audit reconciliation (fixed keys, real sqlite) ──────────────


def _make_audit_logger(tmp_path: Path, master_key: bytes = OLD_KEY) -> AuditLogger:
    return AuditLogger(tmp_path / "vault.db", master_key=master_key)


def _record(logger: AuditLogger, reason: str = "allowed") -> None:
    logger.record(
        AccessLogRecord(
            agent_id="det-agent",
            service="openai",
            action="get_env",
            decision=Decision.allow,
            reason=reason,
            metadata={"ticket": "fixed"},
        )
    )


def _pending_journal(
    old_segment_id: str,
    old_key: bytes = OLD_KEY,
    new_key: bytes = NEW_KEY,
    journal_id: str = JOURNAL_ID,
) -> RotationJournalEntry:
    """Typed v2 journal in the exact state a rotation leaves at interruption."""
    entry = RotationJournalEntry.start(
        old_durable=_pbkdf_material(),
        new_durable=_pbkdf_material(),
        journal_id=journal_id,
        created_at=__import__("datetime").datetime.fromisoformat(CREATED_AT),
    )
    recovery = encrypt_old_key_recovery(old_key, new_key, entry.journal_id)
    return entry.mark_db_committed(
        old_segment_id=old_segment_id,
        old_key_recovery=recovery,
        committed_at=__import__("datetime").datetime.fromisoformat(COMMITTED_AT),
    )


def _segment_count(tmp_path: Path) -> int:
    with sqlite3.connect(tmp_path / "vault.db") as conn:
        return conn.execute("SELECT COUNT(*) FROM audit_integrity_segments").fetchone()[0]


def test_reconcile_completes_interrupted_rotation_fixed_keys(tmp_path: Path) -> None:
    logger = _make_audit_logger(tmp_path)
    _record(logger)
    _record(logger)
    old_segment_id = logger.integrity.verify().active_segment_id  # type: ignore[union-attr]
    assert old_segment_id is not None
    journal = _pending_journal(old_segment_id)  # type: ignore[arg-type]

    service = AuditIntegrityService(tmp_path / "vault.db", NEW_KEY)
    before = service.verify()
    assert before.status.value == "failed"
    assert before.reason_code == "active_key_mismatch"

    result = service.recover_pending_rotation(journal, old_master_key=OLD_KEY)

    assert result.status.value == "healthy"
    assert result.active_segment_number == 2
    assert result.verified_count == 2
    assert _segment_count(tmp_path) == 2


def test_reconcile_replay_converges_same_state(tmp_path: Path) -> None:
    """REPLAY REGRESSION: replaying the same journal must converge."""
    logger = _make_audit_logger(tmp_path)
    _record(logger)
    _record(logger)
    old_segment_id = logger.integrity.verify().active_segment_id  # type: ignore[union-attr]
    journal = _pending_journal(old_segment_id)  # type: ignore[arg-type]

    first = AuditIntegrityService(tmp_path / "vault.db", NEW_KEY)
    result1 = first.recover_pending_rotation(journal, old_master_key=OLD_KEY)
    assert result1.status.value == "healthy"
    active_after_first = result1.active_segment_id

    # Replay the identical journal: same active segment, no duplicate successor.
    again = AuditIntegrityService(tmp_path / "vault.db", NEW_KEY)
    result2 = again.recover_pending_rotation(journal, old_master_key=OLD_KEY)
    assert result2.status.value == "healthy"
    assert result2.active_segment_id == active_after_first
    assert result2.active_segment_number == 2
    assert _segment_count(tmp_path) == 2


def test_reconcile_thrice_replay_keeps_same_state(tmp_path: Path) -> None:
    logger = _make_audit_logger(tmp_path)
    _record(logger)
    _record(logger)
    _record(logger)
    old_segment_id = logger.integrity.verify().active_segment_id  # type: ignore[union-attr]
    journal = _pending_journal(old_segment_id)  # type: ignore[arg-type]

    results = [
        AuditIntegrityService(tmp_path / "vault.db", NEW_KEY)
        .recover_pending_rotation(journal, old_master_key=OLD_KEY)
        .active_segment_id
        for _ in range(3)
    ]
    assert results[0] == results[1] == results[2]
    assert _segment_count(tmp_path) == 2


def test_reconcile_resumes_interrupted_audit_same_state(tmp_path: Path) -> None:
    """A lost checkpoint after segment commit resumes to the clean state."""
    logger = _make_audit_logger(tmp_path)
    _record(logger)
    _record(logger)
    old_segment_id = logger.integrity.verify().active_segment_id  # type: ignore[union-attr]

    # Clean rotation creates the successor and writes the checkpoint.
    clean_service = AuditIntegrityService(tmp_path / "vault.db", OLD_KEY)
    clean_service.rotate_segment(NEW_KEY)
    clean_active = clean_service.verify().active_segment_id
    assert _segment_count(tmp_path) == 2

    # Simulate interruption: segment commit done, checkpoint write lost.
    checkpoint = tmp_path / "audit.checkpoint.json"
    checkpoint.unlink()
    interrupted = AuditIntegrityService(tmp_path / "vault.db", NEW_KEY)
    before = interrupted.verify()
    assert before.status.value == "incomplete"

    journal = _pending_journal(old_segment_id)  # type: ignore[arg-type]
    result = interrupted.recover_pending_rotation(journal, old_master_key=OLD_KEY)

    assert result.status.value == "healthy"
    assert result.active_segment_id == clean_active
    assert result.active_segment_number == 2
    assert _segment_count(tmp_path) == 2


def test_reconcile_contradictory_journal_fails_closed(tmp_path: Path) -> None:
    logger = _make_audit_logger(tmp_path)
    _record(logger)
    journal = _pending_journal("seg-does-not-exist")

    service = AuditIntegrityService(tmp_path / "vault.db", NEW_KEY)
    before = service.verify()

    with pytest.raises(AuditIntegrityError, match="contradictory"):
        service.recover_pending_rotation(journal, old_master_key=OLD_KEY)

    # Nothing was mutated: same segments, same verify result.
    assert _segment_count(tmp_path) == 1
    after = service.verify()
    assert after.status is before.status
    assert after.reason_code == before.reason_code


def test_reconcile_wrong_old_key_fails_closed(tmp_path: Path) -> None:
    logger = _make_audit_logger(tmp_path)
    _record(logger)
    old_segment_id = logger.integrity.verify().active_segment_id  # type: ignore[union-attr]
    journal = _pending_journal(old_segment_id)  # type: ignore[arg-type]

    service = AuditIntegrityService(tmp_path / "vault.db", NEW_KEY)
    with pytest.raises(AuditIntegrityError, match="contradictory|old key"):
        service.recover_pending_rotation(journal, old_master_key=bytes(range(64, 96)))


def test_reconcile_started_journal_fails_closed(tmp_path: Path) -> None:
    logger = _make_audit_logger(tmp_path)
    _record(logger)
    entry = _started_entry()

    service = AuditIntegrityService(tmp_path / "vault.db", NEW_KEY)
    with pytest.raises(AuditIntegrityError, match="started"):
        service.recover_pending_rotation(entry, old_master_key=OLD_KEY)


def test_reconcile_checkpoint_committed_journal_is_noop(tmp_path: Path) -> None:
    logger = _make_audit_logger(tmp_path)
    _record(logger)
    old_segment_id = logger.integrity.verify().active_segment_id  # type: ignore[union-attr]

    clean = AuditIntegrityService(tmp_path / "vault.db", OLD_KEY)
    clean.rotate_segment(NEW_KEY)
    segments_before = _segment_count(tmp_path)

    entry = _pending_journal(old_segment_id).mark_audit_checkpoint_committed()  # type: ignore[arg-type]
    assert entry.phase() == JournalPhase.checkpoint_committed

    service = AuditIntegrityService(tmp_path / "vault.db", NEW_KEY)
    result = service.recover_pending_rotation(entry, old_master_key=OLD_KEY)
    assert result.status.value == "healthy"
    assert _segment_count(tmp_path) == segments_before
