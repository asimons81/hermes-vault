"""Focused unit tests for v1 backward compatibility and contradiction retention.

Covers the S1 shared seam from INTEGRITY_RECOVERY_PLAN.md, Slice C
(issues #58 / #66), as scoped to this card: the v1 backward-compat read
plus the fail-closed contradiction path that *retains* the original journal
and records an explicit contradiction marker beside it.

Acceptance covered here:

* A v1 fixture reads without data loss — the legacy ``rotation-journal-v1``
  fixture under ``tests/testdata/rotation_journal_v1.json`` (the exact shape
  written by ``Vault.rotate_master_key`` pre-v2) deserializes through
  ``RotationJournalEntry.from_json`` with every field preserved.
* A contradiction leaves the original journal intact and records a clear
  marker — for each contradiction class (version/kind/durable/state) the
  ``RotationJournalError`` carries a :class:`ContradictionMarker` on
  ``err.marker``; retaining that marker writes a
  ``<journal>.contradiction.json`` file beside the original journal without
  truncating, rewriting, or deleting the journal itself (Slice C retention
  rule).
* The marker file round-trips through :func:`load_contradiction_marker` and
  the marker model serializes deterministically.

The destructive ``recover_checkpoint`` /
``_rebuild_integrity_for_key_mismatch`` semantics in
:mod:`hermes_vault.audit_integrity.service` are intentionally not touched by
this workstream and no test here depends on them.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hermes_vault.dpapi import DPAPI_HEADER
from hermes_vault.rotation_journal import (
    CONTRADICTION_MARKER_SCHEMA,
    JOURNAL_VERSION_V1,
    JOURNAL_VERSION_V2,
    AuditTransitionState,
    ContradictionKind,
    ContradictionMarker,
    DurableKind,
    JournalStatus,
    RotationJournalEntry,
    RotationJournalError,
    contradiction_error,
    load_contradiction_marker,
    retain_contradiction_marker,
)

TESTDATA = Path(__file__).resolve().parent / "testdata"
V1_FIXTURE = TESTDATA / "rotation_journal_v1.json"


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


# ── acceptance: a v1 fixture reads without data loss ───────────────────


def test_v1_fixture_reads_without_data_loss() -> None:
    raw = V1_FIXTURE.read_text(encoding="utf-8")
    payload = json.loads(raw)
    entry = RotationJournalEntry.from_json(raw)

    # Upgraded in memory but every v1 field survives exactly.
    assert entry.version == JOURNAL_VERSION_V2
    assert entry.status == JournalStatus.db_committed
    assert entry.audit_transition_state == AuditTransitionState.pending
    assert entry.old_segment_id == payload["old_segment_id"]
    assert entry.to_dict()["old_salt"] == payload["old_salt"]
    assert entry.to_dict()["new_salt"] == payload["new_salt"]
    assert entry.created_at.isoformat() == payload["created_at"]
    assert entry.committed_at is not None
    assert entry.committed_at.isoformat() == payload["committed_at"]
    assert entry.old_durable.kind == DurableKind.pbkdf_salt
    assert entry.new_durable.kind == DurableKind.pbkdf_salt


def test_v1_fixture_ingests_into_state_machine() -> None:
    raw = V1_FIXTURE.read_text(encoding="utf-8")
    entry = RotationJournalEntry.from_json(raw)
    # The upgraded entry participates in the v2 state machine: phase
    # derivation works, and the pending transition can move forward.
    from hermes_vault.rotation_journal import JournalPhase

    assert entry.phase() == JournalPhase.db_committed_pending
    committed = entry.mark_audit_checkpoint_committed()
    assert committed.audit_transition_state == AuditTransitionState.checkpoint_committed
    assert committed.phase() == JournalPhase.checkpoint_committed
    # The v1-sourced entry keeps its original identity and segment linkage.
    assert committed.old_segment_id == entry.old_segment_id
    assert committed.created_at == entry.created_at


def test_v1_fixture_upgraded_entry_is_not_repersisted_as_v2_without_recovery() -> None:
    # A v1 db_committed/pending journal predates old_key_recovery, so the
    # in-memory upgrade carries none; serializing it back as v2 JSON and
    # re-reading must fail closed (v2 invariant: pending requires recovery
    # material) rather than silently manufacturing a v2 journal that the
    # recovery flow would trust.
    raw = V1_FIXTURE.read_text(encoding="utf-8")
    entry = RotationJournalEntry.from_json(raw)
    assert entry.old_key_recovery is None
    with pytest.raises(RotationJournalError, match="requires old_key_recovery"):
        RotationJournalEntry.from_json(entry.to_json())


# ── contradiction classes carry a marker on the error ──────────────────


def test_v1_ambiguous_durable_error_carries_marker() -> None:
    payload = _v1_payload(old_hex=os.urandom(12).hex(), new_hex=os.urandom(12).hex())
    with pytest.raises(RotationJournalError) as excinfo:
        RotationJournalEntry.from_dict(payload)
    assert excinfo.value.marker is not None
    assert excinfo.value.marker.kind == ContradictionKind.ambiguous_durable
    assert excinfo.value.marker.declared_version == JOURNAL_VERSION_V1
    assert excinfo.value.marker.field == "old_salt"


def test_v1_state_conflict_error_carries_marker() -> None:
    payload = _v1_payload(old_hex=os.urandom(16).hex(), new_hex=os.urandom(16).hex())
    payload["audit_transition_state"] = "pending"  # illegal on a started journal
    with pytest.raises(RotationJournalError) as excinfo:
        RotationJournalEntry.from_dict(payload)
    assert excinfo.value.marker is not None
    assert excinfo.value.marker.kind == ContradictionKind.state_conflict
    assert excinfo.value.marker.declared_version == JOURNAL_VERSION_V1


def test_v1_with_v2_only_fields_error_carries_marker() -> None:
    # A v1 payload carrying a v2-only typed discriminator mixes v1/v2
    # semantics -> version_conflict with a marker (Slice C retention).
    payload = _v1_payload(old_hex=os.urandom(16).hex(), new_hex=os.urandom(16).hex())
    payload["old_durable_type"] = DurableKind.pbkdf_salt.value
    with pytest.raises(RotationJournalError) as excinfo:
        RotationJournalEntry.from_dict(payload)
    assert excinfo.value.marker is not None
    assert excinfo.value.marker.kind == ContradictionKind.version_conflict
    assert excinfo.value.marker.declared_version == JOURNAL_VERSION_V1
    assert excinfo.value.marker.field == "old_durable_type"


def test_v2_kind_conflict_error_carries_marker() -> None:
    payload = {
        "version": JOURNAL_VERSION_V2,
        "status": "started",
        "old_salt": os.urandom(16).hex(),
        "new_salt": os.urandom(16).hex(),
        "old_durable_type": DurableKind.dpapi_envelope.value,
        "new_durable_type": DurableKind.dpapi_envelope.value,
    }
    with pytest.raises(RotationJournalError) as excinfo:
        RotationJournalEntry.from_dict(payload)
    assert excinfo.value.marker is not None
    assert excinfo.value.marker.kind == ContradictionKind.kind_conflict
    assert excinfo.value.marker.declared_version == JOURNAL_VERSION_V2


def test_unknown_version_error_carries_marker() -> None:
    payload = {
        "version": "rotation-journal-v3",
        "status": "started",
        "old_salt": os.urandom(16).hex(),
        "new_salt": os.urandom(16).hex(),
        "old_durable_type": DurableKind.pbkdf_salt.value,
        "new_durable_type": DurableKind.pbkdf_salt.value,
    }
    with pytest.raises(RotationJournalError) as excinfo:
        RotationJournalEntry.from_dict(payload)
    assert excinfo.value.marker is not None
    assert excinfo.value.marker.kind == ContradictionKind.version_conflict
    assert excinfo.value.marker.declared_version == "rotation-journal-v3"


def test_contradiction_error_helper_attaches_marker() -> None:
    err = contradiction_error(
        "boom",
        kind=ContradictionKind.state_conflict,
        field="status",
        declared_version=JOURNAL_VERSION_V1,
    )
    assert isinstance(err, RotationJournalError)
    assert err.marker is not None
    assert err.marker.kind == ContradictionKind.state_conflict
    assert err.marker.field == "status"
    assert err.marker.declared_version == JOURNAL_VERSION_V1
    assert "boom" in err.marker.message


# ── retention: original journal intact + clear marker written ──────────


def test_retain_marker_keeps_journal_byte_identical(tmp_path: Path) -> None:
    journal_path = tmp_path / "rotation-journal.json"
    original = json.dumps(
        _v1_payload(old_hex=os.urandom(12).hex(), new_hex=os.urandom(12).hex()),
        sort_keys=True,
    )
    journal_path.write_text(original, encoding="utf-8")

    with pytest.raises(RotationJournalError) as excinfo:
        RotationJournalEntry.from_json(original)
    assert excinfo.value.marker is not None

    marker_path = retain_contradiction_marker(journal_path, excinfo.value.marker)

    # The original journal is untouched — never truncated or deleted.
    assert journal_path.read_text(encoding="utf-8") == original
    assert journal_path.exists()

    # The marker file records the conflict beside the journal.
    assert marker_path == journal_path.with_name(f"{journal_path.name}.contradiction.json")
    marker_payload = json.loads(marker_path.read_text(encoding="utf-8"))
    assert marker_payload["schema"] == CONTRADICTION_MARKER_SCHEMA
    assert marker_payload["journal_file"] == journal_path.name
    assert marker_payload["marker"]["kind"] == ContradictionKind.ambiguous_durable.value
    assert marker_payload["marker"]["declared_version"] == JOURNAL_VERSION_V1
    assert "message" in marker_payload["marker"]
    assert "detected_at" in marker_payload["marker"]


def test_load_marker_round_trip(tmp_path: Path) -> None:
    marker = ContradictionMarker(
        kind=ContradictionKind.kind_conflict,
        message="declared dpapi over pbkdf bytes",
        field="old_salt",
        declared_version=JOURNAL_VERSION_V2,
    )
    journal_path = tmp_path / "rotation-journal.json"
    marker_path = retain_contradiction_marker(journal_path, marker)
    loaded = load_contradiction_marker(marker_path)
    assert loaded == marker
    assert loaded.kind == ContradictionKind.kind_conflict
    assert loaded.field == "old_salt"
    assert loaded.declared_version == JOURNAL_VERSION_V2
    assert loaded.message == marker.message


def test_marker_dict_round_trip() -> None:
    marker = ContradictionMarker(
        kind=ContradictionKind.version_conflict,
        message="mixed semantics",
        field="version",
        declared_version=JOURNAL_VERSION_V1,
    )
    restored = ContradictionMarker.from_dict(marker.to_dict())
    assert restored == marker


def test_load_marker_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(RotationJournalError, match="unreadable"):
        load_contradiction_marker(tmp_path / "nope.json")


def test_load_marker_rejects_unknown_schema(tmp_path: Path) -> None:
    marker_path = tmp_path / "bad.json"
    marker_path.write_text('{"schema": "something-else"}', encoding="utf-8")
    with pytest.raises(RotationJournalError, match="unknown schema"):
        load_contradiction_marker(marker_path)


def test_load_marker_rejects_invalid_payload(tmp_path: Path) -> None:
    marker_path = tmp_path / "bad.json"
    marker_path.write_text(
        json.dumps({"schema": CONTRADICTION_MARKER_SCHEMA, "marker": {"kind": "nope"}}),
        encoding="utf-8",
    )
    with pytest.raises(RotationJournalError, match="invalid contradiction marker payload"):
        load_contradiction_marker(marker_path)


# ── retention is idempotent: newest detection wins, journal never touched ─


def test_retain_marker_idempotent_overwrites_sidecar_only(tmp_path: Path) -> None:
    journal_path = tmp_path / "rotation-journal.json"
    original = json.dumps(
        _v1_payload(old_hex=os.urandom(12).hex(), new_hex=os.urandom(12).hex()),
        sort_keys=True,
    )
    journal_path.write_text(original, encoding="utf-8")

    first = ContradictionMarker(
        kind=ContradictionKind.ambiguous_durable,
        message="first detection",
        declared_version=JOURNAL_VERSION_V1,
    )
    retain_contradiction_marker(journal_path, first)
    second = ContradictionMarker(
        kind=ContradictionKind.state_conflict,
        message="second detection",
        field="status",
        declared_version=JOURNAL_VERSION_V1,
    )
    marker_path = retain_contradiction_marker(journal_path, second)

    assert journal_path.read_text(encoding="utf-8") == original
    loaded = load_contradiction_marker(marker_path)
    assert loaded.kind == ContradictionKind.state_conflict
    assert loaded.message == "second detection"


# ── v1 fixture sanity: DPAPI inference on the fixture's sibling payloads ─


def test_v1_dpapi_envelope_bytes_infer_dpapi_kind() -> None:
    envelope = DPAPI_HEADER + os.urandom(24)
    salt = os.urandom(16)
    payload = _v1_payload(old_hex=envelope.hex(), new_hex=salt.hex())
    entry = RotationJournalEntry.from_dict(payload)
    assert entry.old_durable.kind == DurableKind.dpapi_envelope
    assert entry.old_durable.envelope == envelope
    assert entry.new_durable.kind == DurableKind.pbkdf_salt
    assert entry.new_durable.salt == salt
