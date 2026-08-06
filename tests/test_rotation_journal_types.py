"""Unit tests for the typed rotation-journal-v2 entry types.

Covers the S1 shared seam from INTEGRITY_RECOVERY_PLAN.md, Slice C
(issues #58 / #66), as scoped to this card: the explicit typed v2 journal
entry types — :class:`DurableKind` / :class:`DurableMaterial` — for the
DPAPI envelope and PBKDF salt durable modes, discriminated by envelope
kind, with the required salt field for PBKDF entries and DPAPI envelope
metadata fields. Round-trip preservation through hex and dict forms is
covered here because the acceptance criterion for the types is that they
expose the fields needed for a round trip.

The encrypted old-key recovery material, the typed journal record, and the
journal-level serialize/deserialize and state-transition helpers are added
by downstream slices and have their own tests. The destructive
``recover_checkpoint`` semantics live in
:mod:`hermes_vault.audit_integrity.service` and are intentionally not
touched — no test here exercises or depends on them.
"""

from __future__ import annotations

import os

import pytest

from hermes_vault.dpapi import DPAPI_ENVELOPE_VERSION, DPAPI_HEADER
from hermes_vault.rotation_journal import (
    JOURNAL_VERSION_V1,
    JOURNAL_VERSION_V2,
    DurableKind,
    DurableMaterial,
    RotationJournalError,
    looks_like_dpapi_envelope,
)


# ── DurableKind discriminator ───────────────────────────────────────


def test_durable_kind_values() -> None:
    assert DurableKind.pbkdf_salt.value == "pbkdf_salt"
    assert DurableKind.dpapi_envelope.value == "dpapi_envelope"


def test_journal_version_labels() -> None:
    assert JOURNAL_VERSION_V1 == "rotation-journal-v1"
    assert JOURNAL_VERSION_V2 == "rotation-journal-v2"


# ── DurableMaterial: per-kind validation ────────────────────────────


def test_pbkdf_salt_material_requires_salt() -> None:
    with pytest.raises(ValueError, match="requires a salt"):
        DurableMaterial(kind=DurableKind.pbkdf_salt)


def test_pbkdf_salt_material_rejects_envelope() -> None:
    with pytest.raises(ValueError, match="must not carry a DPAPI envelope"):
        DurableMaterial(
            kind=DurableKind.pbkdf_salt,
            salt=os.urandom(16),
            envelope=DPAPI_HEADER + os.urandom(24),
        )


def test_pbkdf_salt_material_rejects_wrong_salt_size() -> None:
    with pytest.raises(ValueError, match="must be 16 bytes"):
        DurableMaterial(kind=DurableKind.pbkdf_salt, salt=os.urandom(12))


def test_dpapi_envelope_material_requires_envelope() -> None:
    with pytest.raises(ValueError, match="requires an envelope"):
        DurableMaterial(kind=DurableKind.dpapi_envelope)


def test_dpapi_envelope_material_rejects_salt() -> None:
    with pytest.raises(ValueError, match="must not carry a PBKDF salt"):
        DurableMaterial(
            kind=DurableKind.dpapi_envelope,
            envelope=DPAPI_HEADER + os.urandom(24),
            salt=os.urandom(16),
        )


def test_dpapi_envelope_material_rejects_bad_header() -> None:
    with pytest.raises(ValueError, match="must start with the DPAPI header"):
        DurableMaterial(kind=DurableKind.dpapi_envelope, envelope=b"XXXX" + os.urandom(24))


def test_dpapi_envelope_material_rejects_header_only() -> None:
    with pytest.raises(ValueError, match="longer than the header"):
        DurableMaterial(kind=DurableKind.dpapi_envelope, envelope=DPAPI_HEADER)


def test_dpapi_envelope_material_defaults_version() -> None:
    material = DurableMaterial(
        kind=DurableKind.dpapi_envelope,
        envelope=DPAPI_HEADER + os.urandom(24),
    )
    assert material.envelope_version == DPAPI_ENVELOPE_VERSION
    assert material.length == len(DPAPI_HEADER) + 24


def test_pbkdf_salt_material_exposes_salt_field() -> None:
    salt = os.urandom(16)
    material = DurableMaterial(kind=DurableKind.pbkdf_salt, salt=salt)
    assert material.salt == salt
    assert material.envelope is None
    assert material.envelope_version is None
    assert material.length is None


def test_extra_fields_forbidden() -> None:
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        DurableMaterial(
            kind=DurableKind.pbkdf_salt,
            salt=os.urandom(16),
            unexpected="nope",
        )


# ── looks_like_dpapi_envelope ───────────────────────────────────────


def test_looks_like_dpapi_envelope() -> None:
    assert looks_like_dpapi_envelope(DPAPI_HEADER + os.urandom(24))
    assert not looks_like_dpapi_envelope(DPAPI_HEADER)  # header only, not an envelope
    assert not looks_like_dpapi_envelope(os.urandom(16))  # random salt


# ── DurableMaterial: hex round trips ────────────────────────────────


def test_pbkdf_durable_material_hex_round_trip() -> None:
    salt = os.urandom(16)
    material = DurableMaterial(kind=DurableKind.pbkdf_salt, salt=salt)
    assert material.to_hex() == salt.hex()
    restored = DurableMaterial.from_hex(DurableKind.pbkdf_salt, material.to_hex())
    assert restored.kind == DurableKind.pbkdf_salt
    assert restored.salt == salt
    assert restored.envelope is None


def test_dpapi_durable_material_hex_round_trip() -> None:
    envelope = DPAPI_HEADER + os.urandom(24)
    material = DurableMaterial(kind=DurableKind.dpapi_envelope, envelope=envelope)
    assert material.to_hex() == envelope.hex()
    restored = DurableMaterial.from_hex(
        DurableKind.dpapi_envelope,
        material.to_hex(),
        envelope_version=material.envelope_version,
    )
    assert restored.kind == DurableKind.dpapi_envelope
    assert restored.envelope == envelope
    assert restored.envelope_version == material.envelope_version


def test_from_hex_accepts_string_kind() -> None:
    salt = os.urandom(16)
    restored = DurableMaterial.from_hex("pbkdf_salt", salt.hex())
    assert restored.kind == DurableKind.pbkdf_salt
    assert restored.salt == salt


def test_from_hex_rejects_invalid_hex() -> None:
    with pytest.raises(ValueError, match="not valid hex"):
        DurableMaterial.from_hex(DurableKind.pbkdf_salt, "not-hex!!")


# ── DurableMaterial: dict round trips (round-trip acceptance) ───────


def test_pbkdf_dict_round_trip_preserves_all_fields() -> None:
    salt = os.urandom(16)
    material = DurableMaterial(kind=DurableKind.pbkdf_salt, salt=salt)
    payload = material.to_dict()
    assert payload == {
        "kind": "pbkdf_salt",
        "hex": salt.hex(),
        "envelope_version": None,
    }
    restored = DurableMaterial.from_dict(payload)
    assert restored.kind == DurableKind.pbkdf_salt
    assert restored.salt == salt
    assert restored.envelope is None
    assert restored.envelope_version is None


def test_dpapi_dict_round_trip_preserves_all_fields() -> None:
    envelope = DPAPI_HEADER + os.urandom(24)
    material = DurableMaterial(kind=DurableKind.dpapi_envelope, envelope=envelope)
    payload = material.to_dict()
    assert payload == {
        "kind": "dpapi_envelope",
        "hex": envelope.hex(),
        "envelope_version": DPAPI_ENVELOPE_VERSION,
    }
    restored = DurableMaterial.from_dict(payload)
    assert restored.kind == DurableKind.dpapi_envelope
    assert restored.envelope == envelope
    assert restored.envelope_version == DPAPI_ENVELOPE_VERSION


def test_from_dict_rejects_missing_kind() -> None:
    with pytest.raises(RotationJournalError, match="invalid durable material payload"):
        DurableMaterial.from_dict({"hex": os.urandom(16).hex()})


def test_from_dict_rejects_mixed_kind_with_salt_bytes() -> None:
    # A DPAPI envelope kind entry carrying PBKDF-only salt bytes is rejected:
    # the 16-byte payload is not a valid envelope, so kind mixing is
    # unrepresentable through the typed constructor. from_dict wraps the
    # per-kind validation failure in RotationJournalError (a ValueError).
    salt = os.urandom(16)
    with pytest.raises(RotationJournalError, match="must start with the DPAPI header"):
        DurableMaterial.from_dict({"kind": "dpapi_envelope", "hex": salt.hex()})
