"""Typed rotation-journal-v2 entry types and recovery/transition core (S1 seam; issues #58 / #66).

The rotation journal is the durable record written by
``Vault.rotate_master_key`` so an interrupted rotation can be recovered on
reopen.  Version 1 stored both durable forms under the untyped fields
``old_salt`` / ``new_salt``: a 16-byte PBKDF derivation salt for legacy
vaults, but the raw DPAPI envelope bytes for DPAPI vaults.  Recovery code
that always treated those bytes as a salt therefore bricked a Windows DPAPI
vault after an interrupted rotation (issue #58).

This module is the shared, internal home for the *typed* v2 journal entry
types and the recovery/transition core (the S1 seam in
INTEGRITY_RECOVERY_PLAN.md, Slice C):

* :class:`DurableKind` — discriminator for the durable master-key
  representation on disk (``pbkdf_salt`` | ``dpapi_envelope``).
* :class:`DurableMaterial` — explicit typed journal entry for one durable
  mode, discriminated by envelope kind.  A PBKDF entry must carry its
  16-byte ``salt``; a DPAPI entry carries the ``HVDP``-prefixed envelope and
  its envelope metadata (``envelope_version``).  Per-kind validation makes a
  mixed entry (e.g. a DPAPI envelope with PBKDF-only salt fields, or a PBKDF
  entry missing its required salt) unrepresentable.
* :class:`OldKeyRecovery` — typed, encrypted recovery material for the
  pre-rotation audit/master key.  The plaintext key is wrapped with AES-GCM
  under the *new* master key with AAD bound to the journal id; neither a
  passphrase nor a plaintext key is ever stored in the journal.  This is the
  ``old_key_recovery`` field the v2 journal carries through its
  ``db_committed`` states (issue #66: recovery must not delete the journal
  until the audit-key transition is reconciled under the new key).
* :class:`JournalStatus` / :class:`AuditTransitionState` /
  :class:`JournalPhase` — the v2 state machine enums: journal phase relative
  to the credential DB commit, audit-key transition progress, and the derived
  recovery decision state.
* :class:`RotationJournalEntry` — the typed v2 journal record with explicit
  state transition helpers (``start`` / ``mark_db_committed`` /
  ``mark_audit_checkpoint_committed`` / ``phase``).  Legal transitions are
  enforced: ``started`` journals cannot carry audit fields, and a
  ``db_committed`` journal with a pending audit transition must carry
  ``old_key_recovery``.  Journal-level serialize/deserialize and v1 backward
  reading are layered on by downstream slices; the destructive
  ``recover_checkpoint`` / ``_rebuild_integrity_for_key_mismatch`` semantics
  in :mod:`hermes_vault.audit_integrity.service` are deliberately untouched
  and must not be expanded by this workstream.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict, Field, model_validator

from hermes_vault import _platform, dpapi
from hermes_vault.crypto import AAD_DOMAIN, NONCE_SIZE, SALT_SIZE
from hermes_vault.models import utc_now

#: Legacy journal version label written by every pre-v2 release.
JOURNAL_VERSION_V1 = "rotation-journal-v1"

#: Version label for the typed journal produced by this core.
JOURNAL_VERSION_V2 = "rotation-journal-v2"

#: Version label for the encrypted old-key recovery envelope.
RECOVERY_ENVELOPE_VERSION = "rotation-journal-old-key-v1"

#: Allowed top-level fields in a legacy ``rotation-journal-v1`` payload.
_V1_JOURNAL_KEYS = frozenset(
    {
        "version",
        "status",
        "old_salt",
        "new_salt",
        "created_at",
        "committed_at",
        "audit_transition_state",
        "old_segment_id",
    }
)

#: Allowed top-level fields in a typed ``rotation-journal-v2`` payload.
_V2_JOURNAL_KEYS = frozenset(
    {
        "version",
        "journal_id",
        "status",
        "old_salt",
        "new_salt",
        "old_durable_type",
        "new_durable_type",
        "old_envelope_version",
        "new_envelope_version",
        "created_at",
        "committed_at",
        "audit_transition_state",
        "old_segment_id",
        "old_key_recovery",
    }
)


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp from a journal payload.

    ``model_construct`` (used for v1 backward read) skips pydantic's
    datetime coercion, so timestamps must be normalized here.  Returns
    ``None`` for an absent field; raises :class:`ValueError` on garbage.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))

#: AAD kind/version marker for old-key recovery material.  The domain prefix
#: is shared with credential AAD (:data:`hermes_vault.crypto.AAD_DOMAIN`) so
#: the recovery ciphertext can never be replayed as credential AAD and vice
#: versa (AAD reuse prevention, same rule as issue #60).
RECOVERY_AAD_KIND = "rotation-journal-old-key"
RECOVERY_AAD_VERSION = "v1"

#: Schema label for a contradiction marker file written beside a journal.
CONTRADICTION_MARKER_SCHEMA = "rotation-journal-contradiction-v1"


class RotationJournalError(ValueError):
    """Raised for malformed, contradictory, or invalid rotation journals.

    When the failure is a v1/v2 contradiction, the raised instance carries a
    :class:`ContradictionMarker` on ``marker`` describing the conflict, so
    callers can record the marker and retain the original journal (Slice C
    retention rule — a contradictory journal is never truncated or
    deleted).
    """

    def __init__(
        self,
        message: str,
        *,
        marker: "ContradictionMarker | None" = None,
    ) -> None:
        super().__init__(message)
        self.marker = marker


class DurableKind(str, Enum):
    """Discriminator for the durable master-key representation on disk.

    ``pbkdf_salt`` is the legacy 16-byte derivation salt; ``dpapi_envelope``
    is the ``HVDP``-prefixed DPAPI-wrapped key envelope.
    """

    pbkdf_salt = "pbkdf_salt"
    dpapi_envelope = "dpapi_envelope"


class JournalStatus(str, Enum):
    """Journal phase relative to the credential DB commit."""

    started = "started"
    db_committed = "db_committed"


class AuditTransitionState(str, Enum):
    """Audit-key transition progress within a ``db_committed`` journal."""

    pending = "pending"
    checkpoint_committed = "checkpoint_committed"


class JournalPhase(str, Enum):
    """Derived recovery decision state for the whole state machine.

    Mirrors the recovery branches in Slice C of INTEGRITY_RECOVERY_PLAN.md:

    * ``started`` — pre-DB-commit: restore the old durable form, audit is
      untouched, journal can be deleted once the old form is durable.
    * ``db_committed_pending`` — new credential key is correct but the audit
      transition has not committed: reconcile the audit chain under the new
      key, keep the journal until ``verify()`` is healthy.
    * ``checkpoint_committed`` — audit transition committed: finalize the
      durable write, then delete the journal.
    """

    started = "started"
    db_committed_pending = "db_committed_pending"
    checkpoint_committed = "checkpoint_committed"


class ContradictionKind(str, Enum):
    """Machine-readable class of a v1/v2 journal contradiction.

    ``version_conflict`` — the payload mixes v1 and v2 semantics (e.g. a
    v1 journal carrying v2-only fields, or a v2 journal shaped like v1).

    ``kind_conflict`` — the declared durable kind contradicts the stored
    bytes (a DPAPI envelope declared as ``pbkdf_salt``, or a 16-byte salt
    declared as ``dpapi_envelope``).

    ``ambiguous_durable`` — legacy v1 bytes are neither a 16-byte PBKDF
    salt nor a valid DPAPI envelope, so the durable kind cannot be inferred
    without guessing.

    ``state_conflict`` — the v1/v2 state fields contradict the journal's
    phase (a ``started`` journal carrying audit/segment/committed fields,
    or a ``db_committed`` journal missing required fields).
    """

    version_conflict = "version_conflict"
    kind_conflict = "kind_conflict"
    ambiguous_durable = "ambiguous_durable"
    state_conflict = "state_conflict"


class ContradictionMarker(BaseModel):
    """Explicit annotation describing a v1/v2 journal contradiction.

    Recorded by the retention path when a legacy v1 journal (or a v2
    payload that mixes v1/v2 semantics) cannot be ingested without data
    loss or guesswork.  The marker is written beside the original journal
    (see :func:`retain_contradiction_marker`) — the original journal file
    is never truncated or deleted, per Slice C retention rules.
    """

    model_config = ConfigDict(extra="forbid")

    kind: ContradictionKind
    message: str
    #: The journal field(s) at the center of the conflict (e.g. ``old_salt``).
    field: str | None = None
    #: The version label the payload declared (``rotation-journal-v1`` / ``v2``).
    declared_version: str
    detected_at: datetime = Field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        """Serialized JSON-safe marker form."""
        return {
            "kind": self.kind.value,
            "message": self.message,
            "field": self.field,
            "declared_version": self.declared_version,
            "detected_at": self.detected_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ContradictionMarker:
        """Rebuild a marker from its serialized form."""
        try:
            return cls(
                kind=ContradictionKind(payload["kind"]),
                message=str(payload["message"]),
                field=payload.get("field"),
                declared_version=str(payload.get("declared_version") or JOURNAL_VERSION_V1),
                detected_at=_parse_timestamp(payload.get("detected_at")) or utc_now(),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RotationJournalError(f"invalid contradiction marker payload: {exc}") from exc


def retain_contradiction_marker(journal_path: Path, marker: ContradictionMarker) -> Path:
    """Retain a contradiction marker beside *journal_path*, never touching the journal.

    Writes a marker file named ``<journal>.contradiction.json`` in the same
    directory as the original journal.  The original journal file is never
    truncated, rewritten, or deleted — Slice C retention rule: a contradictory
    journal is preserved for operator inspection, and the marker records the
    conflict class, a human-readable description, and the version the payload
    declared.  Idempotent: repeated retention for the same journal overwrites
    the marker file (the newest detection wins) but never modifies the
    journal itself.

    Returns the marker file path.
    """
    marker_path = journal_path.with_name(f"{journal_path.name}.contradiction.json")
    payload = {
        "schema": CONTRADICTION_MARKER_SCHEMA,
        "journal_file": journal_path.name,
        "marker": marker.to_dict(),
    }
    _platform.write_text_durable(
        marker_path,
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
    )
    _platform.fsync_directory(journal_path.parent)
    return marker_path


def load_contradiction_marker(marker_path: Path) -> ContradictionMarker:
    """Read a contradiction marker file written by :func:`retain_contradiction_marker`.

    Raises :class:`RotationJournalError` if the file is missing, is not the
    expected schema, or carries an invalid marker payload.
    """
    try:
        payload = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RotationJournalError(
            f"contradiction marker file {marker_path} is unreadable: {exc}"
        ) from exc
    if not isinstance(payload, dict) or payload.get("schema") != CONTRADICTION_MARKER_SCHEMA:
        raise RotationJournalError(
            f"contradiction marker file {marker_path} has an unknown schema"
        )
    marker_payload = payload.get("marker")
    if not isinstance(marker_payload, dict):
        raise RotationJournalError(
            f"contradiction marker file {marker_path} carries no marker payload"
        )
    return ContradictionMarker.from_dict(marker_payload)


def contradiction_error(
    message: str,
    *,
    kind: ContradictionKind,
    field: str | None = None,
    declared_version: str,
) -> RotationJournalError:
    """Build a contradiction-class :class:`RotationJournalError` with a marker.

    The marker records the machine-readable :class:`ContradictionKind`, the
    human-readable message, the field at the center of the conflict (when
    known), and the version label the payload declared.  Callers that ingest a
    journal and catch this error can pass ``err.marker`` straight to
    :func:`retain_contradiction_marker` to preserve the original journal and
    annotate the conflict (Slice C retention rule).
    """
    return RotationJournalError(
        message,
        marker=ContradictionMarker(
            kind=kind,
            message=message,
            field=field,
            declared_version=declared_version,
        ),
    )


def build_recovery_aad(journal_id: str) -> bytes:
    """Deterministic canonical AAD for old-key recovery material.

    The marker prefix separates the recovery envelope from credential AAD
    (different kind/version), and the compact, sorted JSON body binds the
    journal id so a recovery envelope cannot be replayed against a different
    journal.
    """
    marker = f"{AAD_DOMAIN}:{RECOVERY_AAD_KIND}:{RECOVERY_AAD_VERSION}"
    body = json.dumps(
        {"journal_id": journal_id},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return f"{marker}:{body}".encode("utf-8")


def looks_like_dpapi_envelope(raw: bytes) -> bool:
    """True iff *raw* is plausibly a DPAPI envelope (not a PBKDF salt).

    Uses the same strict rule as :func:`hermes_vault.dpapi.should_use_dpapi`:
    the ``HVDP`` magic is required and the payload must be longer than the
    4-byte header so a 16-byte random salt that happens to start with the
    magic is never mis-detected.
    """
    return len(raw) > len(dpapi.DPAPI_HEADER) and raw.startswith(dpapi.DPAPI_HEADER)


class DurableMaterial(BaseModel):
    """Typed durable master-key material: a PBKDF salt or a DPAPI envelope.

    Validation is strict and per-kind: a ``pbkdf_salt`` material must carry a
    16-byte ``salt`` and never an envelope or DPAPI envelope metadata; a
    ``dpapi_envelope`` material must carry an ``HVDP``-prefixed envelope
    (longer than the header) and never a salt.  This is what makes "mixing
    envelope kinds" unrepresentable.
    """

    model_config = ConfigDict(extra="forbid")

    kind: DurableKind
    salt: bytes | None = None
    envelope: bytes | None = None
    #: DPAPI envelope metadata: envelope format version (e.g. ``dpapi-v1``).
    envelope_version: str | None = None

    @model_validator(mode="after")
    def _validate_kind_material(self) -> DurableMaterial:
        if self.kind == DurableKind.pbkdf_salt:
            if self.salt is None:
                raise ValueError("pbkdf_salt durable material requires a salt")
            if self.envelope is not None:
                raise ValueError("pbkdf_salt durable material must not carry a DPAPI envelope")
            if self.envelope_version is not None:
                raise ValueError(
                    "pbkdf_salt durable material must not carry DPAPI envelope metadata"
                )
            if len(self.salt) != SALT_SIZE:
                raise ValueError(
                    f"pbkdf salt must be {SALT_SIZE} bytes; got {len(self.salt)}"
                )
            return self
        # dpapi_envelope
        if self.envelope is None:
            raise ValueError("dpapi_envelope durable material requires an envelope")
        if self.salt is not None:
            raise ValueError("dpapi_envelope durable material must not carry a PBKDF salt")
        if not looks_like_dpapi_envelope(self.envelope):
            raise ValueError(
                "dpapi_envelope durable material must start with the DPAPI header "
                "and be longer than the header"
            )
        if self.envelope_version is None:
            self.envelope_version = dpapi.DPAPI_ENVELOPE_VERSION
        return self

    @property
    def length(self) -> int | None:
        """Byte length of the carried material (envelope only)."""
        if self.kind == DurableKind.dpapi_envelope:
            assert self.envelope is not None  # guaranteed by validation
            return len(self.envelope)
        return None

    def to_hex(self) -> str:
        """Hex of the carried bytes — the v1-compatible ``old_salt`` value."""
        if self.kind == DurableKind.pbkdf_salt:
            assert self.salt is not None  # guaranteed by validation
            return self.salt.hex()
        assert self.envelope is not None  # guaranteed by validation
        return self.envelope.hex()

    @classmethod
    def from_hex(
        cls,
        kind: DurableKind | str,
        hex_value: str,
        *,
        envelope_version: str | None = None,
    ) -> DurableMaterial:
        """Build a material from its kind discriminator plus v1 hex bytes."""
        try:
            raw = bytes.fromhex(hex_value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"durable material is not valid hex: {exc}") from exc
        resolved = DurableKind(kind)
        if resolved == DurableKind.pbkdf_salt:
            if envelope_version is not None:
                raise ValueError(
                    "pbkdf_salt durable material must not carry DPAPI envelope metadata"
                )
            return cls(kind=resolved, salt=raw)
        return cls(kind=resolved, envelope=raw, envelope_version=envelope_version)

    def to_dict(self) -> dict[str, Any]:
        """Serialized form: kind + v1-compatible hex + envelope metadata."""
        return {
            "kind": self.kind.value,
            "hex": self.to_hex(),
            "envelope_version": self.envelope_version,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> DurableMaterial:
        try:
            return cls.from_hex(
                payload["kind"],
                payload["hex"],
                envelope_version=payload.get("envelope_version"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RotationJournalError(f"invalid durable material payload: {exc}") from exc


class OldKeyRecovery(BaseModel):
    """Typed encrypted old-key recovery material.

    Carries an AES-GCM wrapped copy of the pre-rotation audit/master key.
    The wrapping key is the *new* master key and the AAD binds the journal id
    (see :func:`encrypt_old_key_recovery`).  The journal never stores a
    passphrase or a plaintext key.
    """

    model_config = ConfigDict(extra="forbid")

    version: str = RECOVERY_ENVELOPE_VERSION
    nonce: bytes
    ciphertext: bytes

    @model_validator(mode="after")
    def _validate_envelope(self) -> OldKeyRecovery:
        if len(self.nonce) != NONCE_SIZE:
            raise ValueError(
                f"old-key recovery nonce must be {NONCE_SIZE} bytes; got {len(self.nonce)}"
            )
        if not self.ciphertext:
            raise ValueError("old-key recovery ciphertext must not be empty")
        return self

    def to_dict(self) -> dict[str, str]:
        return {
            "version": self.version,
            "nonce": self.nonce.hex(),
            "ciphertext": self.ciphertext.hex(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> OldKeyRecovery:
        try:
            return cls(
                version=str(payload.get("version") or RECOVERY_ENVELOPE_VERSION),
                nonce=bytes.fromhex(payload["nonce"]),
                ciphertext=bytes.fromhex(payload["ciphertext"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RotationJournalError(f"invalid old_key_recovery payload: {exc}") from exc


def encrypt_old_key_recovery(
    old_key: bytes,
    new_key: bytes,
    journal_id: str,
) -> OldKeyRecovery:
    """Wrap *old_key* under *new_key* (KEK) with AAD bound to *journal_id*."""
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(new_key).encrypt(nonce, old_key, build_recovery_aad(journal_id))
    return OldKeyRecovery(nonce=nonce, ciphertext=ciphertext)


def decrypt_old_key_recovery(
    recovery: OldKeyRecovery,
    new_key: bytes,
    journal_id: str,
) -> bytes:
    """Unwrap *recovery* using *new_key*; raises on AAD/tamper mismatch."""
    return AESGCM(new_key).decrypt(
        recovery.nonce,
        recovery.ciphertext,
        build_recovery_aad(journal_id),
    )


class RotationJournalEntry(BaseModel):
    """Typed rotation-journal-v2 record with state transition helpers.

    The serialized shape keeps the v1-compatible ``old_salt`` / ``new_salt``
    hex fields and adds the typed discriminators, envelope metadata, and
    recovery material, so older readers keep working on the common fields and
    rollback of the journal code does not orphan a v2 journal.
    """

    model_config = ConfigDict(extra="forbid")

    version: str = JOURNAL_VERSION_V2
    journal_id: str = Field(default_factory=lambda: str(uuid4()))
    status: JournalStatus = JournalStatus.started
    audit_transition_state: AuditTransitionState | None = None
    old_durable: DurableMaterial
    new_durable: DurableMaterial
    old_key_recovery: OldKeyRecovery | None = None
    old_segment_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    committed_at: datetime | None = None

    @model_validator(mode="after")
    def _validate_state_machine(self) -> RotationJournalEntry:
        if self.version != JOURNAL_VERSION_V2:
            raise ValueError(f"unsupported journal version: {self.version!r}")
        if self.status == JournalStatus.started:
            if self.audit_transition_state is not None:
                raise ValueError("a 'started' journal must not carry an audit transition state")
            if self.old_segment_id:
                raise ValueError("a 'started' journal must not carry an old segment id")
            if self.committed_at is not None:
                raise ValueError("a 'started' journal must not carry a committed_at timestamp")
        else:  # db_committed
            if self.audit_transition_state is None:
                raise ValueError("a 'db_committed' journal requires an audit transition state")
            if not self.old_segment_id:
                raise ValueError("a 'db_committed' journal requires an old segment id")
            if self.committed_at is None:
                raise ValueError("a 'db_committed' journal requires a committed_at timestamp")
            if (
                self.audit_transition_state == AuditTransitionState.pending
                and self.old_key_recovery is None
            ):
                raise ValueError(
                    "a 'db_committed' journal with a pending audit transition "
                    "requires old_key_recovery"
                )
        return self

    # ── state machine helpers ─────────────────────────────────────────────

    @classmethod
    def start(
        cls,
        *,
        old_durable: DurableMaterial,
        new_durable: DurableMaterial,
        old_key_recovery: OldKeyRecovery | None = None,
        journal_id: str | None = None,
        created_at: datetime | None = None,
    ) -> RotationJournalEntry:
        """Create the initial ``started`` journal entry."""
        return cls(
            journal_id=journal_id or str(uuid4()),
            status=JournalStatus.started,
            old_durable=old_durable,
            new_durable=new_durable,
            old_key_recovery=old_key_recovery,
            created_at=created_at or utc_now(),
        )

    def phase(self) -> JournalPhase:
        """Derived recovery decision state (see :class:`JournalPhase`)."""
        if self.status == JournalStatus.started:
            return JournalPhase.started
        if self.audit_transition_state == AuditTransitionState.checkpoint_committed:
            return JournalPhase.checkpoint_committed
        return JournalPhase.db_committed_pending

    def mark_db_committed(
        self,
        *,
        old_segment_id: str,
        old_key_recovery: OldKeyRecovery | None = None,
        committed_at: datetime | None = None,
    ) -> RotationJournalEntry:
        """Transition ``started`` -> ``db_committed``/``pending``.

        Requires the encrypted old-key recovery material (the caller typically
        stores it before the DB commit, per Slice C, so it can be passed here
        or already present on the ``started`` entry).
        """
        if self.status != JournalStatus.started:
            raise RotationJournalError(
                f"cannot mark db_committed from phase {self.phase().value!r}"
            )
        recovery = old_key_recovery if old_key_recovery is not None else self.old_key_recovery
        if recovery is None:
            raise RotationJournalError(
                "old_key_recovery is required before marking the journal db_committed"
            )
        return RotationJournalEntry(
            version=self.version,
            journal_id=self.journal_id,
            status=JournalStatus.db_committed,
            audit_transition_state=AuditTransitionState.pending,
            old_durable=self.old_durable,
            new_durable=self.new_durable,
            old_key_recovery=recovery,
            old_segment_id=old_segment_id,
            created_at=self.created_at,
            committed_at=committed_at or utc_now(),
        )

    def mark_audit_checkpoint_committed(
        self,
        *,
        committed_at: datetime | None = None,
    ) -> RotationJournalEntry:
        """Transition ``db_committed``/``pending`` -> ``checkpoint_committed``."""
        if self.phase() != JournalPhase.db_committed_pending:
            raise RotationJournalError(
                f"cannot mark audit checkpoint committed from phase {self.phase().value!r}"
            )
        return RotationJournalEntry(
            version=self.version,
            journal_id=self.journal_id,
            status=self.status,
            audit_transition_state=AuditTransitionState.checkpoint_committed,
            old_durable=self.old_durable,
            new_durable=self.new_durable,
            old_key_recovery=self.old_key_recovery,
            old_segment_id=self.old_segment_id,
            created_at=self.created_at,
            committed_at=committed_at or self.committed_at,
        )

    # ── journal-level serialize/deserialize and validation ─────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialized JSON-safe form: v1-compatible hex plus typed fields.

        Keeps the v1-compatible ``old_salt`` / ``new_salt`` hex values at the
        top level (pre-v2 readers keep working on the common fields) and adds
        the typed discriminators (``old_durable_type`` /
        ``new_durable_type``), envelope metadata, and recovery material.
        Round-trips exactly through :meth:`from_dict`.
        """
        payload: dict[str, Any] = {
            "version": self.version,
            "journal_id": self.journal_id,
            "status": self.status.value,
            "old_salt": self.old_durable.to_hex(),
            "new_salt": self.new_durable.to_hex(),
            "old_durable_type": self.old_durable.kind.value,
            "new_durable_type": self.new_durable.kind.value,
            "old_envelope_version": self.old_durable.envelope_version,
            "new_envelope_version": self.new_durable.envelope_version,
            "created_at": self.created_at.isoformat(),
            "committed_at": self.committed_at.isoformat() if self.committed_at is not None else None,
            "audit_transition_state": (
                self.audit_transition_state.value
                if self.audit_transition_state is not None
                else None
            ),
            "old_segment_id": self.old_segment_id,
            "old_key_recovery": (
                self.old_key_recovery.to_dict() if self.old_key_recovery is not None else None
            ),
        }
        return payload

    def to_json(self) -> str:
        """Deterministic JSON form of :meth:`to_dict` (canonical separators)."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RotationJournalEntry:
        """Deserialize a journal record; accepts v2 and v1 (backward read).

        For ``rotation-journal-v2`` payloads the typed discriminators are
        required, unknown keys are rejected, and each durable side is rebuilt
        through :meth:`DurableMaterial.from_hex`, whose per-kind validation
        rejects envelope-kind mixing (a DPAPI envelope kind over PBKDF-only
        salt bytes, or a PBKDF entry missing its required salt).

        For ``rotation-journal-v1`` payloads the durable kind is inferred
        from the stored bytes (``HVDP`` magic + length gate) and the entry is
        upgraded to v2 in memory; ambiguous bytes fail closed.  A v1
        ``db_committed`` journal legitimately predates the
        ``old_key_recovery`` material, so the v2-only state-machine invariant
        that requires it is not applied to backward-read entries.

        All invalid payloads raise :class:`RotationJournalError`.  Contradiction
        classes (version/kind/durable/state conflicts between the payload's
        declared semantics and its contents) raise with a
        :class:`ContradictionMarker` attached on ``err.marker`` so callers can
        retain the original journal and record the conflict (Slice C).
        """
        try:
            version = str(payload.get("version") or JOURNAL_VERSION_V1)
            status = str(payload.get("status") or JournalStatus.started.value)
            old_salt = str(payload["old_salt"])
            new_salt = str(payload["new_salt"])

            if version == JOURNAL_VERSION_V2:
                cls._reject_unknown_keys(payload, _V2_JOURNAL_KEYS, declared_version=version)
                try:
                    old_type = DurableKind(payload["old_durable_type"])
                    new_type = DurableKind(payload["new_durable_type"])
                except (KeyError, ValueError) as exc:
                    raise contradiction_error(
                        f"a v2 journal requires typed durable discriminators "
                        f"(old_durable_type/new_durable_type): {exc}",
                        kind=ContradictionKind.version_conflict,
                        field="old_durable_type",
                        declared_version=version,
                    ) from exc
                try:
                    old_durable = DurableMaterial.from_hex(
                        old_type,
                        old_salt,
                        envelope_version=payload.get("old_envelope_version"),
                    )
                    new_durable = DurableMaterial.from_hex(
                        new_type,
                        new_salt,
                        envelope_version=payload.get("new_envelope_version"),
                    )
                except ValueError as exc:
                    raise contradiction_error(
                        f"durable material contradicts its declared kind: {exc}",
                        kind=ContradictionKind.kind_conflict,
                        field="old_salt",
                        declared_version=version,
                    ) from exc
                recovery_payload = payload.get("old_key_recovery")
                old_key_recovery = (
                    OldKeyRecovery.from_dict(recovery_payload)
                    if recovery_payload is not None
                    else None
                )
                try:
                    audit_transition_state = (
                        AuditTransitionState(payload["audit_transition_state"])
                        if payload.get("audit_transition_state") is not None
                        else None
                    )
                    return cls(
                        version=JOURNAL_VERSION_V2,
                        journal_id=str(payload.get("journal_id") or ""),
                        status=JournalStatus(status),
                        audit_transition_state=audit_transition_state,
                        old_durable=old_durable,
                        new_durable=new_durable,
                        old_key_recovery=old_key_recovery,
                        old_segment_id=payload.get("old_segment_id"),
                        created_at=payload.get("created_at") or utc_now(),
                        committed_at=payload.get("committed_at"),
                    )
                except ValueError as exc:
                    raise contradiction_error(
                        f"v2 journal state contradicts its declared phase: {exc}",
                        kind=ContradictionKind.state_conflict,
                        field="status",
                        declared_version=version,
                    ) from exc

            if version == JOURNAL_VERSION_V1:
                return cls._from_v1_dict(payload, status, old_salt, new_salt)

            raise contradiction_error(
                f"unsupported journal version: {version!r}",
                kind=ContradictionKind.version_conflict,
                field="version",
                declared_version=version,
            )
        except RotationJournalError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise RotationJournalError(f"invalid rotation journal payload: {exc}") from exc

    @classmethod
    def _from_v1_dict(
        cls,
        payload: Mapping[str, Any],
        status: str,
        old_salt: str,
        new_salt: str,
    ) -> RotationJournalEntry:
        """Backward-read a legacy ``rotation-journal-v1`` payload.

        v1 journals have no typed discriminators and no recovery material;
        the durable kind is inferred from the stored bytes and the entry is
        upgraded to v2 in memory.  The v2 state-machine shape is still
        enforced (started vs db_committed field sets), but the
        ``old_key_recovery``-for-pending invariant is deliberately not
        applied because the material did not exist in v1 (issue #66's
        recovery copy is a v2 addition).
        """
        cls._reject_unknown_keys(payload, _V1_JOURNAL_KEYS, declared_version=JOURNAL_VERSION_V1)
        try:
            old_durable = DurableMaterial.from_hex(cls._infer_v1_kind(old_salt), old_salt)
            new_durable = DurableMaterial.from_hex(cls._infer_v1_kind(new_salt), new_salt)
        except ValueError as exc:
            raise contradiction_error(
                f"legacy v1 durable bytes are ambiguous (neither a 16-byte "
                f"PBKDF salt nor a valid DPAPI envelope): {exc}",
                kind=ContradictionKind.ambiguous_durable,
                field="old_salt",
                declared_version=JOURNAL_VERSION_V1,
            ) from exc

        try:
            audit_state = payload.get("audit_transition_state")
            audit_transition_state = (
                AuditTransitionState(audit_state) if audit_state is not None else None
            )
            old_segment_id = payload.get("old_segment_id")
            committed_at = payload.get("committed_at")
            journal_status = JournalStatus(status)
        except ValueError as exc:
            raise contradiction_error(
                f"legacy v1 journal state is invalid: {exc}",
                kind=ContradictionKind.state_conflict,
                field="status",
                declared_version=JOURNAL_VERSION_V1,
            ) from exc

        # Enforce the v1-visible state-machine shape (mirror of the v2
        # validator, minus the v2-only old_key_recovery requirement).
        if journal_status == JournalStatus.started:
            if audit_transition_state is not None or old_segment_id or committed_at is not None:
                raise contradiction_error(
                    "a v1 'started' journal must not carry audit/segment/committed fields",
                    kind=ContradictionKind.state_conflict,
                    field="audit_transition_state",
                    declared_version=JOURNAL_VERSION_V1,
                )
        else:
            if audit_transition_state is None or not old_segment_id or committed_at is None:
                raise contradiction_error(
                    "a v1 'db_committed' journal requires audit_transition_state, "
                    "old_segment_id, and committed_at",
                    kind=ContradictionKind.state_conflict,
                    field="old_segment_id",
                    declared_version=JOURNAL_VERSION_V1,
                )

        try:
            created_at = _parse_timestamp(payload.get("created_at"))
            committed_at_dt = _parse_timestamp(committed_at)
        except ValueError as exc:
            raise contradiction_error(
                f"legacy v1 journal carries an invalid timestamp: {exc}",
                kind=ContradictionKind.state_conflict,
                field="created_at",
                declared_version=JOURNAL_VERSION_V1,
            ) from exc

        # model_construct skips pydantic re-validation: every field below was
        # validated explicitly above (enums, hex materials, timestamps), and
        # the v2 state-machine validator's old_key_recovery requirement is
        # intentionally not applied to legacy journals.
        return cls.model_construct(
            version=JOURNAL_VERSION_V2,
            journal_id=str(payload.get("journal_id") or uuid4()),
            status=journal_status,
            audit_transition_state=audit_transition_state,
            old_durable=old_durable,
            new_durable=new_durable,
            old_key_recovery=None,
            old_segment_id=old_segment_id,
            created_at=created_at,
            committed_at=committed_at_dt,
        )

    @staticmethod
    def _reject_unknown_keys(
        payload: Mapping[str, Any],
        allowed: frozenset[str],
        *,
        declared_version: str,
    ) -> None:
        unknown = set(payload) - allowed
        if unknown:
            raise contradiction_error(
                f"unknown rotation journal field(s) for {declared_version}: "
                f"{', '.join(sorted(unknown))}",
                kind=ContradictionKind.version_conflict,
                field=sorted(unknown)[0],
                declared_version=declared_version,
            )

    @classmethod
    def from_json(cls, raw: str) -> RotationJournalEntry:
        """Deserialize from a JSON string (see :meth:`from_dict`)."""
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise RotationJournalError(f"invalid rotation journal JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise RotationJournalError("rotation journal JSON must be an object")
        return cls.from_dict(payload)

    @staticmethod
    def _infer_v1_kind(hex_value: str) -> DurableKind:
        """Infer the durable kind of a v1 journal field from its bytes.

        Uses the same strict rule as :func:`looks_like_dpapi_envelope`: the
        ``HVDP`` magic is required and the payload must be longer than the
        4-byte header.  Anything else is treated as a PBKDF salt and the
        subsequent :meth:`DurableMaterial.from_hex` validation fails closed
        if the bytes are not a 16-byte salt either.
        """
        raw = bytes.fromhex(hex_value)
        if looks_like_dpapi_envelope(raw):
            return DurableKind.dpapi_envelope
        return DurableKind.pbkdf_salt
