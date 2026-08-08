from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from hermes_vault import _platform
from hermes_vault.audit_integrity.checkpoint import AuditLockError, audit_write_lock
from hermes_vault.audit_integrity.detached import DETACHED_HEALTHY, verify_detached_evidence
from hermes_vault.audit_integrity.models import AuditIntegrityStatus
from hermes_vault.audit_integrity.service import AuditIntegrityError, AuditIntegrityService
from hermes_vault.crypto import (
    CRYPTO_VERSION,
    CRYPTO_VERSION_V2,
    CorruptKeyMaterialError,
    MissingKeyMaterialError,
    SALT_SIZE,
    build_canonical_aad,
    credential_aad_metadata,
    current_write_version,
    decrypt_secret_versioned,
    derive_key,
    encrypt_secret_versioned,
    load_or_create_master_key,
)
from hermes_vault.models import (
    AccessLogRecord,
    AccessRequestRecord,
    AccessRequestStatus,
    CredentialRecord,
    CredentialSecret,
    CredentialStatus,
    Decision,
    LeaseRecord,
    LeaseStatus,
    utc_now,
)
from hermes_vault.rotation_journal import (
    DurableKind,
    DurableMaterial,
    JournalPhase,
    RotationJournalEntry,
    RotationJournalError,
    decrypt_old_key_recovery,
    encrypt_old_key_recovery,
    looks_like_dpapi_envelope,
    retain_contradiction_marker,
)
from hermes_vault.service_ids import normalize


class DuplicateCredentialError(RuntimeError):
    pass


class AmbiguousTargetError(RuntimeError):
    """Raised when a service-only lookup matches multiple credentials."""
    pass


class RotationRecoveryError(RuntimeError):
    """Raised when an interrupted master-key rotation cannot be recovered."""


class RestoreCommittedCheckpointError(RuntimeError):
    """The restore data committed, but the audit checkpoint could not be published.

    Raised after the restore transaction has committed and its protected
    restore event is durable; the failure is confined to the filesystem
    checkpoint publication. The chain will verify as ``checkpoint_stale``
    until the checkpoint is re-published (re-run the restore — it is
    idempotent — or run ``hermes-vault audit checkpoint advance``).
    """


def _restore_event_id(backup: dict, version: str, agent_id: str = "operator") -> str:
    """Deterministic id for a restore's protected audit event (issue #62B / F6).

    Derived from the backup's restore-relevant content *and acting agent* so a
    retry of the same restore by the same principal reuses the same event id,
    while a distinct actor restoring identical content gets its own protected
    restore attribution.
    """
    content = json.dumps(
        {
            "version": version,
            "credentials": backup.get("credentials", []),
            "leases": backup.get("leases", []),
            "agent_id": agent_id,
        },
        sort_keys=True,
        default=str,
    )
    return f"restore-{hashlib.sha256(content.encode('utf-8')).hexdigest()[:32]}"


def _record_aad_metadata(record: "CredentialRecord") -> dict[str, Any]:
    """Authorization metadata bound into a credential row's v2 AAD."""
    return credential_aad_metadata(
        record.id,
        record.service,
        record.alias,
        record.credential_type,
        record.scopes,
    )


def _durable_from_bytes(raw: bytes, fallback_salt: bytes) -> DurableMaterial:
    """Typed durable material from the on-disk salt bytes.

    The existing salt file is either a 16-byte PBKDF derivation salt or a
    DPAPI envelope (``HVDP`` magic + payload).  A missing/empty file falls
    back to the new derivation salt (mirrors the legacy journal behavior of
    recording ``old_salt = new_salt`` for a fresh vault).
    """
    if not raw:
        return DurableMaterial(kind=DurableKind.pbkdf_salt, salt=fallback_salt)
    if looks_like_dpapi_envelope(raw):
        return DurableMaterial(kind=DurableKind.dpapi_envelope, envelope=raw)
    return DurableMaterial(kind=DurableKind.pbkdf_salt, salt=raw)


class Vault:
    def __init__(self, db_path: Path, salt_path: Path, passphrase: str) -> None:
        self.db_path = db_path
        self.salt_path = salt_path
        self._recover_rotation_journal(passphrase)
        self._prepare_storage()
        # DPAPI opt-in: enabled when the env var is set AND we are
        # creating a fresh salt (the file does not exist yet). When a
        # salt file already exists the format is detected by magic
        # header inside load_or_create_master_key, so existing legacy
        # vaults continue to work without any env-var trickery.
        # When the env var is set but DPAPI is not actually usable on
        # this process (e.g. POSIX), downgrade silently to the legacy
        # path with a one-line stderr warning. This is the soft
        # opt-in described in spec §8 risk #1.
        from hermes_vault import dpapi  # deferred import keeps the cold path clean

        if (
            not salt_path.exists()
            and os.environ.get("HERMES_VAULT_DPAPI", "").strip() == "1"
        ):
            if dpapi.is_available():
                enable_dpapi = True
            else:
                print(
                    "DPAPI requested but not available; falling back to legacy path.",
                    file=sys.stderr,
                )
                enable_dpapi = False
        else:
            enable_dpapi = False
        self.key = load_or_create_master_key(
            salt_path, passphrase, enable_dpapi=enable_dpapi,
        )
        self.initialize()

    @property
    def rotation_journal_path(self) -> Path:
        return self.salt_path.with_name(f"{self.salt_path.name}.rotation.json")

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS credentials (
                    id TEXT PRIMARY KEY,
                    service TEXT NOT NULL,
                    alias TEXT NOT NULL,
                    credential_type TEXT NOT NULL,
                    encrypted_payload TEXT NOT NULL,
                    status TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_verified_at TEXT,
                    imported_from TEXT,
                    expiry TEXT,
                    tags TEXT NOT NULL DEFAULT '[]',
                    notes TEXT,
                    crypto_version TEXT NOT NULL
                )
                """
            )
            self._migrate_credentials_schema(conn)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_credentials_service_alias ON credentials(service, alias)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_credentials_status ON credentials(status)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_credentials_last_verified_at ON credentials(last_verified_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_credentials_expiry ON credentials(expiry)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS leases (
                    id TEXT PRIMARY KEY,
                    service TEXT NOT NULL,
                    alias TEXT NOT NULL,
                    credential_id TEXT NOT NULL,
                    credential_type TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    issued_by TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    status TEXT NOT NULL,
                    ttl_seconds INTEGER NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT,
                    renewed_at TEXT,
                    renew_count INTEGER NOT NULL DEFAULT 0,
                    reason TEXT,
                    scopes TEXT NOT NULL DEFAULT '[]',
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            self._migrate_leases_schema(conn)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_leases_service ON leases(service)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_leases_agent_id ON leases(agent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_leases_status ON leases(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_leases_expires_at ON leases(expires_at)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS access_requests (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    service TEXT NOT NULL,
                    alias TEXT NOT NULL,
                    action TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    status TEXT NOT NULL,
                    requested_ttl_seconds INTEGER,
                    created_at TEXT NOT NULL,
                    decided_at TEXT,
                    decided_by TEXT,
                    decision_reason TEXT,
                    lease_id TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_access_requests_agent_id ON access_requests(agent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_access_requests_service ON access_requests(service)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_access_requests_status ON access_requests(status)")
            conn.commit()
        self._secure_storage_files()

    def _migrate_credentials_schema(self, conn: sqlite3.Connection) -> None:
        """Add metadata columns introduced after the original credentials table."""
        columns = {row[1] for row in conn.execute("PRAGMA table_info(credentials)").fetchall()}
        if "tags" not in columns:
            conn.execute("ALTER TABLE credentials ADD COLUMN tags TEXT NOT NULL DEFAULT '[]'")
        if "notes" not in columns:
            conn.execute("ALTER TABLE credentials ADD COLUMN notes TEXT")

    def _migrate_leases_schema(self, conn: sqlite3.Connection) -> None:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(leases)").fetchall()}
        if not columns:
            return
        if "service" not in columns:
            conn.execute("ALTER TABLE leases ADD COLUMN service TEXT NOT NULL DEFAULT ''")
        if "alias" not in columns:
            conn.execute("ALTER TABLE leases ADD COLUMN alias TEXT NOT NULL DEFAULT 'default'")
        if "credential_id" not in columns:
            conn.execute("ALTER TABLE leases ADD COLUMN credential_id TEXT NOT NULL DEFAULT ''")
        if "credential_type" not in columns:
            conn.execute("ALTER TABLE leases ADD COLUMN credential_type TEXT NOT NULL DEFAULT 'unknown'")
        if "agent_id" not in columns:
            conn.execute("ALTER TABLE leases ADD COLUMN agent_id TEXT NOT NULL DEFAULT ''")
        if "issued_by" not in columns:
            conn.execute("ALTER TABLE leases ADD COLUMN issued_by TEXT NOT NULL DEFAULT ''")
        if "purpose" not in columns:
            conn.execute("ALTER TABLE leases ADD COLUMN purpose TEXT NOT NULL DEFAULT 'task'")
        if "status" not in columns:
            conn.execute("ALTER TABLE leases ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
        if "ttl_seconds" not in columns:
            conn.execute("ALTER TABLE leases ADD COLUMN ttl_seconds INTEGER NOT NULL DEFAULT 0")
        if "issued_at" not in columns:
            conn.execute("ALTER TABLE leases ADD COLUMN issued_at TEXT NOT NULL DEFAULT ''")
        if "expires_at" not in columns:
            conn.execute("ALTER TABLE leases ADD COLUMN expires_at TEXT NOT NULL DEFAULT ''")
        if "revoked_at" not in columns:
            conn.execute("ALTER TABLE leases ADD COLUMN revoked_at TEXT")
        if "renewed_at" not in columns:
            conn.execute("ALTER TABLE leases ADD COLUMN renewed_at TEXT")
        if "renew_count" not in columns:
            conn.execute("ALTER TABLE leases ADD COLUMN renew_count INTEGER NOT NULL DEFAULT 0")
        if "reason" not in columns:
            conn.execute("ALTER TABLE leases ADD COLUMN reason TEXT")
        if "scopes" not in columns:
            conn.execute("ALTER TABLE leases ADD COLUMN scopes TEXT NOT NULL DEFAULT '[]'")
        if "metadata_json" not in columns:
            conn.execute("ALTER TABLE leases ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}'")

    @staticmethod
    def _normalize_tags(tags: list[str] | None) -> list[str]:
        if not tags:
            return []
        normalized: list[str] = []
        seen: set[str] = set()
        for tag in tags:
            value = str(tag).strip()
            if not value or value in seen:
                continue
            normalized.append(value)
            seen.add(value)
        return normalized

    @staticmethod
    def _normalize_notes(notes: str | None) -> str | None:
        if notes is None:
            return None
        value = str(notes).strip()
        return value or None

    def _prepare_storage(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if self.db_path.exists() and not self.salt_path.exists():
            raise MissingKeyMaterialError(
                f"Vault database exists at {self.db_path} but salt file {self.salt_path} is missing."
            )
        # The salt file is either a 16-byte legacy salt or a DPAPI
        # envelope (4-byte magic header + wrapped bytes). Reject only
        # the formats that are neither. The DPAPI module is the
        # single source of truth for envelope detection; importing it
        # here keeps the rule in one place.
        if self.salt_path.exists():
            from hermes_vault import dpapi  # deferred import keeps the cold path clean

            raw = self.salt_path.read_bytes()
            if dpapi.should_use_dpapi(self.salt_path):
                # DPAPI envelope present -- accept any size > 4 bytes.
                return
            if len(raw) != SALT_SIZE:
                raise CorruptKeyMaterialError(
                    f"Salt file {self.salt_path} is corrupted or the wrong size."
                )

    @staticmethod
    def _write_bytes_durable(path: Path, content: bytes, mode: int = 0o600) -> None:
        _platform.write_bytes_durable(path, content)

    @staticmethod
    def _write_text_durable(path: Path, content: str, mode: int = 0o600) -> None:
        _platform.write_text_durable(path, content)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        _platform.fsync_directory(path)

    def _write_rotation_journal(self, payload: dict[str, Any]) -> None:
        self._write_text_durable(
            self.rotation_journal_path,
            json.dumps(payload, sort_keys=True),
        )
        self._fsync_directory(self.rotation_journal_path.parent)

    def _replace_salt_durable(self, salt: bytes) -> None:
        tmp_salt = self.salt_path.with_suffix(".tmp")
        self._write_bytes_durable(tmp_salt, salt)
        os.replace(tmp_salt, self.salt_path)
        _platform.secure_file(self.salt_path)
        self._fsync_directory(self.salt_path.parent)

    def _write_master_key_durable(self, derivation_salt: bytes, master_key: bytes) -> None:
        """Write the new master-key durable form. The format is decided
        by the HERMES_VAULT_DPAPI opt-in env var (and whether DPAPI is
        actually available on this process). When opt-in is active the
        *master_key* is wrapped with DPAPI; otherwise the
        *derivation_salt* is written verbatim (legacy behaviour).
        """
        from hermes_vault import dpapi  # deferred: keeps win32crypt off the cold path

        if os.environ.get("HERMES_VAULT_DPAPI", "").strip() == "1":
            if dpapi.is_available():
                payload = dpapi.protect_master_key(master_key)
            else:
                print(
                    "DPAPI requested but not available; falling back to legacy path.",
                    file=sys.stderr,
                )
                payload = derivation_salt
        else:
            payload = derivation_salt
        self._replace_salt_durable(payload)

    def _first_encrypted_payload(self) -> dict[str, Any] | None:
        """Return the most recently updated credential row (or None)."""
        if not self.db_path.exists():
            return None
        with self._connection() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM credentials ORDER BY updated_at DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    def _recover_rotation_journal(self, passphrase: str) -> None:
        journal_path = self.rotation_journal_path
        if not journal_path.exists():
            return
        try:
            entry = RotationJournalEntry.from_json(journal_path.read_text(encoding="utf-8"))
        except RotationJournalError as exc:
            # Contradiction-class failure (v1/v2 version/kind/state conflicts):
            # retain the original journal, record the marker when available,
            # and surface a clear recovery error (Slice C retention rule).
            if exc.marker is not None:
                try:
                    retain_contradiction_marker(journal_path, exc.marker)
                except Exception:
                    pass
            raise RotationRecoveryError(
                f"Master-key rotation journal at {journal_path} is malformed or contradictory "
                f"and was retained for operator review: {exc}"
            ) from exc
        except Exception as exc:
            raise RotationRecoveryError(
                f"Master-key rotation journal at {journal_path} is unreadable."
            ) from exc

        phase = entry.phase()

        if phase == JournalPhase.started:
            self._recover_started_journal(entry, passphrase, journal_path)
            return

        # db_committed (pending or checkpoint_committed): the credential DB is
        # already encrypted under the new key. Derive the new key from the
        # journaled new durable material, unwrap the old audit/master key from
        # the recovery envelope, reconcile the audit transition idempotently,
        # verify a healthy audit state, and only then finalize the new durable
        # material and delete the journal.
        new_key = self._durable_key(entry.new_durable, passphrase)
        if entry.old_key_recovery is None:
            if phase == JournalPhase.db_committed_pending:
                # Legacy v1 pending journal predates protected old-key
                # recovery: cannot reconcile without the old audit key. Retain
                # and surface a clear recovery error (issue #66 requirement).
                raise RotationRecoveryError(
                    "Legacy rotation journal is pending but lacks protected old-key "
                    "recovery material; journal retained for operator review. Manual "
                    "recovery is required before this vault can reopen."
                )
            # checkpoint_committed: the audit transition already completed, so
            # the old key is not needed by the reconciliation seam.
            old_key = new_key
        else:
            try:
                old_key = decrypt_old_key_recovery(
                    entry.old_key_recovery, new_key, entry.journal_id
                )
            except Exception as exc:
                raise RotationRecoveryError(
                    "Master-key rotation journal old-key recovery could not be decrypted "
                    f"(wrong passphrase or tampered journal); journal retained: {exc}"
                ) from exc

        service = AuditIntegrityService(self.db_path, new_key)
        try:
            result = service.recover_pending_rotation(entry, old_master_key=old_key)
        except AuditIntegrityError as exc:
            raise RotationRecoveryError(
                f"Master-key rotation journal audit reconciliation failed; journal retained: {exc}"
            ) from exc
        if result.status != AuditIntegrityStatus.healthy:
            raise RotationRecoveryError(
                "Master-key rotation journal audit verification is not healthy after recovery "
                f"({result.sanitized_reason}); journal retained for operator review."
            )

        # All checks passed: finalize the new durable material, then delete.
        self._write_new_durable(entry.new_durable, new_key)
        journal_path.unlink()
        self._fsync_directory(journal_path.parent)

    def _recover_started_journal(
        self,
        entry: RotationJournalEntry,
        passphrase: str,
        journal_path: Path,
    ) -> None:
        """Recover a pre-commit ``started`` journal (safe rollback).

        A started journal means the credential DB was never committed under
        the new key, so the old durable form is still correct.  Restore it
        and delete the journal.  If the old key does not decrypt the DB but
        the journaled new key does, the DB was committed without the journal
        being updated — an ambiguous state that fails closed and retains the
        journal (issue #66: never silently delete a pending journal).
        """
        old_key = self._durable_key(entry.old_durable, passphrase)
        first = self._first_encrypted_payload()
        if first is None:
            self._restore_durable_bytes(entry.old_durable)
            journal_path.unlink()
            self._fsync_directory(journal_path.parent)
            return
        version = first.get("crypto_version") or CRYPTO_VERSION
        aad_metadata = credential_aad_metadata(
            first.get("id", ""),
            first.get("service", ""),
            first.get("alias", "default"),
            first.get("credential_type", ""),
            json.loads(first.get("scopes") or "[]"),
        )
        if self._payload_decrypts_with_key(
            old_key,
            first["encrypted_payload"],
            version=version,
            aad_metadata=aad_metadata,
        ):
            self._restore_durable_bytes(entry.old_durable)
            journal_path.unlink()
            self._fsync_directory(journal_path.parent)
            return
        new_key = self._durable_key(entry.new_durable, passphrase)
        if self._payload_decrypts_with_key(
            new_key,
            first["encrypted_payload"],
            version=version,
            aad_metadata=aad_metadata,
        ):
            raise RotationRecoveryError(
                "Master-key rotation journal is 'started' but the credential DB is already "
                "encrypted under the new key (ambiguous state); journal retained for operator review."
            )
        raise RotationRecoveryError(
            "Interrupted master-key rotation could not be recovered with the provided "
            "passphrase (neither journaled key decrypts the vault); journal retained."
        )

    def _durable_key(self, durable: DurableMaterial, passphrase: str) -> bytes:
        """Derive/unwrap the master key for a typed durable material."""
        if durable.kind == DurableKind.pbkdf_salt:
            assert durable.salt is not None
            return derive_key(passphrase, durable.salt)
        from hermes_vault import dpapi  # deferred: keeps win32crypt off the cold path

        assert durable.envelope is not None
        return dpapi.unprotect_master_key(durable.envelope)

    def _restore_durable_bytes(self, durable: DurableMaterial) -> None:
        """Write the exact durable bytes back to the salt file (rollback)."""
        if durable.kind == DurableKind.pbkdf_salt:
            assert durable.salt is not None
            self._replace_salt_durable(durable.salt)
        else:
            assert durable.envelope is not None
            self._replace_salt_durable(durable.envelope)

    def _write_new_durable(self, durable: DurableMaterial, new_key: bytes) -> None:
        """Persist the new durable form (DPAPI-aware for PBKDF salts)."""
        if durable.kind == DurableKind.pbkdf_salt:
            assert durable.salt is not None
            self._write_master_key_durable(durable.salt, new_key)
        else:
            assert durable.envelope is not None
            self._replace_salt_durable(durable.envelope)

    def _payload_decrypts_with_key(
        self,
        key: bytes,
        payload: str,
        *,
        version: str,
        aad_metadata: dict[str, Any] | None,
    ) -> bool:
        try:
            decrypt_secret_versioned(payload, key, version, aad_metadata)
            return True
        except Exception:
            return False

    def _secure_storage_files(self) -> None:
        _platform.secure_file(self.db_path)
        _platform.secure_file(self.salt_path)

    def add_credential(
        self,
        service: str,
        secret: str,
        credential_type: str,
        alias: str = "default",
        imported_from: str | None = None,
        scopes: list[str] | None = None,
        tags: list[str] | None = None,
        notes: str | None = None,
        replace_existing: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> CredentialRecord:
        service = normalize(service)
        existing = self._find_by_service_alias(service, alias)
        if existing and not replace_existing:
            raise DuplicateCredentialError(
                f"Credential for service '{service}' and alias '{alias}' already exists."
            )
        resolved_tags = self._normalize_tags(tags) if tags is not None else (existing.tags if existing else [])
        resolved_notes = self._normalize_notes(notes) if notes is not None else (existing.notes if existing else None)
        # Pre-generate the record id so the authorization metadata bound into
        # the v2 AAD matches the row that is actually stored (issue #60).
        write_version = current_write_version()
        record_id = existing.id if (existing and replace_existing) else str(uuid4())
        aad_metadata = credential_aad_metadata(
            record_id,
            service,
            alias,
            credential_type,
            scopes or [],
        )
        payload = CredentialSecret(
            secret=secret,
            metadata=self._resolve_secret_metadata(existing.id if existing else None, metadata),
            tags=resolved_tags,
            notes=resolved_notes,
        ).model_dump_json()
        encrypted_payload = encrypt_secret_versioned(payload, self.key, write_version, aad_metadata)
        record = existing.model_copy(update={
            "credential_type": credential_type,
            "encrypted_payload": encrypted_payload,
            "imported_from": imported_from,
            "scopes": scopes or [],
            "tags": resolved_tags,
            "notes": resolved_notes,
            "status": CredentialStatus.unknown,
            "updated_at": utc_now(),
            "expiry": None,
            "crypto_version": write_version,
        }) if existing and replace_existing else CredentialRecord(
            id=record_id,
            service=service,
            alias=alias,
            credential_type=credential_type,
            encrypted_payload=encrypted_payload,
            imported_from=imported_from,
            scopes=scopes or [],
            tags=resolved_tags,
            notes=resolved_notes,
            crypto_version=write_version,
        )
        with self._connection() as conn:
            if existing and replace_existing:
                conn.execute(
                    """
                    UPDATE credentials
                    SET credential_type = ?, encrypted_payload = ?, status = ?, scopes = ?,
                        tags = ?, notes = ?, updated_at = ?, last_verified_at = ?,
                        imported_from = ?, expiry = ?, crypto_version = ?
                    WHERE id = ?
                    """,
                    (
                        record.credential_type,
                        record.encrypted_payload,
                        record.status.value,
                        json.dumps(record.scopes),
                        json.dumps(record.tags),
                        record.notes,
                        record.updated_at.isoformat(),
                        record.last_verified_at.isoformat() if record.last_verified_at else None,
                        record.imported_from,
                        record.expiry.isoformat() if record.expiry else None,
                        record.crypto_version,
                        record.id,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO credentials (
                        id, service, alias, credential_type, encrypted_payload, status, scopes,
                        tags, notes, created_at, updated_at, last_verified_at, imported_from, expiry, crypto_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.id,
                        record.service,
                        record.alias,
                        record.credential_type,
                        record.encrypted_payload,
                        record.status.value,
                        json.dumps(record.scopes),
                        json.dumps(record.tags),
                        record.notes,
                        record.created_at.isoformat(),
                        record.updated_at.isoformat(),
                        record.last_verified_at.isoformat() if record.last_verified_at else None,
                        record.imported_from,
                        record.expiry.isoformat() if record.expiry else None,
                        record.crypto_version,
                    ),
                )
            conn.commit()
        return record

    def list_credentials(self) -> list[CredentialRecord]:
        with self._connection() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM credentials ORDER BY service, alias").fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_credential(self, service_or_id: str) -> CredentialRecord | None:
        # Try by raw id first (UUID), then by canonicalized service name
        with self._connection() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT * FROM credentials
                WHERE id = ?
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (service_or_id,),
            ).fetchone()
            if row:
                return self._row_to_record(row)
            # Fall back to service lookup with normalization
            normalized = normalize(service_or_id)
            row = conn.execute(
                """
                SELECT * FROM credentials
                WHERE service = ?
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (normalized,),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def get_secret(self, service_or_id: str) -> CredentialSecret | None:
        record = self.get_credential(service_or_id)
        if not record:
            return None
        payload = decrypt_secret_versioned(
            record.encrypted_payload,
            self.key,
            record.crypto_version,
            _record_aad_metadata(record),
        )
        return CredentialSecret.model_validate_json(payload)

    def update_status(
        self, service_or_id: str, status: CredentialStatus, verified_at: str | None = None,
        alias: str | None = None,
    ) -> None:
        """Update credential status deterministically.

        Requires credential_id or service+alias when multiple credentials share a service.
        Service-only is allowed only when exactly one credential matches.
        """
        if alias is not None:
            normalized = normalize(service_or_id)
            with self._connection() as conn:
                conn.execute(
                    """
                    UPDATE credentials
                    SET status = ?, last_verified_at = COALESCE(?, last_verified_at), updated_at = CURRENT_TIMESTAMP
                    WHERE service = ? AND alias = ?
                    """,
                    (status.value, verified_at, normalized, alias),
                )
                conn.commit()
            return

        with self._connection() as conn:
            # Try raw id first
            cursor = conn.execute(
                """
                UPDATE credentials
                SET status = ?, last_verified_at = COALESCE(?, last_verified_at), updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (status.value, verified_at, service_or_id),
            )
            if cursor.rowcount > 0:
                conn.commit()
                return

            # Service-only — check count
            normalized = normalize(service_or_id)
            count_row = conn.execute(
                "SELECT COUNT(*) FROM credentials WHERE service = ?", (normalized,)
            ).fetchone()
            count = count_row[0] if count_row else 0

            if count == 0:
                conn.commit()
                return
            if count > 1:
                conn.commit()
                raise AmbiguousTargetError(
                    f"Service '{normalized}' has {count} credentials — "
                    f"specify credential ID or service+alias to update exactly one"
                )
            conn.execute(
                """
                UPDATE credentials
                SET status = ?, last_verified_at = COALESCE(?, last_verified_at), updated_at = CURRENT_TIMESTAMP
                WHERE service = ?
                """,
                (status.value, verified_at, normalized),
            )
            conn.commit()

    def rotate(
        self,
        service_or_id: str,
        new_secret: str,
        imported_from: str | None = None,
        alias: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CredentialRecord:
        current = self.resolve_credential(service_or_id, alias=alias)
        if not current:
            raise KeyError(f"Credential '{service_or_id}' not found")
        payload = CredentialSecret(
            secret=new_secret,
            metadata=self._resolve_secret_metadata(current.id, metadata),
            tags=current.tags,
            notes=current.notes,
        ).model_dump_json()
        encrypted_payload = encrypt_secret_versioned(
            payload,
            self.key,
            current.crypto_version,
            _record_aad_metadata(current),
        )
        current.encrypted_payload = encrypted_payload
        current.imported_from = imported_from or current.imported_from
        current.updated_at = utc_now()
        current.status = CredentialStatus.unknown
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE credentials
                SET encrypted_payload = ?, imported_from = ?, status = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    current.encrypted_payload,
                    current.imported_from,
                    current.status.value,
                    current.updated_at.isoformat(),
                    current.id,
                ),
            )
            conn.commit()
        return current

    def delete(self, service_or_id: str, alias: str | None = None) -> bool:
        """Delete a credential deterministically.

        If alias is provided, deletes service+alias.
        If service_or_id is a UUID, deletes that exact record.
        If service_only and multiple exist, raises AmbiguousTargetError.
        If service_only and exactly one exists, deletes it.
        """
        if alias is not None:
            normalized = normalize(service_or_id)
            with self._connection() as conn:
                cursor = conn.execute(
                    "DELETE FROM credentials WHERE service = ? AND alias = ?",
                    (normalized, alias),
                )
                conn.commit()
            return cursor.rowcount > 0

        with self._connection() as conn:
            # Try raw id first
            cursor = conn.execute(
                "DELETE FROM credentials WHERE id = ?", (service_or_id,)
            )
            if cursor.rowcount > 0:
                conn.commit()
                return True

            # Service-only — check count before deleting
            normalized = normalize(service_or_id)
            count_row = conn.execute(
                "SELECT COUNT(*) FROM credentials WHERE service = ?", (normalized,)
            ).fetchone()
            count = count_row[0] if count_row else 0

            if count == 0:
                conn.commit()
                return False
            if count > 1:
                conn.commit()
                raise AmbiguousTargetError(
                    f"Service '{normalized}' has {count} credentials — "
                    f"specify credential ID or service+alias to delete exactly one"
                )
            cursor = conn.execute(
                "DELETE FROM credentials WHERE service = ?", (normalized,)
            )
            conn.commit()
        return cursor.rowcount > 0

    def restore_credential(self, record: CredentialRecord) -> None:
        """Idempotently restore a complete credential row by id (upsert).

        Used to roll back a state-changing mutation when the audit chain
        refuses to seal the audit append. Because ``(service, alias)`` has
        no unique constraint, restoring by ``id`` is unambiguous. Safe to
        call repeatedly: a second application is a no-op write of the same
        row.

        The row is written verbatim from ``record`` using the same column
        set as ``add_credential``'s INSERT/UPDATE, so the original
        ciphertext and metadata are preserved exactly.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO credentials (
                    id, service, alias, credential_type, encrypted_payload, status, scopes,
                    tags, notes, created_at, updated_at, last_verified_at, imported_from, expiry, crypto_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    service = excluded.service,
                    alias = excluded.alias,
                    credential_type = excluded.credential_type,
                    encrypted_payload = excluded.encrypted_payload,
                    status = excluded.status,
                    scopes = excluded.scopes,
                    tags = excluded.tags,
                    notes = excluded.notes,
                    created_at = excluded.created_at,
                    updated_at = excluded.updated_at,
                    last_verified_at = excluded.last_verified_at,
                    imported_from = excluded.imported_from,
                    expiry = excluded.expiry,
                    crypto_version = excluded.crypto_version
                """,
                (
                    record.id,
                    record.service,
                    record.alias,
                    record.credential_type,
                    record.encrypted_payload,
                    record.status.value,
                    json.dumps(record.scopes),
                    json.dumps(record.tags),
                    record.notes,
                    record.created_at.isoformat(),
                    record.updated_at.isoformat(),
                    record.last_verified_at.isoformat() if record.last_verified_at else None,
                    record.imported_from,
                    record.expiry.isoformat() if record.expiry else None,
                    record.crypto_version,
                ),
            )
            conn.commit()

    def _row_to_record(self, row: sqlite3.Row) -> CredentialRecord:
        payload = dict(row)
        payload["scopes"] = json.loads(payload["scopes"])
        try:
            payload["tags"] = self._normalize_tags(json.loads(payload.get("tags") or "[]"))
        except (TypeError, json.JSONDecodeError):
            payload["tags"] = []
        payload["notes"] = self._normalize_notes(payload.get("notes"))
        payload["status"] = CredentialStatus(payload["status"])
        return CredentialRecord.model_validate(payload)

    def resolve_credential(self, service_or_id: str, alias: str | None = None) -> CredentialRecord:
        """Resolve a credential deterministically.

        Accepts:
          - credential UUID → exact match
          - service + alias → exact match
          - service only → only if exactly one credential exists for that service

        Raises:
          AmbiguousTargetError: service-only lookup matches multiple credentials.
          KeyError: no matching credential found.
        """
        # If alias is provided, always do service+alias lookup
        if alias is not None:
            record = self._find_by_service_alias(service_or_id, alias)
            if record:
                return record
            normalized = normalize(service_or_id)
            record = self._find_by_service_alias(normalized, alias)
            if not record:
                raise KeyError(f"No credential for service '{normalized}' alias '{alias}'")
            return record

        # Try by raw id first (UUID exact match)
        with self._connection() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM credentials WHERE id = ?", (service_or_id,)
            ).fetchone()
            if row:
                return self._row_to_record(row)

            # Service-only lookup — must be unambiguous
            normalized = normalize(service_or_id)
            if normalized != service_or_id:
                rows = conn.execute(
                    "SELECT * FROM credentials WHERE service = ? ORDER BY updated_at DESC",
                    (service_or_id,),
                ).fetchall()
                if rows:
                    if len(rows) > 1:
                        raise AmbiguousTargetError(
                            f"Service '{service_or_id}' has {len(rows)} credentials — "
                            f"specify credential ID or service+alias to target exactly one"
                        )
                    return self._row_to_record(rows[0])
            rows = conn.execute(
                "SELECT * FROM credentials WHERE service = ? ORDER BY updated_at DESC",
                (normalized,),
            ).fetchall()

        if not rows:
            raise KeyError(f"Service '{normalized}' not found in vault")
        if len(rows) > 1:
            raise AmbiguousTargetError(
                f"Service '{normalized}' has {len(rows)} credentials — "
                f"specify credential ID or service+alias to target exactly one"
            )
        return self._row_to_record(rows[0])

    def set_expiry(
        self,
        service_or_id: str,
        expiry: datetime,
        alias: str | None = None,
    ) -> CredentialRecord:
        """Set the expiry datetime for a credential.

        Uses resolve_credential() for selector resolution.
        Raises KeyError if credential not found.
        Raises AmbiguousTargetError if service-only matches multiple credentials.
        """
        record = self.resolve_credential(service_or_id, alias=alias)
        updated_at = utc_now()
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE credentials
                SET expiry = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    expiry.isoformat(),
                    updated_at.isoformat(),
                    record.id,
                ),
            )
            conn.commit()
        # Return the updated record. The row was just updated, so absence is corruption.
        updated = self.get_credential(record.id)
        if updated is None:
            raise KeyError(f"Credential disappeared after expiry update: {record.id}")
        return updated

    def clear_expiry(
        self,
        service_or_id: str,
        alias: str | None = None,
    ) -> bool:
        """Clear the expiry for a credential (sets expiry=NULL).

        Uses resolve_credential() for selector resolution.
        Returns True if a record was updated.
        Raises KeyError if credential not found.
        Raises AmbiguousTargetError if service-only matches multiple credentials.
        """
        record = self.resolve_credential(service_or_id, alias=alias)
        updated_at = utc_now()
        with self._connection() as conn:
            cursor = conn.execute(
                """
                UPDATE credentials
                SET expiry = NULL, updated_at = ?
                WHERE id = ?
                """,
                (
                    updated_at.isoformat(),
                    record.id,
                ),
            )
            conn.commit()
        return cursor.rowcount > 0

    def _count_by_service(self, service: str) -> int:
        """Count credentials for a normalized service name."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM credentials WHERE service = ?", (service,)
            ).fetchone()
            return row[0] if row else 0

    def _find_by_service_alias(self, service: str, alias: str) -> CredentialRecord | None:
        with self._connection() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT * FROM credentials
                WHERE service = ? AND alias = ?
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (service, alias),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def _resolve_secret_metadata(
        self,
        credential_id: str | None,
        metadata: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Return merged secret metadata for a credential write.

        Existing metadata is preserved when no explicit metadata override is
        supplied. When a credential is being replaced, this keeps non-secret
        fields intact unless the caller intentionally overrides them.
        """
        current_metadata: dict[str, Any] = {}
        if credential_id is not None:
            try:
                current_secret = self.get_secret(credential_id)
            except Exception:
                current_secret = None
            if current_secret and isinstance(current_secret.metadata, dict):
                current_metadata = dict(current_secret.metadata)
        if metadata is None:
            return current_metadata
        merged = dict(current_metadata)
        merged.update(metadata)
        return merged

    def _refresh_expired_leases(self, conn: sqlite3.Connection) -> None:
        now = utc_now().isoformat()
        conn.execute(
            """
            UPDATE leases
            SET status = ?,
                expires_at = CASE WHEN expires_at < ? THEN expires_at ELSE expires_at END
            WHERE status = ? AND expires_at < ?
            """,
            (LeaseStatus.expired.value, now, LeaseStatus.active.value, now),
        )

    def _row_to_lease_record(self, row: sqlite3.Row) -> LeaseRecord:
        payload = dict(row)
        payload["status"] = LeaseStatus(payload["status"])
        payload["ttl_seconds"] = int(payload["ttl_seconds"])
        payload["renew_count"] = int(payload.get("renew_count") or 0)
        payload["scopes"] = json.loads(payload.get("scopes") or "[]")
        metadata_raw = payload.get("metadata_json") or "{}"
        try:
            payload["metadata"] = json.loads(metadata_raw)
        except json.JSONDecodeError:
            payload["metadata"] = {"raw": metadata_raw}
        payload.pop("metadata_json", None)
        return LeaseRecord.model_validate(payload)

    def _find_lease(self, lease_id: str) -> LeaseRecord | None:
        with self._connection() as conn:
            conn.row_factory = sqlite3.Row
            self._refresh_expired_leases(conn)
            row = conn.execute("SELECT * FROM leases WHERE id = ?", (lease_id,)).fetchone()
        return self._row_to_lease_record(row) if row else None

    def issue_lease(
        self,
        service_or_id: str,
        agent_id: str,
        ttl_seconds: int,
        alias: str | None = None,
        purpose: str = "task",
        issued_by: str | None = None,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> LeaseRecord:
        record = self.resolve_credential(service_or_id, alias=alias)
        now = utc_now()
        expires_at = now + timedelta(seconds=ttl_seconds)
        lease = LeaseRecord(
            service=record.service,
            alias=record.alias,
            credential_id=record.id,
            credential_type=record.credential_type,
            agent_id=agent_id,
            issued_by=issued_by or agent_id,
            purpose=purpose,
            ttl_seconds=ttl_seconds,
            issued_at=now,
            expires_at=expires_at,
            reason=reason,
            scopes=record.scopes,
            metadata=metadata or {},
        )
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO leases (
                    id, service, alias, credential_id, credential_type, agent_id, issued_by, purpose,
                    status, ttl_seconds, issued_at, expires_at, revoked_at, renewed_at, renew_count,
                    reason, scopes, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    lease.id,
                    lease.service,
                    lease.alias,
                    lease.credential_id,
                    lease.credential_type,
                    lease.agent_id,
                    lease.issued_by,
                    lease.purpose,
                    lease.status.value,
                    lease.ttl_seconds,
                    lease.issued_at.isoformat(),
                    lease.expires_at.isoformat(),
                    lease.revoked_at.isoformat() if lease.revoked_at else None,
                    lease.renewed_at.isoformat() if lease.renewed_at else None,
                    lease.renew_count,
                    lease.reason,
                    json.dumps(lease.scopes),
                    json.dumps(lease.metadata, sort_keys=True),
                ),
            )
            conn.commit()
        return lease

    def list_leases(
        self,
        agent_id: str | None = None,
        service: str | None = None,
        status: LeaseStatus | str | None = None,
    ) -> list[LeaseRecord]:
        with self._connection() as conn:
            conn.row_factory = sqlite3.Row
            self._refresh_expired_leases(conn)
            conditions: list[str] = []
            params: list[Any] = []
            if agent_id is not None:
                conditions.append("agent_id = ?")
                params.append(agent_id)
            if service is not None:
                conditions.append("service = ?")
                params.append(normalize(service))
            if status is not None:
                status_value = status.value if isinstance(status, LeaseStatus) else str(status)
                conditions.append("status = ?")
                params.append(status_value)
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            rows = conn.execute(
                f"SELECT * FROM leases WHERE {where_clause} ORDER BY issued_at DESC"
            , params).fetchall()
        return [self._row_to_lease_record(row) for row in rows]

    def get_lease(self, lease_id: str) -> LeaseRecord | None:
        return self._find_lease(lease_id)

    def find_active_lease(
        self,
        *,
        agent_id: str,
        service: str,
        alias: str = "default",
    ) -> LeaseRecord | None:
        service = normalize(service)
        with self._connection() as conn:
            conn.row_factory = sqlite3.Row
            self._refresh_expired_leases(conn)
            row = conn.execute(
                """
                SELECT * FROM leases
                WHERE agent_id = ? AND service = ? AND alias = ? AND status = ?
                ORDER BY expires_at DESC
                LIMIT 1
                """,
                (agent_id, service, alias, LeaseStatus.active.value),
            ).fetchone()
        return self._row_to_lease_record(row) if row else None

    def _row_to_access_request_record(self, row: sqlite3.Row) -> AccessRequestRecord:
        payload = dict(row)
        payload["status"] = AccessRequestStatus(payload["status"])
        if payload.get("requested_ttl_seconds") is not None:
            payload["requested_ttl_seconds"] = int(payload["requested_ttl_seconds"])
        metadata_raw = payload.get("metadata_json") or "{}"
        try:
            payload["metadata"] = json.loads(metadata_raw)
        except json.JSONDecodeError:
            payload["metadata"] = {"raw": metadata_raw}
        payload.pop("metadata_json", None)
        return AccessRequestRecord.model_validate(payload)

    def create_access_request(
        self,
        *,
        agent_id: str,
        service: str,
        action: str,
        purpose: str,
        alias: str = "default",
        requested_ttl_seconds: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AccessRequestRecord:
        request = AccessRequestRecord(
            agent_id=agent_id,
            service=normalize(service),
            alias=alias,
            action=action,
            purpose=purpose,
            requested_ttl_seconds=requested_ttl_seconds,
            metadata=metadata or {},
        )
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO access_requests (
                    id, agent_id, service, alias, action, purpose, status,
                    requested_ttl_seconds, created_at, decided_at, decided_by,
                    decision_reason, lease_id, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.id,
                    request.agent_id,
                    request.service,
                    request.alias,
                    request.action,
                    request.purpose,
                    request.status.value,
                    request.requested_ttl_seconds,
                    request.created_at.isoformat(),
                    None,
                    request.decided_by,
                    request.decision_reason,
                    request.lease_id,
                    json.dumps(request.metadata, sort_keys=True),
                ),
            )
            conn.commit()
        return request

    def list_access_requests(
        self,
        *,
        agent_id: str | None = None,
        service: str | None = None,
        status: str | AccessRequestStatus | None = None,
    ) -> list[AccessRequestRecord]:
        with self._connection() as conn:
            conn.row_factory = sqlite3.Row
            conditions: list[str] = []
            params: list[Any] = []
            if agent_id is not None:
                conditions.append("agent_id = ?")
                params.append(agent_id)
            if service is not None:
                conditions.append("service = ?")
                params.append(normalize(service))
            if status is not None:
                status_value = status.value if isinstance(status, AccessRequestStatus) else str(status)
                conditions.append("status = ?")
                params.append(status_value)
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            rows = conn.execute(
                f"SELECT * FROM access_requests WHERE {where_clause} ORDER BY created_at DESC",
                params,
            ).fetchall()
        return [self._row_to_access_request_record(row) for row in rows]

    def get_access_request(self, request_id: str) -> AccessRequestRecord | None:
        with self._connection() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM access_requests WHERE id = ?", (request_id,)).fetchone()
        return self._row_to_access_request_record(row) if row else None

    def decide_access_request(
        self,
        request_id: str,
        *,
        status: AccessRequestStatus | str,
        decided_by: str,
        reason: str | None = None,
        lease_id: str | None = None,
    ) -> AccessRequestRecord:
        current = self.get_access_request(request_id)
        if current is None:
            raise KeyError(f"Access request '{request_id}' not found")
        if current.status is not AccessRequestStatus.pending:
            raise ValueError(f"Access request '{request_id}' is already {current.status.value}")
        status_value = status.value if isinstance(status, AccessRequestStatus) else str(status)
        decided_at = utc_now()
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE access_requests
                SET status = ?, decided_at = ?, decided_by = ?, decision_reason = ?, lease_id = ?
                WHERE id = ?
                """,
                (status_value, decided_at.isoformat(), decided_by, reason, lease_id, request_id),
            )
            conn.commit()
        updated = self.get_access_request(request_id)
        if updated is None:
            raise KeyError(f"Access request '{request_id}' not found after update")
        return updated

    def renew_lease(
        self,
        lease_id: str,
        ttl_seconds: int,
    ) -> LeaseRecord:
        lease = self._find_lease(lease_id)
        if lease is None:
            raise KeyError(f"Lease '{lease_id}' not found")
        if lease.status == LeaseStatus.revoked:
            raise ValueError(f"Lease '{lease_id}' has been revoked")
        now = utc_now()
        base = lease.expires_at if lease.status != LeaseStatus.expired and lease.expires_at > now else now
        updated = lease.model_copy(update={
            "status": LeaseStatus.active,
            "ttl_seconds": ttl_seconds,
            "expires_at": base + timedelta(seconds=ttl_seconds),
            "renewed_at": now,
            "renew_count": lease.renew_count + 1,
        })
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE leases
                SET status = ?, ttl_seconds = ?, expires_at = ?, renewed_at = ?, renew_count = ?
                WHERE id = ?
                """,
                (
                    updated.status.value,
                    updated.ttl_seconds,
                    updated.expires_at.isoformat(),
                    updated.renewed_at.isoformat() if updated.renewed_at else None,
                    updated.renew_count,
                    updated.id,
                ),
            )
            conn.commit()
        return updated

    def revoke_lease(self, lease_id: str, reason: str | None = None) -> LeaseRecord:
        lease = self._find_lease(lease_id)
        if lease is None:
            raise KeyError(f"Lease '{lease_id}' not found")
        if lease.status == LeaseStatus.revoked:
            raise ValueError(f"Lease '{lease_id}' has already been revoked")
        now = utc_now()
        updated = lease.model_copy(update={
            "status": LeaseStatus.revoked,
            "revoked_at": now,
            "reason": reason if reason is not None else lease.reason,
        })
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE leases
                SET status = ?, revoked_at = ?, reason = ?
                WHERE id = ?
                """,
                (
                    updated.status.value,
                    updated.revoked_at.isoformat() if updated.revoked_at else None,
                    updated.reason,
                    updated.id,
                ),
            )
            conn.commit()
        return updated

    def export_backup(self, *, metadata_only: bool = False, include_audit: bool = False) -> dict:
        """Export all credentials as a portable backup dict.

        When *metadata_only* is True encrypted payloads are excluded.
        """
        records = self.list_credentials()
        backup_creds = []
        for rec in records:
            entry = {
                "id": rec.id,
                "service": rec.service,
                "alias": rec.alias,
                "credential_type": rec.credential_type,
                "status": rec.status.value,
                "scopes": rec.scopes,
                "tags": rec.tags,
                "notes": rec.notes,
                "imported_from": rec.imported_from,
                "expiry": rec.expiry.isoformat() if rec.expiry else None,
                "crypto_version": rec.crypto_version,
                "created_at": rec.created_at.isoformat(),
                "updated_at": rec.updated_at.isoformat(),
                "last_verified_at": rec.last_verified_at.isoformat() if rec.last_verified_at else None,
            }
            if not metadata_only:
                entry["encrypted_payload"] = rec.encrypted_payload
            backup_creds.append(entry)
        backup_leases = []
        for lease in self.list_leases():
            backup_leases.append({
                "id": lease.id,
                "service": lease.service,
                "alias": lease.alias,
                "credential_id": lease.credential_id,
                "credential_type": lease.credential_type,
                "agent_id": lease.agent_id,
                "issued_by": lease.issued_by,
                "purpose": lease.purpose,
                "status": lease.status.value,
                "ttl_seconds": lease.ttl_seconds,
                "issued_at": lease.issued_at.isoformat(),
                "expires_at": lease.expires_at.isoformat(),
                "revoked_at": lease.revoked_at.isoformat() if lease.revoked_at else None,
                "renewed_at": lease.renewed_at.isoformat() if lease.renewed_at else None,
                "renew_count": lease.renew_count,
                "reason": lease.reason,
                "scopes": lease.scopes,
                "metadata": lease.metadata,
            })
        backup = {
            "version": "hvbackup-v1",
            "exported_at": utc_now().isoformat(),
            "credentials": backup_creds,
            "leases": backup_leases,
        }
        if include_audit:
            audit_service = AuditIntegrityService(self.db_path, self.key)
            audit_service.ensure_initialized()
            backup["version"] = "hvbackup-v2"
            backup["audit_integrity"] = audit_service.export_evidence()  # type: ignore[assignment]
        return backup

    def import_backup(
        self,
        backup: dict,
        replace: bool = True,
        agent_id: str = "operator",  # matches OPERATOR_AGENT_ID in mutations.py
    ) -> list[CredentialRecord]:
        """Import credentials from a backup dict. Existing records are replaced by default.

        Supports hvbackup-v1 and hvbackup-v2 (credential portion only).
        Rejects metadata-only backups (entries missing encrypted_payload).

        *agent_id* names the acting principal for the protected restore audit
        event. Operator/CLI callers keep the explicit safe default
        (``operator``); broker-driven imports pass the real agent so the
        tamper-evident trail attributes the restore correctly (issue #62A F4).

        Slice E1 (issue #62): the restore is validated by a preflight routine
        before any mutation — the evidence contract is confirmed (v2 backups
        must carry audit integrity evidence that detached-verifies healthy,
        matching backup-verify / restore --dry-run semantics), restored
        leases are rejected if they would mint a forged active lease identity
        or reference a foreign credential, and every lease's broker identity
        must match the credential it references. The import then runs as a
        single transaction together with a protected restore audit event
        through the shared audit seam; if any row, validation, or audit
        append fails, the whole restore rolls back atomically.

        Issue #62B (F5/F6): the audit write lock is held across the health
        gate and the transaction, and lease/credential linkage plus broker
        identity are re-verified inside ``BEGIN IMMEDIATE`` against fresh
        state, closing the preflight-to-transaction TOCTOU. The protected
        restore event uses a deterministic id derived from the backup content
        so a retry is idempotent; the checkpoint is published after commit,
        and a checkpoint publication failure raises
        :class:`RestoreCommittedCheckpointError` — the restore data is
        durable and the chain verifies ``checkpoint_stale`` until the
        checkpoint is re-published, never a rolled-back restore.
        """
        version = backup.get("version")
        if version not in ("hvbackup-v1", "hvbackup-v2"):
            raise ValueError(f"Unsupported backup version: {version}")

        # ── E1 preflight: validate before any mutation ──
        # 1. Evidence contract: hvbackup-v2 backups must carry detached
        #    audit integrity evidence that verifies healthy (slice D
        #    prerequisite, issue #62A F3). The integrity_available marker
        #    alone is not evidence: the full payload is detached-verified
        #    against the current vault key with the same healthy/complete
        #    semantics as backup-verify / restore --dry-run, so a marker-only
        #    or forged payload fails closed before any write.
        if version == "hvbackup-v2":
            evidence = backup.get("audit_integrity")
            if not isinstance(evidence, dict) or evidence.get("integrity_available") is not True:
                raise ValueError(
                    "Cannot restore an hvbackup-v2 backup without audit integrity evidence. "
                    "Use a full v2 backup (with audit evidence) for restore."
                )
            status, reason = verify_detached_evidence(evidence, self.key)
            if status != DETACHED_HEALTHY:
                raise ValueError(
                    f"Cannot restore an hvbackup-v2 backup with invalid audit integrity "
                    f"evidence ({status}: {reason}). Run backup-verify or restore "
                    "--dry-run for a full report."
                )

        # 2. Parse and validate every credential row before writing anything.
        prepared_creds: list[tuple[CredentialRecord, CredentialRecord | None]] = []
        for cred_data in backup.get("credentials", []):
            if cred_data.get("encrypted_payload") is None:
                raise ValueError(
                    "Cannot restore a metadata-only backup. "
                    "Metadata-only backups are for inspection/diff only. "
                    "Use a full backup (without --metadata-only) for restore."
                )
            # Normalize service name on import
            service = normalize(cred_data["service"])
            existing = self._find_by_service_alias(service, cred_data["alias"])
            if existing and not replace:
                continue
            # Parse ISO strings back to datetimes
            last_verified_at = None
            if cred_data.get("last_verified_at"):
                last_verified_at = datetime.fromisoformat(cred_data["last_verified_at"])
            expiry = None
            if cred_data.get("expiry"):
                expiry = datetime.fromisoformat(cred_data["expiry"])
            record = CredentialRecord(
                id=cred_data.get("id") or str(uuid4()),  # validate or regenerate id
                service=service,
                alias=cred_data["alias"],
                credential_type=cred_data["credential_type"],
                encrypted_payload=cred_data["encrypted_payload"],
                status=CredentialStatus(cred_data.get("status", "unknown")),
                scopes=cred_data.get("scopes", []),
                tags=self._normalize_tags(cred_data.get("tags") or []),
                notes=self._normalize_notes(cred_data.get("notes")),
                imported_from=cred_data.get("imported_from"),
                expiry=expiry,
                last_verified_at=last_verified_at,
                created_at=utc_now(),  # restore is a new creation event
                updated_at=utc_now(),
                crypto_version=cred_data.get("crypto_version", "aesgcm-v1"),
            )
            if existing:
                # The destination row keeps its own id/metadata. A v2 payload
                # from the backup was encrypted against the SOURCE row's
                # metadata; when the bound metadata differs (e.g. a different
                # id), rebind the payload to this row so restore stays
                # decryptable (issue #60).
                incoming_version = record.crypto_version
                dest_payload = record.encrypted_payload
                if incoming_version == CRYPTO_VERSION_V2:
                    source_meta = credential_aad_metadata(
                        cred_data.get("id") or existing.id,
                        normalize(cred_data.get("service") or existing.service),
                        cred_data.get("alias") or existing.alias,
                        cred_data.get("credential_type") or existing.credential_type,
                        cred_data.get("scopes") or existing.scopes,
                    )
                    dest_meta = credential_aad_metadata(
                        existing.id,
                        existing.service,
                        existing.alias,
                        record.credential_type,
                        record.scopes,
                    )
                    if build_canonical_aad(source_meta) != build_canonical_aad(dest_meta):
                        try:
                            plaintext = decrypt_secret_versioned(
                                dest_payload, self.key, incoming_version, source_meta
                            )
                        except Exception:
                            raise ValueError(
                                "Imported v2 credential payload could not be decrypted "
                                f"with the source metadata for {service}/{record.alias}."
                            )
                        dest_payload = encrypt_secret_versioned(
                            plaintext, self.key, incoming_version, dest_meta
                        )
                record = existing.model_copy(update={
                    "credential_type": cred_data["credential_type"],
                    "encrypted_payload": dest_payload,
                    "status": CredentialStatus(cred_data.get("status", "unknown")),
                    "scopes": cred_data.get("scopes", []),
                    "tags": self._normalize_tags(cred_data.get("tags")) if "tags" in cred_data else existing.tags,
                    "notes": self._normalize_notes(cred_data.get("notes")) if "notes" in cred_data else existing.notes,
                    "imported_from": cred_data.get("imported_from"),
                    "last_verified_at": last_verified_at,
                    "updated_at": utc_now(),
                    "crypto_version": incoming_version,
                })
            prepared_creds.append((record, existing))

        # 3. Parse and validate leases: credential_id linkage must resolve to
        #    a credential in this backup or already in the vault, and the
        #    lease's broker identity must match the referenced credential.
        allowed_credential_ids = {rec.id for rec, _ in prepared_creds}
        allowed_credential_ids.update(rec.id for rec in self.list_credentials())
        credential_identity: dict[str, CredentialRecord] = {
            rec.id: rec for rec, _ in prepared_creds
        }
        for rec in self.list_credentials():
            credential_identity.setdefault(rec.id, rec)

        prepared_leases: list[tuple[LeaseRecord, LeaseRecord | None]] = []
        for lease_data in backup.get("leases", []):
            lease_id = lease_data.get("id") or str(uuid4())
            metadata = lease_data.get("metadata") or {}
            if not isinstance(metadata, dict):
                metadata = {"raw": metadata}
            scopes = lease_data.get("scopes") or []
            if not isinstance(scopes, list):
                scopes = [str(scopes)]
            lease = LeaseRecord(
                id=lease_id,
                service=normalize(lease_data.get("service", "")),
                alias=str(lease_data.get("alias") or "default"),
                credential_id=str(lease_data.get("credential_id") or ""),
                credential_type=str(lease_data.get("credential_type") or "unknown"),
                agent_id=str(lease_data.get("agent_id") or ""),
                issued_by=str(lease_data.get("issued_by") or lease_data.get("agent_id") or ""),
                purpose=str(lease_data.get("purpose") or "task"),
                status=LeaseStatus(str(lease_data.get("status") or LeaseStatus.active.value)),
                ttl_seconds=int(lease_data.get("ttl_seconds") or 0),
                issued_at=datetime.fromisoformat(lease_data.get("issued_at")) if lease_data.get("issued_at") else utc_now(),
                expires_at=datetime.fromisoformat(lease_data.get("expires_at")) if lease_data.get("expires_at") else utc_now(),
                revoked_at=datetime.fromisoformat(lease_data["revoked_at"]) if lease_data.get("revoked_at") else None,
                renewed_at=datetime.fromisoformat(lease_data["renewed_at"]) if lease_data.get("renewed_at") else None,
                renew_count=int(lease_data.get("renew_count") or 0),
                reason=lease_data.get("reason"),
                scopes=[str(item) for item in scopes],
                metadata=metadata,
            )
            if lease.credential_id not in allowed_credential_ids:
                raise ValueError(
                    f"Lease {lease_id!r} references credential {lease.credential_id!r} "
                    "which is not part of the backup or the vault (foreign credential linkage)."
                )
            referenced = credential_identity.get(lease.credential_id)
            if referenced is not None and (
                lease.service != referenced.service
                or lease.alias != referenced.alias
                or lease.credential_type != referenced.credential_type
            ):
                raise ValueError(
                    f"Lease {lease_id!r} broker identity "
                    f"({lease.service}/{lease.alias}/{lease.credential_type}) does not match "
                    f"credential {referenced.id!r} ({referenced.service}/{referenced.alias}/{referenced.credential_type})."
                )
            # No active forged leases as part of import policy: a restored
            # lease is never minted active (issue #62).
            if lease.status is LeaseStatus.active:
                lease = lease.model_copy(update={
                    "status": LeaseStatus.revoked,
                    "revoked_at": utc_now(),
                    "reason": "restored as revoked (active leases are never restored)",
                })
            prepared_leases.append((lease, self.get_lease(lease_id)))

        # 4. Build the protected restore event. Its id is deterministic
        #    (derived from the backup's restore-relevant content and acting
        #    agent) so a retry of the same restore reuses the event instead
        #    of appending a duplicate protected event (issue #62B / F6).
        audit_service = AuditIntegrityService(self.db_path, self.key)
        audit_service.ensure_initialized()
        restore_event = AccessLogRecord(
            id=_restore_event_id(backup, version, agent_id),
            agent_id=agent_id,  # real acting agent (operator default; broker passes the agent)
            service="*",
            action="restore",
            decision=Decision.allow,
            reason=(
                f"restored {len(prepared_creds)} credential(s) and "
                f"{len(prepared_leases)} lease(s) from {version} backup"
            ),
            metadata={
                "backup_version": version,
                "credential_count": len(prepared_creds),
                "lease_count": len(prepared_leases),
            },
        )

        # ── E1 single transaction: credentials + leases + protected audit ──
        # The audit write lock is held across the health gate AND the
        # transaction, so the preflight audit verification cannot be
        # invalidated by a concurrent audit writer before the append
        # (issue #62B / F5).
        imported: list[CredentialRecord] = []
        try:
            with audit_write_lock(audit_service.lock_path):
                current = audit_service.verify()
                if current.status != AuditIntegrityStatus.healthy:
                    # A retry of an already-committed restore is the one case
                    # where the chain may be checkpoint_stale: the previous
                    # attempt committed the protected event but failed to
                    # publish the checkpoint (F6). checkpoint_stale is only
                    # reported after the full chain walk passes, so the chain
                    # itself is healthy and the retry may proceed to
                    # re-publish the checkpoint instead of duplicating it.
                    event_already_committed = audit_service.access_log_exists(restore_event.id)
                    if not (event_already_committed and current.reason_code == "checkpoint_stale"):
                        raise AuditIntegrityError(current.sanitized_reason)
                with self._connection() as conn:
                    conn.row_factory = sqlite3.Row
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        # ── F5: re-verify linkage/identity inside the write
                        # transaction. The preflight validated against the
                        # pre-lock snapshot; BEGIN IMMEDIATE now holds the
                        # SQLite write lock, so re-checking against fresh
                        # state closes the preflight-to-transaction TOCTOU:
                        # a concurrent writer can no longer interleave once
                        # we hold the write lock, and a dangling lease or
                        # stale-identity import is rejected atomically.
                        existing_ids = {row["id"] for row in conn.execute("SELECT id FROM credentials")}
                        inserted_ids = {rec.id for rec, existing in prepared_creds if existing is None}
                        for rec, existing in prepared_creds:
                            if existing is not None and rec.id not in existing_ids:
                                raise ValueError(
                                    f"Credential {rec.service}/{rec.alias} was removed while the restore "
                                    "was being prepared; the restore was aborted to preserve atomicity. "
                                    "Retry the restore."
                                )
                        final_cred_ids = existing_ids | inserted_ids
                        prepared_identity = {rec.id: rec for rec, _existing in prepared_creds}
                        for lease, _existing_lease in prepared_leases:
                            if lease.credential_id not in final_cred_ids:
                                raise ValueError(
                                    f"Lease {lease.id!r} references credential {lease.credential_id!r} "
                                    "which is not part of the backup or the vault (foreign credential linkage)."
                                )
                            row = conn.execute(
                                "SELECT service, alias, credential_type FROM credentials WHERE id = ?",
                                (lease.credential_id,),
                            ).fetchone()
                            if row is None:
                                referenced = prepared_identity[lease.credential_id]
                                referenced_identity = (referenced.service, referenced.alias, referenced.credential_type)
                            else:
                                referenced_identity = (row["service"], row["alias"], row["credential_type"])
                            lease_identity = (lease.service, lease.alias, lease.credential_type)
                            if lease_identity != referenced_identity:
                                raise ValueError(
                                    f"Lease {lease.id!r} broker identity "
                                    f"({lease.service}/{lease.alias}/{lease.credential_type}) does not match "
                                    f"credential {lease.credential_id!r} "
                                    f"({referenced_identity[0]}/{referenced_identity[1]}/{referenced_identity[2]})."
                                )
                        for record, existing in prepared_creds:
                            if existing:
                                conn.execute(
                                    """
                                    UPDATE credentials
                                    SET credential_type=?, encrypted_payload=?, status=?, scopes=?,
                                        tags=?, notes=?, updated_at=?, last_verified_at=?, imported_from=?, expiry=?, crypto_version=?
                                    WHERE id=?
                                    """,
                                    (
                                        record.credential_type,
                                        record.encrypted_payload,
                                        record.status.value,
                                        json.dumps(record.scopes),
                                        json.dumps(record.tags),
                                        record.notes,
                                        record.updated_at.isoformat(),
                                        record.last_verified_at.isoformat() if record.last_verified_at else None,
                                        record.imported_from,
                                        record.expiry.isoformat() if record.expiry else None,
                                        record.crypto_version,
                                        record.id,
                                    ),
                                )
                            else:
                                conn.execute(
                                    """
                                    INSERT INTO credentials (
                                        id, service, alias, credential_type, encrypted_payload, status, scopes,
                                        tags, notes, created_at, updated_at, last_verified_at, imported_from, expiry, crypto_version
                                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                    """,
                                    (
                                        record.id,
                                        record.service,
                                        record.alias,
                                        record.credential_type,
                                        record.encrypted_payload,
                                        record.status.value,
                                        json.dumps(record.scopes),
                                        json.dumps(record.tags),
                                        record.notes,
                                        record.created_at.isoformat(),
                                        record.updated_at.isoformat(),
                                        record.last_verified_at.isoformat() if record.last_verified_at else None,
                                        record.imported_from,
                                        record.expiry.isoformat() if record.expiry else None,
                                        record.crypto_version,
                                    ),
                                )
                            imported.append(record)
                        for lease, existing_lease in prepared_leases:
                            if existing_lease:
                                conn.execute(
                                    """
                                    UPDATE leases
                                    SET service=?, alias=?, credential_id=?, credential_type=?, agent_id=?, issued_by=?,
                                        purpose=?, status=?, ttl_seconds=?, issued_at=?, expires_at=?, revoked_at=?,
                                        renewed_at=?, renew_count=?, reason=?, scopes=?, metadata_json=?
                                    WHERE id=?
                                    """,
                                    (
                                        lease.service,
                                        lease.alias,
                                        lease.credential_id,
                                        lease.credential_type,
                                        lease.agent_id,
                                        lease.issued_by,
                                        lease.purpose,
                                        lease.status.value,
                                        lease.ttl_seconds,
                                        lease.issued_at.isoformat(),
                                        lease.expires_at.isoformat(),
                                        lease.revoked_at.isoformat() if lease.revoked_at else None,
                                        lease.renewed_at.isoformat() if lease.renewed_at else None,
                                        lease.renew_count,
                                        lease.reason,
                                        json.dumps(lease.scopes),
                                        json.dumps(lease.metadata, sort_keys=True),
                                        lease.id,
                                    ),
                                )
                            else:
                                conn.execute(
                                    """
                                    INSERT INTO leases (
                                        id, service, alias, credential_id, credential_type, agent_id, issued_by, purpose,
                                        status, ttl_seconds, issued_at, expires_at, revoked_at, renewed_at, renew_count,
                                        reason, scopes, metadata_json
                                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                    """,
                                    (
                                        lease.id,
                                        lease.service,
                                        lease.alias,
                                        lease.credential_id,
                                        lease.credential_type,
                                        lease.agent_id,
                                        lease.issued_by,
                                        lease.purpose,
                                        lease.status.value,
                                        lease.ttl_seconds,
                                        lease.issued_at.isoformat(),
                                        lease.expires_at.isoformat(),
                                        lease.revoked_at.isoformat() if lease.revoked_at else None,
                                        lease.renewed_at.isoformat() if lease.renewed_at else None,
                                        lease.renew_count,
                                        lease.reason,
                                        json.dumps(lease.scopes),
                                        json.dumps(lease.metadata, sort_keys=True),
                                    ),
                                )
                        # ── F6: idempotent protected event. A retry of an
                        # already-committed restore reuses the deterministic
                        # event id and skips the append; the credential/lease
                        # writes above are row-idempotent, so the replay only
                        # re-publishes the checkpoint.
                        existing_event = conn.execute(
                            "SELECT id FROM access_logs WHERE id = ?", (restore_event.id,)
                        ).fetchone()
                        if existing_event is None:
                            append_result = audit_service.append_in_transaction(conn, restore_event)
                        else:
                            append_result = None
                        conn.commit()
                    except Exception:
                        conn.rollback()
                        raise
                    # Checkpoint publication runs after commit by design: the
                    # SQLite commit is the durability boundary for the restore
                    # data and its protected event. A failure here must not
                    # report a rolled-back restore (F6) — the data is durable,
                    # and the chain verifies checkpoint_stale until the
                    # checkpoint is re-published.
                    try:
                        if append_result is not None:
                            audit_service.write_checkpoint_after_append(conn, append_result)
                        else:
                            audit_service.refresh_checkpoint(conn)
                    except Exception as exc:
                        raise RestoreCommittedCheckpointError(
                            "Restore data committed, but the audit checkpoint could not be published "
                            f"after commit ({exc}). Audit integrity will report checkpoint_stale until "
                            "the checkpoint is re-published; re-run this restore (it is idempotent) or "
                            "run 'hermes-vault audit checkpoint advance'."
                        ) from exc
        except AuditLockError as exc:
            raise AuditIntegrityError(str(exc)) from exc
        return imported

    def rotate_master_key(
        self,
        old_passphrase: str,
        new_passphrase: str,
        backup_path: Path | None = None,
    ) -> dict[str, int]:
        """Re-encrypt all credentials under a new master key.

        Derives a new salt and new key from *new_passphrase*, then re-encrypts
        every credential row. The operation is atomic — if any credential
        fails, the entire rotation is rolled back.

        If *backup_path* is provided, an encrypted backup of the vault is
        written before rotation begins.

        Returns a dict with ``re_encrypted`` (count) and ``failed`` (always 0
        on success).

        Raises ValueError if the old passphrase does not match the current key
        or if any credential fails re-encryption.
        """
        # Read the existing master key (format-agnostic: 16-byte salt
        # or DPAPI envelope). load_or_create_master_key returns the
        # 32-byte master key bytes directly, regardless of which
        # on-disk format is in use. enable_dpapi=False ensures we
        # never accidentally write a DPAPI envelope during this read.
        old_key = load_or_create_master_key(
            self.salt_path, old_passphrase, enable_dpapi=False,
        )
        test_records = self.list_credentials()
        if test_records:
            try:
                decrypt_secret_versioned(
                    test_records[0].encrypted_payload,
                    old_key,
                    test_records[0].crypto_version,
                    _record_aad_metadata(test_records[0]),
                )
            except Exception:
                raise ValueError(
                    "Old passphrase does not match this vault — rotation aborted."
                )
        else:
            pass  # empty vault — old passphrase can't be verified by data

        audit_integrity = AuditIntegrityService(self.db_path, old_key)
        audit_integrity.ensure_initialized()
        audit_result = audit_integrity.verify()
        if audit_result.status.value != "healthy":
            raise AuditIntegrityError(audit_result.sanitized_reason)

        if backup_path is not None:
            self.export_backup()
            content = json.dumps(self.export_backup(), indent=2, sort_keys=True)
            backup_path.write_text(content, encoding="utf-8")
            backup_path.chmod(0o600)

        new_salt = os.urandom(SALT_SIZE)
        new_key = derive_key(new_passphrase, new_salt)

        # Typed v2 journal (issue #66 / Slice C): persist the old/new
        # durable material plus the encrypted old audit/master key under
        # the new key BEFORE the credential DB commit. The journal never
        # stores a passphrase or a plaintext key; the recovery envelope
        # is AES-GCM-wrapped under the new key with AAD bound to the
        # journal id.
        existing_durable = self.salt_path.read_bytes() if self.salt_path.exists() else b""
        old_durable = _durable_from_bytes(existing_durable, new_salt)
        new_durable = DurableMaterial(kind=DurableKind.pbkdf_salt, salt=new_salt)
        journal_id = str(uuid4())
        recovery = encrypt_old_key_recovery(old_key, new_key, journal_id)
        entry = RotationJournalEntry.start(
            old_durable=old_durable,
            new_durable=new_durable,
            old_key_recovery=recovery,
            journal_id=journal_id,
        )
        self._write_rotation_journal(entry.to_dict())

        # Record the exact old audit segment BEFORE the DB commit so a
        # crash between the commit and the db_committed journal write can
        # still be reconciled on reopen.
        old_segment_id = audit_result.active_segment_id or ""

        re_encrypted = 0
        all_records = self.list_credentials()
        with self._connection() as conn:
            conn.execute("BEGIN EXCLUSIVE")
            try:
                for rec in all_records:
                    payload_plain = decrypt_secret_versioned(
                        rec.encrypted_payload,
                        old_key,
                        rec.crypto_version,
                        _record_aad_metadata(rec),
                    )
                    new_encrypted = encrypt_secret_versioned(
                        payload_plain,
                        new_key,
                        rec.crypto_version,
                        _record_aad_metadata(rec),
                    )
                    conn.execute(
                        "UPDATE credentials SET encrypted_payload = ?, updated_at = ? WHERE id = ?",
                        (new_encrypted, utc_now().isoformat(), rec.id),
                    )
                    re_encrypted += 1
                conn.commit()
            except Exception:
                conn.rollback()
                raise

        # After the DB commit persist db_committed/pending with the exact
        # old audit segment captured before the commit.
        committed = entry.mark_db_committed(
            old_segment_id=old_segment_id,
            old_key_recovery=recovery,
        )
        self._write_rotation_journal(committed.to_dict())

        audit_integrity.rotate_segment(new_key)

        final = committed.mark_audit_checkpoint_committed()
        self._write_rotation_journal(final.to_dict())

        # Verify the audit chain is healthy under the new key before
        # finalizing the durable material and deleting the journal (issue
        # #66: deletion only after all checks pass).
        post_result = audit_integrity.verify()
        if post_result.status.value != "healthy":
            raise AuditIntegrityError(
                f"Master-key rotation completed but audit verification is not healthy "
                f"({post_result.sanitized_reason}); rotation journal retained for recovery."
            )

        # DPAPI-aware write: when HERMES_VAULT_DPAPI=1 is set, the
        # new master key is wrapped with DPAPI on write. Otherwise the
        # legacy 16-byte derivation salt is written verbatim. No
        # silent migration: a legacy vault with no opt-in continues to
        # write the legacy salt format.
        self._write_master_key_durable(new_salt, new_key)
        self.rotation_journal_path.unlink(missing_ok=True)
        self._fsync_directory(self.rotation_journal_path.parent)

        self.key = new_key
        return {"re_encrypted": re_encrypted, "failed": 0}
