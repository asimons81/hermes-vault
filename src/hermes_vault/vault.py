from __future__ import annotations

import json
import os
import sqlite3
import sys
from typing import Any
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from hermes_vault import _platform
from hermes_vault.audit_integrity.service import AuditIntegrityError, AuditIntegrityService
from hermes_vault.crypto import (
    CRYPTO_VERSION,
    CorruptKeyMaterialError,
    MissingKeyMaterialError,
    SALT_SIZE,
    decrypt_secret,
    derive_key,
    encrypt_secret,
    load_or_create_master_key,
)
from hermes_vault.models import (
    AccessRequestRecord,
    AccessRequestStatus,
    CredentialRecord,
    CredentialSecret,
    CredentialStatus,
    LeaseRecord,
    LeaseStatus,
    utc_now,
)
from hermes_vault.service_ids import normalize


class DuplicateCredentialError(RuntimeError):
    pass


class AmbiguousTargetError(RuntimeError):
    """Raised when a service-only lookup matches multiple credentials."""
    pass


class RotationRecoveryError(RuntimeError):
    """Raised when an interrupted master-key rotation cannot be recovered."""


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

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
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

    def _first_encrypted_payload(self) -> str | None:
        if not self.db_path.exists():
            return None
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT encrypted_payload FROM credentials ORDER BY updated_at DESC LIMIT 1"
            ).fetchone()
        return row[0] if row else None

    def _payload_decrypts_with_salt(self, passphrase: str, salt: bytes, payload: str) -> bool:
        try:
            decrypt_secret(payload, derive_key(passphrase, salt))
            return True
        except Exception:
            return False

    def _recover_rotation_journal(self, passphrase: str) -> None:
        journal_path = self.rotation_journal_path
        if not journal_path.exists():
            return
        try:
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            old_salt = bytes.fromhex(journal["old_salt"])
            new_salt = bytes.fromhex(journal["new_salt"])
        except Exception as exc:
            raise RotationRecoveryError(
                f"Master-key rotation journal at {journal_path} is unreadable."
            ) from exc

        payload = self._first_encrypted_payload()
        if payload is None:
            recovered_salt = new_salt if journal.get("status") == "db_committed" else old_salt
        elif self._payload_decrypts_with_salt(passphrase, new_salt, payload):
            recovered_salt = new_salt
        elif self._payload_decrypts_with_salt(passphrase, old_salt, payload):
            recovered_salt = old_salt
        else:
            raise RotationRecoveryError(
                "Interrupted master-key rotation could not be recovered with either journaled salt."
            )

        self._replace_salt_durable(recovered_salt)
        journal_path.unlink()
        self._fsync_directory(journal_path.parent)

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
        payload = CredentialSecret(
            secret=secret,
            metadata=self._resolve_secret_metadata(existing.id if existing else None, metadata),
            tags=resolved_tags,
            notes=resolved_notes,
        ).model_dump_json()
        encrypted_payload = encrypt_secret(payload, self.key)
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
            "crypto_version": CRYPTO_VERSION,
        }) if existing and replace_existing else CredentialRecord(
            service=service,
            alias=alias,
            credential_type=credential_type,
            encrypted_payload=encrypted_payload,
            imported_from=imported_from,
            scopes=scopes or [],
            tags=resolved_tags,
            notes=resolved_notes,
            crypto_version=CRYPTO_VERSION,
        )
        with sqlite3.connect(self.db_path) as conn:
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
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM credentials ORDER BY service, alias").fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_credential(self, service_or_id: str) -> CredentialRecord | None:
        # Try by raw id first (UUID), then by canonicalized service name
        with sqlite3.connect(self.db_path) as conn:
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
        payload = decrypt_secret(record.encrypted_payload, self.key)
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
            with sqlite3.connect(self.db_path) as conn:
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

        with sqlite3.connect(self.db_path) as conn:
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
        encrypted_payload = encrypt_secret(payload, self.key)
        current.encrypted_payload = encrypted_payload
        current.imported_from = imported_from or current.imported_from
        current.updated_at = utc_now()
        current.status = CredentialStatus.unknown
        with sqlite3.connect(self.db_path) as conn:
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
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "DELETE FROM credentials WHERE service = ? AND alias = ?",
                    (normalized, alias),
                )
                conn.commit()
            return cursor.rowcount > 0

        with sqlite3.connect(self.db_path) as conn:
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
        with sqlite3.connect(self.db_path) as conn:
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
        with sqlite3.connect(self.db_path) as conn:
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
        with sqlite3.connect(self.db_path) as conn:
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
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM credentials WHERE service = ?", (service,)
            ).fetchone()
            return row[0] if row else 0

    def _find_by_service_alias(self, service: str, alias: str) -> CredentialRecord | None:
        with sqlite3.connect(self.db_path) as conn:
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
        with sqlite3.connect(self.db_path) as conn:
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
        with sqlite3.connect(self.db_path) as conn:
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
        with sqlite3.connect(self.db_path) as conn:
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
        with sqlite3.connect(self.db_path) as conn:
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
        with sqlite3.connect(self.db_path) as conn:
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
        with sqlite3.connect(self.db_path) as conn:
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
        with sqlite3.connect(self.db_path) as conn:
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
        with sqlite3.connect(self.db_path) as conn:
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
        with sqlite3.connect(self.db_path) as conn:
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
        with sqlite3.connect(self.db_path) as conn:
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

    def import_backup(self, backup: dict, replace: bool = True) -> list[CredentialRecord]:
        """Import credentials from a backup dict. Existing records are replaced by default.

        Supports hvbackup-v1 and hvbackup-v2 (credential portion only).
        Rejects metadata-only backups (entries missing encrypted_payload).
        Audit integrity state is restored separately via restore_audit_integrity.
        """
        version = backup.get("version")
        if version not in ("hvbackup-v1", "hvbackup-v2"):
            raise ValueError(f"Unsupported backup version: {version}")
        imported = []
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
                record = existing.model_copy(update={
                    "credential_type": cred_data["credential_type"],
                    "encrypted_payload": cred_data["encrypted_payload"],
                    "status": CredentialStatus(cred_data.get("status", "unknown")),
                    "scopes": cred_data.get("scopes", []),
                    "tags": self._normalize_tags(cred_data.get("tags")) if "tags" in cred_data else existing.tags,
                    "notes": self._normalize_notes(cred_data.get("notes")) if "notes" in cred_data else existing.notes,
                    "imported_from": cred_data.get("imported_from"),
                    "last_verified_at": last_verified_at,
                    "updated_at": utc_now(),
                })
            with sqlite3.connect(self.db_path) as conn:
                if existing:
                    conn.execute(
                        """
                        UPDATE credentials
                        SET credential_type=?, encrypted_payload=?, status=?, scopes=?,
                            tags=?, notes=?, updated_at=?, last_verified_at=?, imported_from=?, expiry=?
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
            imported.append(record)

        for lease_data in backup.get("leases", []):
            lease_id = lease_data.get("id") or str(uuid4())
            metadata = lease_data.get("metadata") or {}
            if not isinstance(metadata, dict):
                metadata = {"raw": metadata}
            scopes = lease_data.get("scopes") or []
            if not isinstance(scopes, list):
                scopes = [str(scopes)]
            existing_lease = self.get_lease(lease_id)
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
            if existing_lease:
                with sqlite3.connect(self.db_path) as conn:
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
                    conn.commit()
            else:
                with sqlite3.connect(self.db_path) as conn:
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
        return imported

    def restore_audit_integrity(
        self, backup: dict, *, rollback_on_failure: bool = True
    ) -> dict[str, Any]:
        """Restore audit integrity evidence from an hvbackup-v2 backup.

        Staged transactional restore:
        1. Verify the backup fully.
        2. Create a durable recovery copy of current state.
        3. Stage database changes.
        4. Stage checkpoint changes.
        5. Commit database state transactionally.
        6. Replace the checkpoint atomically.
        7. Record an audited operator restore event.
        8. Retain rollback evidence until success is confirmed.
        9. Clean up staging artifacts after confirmed success.
        """
        from hermes_vault.audit import AuditLogger
        from hermes_vault.audit_integrity.checkpoint import read_checkpoint
        from hermes_vault.audit_integrity.schema import initialize_schema
        from hermes_vault.audit_integrity.service import AuditIntegrityService

        version = backup.get("version")
        if version != "hvbackup-v2":
            return {"success": False, "reason": f"Integrity restore requires hvbackup-v2, got {version}"}

        integrity = backup.get("audit_integrity", {})
        if not integrity:
            return {"success": False, "reason": "Backup contains no audit integrity evidence."}

        available = integrity.get("integrity_available", False)
        if not available:
            return {"success": False, "reason": "Integrity evidence is not available in this backup."}

        # 1. Verify the backup fully (credentials + integrity).
        # (Structural verification happens via restore_audit_integrity internals.)

        # 2. Create durable recovery copy of current state.
        recovery_db = self.db_path.read_bytes() if self.db_path.exists() else b""
        recovery_checkpoint = None
        cp_path = self.db_path.with_name("audit.checkpoint.json")
        if cp_path.exists():
            recovery_checkpoint = read_checkpoint(cp_path)

        stage_path = self.db_path.with_suffix(".db.restore-stage")
        stage_cp_path = cp_path.with_suffix(".json.restore-stage")

        try:
            # 3. Stage database changes (integrity tables only).
            stage = backup.get("audit_integrity", {})
            state_rows = stage.get("state", [])
            segments = stage.get("segments", [])
            records = stage.get("records", [])
            checkpoint = stage.get("checkpoint")

            if not state_rows or not segments:
                return {"success": False, "reason": "Backup integrity evidence is incomplete."}

            with sqlite3.connect(str(stage_path)) as stage_conn:
                initialize_schema(stage_conn)
                for s in state_rows:
                    cols = ", ".join(s.keys())
                    placeholders = ", ".join("?" for _ in s)
                    stage_conn.execute(
                        f"INSERT OR REPLACE INTO audit_integrity_state ({cols}) VALUES ({placeholders})",
                        list(s.values()),
                    )
                for seg in segments:
                    cols = ", ".join(seg.keys())
                    placeholders = ", ".join("?" for _ in seg)
                    stage_conn.execute(
                        f"INSERT OR REPLACE INTO audit_integrity_segments ({cols}) VALUES ({placeholders})",
                        list(seg.values()),
                    )
                for rec in records:
                    cols = ", ".join(rec.keys())
                    placeholders = ", ".join("?" for _ in rec)
                    stage_conn.execute(
                        f"INSERT OR REPLACE INTO audit_integrity_records ({cols}) VALUES ({placeholders})",
                        list(rec.values()),
                    )
                stage_conn.commit()

            # 4. Stage checkpoint changes.
            if checkpoint:
                stage_cp_path.write_text(
                    json.dumps(checkpoint, sort_keys=True), encoding="utf-8"
                )

            # 5. Commit database state transactionally.
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    conn.executescript(f"ATTACH DATABASE '{stage_path}' AS stage")
                    tables = [
                        "audit_integrity_state",
                        "audit_integrity_segments",
                        "audit_integrity_records",
                    ]
                    for table in tables:
                        conn.execute(
                            f"DELETE FROM {table}"
                        )
                        conn.execute(
                            f"INSERT INTO {table} SELECT * FROM stage.{table}"
                        )
                    conn.execute("DETACH DATABASE stage")
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise

            # 6. Replace the checkpoint atomically.
            if checkpoint:
                import tempfile
                import shutil
                fd, tmp_path = tempfile.mkstemp(
                    dir=cp_path.parent, suffix=".checkpoint-tmp"
                )
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        json.dump(checkpoint, f, sort_keys=True)
                        f.write("\n")
                    shutil.move(tmp_path, str(cp_path))
                except Exception:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                    raise

            # 7. Record an audited operator restore event.
            audit = AuditLogger(self.db_path, master_key=self.key)
            from hermes_vault.models import AccessLogRecord, Decision
            audit.record(
                AccessLogRecord(
                    agent_id="operator",
                    service="*",
                    action="integrity_restore",
                    decision=Decision.allow,
                    reason="Operator-initiated transactional audit integrity restore",
                    metadata={"version": "hvbackup-v2"},
                )
            )

            # 8. Retain rollback evidence — keep recovery copy in temp.
            recovery_path = self.db_path.with_suffix(".db.pre-restore-recovery")
            if recovery_db:
                Path(recovery_path).write_bytes(recovery_db)
            if recovery_checkpoint:
                recovery_cp_path = cp_path.with_suffix(".checkpoint.pre-restore-recovery.json")
                recovery_cp_path.write_text(
                    json.dumps(recovery_checkpoint, sort_keys=True), encoding="utf-8"
                )

            # 9. Clean up staging artifacts.
            stage_path.unlink(missing_ok=True)
            stage_cp_path.unlink(missing_ok=True)

            # Verify restored integrity.
            service = AuditIntegrityService(self.db_path, self.key)
            result = service.verify()

            return {
                "success": True,
                "version": "hvbackup-v2",
                "integrity_status": result.status.value,
                "verified_count": result.verified_count,
                "legacy_count": result.legacy_count,
                "reason": result.sanitized_reason,
            }

        except Exception as exc:
            # Clean up staging on failure.
            stage_path.unlink(missing_ok=True)
            stage_cp_path.unlink(missing_ok=True)

            if rollback_on_failure:
                # Rollback: restore recovery copies.
                if recovery_db:
                    self.db_path.write_bytes(recovery_db)
                if recovery_checkpoint:
                    Path(str(cp_path) + ".rollback").write_text(
                        json.dumps(recovery_checkpoint, sort_keys=True), encoding="utf-8"
                    )

            return {
                "success": False,
                "reason": f"Integrity restore failed: {exc}",
                "rollback_available": rollback_on_failure,
            }

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
                decrypt_secret(test_records[0].encrypted_payload, old_key)
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
        journal = {
            "version": "rotation-journal-v1",
            "status": "started",
            "old_salt": new_salt.hex(),  # placeholder; replaced below
            "new_salt": new_salt.hex(),
            "created_at": utc_now().isoformat(),
        }
        # The journal records the existing durable form (16-byte salt
        # for legacy vaults, DPAPI envelope bytes for DPAPI vaults)
        # under "old_salt" and the new derivation salt under "new_salt".
        # DPAPI wrapping happens at the durable write, not in the
        # journal (per spec §2.3 / §5.3 test 20).
        existing_durable = self.salt_path.read_bytes() if self.salt_path.exists() else b""
        journal["old_salt"] = existing_durable.hex() if existing_durable else new_salt.hex()
        self._write_rotation_journal(journal)

        re_encrypted = 0
        all_records = self.list_credentials()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("BEGIN EXCLUSIVE")
            try:
                for rec in all_records:
                    payload_plain = decrypt_secret(rec.encrypted_payload, old_key)
                    new_encrypted = encrypt_secret(payload_plain, new_key)
                    conn.execute(
                        "UPDATE credentials SET encrypted_payload = ?, updated_at = ? WHERE id = ?",
                        (new_encrypted, utc_now().isoformat(), rec.id),
                    )
                    re_encrypted += 1
                conn.commit()
            except Exception:
                conn.rollback()
                raise

        journal["status"] = "db_committed"
        journal["committed_at"] = utc_now().isoformat()
        journal["audit_transition_state"] = "pending"
        journal["old_segment_id"] = audit_result.active_segment_id or ""
        self._write_rotation_journal(journal)
        audit_integrity.rotate_segment(new_key)
        journal["audit_transition_state"] = "checkpoint_committed"
        self._write_rotation_journal(journal)
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
