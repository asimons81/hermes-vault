from __future__ import annotations

import json
import os
import sqlite3
from typing import Any
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from hermes_vault.crypto import (
    CRYPTO_VERSION,
    CorruptKeyMaterialError,
    MissingKeyMaterialError,
    SALT_SIZE,
    decrypt_secret,
    derive_key,
    encrypt_secret,
    load_or_create_salt,
)
from hermes_vault.models import CredentialRecord, CredentialSecret, CredentialStatus, utc_now
from hermes_vault.service_ids import normalize


class DuplicateCredentialError(RuntimeError):
    pass


class AmbiguousTargetError(RuntimeError):
    """Raised when a service-only lookup matches multiple credentials."""
    pass


class Vault:
    def __init__(self, db_path: Path, salt_path: Path, passphrase: str) -> None:
        self.db_path = db_path
        self.salt_path = salt_path
        self._prepare_storage()
        self.key = derive_key(passphrase, load_or_create_salt(salt_path, create_if_missing=not db_path.exists()))
        self.initialize()

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
                    crypto_version TEXT NOT NULL
                )
                """
            )
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
            conn.commit()
        self._secure_storage_files()

    def _prepare_storage(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if self.db_path.exists() and not self.salt_path.exists():
            raise MissingKeyMaterialError(
                f"Vault database exists at {self.db_path} but salt file {self.salt_path} is missing."
            )
        if self.salt_path.exists() and self.salt_path.stat().st_size != SALT_SIZE:
            raise CorruptKeyMaterialError(
                f"Salt file {self.salt_path} is corrupted or the wrong size."
            )

    def _secure_storage_files(self) -> None:
        if self.db_path.exists():
            self.db_path.chmod(0o600)
        if self.salt_path.exists():
            self.salt_path.chmod(0o600)

    def add_credential(
        self,
        service: str,
        secret: str,
        credential_type: str,
        alias: str = "default",
        imported_from: str | None = None,
        scopes: list[str] | None = None,
        replace_existing: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> CredentialRecord:
        service = normalize(service)
        existing = self._find_by_service_alias(service, alias)
        if existing and not replace_existing:
            raise DuplicateCredentialError(
                f"Credential for service '{service}' and alias '{alias}' already exists."
            )
        payload = CredentialSecret(
            secret=secret,
            metadata=self._resolve_secret_metadata(existing.id if existing else None, metadata),
        ).model_dump_json()
        encrypted_payload = encrypt_secret(payload, self.key)
        record = existing.model_copy(update={
            "credential_type": credential_type,
            "encrypted_payload": encrypted_payload,
            "imported_from": imported_from,
            "scopes": scopes or [],
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
            crypto_version=CRYPTO_VERSION,
        )
        with sqlite3.connect(self.db_path) as conn:
            if existing and replace_existing:
                conn.execute(
                    """
                    UPDATE credentials
                    SET credential_type = ?, encrypted_payload = ?, status = ?, scopes = ?,
                        updated_at = ?, last_verified_at = ?, imported_from = ?, expiry = ?, crypto_version = ?
                    WHERE id = ?
                    """,
                    (
                        record.credential_type,
                        record.encrypted_payload,
                        record.status.value,
                        json.dumps(record.scopes),
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
                        created_at, updated_at, last_verified_at, imported_from, expiry, crypto_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.id,
                        record.service,
                        record.alias,
                        record.credential_type,
                        record.encrypted_payload,
                        record.status.value,
                        json.dumps(record.scopes),
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
        # Return the updated record
        return self.get_credential(record.id)

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

    def export_backup(self, *, metadata_only: bool = False) -> dict:
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
        return {
            "version": "hvbackup-v1",
            "exported_at": utc_now().isoformat(),
            "credentials": backup_creds,
        }

    def import_backup(self, backup: dict, replace: bool = True) -> list[CredentialRecord]:
        """Import credentials from a backup dict. Existing records are replaced by default.

        Rejects metadata-only backups (entries missing encrypted_payload).
        """
        if backup.get("version") != "hvbackup-v1":
            raise ValueError(f"Unsupported backup version: {backup.get('version')}")
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
                            updated_at=?, last_verified_at=?, imported_from=?, expiry=?
                        WHERE id=?
                        """,
                        (
                            record.credential_type,
                            record.encrypted_payload,
                            record.status.value,
                            json.dumps(record.scopes),
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
                            created_at, updated_at, last_verified_at, imported_from, expiry, crypto_version
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record.id,
                            record.service,
                            record.alias,
                            record.credential_type,
                            record.encrypted_payload,
                            record.status.value,
                            json.dumps(record.scopes),
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
        # Verify old passphrase by trying to decrypt at least one credential
        old_key = derive_key(old_passphrase, load_or_create_salt(self.salt_path))
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

        if backup_path is not None:
            self.export_backup()
            content = json.dumps(self.export_backup(), indent=2, sort_keys=True)
            backup_path.write_text(content, encoding="utf-8")
            backup_path.chmod(0o600)

        new_salt = os.urandom(SALT_SIZE)
        new_key = derive_key(new_passphrase, new_salt)

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

        # Atomically write new salt
        tmp_salt = self.salt_path.with_suffix(".tmp")
        tmp_salt.write_bytes(new_salt)
        os.replace(tmp_salt, self.salt_path)
        self.salt_path.chmod(0o600)

        self.key = new_key
        return {"re_encrypted": re_encrypted, "failed": 0}
