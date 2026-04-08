from __future__ import annotations

import json
import sqlite3
from pathlib import Path

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


class DuplicateCredentialError(RuntimeError):
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
    ) -> CredentialRecord:
        existing = self._find_by_service_alias(service, alias)
        if existing and not replace_existing:
            raise DuplicateCredentialError(
                f"Credential for service '{service}' and alias '{alias}' already exists."
            )
        payload = CredentialSecret(secret=secret).model_dump_json()
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
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT * FROM credentials
                WHERE id = ? OR service = ?
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (service_or_id, service_or_id),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def get_secret(self, service_or_id: str) -> CredentialSecret | None:
        record = self.get_credential(service_or_id)
        if not record:
            return None
        payload = decrypt_secret(record.encrypted_payload, self.key)
        return CredentialSecret.model_validate_json(payload)

    def update_status(
        self, service_or_id: str, status: CredentialStatus, verified_at: str | None = None
    ) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                UPDATE credentials
                SET status = ?, last_verified_at = COALESCE(?, last_verified_at), updated_at = CURRENT_TIMESTAMP
                WHERE id = ? OR service = ?
                """,
                (status.value, verified_at, service_or_id, service_or_id),
            )
            conn.commit()

    def rotate(
        self,
        service_or_id: str,
        new_secret: str,
        imported_from: str | None = None,
    ) -> CredentialRecord:
        current = self.get_credential(service_or_id)
        if not current:
            raise KeyError(f"Credential '{service_or_id}' not found")
        payload = CredentialSecret(secret=new_secret).model_dump_json()
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

    def delete(self, service_or_id: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM credentials WHERE id = ? OR service = ?", (service_or_id, service_or_id)
            )
            conn.commit()
        return cursor.rowcount > 0

    def _row_to_record(self, row: sqlite3.Row) -> CredentialRecord:
        payload = dict(row)
        payload["scopes"] = json.loads(payload["scopes"])
        payload["status"] = CredentialStatus(payload["status"])
        return CredentialRecord.model_validate(payload)

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
