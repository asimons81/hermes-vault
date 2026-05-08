"""OAuth token normalization helpers.

This module rewrites v0.6.0 OAuth token records into the v0.7.0 storage
shape without changing token values.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any

from hermes_vault.crypto import encrypt_secret
from hermes_vault.models import CredentialRecord, CredentialSecret, utc_now
from hermes_vault.oauth.oauth_refresh import refresh_alias_for
from hermes_vault.vault import Vault


REPORT_VERSION = "oauth-normalize-v1"


@dataclass
class OAuthNormalizeChange:
    credential_id: str
    service: str
    alias: str
    credential_type: str
    action: str
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "credential_id": self.credential_id,
            "service": self.service,
            "alias": self.alias,
            "credential_type": self.credential_type,
            "action": self.action,
            "detail": self.detail,
        }


@dataclass
class OAuthNormalizeReport:
    version: str = REPORT_VERSION
    generated_at: str = field(default_factory=lambda: utc_now().isoformat())
    dry_run: bool = True
    changed_count: int = 0
    skipped_count: int = 0
    changes: list[OAuthNormalizeChange] = field(default_factory=list)
    skips: list[OAuthNormalizeChange] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "generated_at": self.generated_at,
            "dry_run": self.dry_run,
            "changed_count": self.changed_count,
            "skipped_count": self.skipped_count,
            "changes": [change.as_dict() for change in self.changes],
            "skips": [skip.as_dict() for skip in self.skips],
        }


def normalize_oauth_records(vault: Vault, *, dry_run: bool = True) -> OAuthNormalizeReport:
    """Normalize OAuth records to the v0.7.0 storage shape.

    Safe rewrites:
    - remove token-bearing metadata from OAuth access-token payloads
    - add missing safe metadata derived from record fields
    - rename a legacy refresh-token alias from ``refresh`` to ``refresh:<alias>``
      when the paired access-token alias is unambiguous and the target alias is
      not already present
    """
    report = OAuthNormalizeReport(dry_run=dry_run)
    records = vault.list_credentials()

    access_records = [r for r in records if r.credential_type == "oauth_access_token"]
    for access in access_records:
        secret = vault.get_secret(access.id)
        if secret is None:
            report.skips.append(_change(access, "skip", "access token cannot be decrypted"))
            continue
        metadata = _sanitized_access_metadata(access, secret.metadata)
        if metadata != secret.metadata:
            change = _change(access, "sanitize_metadata", "removed unsafe OAuth access-token metadata")
            report.changes.append(change)
            if not dry_run:
                _rewrite_secret(vault, access, secret.secret, metadata)

    for refresh in [r for r in records if r.credential_type == "oauth_refresh_token"]:
        secret = vault.get_secret(refresh.id)
        if secret is None:
            report.skips.append(_change(refresh, "skip", "refresh token cannot be decrypted"))
            continue
        associated_alias = None
        if isinstance(secret.metadata, dict):
            value = secret.metadata.get("associated_access_token_alias")
            if isinstance(value, str) and value:
                associated_alias = value
        if associated_alias is None:
            candidates = [r for r in access_records if r.service == refresh.service]
            if len(candidates) == 1:
                associated_alias = candidates[0].alias
        if associated_alias is None:
            report.skips.append(_change(refresh, "skip", "refresh-token pair is ambiguous"))
            continue

        target_alias = refresh_alias_for(associated_alias)
        metadata = _sanitized_refresh_metadata(refresh.service, associated_alias, secret.metadata)
        if metadata != secret.metadata:
            change = _change(refresh, "sanitize_metadata", "normalized refresh-token metadata")
            report.changes.append(change)
            if not dry_run:
                _rewrite_secret(vault, refresh, secret.secret, metadata)

        if refresh.alias == target_alias:
            continue
        if refresh.alias != "refresh":
            report.skips.append(_change(refresh, "skip", f"non-legacy refresh alias '{refresh.alias}' left unchanged"))
            continue
        if _alias_exists(records, refresh.service, target_alias, exclude_id=refresh.id):
            report.skips.append(_change(refresh, "skip", f"target alias '{target_alias}' already exists"))
            continue

        change = _change(refresh, "rename_alias", f"renamed refresh alias to '{target_alias}'")
        report.changes.append(change)
        if not dry_run:
            _rename_alias(vault, refresh.id, target_alias)

    report.changed_count = len(report.changes)
    report.skipped_count = len(report.skips)
    return report


def _sanitized_access_metadata(record: CredentialRecord, metadata: dict[str, Any]) -> dict[str, Any]:
    safe = dict(metadata or {})
    safe.pop("refresh_token", None)
    safe.pop("raw_response", None)
    safe["provider"] = record.service
    safe.setdefault("issued_at", record.created_at.isoformat())
    safe.setdefault("token_type", "Bearer")
    if record.expiry is not None:
        safe["expires_at"] = record.expiry.isoformat()
    if record.scopes:
        safe["scopes"] = list(record.scopes)
    elif "scope" in safe and isinstance(safe["scope"], str):
        safe["scopes"] = [part for part in safe.pop("scope").split(" ") if part]
    else:
        safe.pop("scope", None)
    return safe


def _sanitized_refresh_metadata(
    service: str,
    associated_alias: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    safe = dict(metadata or {})
    safe.pop("refresh_token", None)
    safe.pop("raw_response", None)
    safe["provider"] = service
    safe["associated_access_token_alias"] = associated_alias
    safe.setdefault("rotation_counter", 0)
    return safe


def _rewrite_secret(
    vault: Vault,
    record: CredentialRecord,
    secret_value: str,
    metadata: dict[str, Any],
) -> None:
    encrypted = encrypt_secret(
        CredentialSecret(secret=secret_value, metadata=metadata).model_dump_json(),
        vault.key,
    )
    now = utc_now().isoformat()
    with sqlite3.connect(vault.db_path) as conn:
        conn.execute(
            "UPDATE credentials SET encrypted_payload = ?, updated_at = ? WHERE id = ?",
            (encrypted, now, record.id),
        )
        conn.commit()


def _rename_alias(vault: Vault, credential_id: str, alias: str) -> None:
    now = utc_now().isoformat()
    with sqlite3.connect(vault.db_path) as conn:
        conn.execute(
            "UPDATE credentials SET alias = ?, updated_at = ? WHERE id = ?",
            (alias, now, credential_id),
        )
        conn.commit()


def _alias_exists(
    records: list[CredentialRecord],
    service: str,
    alias: str,
    *,
    exclude_id: str,
) -> bool:
    return any(r.id != exclude_id and r.service == service and r.alias == alias for r in records)


def _change(record: CredentialRecord, action: str, detail: str) -> OAuthNormalizeChange:
    return OAuthNormalizeChange(
        credential_id=record.id,
        service=record.service,
        alias=record.alias,
        credential_type=record.credential_type,
        action=action,
        detail=detail,
    )
