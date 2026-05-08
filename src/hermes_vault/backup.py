from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hermes_vault.crypto import decrypt_secret
from hermes_vault.models import utc_now
from hermes_vault.vault import Vault


REPORT_VERSION = "backup-verification-v1"
BACKUP_VERSION = "hvbackup-v1"


@dataclass
class BackupVerificationReport:
    version: str = REPORT_VERSION
    generated_at: str = field(default_factory=lambda: utc_now().isoformat())
    mode: str = "verify"
    backup_path: str = ""
    backup_version: str | None = None
    credential_count: int = 0
    decryptable_credential_count: int = 0
    audit_included: bool = False
    decryptable: bool = False
    findings: list[str] = field(default_factory=list)
    would_restore_count: int = 0

    def as_dict(self, *, exclude_none: bool = True) -> dict[str, Any]:
        data = {
            "version": self.version,
            "generated_at": self.generated_at,
            "mode": self.mode,
            "backup_path": self.backup_path,
            "backup_version": self.backup_version,
            "credential_count": self.credential_count,
            "decryptable_credential_count": self.decryptable_credential_count,
            "audit_included": self.audit_included,
            "decryptable": self.decryptable,
            "findings": list(self.findings),
            "would_restore_count": self.would_restore_count,
        }
        if exclude_none:
            return {key: value for key, value in data.items() if value is not None}
        return data


def _load_backup_json(path: Path) -> dict[str, Any]:
    content = path.read_text(encoding="utf-8")
    backup = json.loads(content)
    if not isinstance(backup, dict):
        raise ValueError("Backup file must contain a JSON object.")
    return backup


def _report_from_backup(path: Path, vault: Vault, *, mode: str) -> BackupVerificationReport:
    report = BackupVerificationReport(mode=mode, backup_path=str(path))
    try:
        backup = _load_backup_json(path)
    except Exception as exc:
        report.findings.append(f"Corrupted backup JSON: {exc}")
        return report

    report.backup_version = backup.get("version")
    report.audit_included = "audit_log" in backup and backup.get("audit_log") is not None

    if report.backup_version != BACKUP_VERSION:
        report.findings.append(f"Unsupported backup version: {report.backup_version}")
        return report

    credentials = backup.get("credentials")
    if not isinstance(credentials, list):
        report.findings.append("Backup file is missing a credentials list.")
        return report

    report.credential_count = len(credentials)
    if any(not isinstance(entry, dict) or entry.get("encrypted_payload") is None for entry in credentials):
        report.findings.append(
            "Cannot verify or restore a metadata-only backup. "
            "Metadata-only backups exclude encrypted_payload and are for inspection only."
        )
        return report

    decryptable_count = 0
    for entry in credentials:
        try:
            decrypt_secret(entry["encrypted_payload"], vault.key)
        except Exception:
            service = entry.get("service", "?")
            alias = entry.get("alias", "default")
            report.findings.append(
                f"Encrypted payload for {service}/{alias} could not be decrypted with the current vault key."
            )
            report.decryptable = False
            report.decryptable_credential_count = decryptable_count
            report.would_restore_count = 0
            return report
        decryptable_count += 1

    report.decryptable_credential_count = decryptable_count
    report.decryptable = True
    report.would_restore_count = report.credential_count
    return report


def verify_backup_file(path: str | Path, vault: Vault) -> BackupVerificationReport:
    """Validate a backup file and check whether it decrypts with the current vault key."""
    return _report_from_backup(Path(path), vault, mode="verify")


def restore_dry_run(path: str | Path, vault: Vault) -> BackupVerificationReport:
    """Validate a backup file using restore semantics without mutating the live vault."""
    return _report_from_backup(Path(path), vault, mode="restore-dry-run")
