from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hermes_vault.crypto import decrypt_secret
from hermes_vault.models import utc_now
from hermes_vault.vault import Vault


REPORT_VERSION = "backup-verification-v2"
BACKUP_VERSION_V1 = "hvbackup-v1"
BACKUP_VERSION_V2 = "hvbackup-v2"

# Backup-integrity states returned by v2 verification.
BACKUP_INTEGRITY_HEALTHY = "healthy"
BACKUP_INTEGRITY_LEGACY = "legacy"
BACKUP_INTEGRITY_INCOMPLETE = "incomplete"
BACKUP_INTEGRITY_FAILED = "failed"


@dataclass
class BackupVerificationReport:
    version: str = REPORT_VERSION
    generated_at: str = field(default_factory=lambda: utc_now().isoformat())
    mode: str = "verify"
    backup_path: str = ""
    backup_version: str | None = None
    credential_count: int = 0
    decryptable_credential_count: int = 0
    decryptable: bool = False
    integrity_status: str | None = None
    integrity_available: bool = False
    integrity_reason: str | None = None
    audit_included: bool = False
    findings: list[str] = field(default_factory=list)
    would_restore_count: int = 0

    def as_dict(self, *, exclude_none: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "version": self.version,
            "generated_at": self.generated_at,
            "mode": self.mode,
            "backup_path": self.backup_path,
            "backup_version": self.backup_version,
            "credential_count": self.credential_count,
            "decryptable_credential_count": self.decryptable_credential_count,
            "decryptable": self.decryptable,
            "findings": list(self.findings),
            "would_restore_count": self.would_restore_count,
        }
        if self.integrity_available:
            data["integrity_status"] = self.integrity_status
            data["integrity_available"] = True
            if self.integrity_reason:
                data["integrity_reason"] = self.integrity_reason
        if exclude_none:
            return {key: value for key, value in data.items() if value is not None}
        return data


def _load_backup_json(path: Path) -> dict[str, Any]:
    content = path.read_text(encoding="utf-8")
    backup = json.loads(content)
    if not isinstance(backup, dict):
        raise ValueError("Backup file must contain a JSON object.")
    return backup


def _classify_v2_integrity(integrity: dict[str, Any], vault: Vault) -> tuple[str, str | None]:
    """Classify backup integrity evidence.

    Checks structural consistency and key compatibility.
    Does NOT run full chain verification (that requires the live database).
    """
    available = integrity.get("integrity_available", False)
    if not available:
        return BACKUP_INTEGRITY_LEGACY, "integrity_evidence_not_available"

    state_rows = integrity.get("state")
    if not state_rows:
        return BACKUP_INTEGRITY_INCOMPLETE, "integrity_state_missing"

    segments = integrity.get("segments")
    if not segments:
        return BACKUP_INTEGRITY_INCOMPLETE, "integrity_segments_missing"

    records = integrity.get("records")
    checkpoint = integrity.get("checkpoint")

    # Verify active key compatibility.
    from hermes_vault.audit_integrity.crypto import public_key_b64, ENTRY_SIGNING_CONTEXT, CHECKPOINT_SIGNING_CONTEXT
    expected_entry_key = public_key_b64(vault.key, ENTRY_SIGNING_CONTEXT)
    expected_checkpoint_key = public_key_b64(vault.key, CHECKPOINT_SIGNING_CONTEXT)

    active_segment = None
    state = state_rows[0] if state_rows else {}
    active_segment_id = state.get("active_segment_id")
    for seg in segments:
        if seg.get("segment_id") == active_segment_id:
            active_segment = seg
            break

    if active_segment:
        entry_key = active_segment.get("entry_public_key", "")
        cp_key = active_segment.get("checkpoint_public_key", "")
        if entry_key != expected_entry_key or cp_key != expected_checkpoint_key:
            return BACKUP_INTEGRITY_FAILED, "key_mismatch"

    # Check checkpoint structural validity.
    if checkpoint:
        cp_format = checkpoint.get("format", "")
        cp_version = checkpoint.get("version", "")
        if cp_format != "hermes-vault-audit-checkpoint":
            return BACKUP_INTEGRITY_INCOMPLETE, "invalid_checkpoint_format"
        if cp_version != "audit-checkpoint-v1":
            return BACKUP_INTEGRITY_INCOMPLETE, "unsupported_checkpoint_version"

    # Basic structural check: records have required fields.
    if records:
        required = {"sequence", "segment_id", "access_log_id", "entry_digest", "signature"}
        for rec in records:
            if not required.issubset(rec.keys()):
                return BACKUP_INTEGRITY_INCOMPLETE, "record_missing_required_fields"

    # Legacy anchor check.
    if state.get("migration_state") == "active":
        return BACKUP_INTEGRITY_HEALTHY, None
    return BACKUP_INTEGRITY_LEGACY, "migration_not_active"


def _verify_v1_backup(report: BackupVerificationReport, backup: dict[str, Any], vault: Vault) -> BackupVerificationReport:
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


def _verify_v2_backup(report: BackupVerificationReport, backup: dict[str, Any], vault: Vault) -> BackupVerificationReport:
    """Verify a v2 backup including integrity evidence."""
    report = _verify_v1_backup(report, backup, vault)
    if not report.decryptable:
        return report

    integrity = backup.get("audit_integrity", {})
    if not integrity:
        report.integrity_available = False
        report.integrity_status = BACKUP_INTEGRITY_LEGACY
        report.findings.append("Audit integrity evidence is missing from hvbackup-v2 backup.")
        return report

    report.integrity_available = True
    status, reason = _classify_v2_integrity(integrity, vault)
    report.integrity_status = status
    if reason:
        report.integrity_reason = reason
        report.findings.append(f"Backup integrity: {status} ({reason})")
    return report


def _report_from_backup(path: Path, vault: Vault, *, mode: str) -> BackupVerificationReport:
    report = BackupVerificationReport(mode=mode, backup_path=str(path))
    try:
        backup = _load_backup_json(path)
    except Exception as exc:
        report.findings.append(f"Corrupted backup JSON: {exc}")
        return report

    report.backup_version = backup.get("version")

    if report.backup_version == BACKUP_VERSION_V1:
        report.audit_included = "audit_log" in backup and backup.get("audit_log") is not None
        return _verify_v1_backup(report, backup, vault)
    elif report.backup_version == BACKUP_VERSION_V2:
        report.audit_included = True
        return _verify_v2_backup(report, backup, vault)
    else:
        report.findings.append(f"Unsupported backup version: {report.backup_version}")
        return report


def verify_backup_file(path: str | Path, vault: Vault) -> BackupVerificationReport:
    """Validate a backup file and check whether it decrypts with the current vault key."""
    return _report_from_backup(Path(path), vault, mode="verify")


def restore_dry_run(path: str | Path, vault: Vault) -> BackupVerificationReport:
    """Validate a backup file using restore semantics without mutating the live vault."""
    return _report_from_backup(Path(path), vault, mode="restore-dry-run")
