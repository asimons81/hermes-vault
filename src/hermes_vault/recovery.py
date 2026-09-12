from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hermes_vault.backup import BACKUP_INTEGRITY_HEALTHY, restore_dry_run, verify_backup_file
from hermes_vault.diff import diff_backups
from hermes_vault.models import utc_now
from hermes_vault.policy import PolicyEngine
from hermes_vault.vault import Vault


RECOVERY_DRILL_VERSION = "recovery-drill-v1"
RESTORE_RECEIPT_VERSION = "restore-receipt-v1"


class ReceiptWriteError(RuntimeError):
    """The restore receipt could not be written (fail-closed P1 rule).

    The receipt is mandatory, not best-effort: an unwritable
    ``$VAULT_HOME/recovery`` directory blocks the restore before any
    mutation.
    """


@dataclass
class RestoreReceipt:
    """P1 restore receipt (``restore-receipt-v1``).

    Written by every restore attempt (``--dry-run`` and real); rewritten
    once after the import attempt with the final outcome. Carries
    service/alias-scoped findings only — never secrets or key material.
    """

    version: str = RESTORE_RECEIPT_VERSION
    generated_at: str = field(default_factory=lambda: utc_now().isoformat())
    mode: str = "preflight"  # "dry-run" | "preflight"
    backup_path: str = ""
    backup_sha256: str = ""
    backup_version: str | None = None
    credential_count: int = 0
    decryptable_credential_count: int = 0
    integrity_status: str | None = None
    destination_salt_fingerprint: str | None = None
    backup_key_fingerprint: str | None = None
    decision: str = "proceed"  # "proceed" | "blocked"
    blocked_reason: str | None = None
    findings: list[str] = field(default_factory=list)
    deferred_audit_events: list[str] = field(default_factory=list)
    outcome: str = "dry-run-only"  # "dry-run-only" | "preflight-passed" | "blocked" | "restored" | "failed:<class>"

    def as_dict(self, *, exclude_none: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "version": self.version,
            "generated_at": self.generated_at,
            "mode": self.mode,
            "backup_path": self.backup_path,
            "backup_sha256": self.backup_sha256,
            "backup_version": self.backup_version,
            "credential_count": self.credential_count,
            "decryptable_credential_count": self.decryptable_credential_count,
            "integrity_status": self.integrity_status,
            "destination_salt_fingerprint": self.destination_salt_fingerprint,
            "backup_key_fingerprint": self.backup_key_fingerprint,
            "decision": self.decision,
            "blocked_reason": self.blocked_reason,
            "findings": list(self.findings),
            "deferred_audit_events": list(self.deferred_audit_events),
            "outcome": self.outcome,
        }
        if exclude_none:
            return {key: value for key, value in data.items() if value is not None}
        return data


def write_restore_receipt(
    receipt: RestoreReceipt,
    *,
    vault_home: str | Path,
    receipt_dir_name: str = "recovery",
    path: Path | None = None,
) -> Path:
    """Atomically write *receipt* under ``<vault_home>/recovery/`` (0600).

    Fail-closed: any write failure raises :class:`ReceiptWriteError` — the
    caller must block the restore, because the receipt is mandatory P1
    evidence, not a best-effort artifact. Pass *path* to rewrite an
    existing receipt file (two-phase lifecycle: ``preflight-passed`` →
    ``restored``/``failed:<class>``).
    """
    import os
    import tempfile

    recovery_dir = Path(vault_home) / receipt_dir_name
    try:
        recovery_dir.mkdir(parents=True, exist_ok=True)
        if path is None:
            stamp = utc_now().strftime("%Y%m%d-%H%M%S")
            path = recovery_dir / f"restore-receipt-{stamp}.json"
        receipt.generated_at = utc_now().isoformat()
        payload = json.dumps(receipt.as_dict(exclude_none=False), indent=2, sort_keys=False)
        fd, tmp_name = tempfile.mkstemp(dir=recovery_dir, prefix=".restore-receipt-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
    except ReceiptWriteError:
        raise
    except Exception as exc:
        raise ReceiptWriteError(
            f"The restore receipt could not be written to {recovery_dir} ({exc}). "
            "The restore was NOT performed: restore receipts are mandatory recovery "
            "evidence. Fix the directory permissions (or free space) and re-run. "
            "For a read-only vault home, use 'restore --dry-run' against a copied home."
        ) from exc
    return path


def sha256_file(path: str | Path) -> str:
    """Hex sha256 of a file's bytes (receipt provenance helper)."""
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as handle:  # noqa: PTH123
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class RecoveryDrillReport:
    version: str = RECOVERY_DRILL_VERSION
    generated_at: str = field(default_factory=lambda: utc_now().isoformat())
    backup_path: str = ""
    healthy: bool = False
    backup_verify: dict[str, Any] = field(default_factory=dict)
    restore_dry_run: dict[str, Any] = field(default_factory=dict)
    diff: dict[str, Any] = field(default_factory=dict)
    policy_hash: str | None = None
    findings: list[str] = field(default_factory=list)
    recommended_next_step: str = ""

    def as_dict(self, *, exclude_none: bool = True) -> dict[str, Any]:
        data = {
            "version": self.version,
            "generated_at": self.generated_at,
            "backup_path": self.backup_path,
            "healthy": self.healthy,
            "backup_verify": self.backup_verify,
            "restore_dry_run": self.restore_dry_run,
            "diff": self.diff,
            "policy_hash": self.policy_hash,
            "findings": list(self.findings),
            "recommended_next_step": self.recommended_next_step,
        }
        if exclude_none:
            return {key: value for key, value in data.items() if value is not None}
        return data


def _load_backup(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, [f"Backup JSON could not be read: {exc}"]
    if not isinstance(data, dict):
        return None, ["Backup JSON must be an object."]
    return data, []


def run_recovery_drill(
    *,
    backup_path: str | Path,
    vault: Vault,
    policy: PolicyEngine | None = None,
) -> RecoveryDrillReport:
    path = Path(backup_path)
    report = RecoveryDrillReport(backup_path=str(path))

    verify_report = verify_backup_file(path, vault)
    restore_report = restore_dry_run(path, vault)
    report.backup_verify = verify_report.as_dict(exclude_none=False)
    report.restore_dry_run = restore_report.as_dict(exclude_none=False)
    report.findings.extend(verify_report.findings)
    report.findings.extend(
        finding for finding in restore_report.findings if finding not in report.findings
    )

    backup, load_findings = _load_backup(path)
    report.findings.extend(load_findings)
    if backup is not None:
        current = vault.export_backup(metadata_only=True)
        diff_entries = diff_backups(current, backup)
        report.diff = {
            "version": "vault-diff-summary-v1",
            "entry_count": len(diff_entries),
            "entries": [entry.as_dict() for entry in diff_entries],
        }
    else:
        report.diff = {"version": "vault-diff-summary-v1", "entry_count": 0, "entries": []}

    if policy is not None:
        report.policy_hash = policy.compute_policy_hash()

    integrity_ok = (
        not verify_report.integrity_available
        or verify_report.integrity_status == BACKUP_INTEGRITY_HEALTHY
    )
    report.healthy = (
        verify_report.decryptable
        and restore_report.decryptable
        and integrity_ok
        and not report.findings
    )
    report.recommended_next_step = (
        "Recovery drill passed; keep the backup and matching key material together."
        if report.healthy
        else "Fix the recovery findings before trusting this backup in an incident."
    )
    return report
