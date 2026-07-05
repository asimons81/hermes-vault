from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hermes_vault.backup import restore_dry_run, verify_backup_file
from hermes_vault.diff import diff_backups
from hermes_vault.models import utc_now
from hermes_vault.policy import PolicyEngine
from hermes_vault.vault import Vault


RECOVERY_DRILL_VERSION = "recovery-drill-v1"


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

    report.healthy = (
        verify_report.decryptable
        and restore_report.decryptable
        and not report.findings
    )
    report.recommended_next_step = (
        "Recovery drill passed; keep the backup and matching key material together."
        if report.healthy
        else "Fix the recovery findings before trusting this backup in an incident."
    )
    return report
