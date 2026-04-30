"""Health check orchestrator — composes vault status, staleness, expiry,
and backup metadata into a structured report.

Read-only by default.  Never calls provider APIs unless ``--verify-live``
is requested.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from hermes_vault.audit import AuditLogger
from hermes_vault.models import CredentialStatus, utc_now
from hermes_vault.vault import Vault


REPORT_VERSION = "health-v1"


@dataclass
class HealthFinding:
    level: str       # "warning" or "error"
    kind: str        # stale, invalid, expired, expiring, backup, never_verified, live_verify_fail
    service: str
    alias: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {
            "level": self.level,
            "kind": self.kind,
            "service": self.service,
            "alias": self.alias,
            "detail": self.detail,
        }


@dataclass
class HealthReport:
    version: str = REPORT_VERSION
    generated_at: str = ""
    healthy: bool = True
    total_credentials: int = 0
    healthy_count: int = 0
    stale_count: int = 0
    invalid_count: int = 0
    expired_count: int = 0
    expiring_count: int = 0
    never_verified_count: int = 0
    findings: list[HealthFinding] = field(default_factory=list)
    days_since_last_backup: int | None = None
    stale_threshold_days: int = 30
    expiring_threshold_days: int = 7
    backup_threshold_days: int = 30
    verified_live: bool = False

    def as_dict(self, *, exclude_none: bool = True) -> dict[str, Any]:
        d = {
            "version": self.version,
            "generated_at": self.generated_at,
            "healthy": self.healthy,
            "total_credentials": self.total_credentials,
            "healthy_count": self.healthy_count,
            "stale_count": self.stale_count,
            "invalid_count": self.invalid_count,
            "expired_count": self.expired_count,
            "expiring_count": self.expiring_count,
            "never_verified_count": self.never_verified_count,
            "findings": [f.as_dict() for f in self.findings],
            "days_since_last_backup": self.days_since_last_backup,
            "stale_threshold_days": self.stale_threshold_days,
            "expiring_threshold_days": self.expiring_threshold_days,
            "backup_threshold_days": self.backup_threshold_days,
            "verified_live": self.verified_live,
        }
        if exclude_none:
            d = {k: v for k, v in d.items() if v is not None}
        return d


def _query_last_backup(audit: AuditLogger) -> datetime | None:
    """Return the timestamp of the most recent backup-related audit entry."""
    entries = audit.list_recent(limit=500, action="export_backup")
    for entry in entries:
        ts_str = entry.get("timestamp")
        if ts_str and isinstance(ts_str, str):
            try:
                return datetime.fromisoformat(ts_str)
            except ValueError:
                continue
    # Also check for CLI-style backups (backup_vault action, if any exist)
    entries = audit.list_recent(limit=500, action="backup")
    for entry in entries:
        ts_str = entry.get("timestamp")
        if ts_str and isinstance(ts_str, str):
            try:
                return datetime.fromisoformat(ts_str)
            except ValueError:
                continue
    return None


def _cred_staleness(
    record, now: datetime, threshold_days: int
) -> tuple[bool, int | None]:
    """Return (is_stale, days_since_verified)."""
    last_verified = record.last_verified_at
    if last_verified is None:
        return True, None  # never verified = always stale
    lv = last_verified.replace(tzinfo=timezone.utc) if last_verified.tzinfo is None else last_verified
    delta = now - lv
    days = delta.days
    return days >= threshold_days, days


def _cred_expiry(
    record, now: datetime, threshold_days: int
) -> tuple[bool, bool, int | None]:
    """Return (is_expired, is_expiring, days_until_expiry)."""
    expiry = record.expiry
    if expiry is None:
        return False, False, None
    ex = expiry.replace(tzinfo=timezone.utc) if expiry.tzinfo is None else expiry
    delta = ex - now
    days = delta.days
    is_expired = days < 0
    is_expiring = not is_expired and days <= threshold_days
    return is_expired, is_expiring, days


def run_health(
    vault: Vault,
    audit: AuditLogger | None = None,
    *,
    verify_live: bool = False,
    stale_days: int = 30,
    expiring_days: int = 7,
    backup_days: int = 30,
) -> HealthReport:
    """Produce a read-only health report for the vault.

    Parameters
    ----------
    vault:
        An initialised Vault instance.
    audit:
        Optional AuditLogger for backup-timestamp queries.
    verify_live:
        If True the caller is responsible for live-verification.
        Health itself never hits provider endpoints.
    stale_days:
        Credentials not verified within this many days are flagged stale.
    expiring_days:
        Credentials expiring within this many days are flagged.
    backup_days:
        A backup older than this many days produces a warning.

    Returns
    -------
    HealthReport
    """
    now = utc_now()
    report = HealthReport(
        generated_at=now.isoformat(),
        stale_threshold_days=stale_days,
        expiring_threshold_days=expiring_days,
        backup_threshold_days=backup_days,
        verified_live=verify_live,
    )

    # ── credentials ─────────────────────────────────────────────────
    records = vault.list_credentials()
    report.total_credentials = len(records)

    healthy = 0
    for rec in records:
        # staleness
        is_stale, days_since = _cred_staleness(rec, now, stale_days)
        if is_stale:
            report.stale_count += 1
            if rec.last_verified_at is None:
                report.never_verified_count += 1
                report.findings.append(HealthFinding(
                    level="warning",
                    kind="never_verified",
                    service=rec.service,
                    alias=rec.alias,
                    detail="credential has never been verified",
                ))
            else:
                report.findings.append(HealthFinding(
                    level="warning",
                    kind="stale",
                    service=rec.service,
                    alias=rec.alias,
                    detail=f"last verified {days_since} day(s) ago (threshold: {stale_days}d)",
                ))

        # expiry
        is_expired, is_expiring, days_until = _cred_expiry(rec, now, expiring_days)
        if is_expired:
            report.expired_count += 1
            report.findings.append(HealthFinding(
                level="warning",
                kind="expired",
                service=rec.service,
                alias=rec.alias,
                detail=f"expired {abs(days_until or 0)} day(s) ago",
            ))
        elif is_expiring:
            report.expiring_count += 1
            report.findings.append(HealthFinding(
                level="warning",
                kind="expiring",
                service=rec.service,
                alias=rec.alias,
                detail=f"expires in {days_until} day(s) (threshold: {expiring_days}d)",
            ))

        # status
        if rec.status == CredentialStatus.invalid:
            report.invalid_count += 1
            report.findings.append(HealthFinding(
                level="warning",
                kind="invalid",
                service=rec.service,
                alias=rec.alias,
                detail="credential status is invalid",
            ))
        elif rec.status == CredentialStatus.expired:
            report.expired_count += 1
            # Only add finding if not already flagged by expiry datetime
            if not is_expired:
                report.findings.append(HealthFinding(
                    level="warning",
                    kind="status_expired",
                    service=rec.service,
                    alias=rec.alias,
                    detail="credential status is expired",
                ))

        # count healthy
        if (rec.status in (CredentialStatus.active, CredentialStatus.unknown)
                and not is_stale and not is_expired and not is_expiring
                and rec.last_verified_at is not None):
            healthy += 1

    report.healthy_count = healthy

    # ── backup ──────────────────────────────────────────────────────
    if audit is not None:
        last_backup = _query_last_backup(audit)
        if last_backup is None:
            report.days_since_last_backup = None
            report.findings.append(HealthFinding(
                level="warning",
                kind="backup",
                service="*",
                alias="*",
                detail="no backup has been recorded (run `hermes-vault backup`)",
            ))
        else:
            delta = now - last_backup
            report.days_since_last_backup = delta.days
            if delta.days > backup_days:
                report.findings.append(HealthFinding(
                    level="warning",
                    kind="backup",
                    service="*",
                    alias="*",
                    detail=f"last backup was {delta.days} day(s) ago (threshold: {backup_days}d)",
                ))

    # ── verdict ─────────────────────────────────────────────────────
    report.healthy = len(report.findings) == 0

    return report
