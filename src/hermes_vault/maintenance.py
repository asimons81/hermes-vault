"""Maintenance orchestration for Hermes Vault.

This module composes OAuth refresh and health checks into a single
operator-facing maintenance run without owning the CLI surface yet.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hermes_vault.audit import AuditLogger
from hermes_vault.health import run_health
from hermes_vault.models import AccessLogRecord, Decision, utc_now
from hermes_vault.oauth.oauth_refresh import RefreshAttempt, RefreshEngine
from hermes_vault.vault import Vault


REPORT_VERSION = "maintain-v1"


def _health_to_dict(health: Any) -> dict[str, Any]:
    if hasattr(health, "as_dict"):
        return health.as_dict(exclude_none=False)
    if isinstance(health, dict):
        return dict(health)
    return {"value": health}


def _refresh_attempt_to_dict(attempt: RefreshAttempt) -> dict[str, Any]:
    data = {
        "service": attempt.service,
        "alias": attempt.alias,
        "success": attempt.success,
        "reason": attempt.reason,
        "new_access_token": attempt.new_access_token,
        "new_refresh_token": attempt.new_refresh_token,
        "expires_in": attempt.expires_in,
        "scopes": list(attempt.scopes),
        "retry_count": attempt.retry_count,
    }
    data["error_kind"] = _classify_refresh_failure(attempt)
    return data


def _classify_refresh_failure(attempt: RefreshAttempt) -> str:
    """Derive a conservative failure kind from a refresh attempt."""
    if attempt.success:
        return "none"

    reason = (attempt.reason or "").lower()
    if any(
        marker in reason
        for marker in (
            "missing refresh token",
            "re-authentication required",
            "refresh token for",
            "cannot be decrypted",
        )
    ):
        return "missing_refresh_token"
    if any(marker in reason for marker in ("client id", "client secret", "client credential")):
        return "missing_client_credentials"
    if any(marker in reason for marker in ("policy", "denied", "deny")):
        return "policy_denial"
    if any(marker in reason for marker in ("network", "timeout", "connection", "request failed")):
        return "network"
    if any(
        marker in reason
        for marker in (
            "invalid_grant",
            "invalid_request",
            "token rejected",
            "provider",
            "token endpoint error",
            "refresh response missing access_token",
        )
    ):
        return "provider_rejection"
    return "unknown"


def _recommended_exit_code(health: Any, refresh_summary: dict[str, Any]) -> int:
    healthy = bool(getattr(health, "healthy", True))
    failed = int(refresh_summary.get("failed", 0) or 0)
    return 0 if healthy and failed == 0 else 1


@dataclass
class MaintenanceReport:
    version: str = REPORT_VERSION
    generated_at: str = field(default_factory=lambda: utc_now().isoformat())
    dry_run: bool = False
    margin_seconds: int = 300
    health: dict[str, Any] = field(default_factory=dict)
    refresh_results: list[dict[str, Any]] = field(default_factory=list)
    refresh_summary: dict[str, Any] = field(default_factory=dict)
    audit_recorded: bool = False
    recommended_exit_code: int = 0

    def as_dict(self, *, exclude_none: bool = True) -> dict[str, Any]:
        data = {
            "version": self.version,
            "generated_at": self.generated_at,
            "dry_run": self.dry_run,
            "margin_seconds": self.margin_seconds,
            "health": self.health,
            "refresh_results": self.refresh_results,
            "refresh_summary": self.refresh_summary,
            "audit_recorded": self.audit_recorded,
            "recommended_exit_code": self.recommended_exit_code,
        }
        if exclude_none:
            return {key: value for key, value in data.items() if value is not None}
        return data


def run_maintenance(
    vault: Vault,
    audit: AuditLogger | None = None,
    *,
    dry_run: bool = False,
    margin: int = 300,
    stale_days: int = 30,
    expiring_days: int = 7,
    backup_days: int = 30,
    refresh_engine: RefreshEngine | None = None,
) -> MaintenanceReport:
    """Run refresh + health orchestration and return a structured report."""
    engine = refresh_engine or RefreshEngine(
        vault=vault,
        proactive_margin_seconds=margin,
    )
    if audit is not None:
        engine.set_audit(audit)

    refresh_results = engine.refresh_all(dry_run=dry_run)
    health = run_health(
        vault,
        audit=audit,
        verify_live=False,
        stale_days=stale_days,
        expiring_days=expiring_days,
        backup_days=backup_days,
    )

    refresh_dicts = [_refresh_attempt_to_dict(result) for result in refresh_results]
    failure_kinds: dict[str, int] = {}
    for result in refresh_results:
        kind = _classify_refresh_failure(result)
        if kind != "none":
            failure_kinds[kind] = failure_kinds.get(kind, 0) + 1

    refresh_summary = {
        "attempted": len(refresh_results),
        "succeeded": sum(1 for result in refresh_results if result.success),
        "failed": sum(1 for result in refresh_results if not result.success),
        "failure_kinds": failure_kinds,
        "dry_run": dry_run,
    }

    report = MaintenanceReport(
        dry_run=dry_run,
        margin_seconds=margin,
        health=_health_to_dict(health),
        refresh_results=refresh_dicts,
        refresh_summary=refresh_summary,
    )
    report.recommended_exit_code = _recommended_exit_code(health, refresh_summary)

    if audit is not None:
        audit.record(
            AccessLogRecord(
                agent_id="hermes-vault-maintain",
                service="*",
                action="maintain",
                decision=Decision.allow,
                reason=(
                    f"dry_run={dry_run} attempted={refresh_summary['attempted']} "
                    f"succeeded={refresh_summary['succeeded']} failed={refresh_summary['failed']} "
                    f"healthy={bool(getattr(health, 'healthy', True))} "
                    f"exit={report.recommended_exit_code}"
                ),
            )
        )
        report.audit_recorded = True

    return report
