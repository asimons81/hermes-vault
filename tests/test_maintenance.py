from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from hermes_vault.audit import AuditLogger
from hermes_vault.health import HealthFinding, HealthReport
from hermes_vault.maintenance import run_maintenance
from hermes_vault.oauth.oauth_refresh import RefreshAttempt
from hermes_vault.vault import Vault


@pytest.fixture
def vault(tmp_path: Path) -> Vault:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "test-passphrase")
    vault.add_credential("openai", "sk-old", "oauth_access_token", alias="primary")
    vault.add_credential("openai", "refresh-old", "oauth_refresh_token", alias="refresh:primary")
    return vault


def _healthy_report() -> HealthReport:
    return HealthReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        healthy=True,
        total_credentials=2,
        healthy_count=2,
        stale_count=0,
        invalid_count=0,
        expired_count=0,
        expiring_count=0,
        never_verified_count=0,
        findings=[],
        days_since_last_backup=1,
        stale_threshold_days=30,
        expiring_threshold_days=7,
        backup_threshold_days=30,
        verified_live=False,
        leases={"active": 0, "expired": 0, "revoked": 0, "total": 0},
    )


def _warning_report() -> HealthReport:
    report = _healthy_report()
    report.healthy = False
    report.findings.append(
        HealthFinding(
            level="warning",
            kind="backup",
            service="*",
            alias="*",
            detail="last backup was 60 day(s) ago (threshold: 30d)",
        )
    )
    return report


class FakeRefreshEngine:
    def __init__(self, vault: Vault, proactive_margin_seconds: int = 300) -> None:
        self.vault = vault
        self.proactive_margin_seconds = proactive_margin_seconds
        self.calls: list[bool] = []

    def set_audit(self, audit) -> None:  # pragma: no cover - compatibility shim
        self.audit = audit

    def refresh_all(self, dry_run: bool = False):
        self.calls.append(dry_run)
        if not dry_run:
            # This should never happen in the dry-run test.
            self.vault.add_credential(
                "openai",
                "sk-mutated",
                "oauth_access_token",
                alias="primary",
                replace_existing=True,
            )
        return [
            RefreshAttempt(
                service="openai",
                alias="primary",
                success=True,
                reason="Token refresh simulated (dry-run)" if dry_run else "Token refreshed successfully",
                new_access_token="sk-new-access-token-secret-123456",
                new_refresh_token=None,
                expires_in=3600,
                scopes=["openid"],
            )
        ]


def test_run_maintenance_dry_run_does_not_mutate_vault(monkeypatch, vault: Vault, tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "audit.db")
    audit.initialize()
    monkeypatch.setattr("hermes_vault.maintenance.RefreshEngine", FakeRefreshEngine)
    monkeypatch.setattr("hermes_vault.maintenance.run_health", lambda *args, **kwargs: _healthy_report())

    before = vault.get_secret(vault.resolve_credential("openai", alias="primary").id)
    assert before is not None

    report = run_maintenance(vault, audit=audit, dry_run=True)

    after = vault.get_secret(vault.resolve_credential("openai", alias="primary").id)
    assert after is not None
    assert after.secret == before.secret
    assert report.dry_run is True
    assert report.lifecycle_scope == "refresh + health only"
    assert report.policy_drift_checked is False
    assert report.recovery_proven is False
    assert "policy doctor" in report.next_step_hint
    assert "backup-verify" in report.next_step_hint
    assert "restore --dry-run" in report.next_step_hint
    assert report.refresh_summary["attempted"] == 1
    assert report.refresh_summary["succeeded"] == 1
    assert report.refresh_summary["failed"] == 0
    assert report.audit_recorded is True
    assert report.recommended_exit_code == 0


def test_run_maintenance_report_uses_token_previews(monkeypatch, vault: Vault) -> None:
    monkeypatch.setattr("hermes_vault.maintenance.RefreshEngine", FakeRefreshEngine)
    monkeypatch.setattr("hermes_vault.maintenance.run_health", lambda *args, **kwargs: _healthy_report())

    report = run_maintenance(vault, audit=None, dry_run=True)
    data = report.as_dict(exclude_none=False)
    serialized = str(data)
    refresh_result = data["refresh_results"][0]

    assert "sk-new-access-token-secret-123456" not in serialized
    assert "new_access_token" not in refresh_result
    assert "new_refresh_token" not in refresh_result
    assert refresh_result["new_access_token_preview"] == "sk-new-acces..."
    assert refresh_result["new_refresh_token_preview"] is None
    assert refresh_result["access_token_rotated"] is True
    assert refresh_result["refresh_token_rotated"] is False


def test_run_maintenance_refresh_summary_counts(monkeypatch, vault: Vault) -> None:
    class SummaryRefreshEngine(FakeRefreshEngine):
        def refresh_all(self, dry_run: bool = False):
            self.calls.append(dry_run)
            return [
                RefreshAttempt(service="openai", alias="primary", success=True, reason="Token refreshed successfully"),
                RefreshAttempt(
                    service="github",
                    alias="work",
                    success=False,
                    reason="Network failure after 3 retries: timeout",
                ),
                RefreshAttempt(
                    service="gcal",
                    alias="calendar",
                    success=False,
                    reason="Refresh token rejected by provider: invalid_grant — revoked",
                ),
            ]

    monkeypatch.setattr("hermes_vault.maintenance.RefreshEngine", SummaryRefreshEngine)
    monkeypatch.setattr("hermes_vault.maintenance.run_health", lambda *args, **kwargs: _healthy_report())

    report = run_maintenance(vault, audit=None, dry_run=False)

    assert report.refresh_summary["attempted"] == 3
    assert report.refresh_summary["succeeded"] == 1
    assert report.refresh_summary["failed"] == 2
    assert report.refresh_summary["failure_kinds"] == {
        "network": 1,
        "provider_rejection": 1,
    }
    assert [item["error_kind"] for item in report.refresh_results] == [
        "none",
        "network",
        "provider_rejection",
    ]
    assert report.recommended_exit_code == 1


def test_run_maintenance_exit_code_warns_on_health_findings(monkeypatch, vault: Vault) -> None:
    monkeypatch.setattr("hermes_vault.maintenance.RefreshEngine", FakeRefreshEngine)
    monkeypatch.setattr("hermes_vault.maintenance.run_health", lambda *args, **kwargs: _warning_report())

    report = run_maintenance(vault, audit=None, dry_run=False)

    assert report.health["healthy"] is False
    assert report.health["findings"]
    assert report.policy_drift_checked is False
    assert report.recovery_proven is False
    assert "policy doctor" in report.next_step_hint
    assert "restore --dry-run" in report.next_step_hint
    assert report.recommended_exit_code == 1


def test_run_maintenance_failure_summary_classifies_missing_refresh_token(monkeypatch, vault: Vault) -> None:
    class MissingTokenRefreshEngine(FakeRefreshEngine):
        def refresh_all(self, dry_run: bool = False):
            self.calls.append(dry_run)
            return [
                RefreshAttempt(
                    service="openai",
                    alias="primary",
                    success=False,
                    reason="No refresh token found for service 'openai'. Re-authentication required.",
                ),
                RefreshAttempt(
                    service="github",
                    alias="work",
                    success=False,
                    reason="Missing client secret for provider 'github'",
                ),
                RefreshAttempt(
                    service="gcal",
                    alias="calendar",
                    success=False,
                    reason="Denied by policy: agent lacks refresh access",
                ),
            ]

    monkeypatch.setattr("hermes_vault.maintenance.RefreshEngine", MissingTokenRefreshEngine)
    monkeypatch.setattr("hermes_vault.maintenance.run_health", lambda *args, **kwargs: _healthy_report())

    report = run_maintenance(vault, audit=None, dry_run=False)

    assert report.refresh_summary["failed"] == 3
    assert report.refresh_summary["failure_kinds"] == {
        "missing_refresh_token": 1,
        "missing_client_credentials": 1,
        "policy_denial": 1,
    }
    assert [item["error_kind"] for item in report.refresh_results] == [
        "missing_refresh_token",
        "missing_client_credentials",
        "policy_denial",
    ]
    assert report.recommended_exit_code == 1


def test_run_maintenance_reports_lease_summary(monkeypatch, vault: Vault) -> None:
    monkeypatch.setattr("hermes_vault.maintenance.RefreshEngine", FakeRefreshEngine)
    record = vault.resolve_credential("openai", alias="primary")
    active = vault.issue_lease(record.id, agent_id="maint-agent", ttl_seconds=300)
    expired = vault.issue_lease(record.id, agent_id="maint-agent", ttl_seconds=300)
    past = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
    with sqlite3.connect(vault.db_path) as conn:
        conn.execute("UPDATE leases SET expires_at = ?, status = ? WHERE id = ?", (past, "active", expired.id))
        conn.commit()

    report = run_maintenance(vault, audit=None, dry_run=True)

    assert report.leases == {"active": 1, "expired": 1, "revoked": 0, "total": 2}
    assert report.health["leases"] == report.leases
    assert active.id != expired.id


def test_run_maintenance_cleanup_revokes_expired_leases(monkeypatch, vault: Vault) -> None:
    monkeypatch.setattr("hermes_vault.maintenance.RefreshEngine", FakeRefreshEngine)
    record = vault.resolve_credential("openai", alias="primary")
    expired = vault.issue_lease(record.id, agent_id="maint-agent", ttl_seconds=300)
    past = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
    with sqlite3.connect(vault.db_path) as conn:
        conn.execute("UPDATE leases SET expires_at = ?, status = ? WHERE id = ?", (past, "active", expired.id))
        conn.commit()

    report = run_maintenance(vault, audit=None, dry_run=True, cleanup_leases=True)
    cleaned = vault.get_lease(expired.id)

    assert cleaned is not None
    assert cleaned.status.value == "revoked"
    assert report.leases == {"active": 0, "expired": 0, "revoked": 1, "total": 1}


def test_run_maintenance_cleanup_skips_active_leases(monkeypatch, vault: Vault) -> None:
    monkeypatch.setattr("hermes_vault.maintenance.RefreshEngine", FakeRefreshEngine)
    record = vault.resolve_credential("openai", alias="primary")
    active = vault.issue_lease(record.id, agent_id="maint-agent", ttl_seconds=300)

    report = run_maintenance(vault, audit=None, dry_run=True, cleanup_leases=True)
    unchanged = vault.get_lease(active.id)

    assert unchanged is not None
    assert unchanged.status.value == "active"
    assert report.leases["active"] == 1
