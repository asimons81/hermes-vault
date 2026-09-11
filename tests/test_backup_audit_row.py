"""P3 CLI truth pack: backup writes the audit row health scans.

Root cause (v0.25.1): `backup` (cli.py) wrote the file and returned — no
audit.record — while health.py `_query_last_backup` and the broker's backup
reminder scanned for exactly such rows. "Days since last backup" said
"never" forever regardless of operator discipline.

These tests pin the truthful behavior end to end: CLI backup → audit row →
health report sees it. Also covers the shared AuditLogger.last_backup_at()
scanner that dedupes the two previously-duplicated implementations.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from click.testing import CliRunner

from hermes_vault.audit import AuditLogger
from hermes_vault.cli import _hermes_group
from hermes_vault.health import run_health
from hermes_vault.models import AccessLogRecord, Decision
from hermes_vault.vault import Vault


def _make_vault(tmp_path: Path) -> Vault:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "test-passphrase")
    vault.add_credential("openai", "sk-test-secret", "api_key", alias="primary")
    return vault


def _fake_build(vault: Vault):
    def _inner(prompt: bool = False):
        return vault, object(), object(), object()
    return _inner


# ── shared scanner: AuditLogger.last_backup_at ────────────────────────────


def test_last_backup_at_none_when_no_backup(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    audit = AuditLogger(vault.db_path)
    assert audit.last_backup_at() is None


def test_last_backup_at_finds_backup_action_row(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    audit = AuditLogger(vault.db_path)
    audit.record(AccessLogRecord(
        agent_id="operator",
        service="*",
        action="backup",
        decision=Decision.allow,
        reason="backup written",
        timestamp=datetime.now(timezone.utc) - timedelta(hours=2),
    ))
    last = audit.last_backup_at()
    assert last is not None
    assert abs((datetime.now(timezone.utc) - last.replace(tzinfo=timezone.utc)).total_seconds() - 7200) < 60


def test_last_backup_at_finds_export_backup_action_row(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    audit = AuditLogger(vault.db_path)
    audit.record(AccessLogRecord(
        agent_id="operator",
        service="*",
        action="export_backup",
        decision=Decision.allow,
        reason="backup exported",
        timestamp=datetime.now(timezone.utc) - timedelta(days=3),
    ))
    assert audit.last_backup_at() is not None


def test_last_backup_at_prefers_most_recent(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    audit = AuditLogger(vault.db_path)
    audit.record(AccessLogRecord(
        agent_id="operator",
        service="*",
        action="export_backup",
        decision=Decision.allow,
        reason="old backup",
        timestamp=datetime.now(timezone.utc) - timedelta(days=10),
    ))
    audit.record(AccessLogRecord(
        agent_id="operator",
        service="*",
        action="backup",
        decision=Decision.allow,
        reason="recent backup",
        timestamp=datetime.now(timezone.utc) - timedelta(days=1),
    ))
    last = audit.last_backup_at()
    assert last is not None
    age = datetime.now(timezone.utc) - last.replace(tzinfo=timezone.utc)
    assert timedelta(days=0) < age < timedelta(days=2)


def test_last_backup_at_ignores_malformed_timestamps(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    audit = AuditLogger(vault.db_path)
    good = datetime.now(timezone.utc) - timedelta(days=5)
    audit.record(AccessLogRecord(
        agent_id="operator",
        service="*",
        action="export_backup",
        decision=Decision.allow,
        reason="good row",
        timestamp=good,
    ))
    # Corrupt the newest row's timestamp directly in the DB (list_recent is
    # DESC ordered; inject an unparseable newest entry).
    import sqlite3
    with sqlite3.connect(vault.db_path) as conn:
        conn.execute(
            "UPDATE access_logs SET timestamp = 'not-a-timestamp' WHERE action = 'export_backup'"
        )
        conn.commit()
    assert audit.last_backup_at() is None


# ── CLI backup writes the audit row ───────────────────────────────────────


def test_backup_command_writes_audit_row(monkeypatch, tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build(vault))

    out = tmp_path / "backup.json"
    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["--no-banner", "backup", "--output", str(out)])

    assert result.exit_code == 0, result.output
    assert out.exists()
    audit = AuditLogger(vault.db_path)
    rows = [r for r in audit.list_recent(limit=50, action="export_backup")]
    assert len(rows) == 1
    assert rows[0]["agent_id"] == "operator"
    assert "1 credential(s)" in rows[0]["reason"]
    assert rows[0]["metadata"].get("metadata_only") is False


def test_backup_command_audit_failure_does_not_break_backup(monkeypatch, tmp_path: Path) -> None:
    """The audit append must never fail the backup itself (recovery tool)."""
    vault = _make_vault(tmp_path)

    class _FailingAuditLogger(AuditLogger):
        def record(self, record) -> None:
            raise RuntimeError("integrity wedge")

    def _failing_factory(*args, **kwargs):
        return _FailingAuditLogger(*args, **kwargs)

    monkeypatch.setattr("hermes_vault.cli.AuditLogger", _failing_factory)
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build(vault))

    out = tmp_path / "backup.json"
    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["--no-banner", "backup", "--output", str(out)])

    assert result.exit_code == 0, result.output
    assert out.exists()
    assert "could not be written" in result.output


# ── end-to-end truth: backup → health sees it ─────────────────────────────


def test_health_sees_cli_backup_end_to_end(monkeypatch, tmp_path: Path) -> None:
    """The release-level acceptance: after `hermes-vault backup`, health's
    "Days since last backup" reflects reality instead of "never"."""
    vault = _make_vault(tmp_path)
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build(vault))

    out = tmp_path / "backup.json"
    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["--no-banner", "backup", "--output", str(out)])
    assert result.exit_code == 0, result.output

    audit = AuditLogger(vault.db_path)
    report = run_health(vault, audit=audit)
    assert report.days_since_last_backup == 0
    backup_findings = [f for f in report.findings if f.kind == "backup"]
    assert backup_findings == []


def test_health_backup_warning_persists_without_backup(monkeypatch, tmp_path: Path) -> None:
    """Negative control: no backup run → health still warns truthfully."""
    vault = _make_vault(tmp_path)
    audit = AuditLogger(vault.db_path)
    report = run_health(vault, audit=audit)
    assert report.days_since_last_backup is None
    backup_findings = [f for f in report.findings if f.kind == "backup"]
    assert len(backup_findings) == 1
    assert "no backup has been recorded" in backup_findings[0].detail.lower()
