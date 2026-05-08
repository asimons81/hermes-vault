from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from hermes_vault.audit import AuditLogger
from hermes_vault.cli import _hermes_group
from hermes_vault.models import AccessLogRecord, Decision, VerificationCategory


def _make_record(
    agent_id: str = "hermes",
    service: str = "openai",
    action: str = "get_credential",
    decision: Decision = Decision.allow,
    verification_result: VerificationCategory | None = VerificationCategory.valid,
    timestamp: datetime | None = None,
) -> AccessLogRecord:
    return AccessLogRecord(
        id=str(uuid.uuid4()),
        timestamp=timestamp or datetime.now(timezone.utc),
        agent_id=agent_id,
        service=service,
        action=action,
        decision=decision,
        reason="test",
        ttl_seconds=900,
        verification_result=verification_result,
    )


class TestAuditLoggerListRecent:
    def test_initialize_migrates_metadata_column(self, tmp_path: Path) -> None:
        db_path = tmp_path / "audit.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                """
                CREATE TABLE access_logs (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    service TEXT NOT NULL,
                    action TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    ttl_seconds INTEGER,
                    verification_result TEXT
                )
                """
            )
            conn.commit()

        audit = AuditLogger(db_path)
        audit.initialize()

        with sqlite3.connect(db_path) as conn:
            columns = [row[1] for row in conn.execute("PRAGMA table_info(access_logs)")]

        assert "metadata_json" in columns

    def test_metadata_round_trip(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        audit.record(
            _make_record(
                agent_id="intruder",
                service="*",
                action="mcp_bind:list_services",
                decision=Decision.deny,
                verification_result=None,
            ).model_copy(
                update={
                    "metadata": {
                        "requested_agent_id": "intruder",
                        "mcp_binding_mode": "bound",
                        "mcp_allowed_agents": ["test-agent"],
                        "mcp_default_agent": "test-agent",
                        "policy_decision": "not_evaluated",
                    }
                }
            )
        )

        results = audit.list_recent(limit=10)

        assert len(results) == 1
        assert results[0]["metadata"]["requested_agent_id"] == "intruder"
        assert results[0]["metadata"]["mcp_allowed_agents"] == ["test-agent"]
        assert results[0]["metadata"]["policy_decision"] == "not_evaluated"

    def test_no_filters_returns_all(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        audit.record(_make_record(agent_id="alice", service="openai"))
        audit.record(_make_record(agent_id="bob", service="github"))

        results = audit.list_recent(limit=10)

        assert len(results) == 2

    def test_filter_by_agent_id(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        audit.record(_make_record(agent_id="alice"))
        audit.record(_make_record(agent_id="bob"))
        audit.record(_make_record(agent_id="alice"))

        results = audit.list_recent(limit=10, agent_id="alice")

        assert len(results) == 2
        for row in results:
            assert row["agent_id"] == "alice"

    def test_filter_by_service(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        audit.record(_make_record(service="openai"))
        audit.record(_make_record(service="github"))
        audit.record(_make_record(service="openai"))

        results = audit.list_recent(limit=10, service="github")

        assert len(results) == 1
        assert results[0]["service"] == "github"

    def test_filter_by_action(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        audit.record(_make_record(action="get_credential"))
        audit.record(_make_record(action="verify"))
        audit.record(_make_record(action="get_credential"))

        results = audit.list_recent(limit=10, action="verify")

        assert len(results) == 1
        assert results[0]["action"] == "verify"

    def test_filter_by_decision(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        audit.record(_make_record(decision=Decision.allow))
        audit.record(_make_record(decision=Decision.deny))
        audit.record(_make_record(decision=Decision.allow))

        results = audit.list_recent(limit=10, decision="deny")

        assert len(results) == 1
        assert results[0]["decision"] == "deny"

    def test_filter_by_since(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        now = datetime.now(timezone.utc)
        audit.record(_make_record(timestamp=now - timedelta(days=10)))
        audit.record(_make_record(timestamp=now - timedelta(days=5)))
        audit.record(_make_record(timestamp=now - timedelta(days=1)))

        results = audit.list_recent(limit=10, since=now - timedelta(days=7))

        assert len(results) == 2

    def test_filter_by_until(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        # Use fixed-reference timestamps so comparisons are exact
        base = datetime(2026, 4, 25, 12, 0, 0, tzinfo=timezone.utc)
        audit.record(_make_record(timestamp=base - timedelta(days=10)))  # April 15
        audit.record(_make_record(timestamp=base - timedelta(days=5)))   # April 20
        audit.record(_make_record(timestamp=base - timedelta(days=1)))   # April 24

        # until = April 22 → records on April 15 and April 20 pass
        results = audit.list_recent(limit=10, until=base - timedelta(days=3))

        assert len(results) == 2

    def test_filter_since_and_until(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        now = datetime.now(timezone.utc)
        audit.record(_make_record(timestamp=now - timedelta(days=10)))
        audit.record(_make_record(timestamp=now - timedelta(days=5)))
        audit.record(_make_record(timestamp=now - timedelta(days=1)))

        results = audit.list_recent(
            limit=10,
            since=now - timedelta(days=7),
            until=now - timedelta(days=3),
        )

        assert len(results) == 1

    def test_combined_filters(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        audit.record(_make_record(agent_id="alice", service="openai", decision=Decision.allow))
        audit.record(_make_record(agent_id="bob", service="openai", decision=Decision.deny))
        audit.record(_make_record(agent_id="alice", service="github", decision=Decision.deny))

        results = audit.list_recent(limit=10, agent_id="alice", decision="allow")

        assert len(results) == 1
        assert results[0]["agent_id"] == "alice"
        assert results[0]["service"] == "openai"
        assert results[0]["decision"] == "allow"

    def test_limit_applied(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        for i in range(20):
            audit.record(_make_record(agent_id=f"agent-{i}"))

        results = audit.list_recent(limit=5)

        assert len(results) == 5

    def test_order_by_timestamp_desc(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        now = datetime.now(timezone.utc)
        audit.record(_make_record(timestamp=now - timedelta(days=3)))
        audit.record(_make_record(timestamp=now - timedelta(days=1)))
        audit.record(_make_record(timestamp=now - timedelta(days=2)))

        results = audit.list_recent(limit=10)

        timestamps = [r["timestamp"] for r in results]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_empty_result(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        audit.record(_make_record(agent_id="alice"))

        results = audit.list_recent(limit=10, agent_id="bob")

        assert results == []


class TestAuditCLi:
    """Tests for `hermes-vault audit` command."""

    @pytest.fixture
    def runner(self) -> CliRunner:
        return CliRunner()

    def test_audit_command_no_filter(self, runner: CliRunner, tmp_path: Path, monkeypatch) -> None:
        """No filter returns entries and exits 0."""
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        audit.record(_make_record(agent_id="hermes", service="openai"))
        audit.record(_make_record(agent_id="dwight", service="github"))

        class FakeSettings:
            db_path = audit.db_path

        monkeypatch.setattr("hermes_vault.cli.get_settings", lambda: FakeSettings())

        result = runner.invoke(_hermes_group, ["audit"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "hermes" in result.output

    def test_audit_command_filter_agent(self, runner: CliRunner, tmp_path: Path, monkeypatch) -> None:
        """--agent filters results."""
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        audit.record(_make_record(agent_id="hermes", service="openai"))
        audit.record(_make_record(agent_id="dwight", service="github"))

        class FakeSettings:
            db_path = audit.db_path

        monkeypatch.setattr("hermes_vault.cli.get_settings", lambda: FakeSettings())

        result = runner.invoke(_hermes_group, ["audit", "--agent", "hermes"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "hermes" in result.output
        assert "dwight" not in result.output

    def test_audit_command_filter_decision_deny(self, runner: CliRunner, tmp_path: Path, monkeypatch) -> None:
        """--decision deny filters to denied entries."""
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        audit.record(_make_record(decision=Decision.allow))
        audit.record(_make_record(decision=Decision.deny))

        class FakeSettings:
            db_path = audit.db_path

        monkeypatch.setattr("hermes_vault.cli.get_settings", lambda: FakeSettings())

        result = runner.invoke(_hermes_group, ["audit", "--decision", "deny"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "deny" in result.output

    def test_audit_command_invalid_decision(self, runner: CliRunner, tmp_path: Path, monkeypatch) -> None:
        """--decision with invalid value exits 1."""
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()

        class FakeSettings:
            db_path = audit.db_path

        monkeypatch.setattr("hermes_vault.cli.get_settings", lambda: FakeSettings())

        result = runner.invoke(_hermes_group, ["audit", "--decision", "invalid"], catch_exceptions=False)
        assert result.exit_code == 1

    def test_audit_command_invalid_limit(self, runner: CliRunner, tmp_path: Path, monkeypatch) -> None:
        """--limit 0 exits 1."""
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()

        class FakeSettings:
            db_path = audit.db_path

        monkeypatch.setattr("hermes_vault.cli.get_settings", lambda: FakeSettings())

        result = runner.invoke(_hermes_group, ["audit", "--limit", "0"], catch_exceptions=False)
        assert result.exit_code == 1

    def test_audit_command_since_relative(self, runner: CliRunner, tmp_path: Path, monkeypatch) -> None:
        """--since 7d parses relative date."""
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        audit.record(_make_record())

        class FakeSettings:
            db_path = audit.db_path

        monkeypatch.setattr("hermes_vault.cli.get_settings", lambda: FakeSettings())

        result = runner.invoke(_hermes_group, ["audit", "--since", "7d"], catch_exceptions=False)
        assert result.exit_code == 0

    def test_audit_command_invalid_since(self, runner: CliRunner, tmp_path: Path, monkeypatch) -> None:
        """--since with unparseable value exits 1."""
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()

        class FakeSettings:
            db_path = audit.db_path

        monkeypatch.setattr("hermes_vault.cli.get_settings", lambda: FakeSettings())

        result = runner.invoke(_hermes_group, ["audit", "--since", "not-a-date"], catch_exceptions=False)
        assert result.exit_code == 1

    def test_audit_command_format_json(self, runner: CliRunner, tmp_path: Path, monkeypatch) -> None:
        """--format json outputs valid JSON."""
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        audit.record(_make_record())

        class FakeSettings:
            db_path = audit.db_path

        monkeypatch.setattr("hermes_vault.cli.get_settings", lambda: FakeSettings())

        result = runner.invoke(_hermes_group, ["audit", "--format", "json", "--limit", "1"], catch_exceptions=False)
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)
        assert len(parsed) == 1

    def test_audit_command_empty_result(self, runner: CliRunner, tmp_path: Path, monkeypatch) -> None:
        """Filter matching nothing exits 0."""
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        audit.record(_make_record(agent_id="alice"))

        class FakeSettings:
            db_path = audit.db_path

        monkeypatch.setattr("hermes_vault.cli.get_settings", lambda: FakeSettings())

        result = runner.invoke(_hermes_group, ["audit", "--agent", "nonexistent"], catch_exceptions=False)
        assert result.exit_code == 0

    def test_audit_command_since_absolute_date(self, runner: CliRunner, tmp_path: Path, monkeypatch) -> None:
        """--since YYYY-MM-DD parses absolute date."""
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        audit.record(_make_record())

        class FakeSettings:
            db_path = audit.db_path

        monkeypatch.setattr("hermes_vault.cli.get_settings", lambda: FakeSettings())

        result = runner.invoke(_hermes_group, ["audit", "--since", "2026-01-01"], catch_exceptions=False)
        assert result.exit_code == 0

    def test_audit_command_until_includes_entire_date(self, runner: CliRunner, tmp_path: Path, monkeypatch) -> None:
        """--until YYYY-MM-DD should include entries later that same UTC day."""
        audit = AuditLogger(tmp_path / "audit.db")
        audit.initialize()
        audit.record(_make_record(timestamp=datetime(2026, 4, 20, 18, 30, 0, tzinfo=timezone.utc)))
        audit.record(_make_record(timestamp=datetime(2026, 4, 21, 0, 0, 0, tzinfo=timezone.utc)))

        class FakeSettings:
            db_path = audit.db_path

        monkeypatch.setattr("hermes_vault.cli.get_settings", lambda: FakeSettings())

        result = runner.invoke(_hermes_group, ["audit", "--until", "2026-04-20", "--format", "json"], catch_exceptions=False)
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert len(parsed) == 1
        assert parsed[0]["timestamp"].startswith("2026-04-20T18:30:00")
