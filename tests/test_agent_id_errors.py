"""P3 CLI truth pack: actionable agent_id errors + broker JSON encoding.

Live probes at v0.25.1:
- ``broker get x --agent ghost`` printed only a denial JSON with
  "agent 'ghost' is not defined in policy" — no way to discover valid ids
  or the default-binding mechanism (MCP ``?agent_id=`` /
  ``HERMES_VAULT_MCP_DEFAULT_AGENT``).
- ``broker get`` on BOTH allow and deny paths printed a JSON *string
  containing* JSON (rich print_json(data=<pre-encoded str>) re-encodes).
- ``broker list --agent ghost`` printed ``[]`` and exited 0, silently.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from hermes_vault.cli import _hermes_group
from hermes_vault.models import BrokerDecision


class _BrokerGettable:
    def __init__(self, *, allowed: bool, reason: str) -> None:
        self.allowed = allowed
        self.reason = reason

    def get_credential(self, service, purpose, agent_id):
        return BrokerDecision(
            allowed=self.allowed,
            service=service,
            agent_id=agent_id,
            reason=self.reason,
        )

    def get_ephemeral_env(self, service, agent_id, ttl):
        return BrokerDecision(
            allowed=self.allowed,
            service=service,
            agent_id=agent_id,
            reason=self.reason,
            ttl_seconds=ttl,
        )


def _fake_build(broker):
    def _inner(prompt: bool = False):
        return object(), object(), broker, object()
    return _inner


def _write_policy(tmp_path: Path, agents: list[str]) -> Path:
    policy_path = tmp_path / "policy.yaml"
    lines = ["agents:"]
    for agent in agents:
        lines.append(f"  {agent}:")
        lines.append("    services: [openai]")
    policy_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return policy_path


# ── actionable agent_id errors ──────────────────────────────────────────────


def test_broker_get_undefined_agent_lists_defined_agents(monkeypatch, tmp_path) -> None:
    policy_path = _write_policy(tmp_path, ["hermes", "deploy-bot"])
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))

    broker = _BrokerGettable(
        allowed=False, reason="agent 'ghost' is not defined in policy"
    )
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build(broker))

    result = CliRunner().invoke(
        _hermes_group, ["--no-banner", "broker", "get", "openai", "--agent", "ghost"]
    )

    assert result.exit_code == 1
    # stdout stays parseable JSON (the denial decision)
    payload = json.loads(result.stdout)
    assert payload["allowed"] is False
    # stderr carries the actionable hint
    assert "agent 'ghost' is not defined in policy" in result.stderr
    assert "hermes" in result.stderr and "deploy-bot" in result.stderr
    assert "HERMES_VAULT_MCP_DEFAULT_AGENT" in result.stderr


def test_broker_get_service_denial_does_not_emit_agent_hint(monkeypatch, tmp_path) -> None:
    """A denial unrelated to agent definition must not misfire the hint."""
    policy_path = _write_policy(tmp_path, ["hermes"])
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))

    broker = _BrokerGettable(
        allowed=False, reason="service 'closedai' is not allowed for agent 'hermes'"
    )
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build(broker))

    result = CliRunner().invoke(
        _hermes_group, ["--no-banner", "broker", "get", "closedai", "--agent", "hermes"]
    )

    assert result.exit_code == 1
    assert "is not defined in policy" not in result.stderr
    assert "Defined agents" not in result.stderr


def test_broker_list_undefined_agent_hints_instead_of_silent_empty(monkeypatch, tmp_path) -> None:
    policy_path = _write_policy(tmp_path, ["hermes"])
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))

    class EmptyListBroker:
        def list_available_credentials(self, agent_id):
            return []

    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build(EmptyListBroker()))

    result = CliRunner().invoke(
        _hermes_group, ["--no-banner", "broker", "list", "--agent", "ghost"]
    )

    # Listing stays exit 0 (empty list is truthful), but the hint explains why.
    assert result.exit_code == 0
    assert json.loads(result.stdout) == []
    assert "agent 'ghost' is not defined in policy" in result.stderr
    assert "hermes" in result.stderr


def test_broker_list_defined_agent_empty_listing_has_no_hint(monkeypatch, tmp_path) -> None:
    """Empty listing for a *defined* agent (no overlapping services) is a
    different condition — the hint must not claim the agent is undefined."""
    policy_path = _write_policy(tmp_path, ["hermes"])
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))

    class EmptyListBroker:
        def list_available_credentials(self, agent_id):
            return []

    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build(EmptyListBroker()))

    result = CliRunner().invoke(
        _hermes_group, ["--no-banner", "broker", "list", "--agent", "hermes"]
    )

    assert result.exit_code == 0
    assert "is not defined in policy" not in result.stderr


def test_lease_issue_undefined_agent_hint(monkeypatch, tmp_path) -> None:
    policy_path = _write_policy(tmp_path, ["hermes"])
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))

    class LeaseBroker:
        def issue_lease(self, service_or_id, agent_id, ttl_seconds, alias=None, purpose="task", reason=None):
            return BrokerDecision(
                allowed=False,
                service=service_or_id,
                agent_id=agent_id,
                reason=f"agent '{agent_id}' is not defined in policy",
            )

    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build(LeaseBroker()))

    result = CliRunner().invoke(
        _hermes_group,
        ["--no-banner", "lease", "issue", "openai", "--agent", "ghost"],
    )

    assert result.exit_code == 1
    assert "Defined agents: hermes" in result.stderr


# ── broker JSON encoding (E#4 class) ────────────────────────────────────────


def test_broker_get_json_not_double_encoded_allow_and_deny(monkeypatch) -> None:
    for allowed, reason in (
        (True, "ok"),
        (False, "credential not found in vault"),
    ):
        broker = _BrokerGettable(allowed=allowed, reason=reason)
        monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build(broker))

        result = CliRunner().invoke(
            _hermes_group, ["--no-banner", "broker", "get", "openai", "--agent", "hermes"]
        )

        assert result.exit_code == (0 if allowed else 1)
        payload = json.loads(result.output)
        assert isinstance(payload, dict)
        assert payload["allowed"] is allowed
        assert payload["service"] == "openai"


def test_broker_list_json_not_double_encoded(monkeypatch) -> None:
    class ListBroker:
        def list_available_credentials(self, agent_id):
            return [
                {"service": "openai", "alias": "default", "credential_type": "api_key", "status": "active"}
            ]

    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build(ListBroker()))

    result = CliRunner().invoke(
        _hermes_group, ["--no-banner", "broker", "list", "--agent", "hermes"]
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert isinstance(payload, list)
    assert payload[0]["service"] == "openai"
