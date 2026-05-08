from __future__ import annotations

import pytest
from pathlib import Path

from hermes_vault.config import AppSettings


def test_appsettings_parses_mcp_allowed_agents(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HERMES_VAULT_MCP_ALLOWED_AGENTS", "hermes, claude-desktop, cursor")
    settings = AppSettings(runtime_home=Path("/tmp/hermes-vault-test"))

    assert settings.mcp_allowed_agents == ["hermes", "claude-desktop", "cursor"]
    assert settings.mcp_binding_enabled is True


def test_appsettings_parses_mcp_default_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HERMES_VAULT_MCP_DEFAULT_AGENT", "claude-desktop")
    settings = AppSettings(runtime_home=Path("/tmp/hermes-vault-test"))

    assert settings.mcp_default_agent == "claude-desktop"


def test_appsettings_uses_unrestricted_mode_when_binding_env_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HERMES_VAULT_MCP_ALLOWED_AGENTS", raising=False)
    monkeypatch.delenv("HERMES_VAULT_MCP_DEFAULT_AGENT", raising=False)
    settings = AppSettings(runtime_home=Path("/tmp/hermes-vault-test"))

    assert settings.mcp_allowed_agents == []
    assert settings.mcp_default_agent is None
    assert settings.mcp_binding_enabled is False


def test_appsettings_rejects_default_agent_outside_allowed_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HERMES_VAULT_MCP_ALLOWED_AGENTS", "hermes,claude-desktop")
    monkeypatch.setenv("HERMES_VAULT_MCP_DEFAULT_AGENT", "cursor")

    with pytest.raises(ValueError):
        AppSettings(runtime_home=Path("/tmp/hermes-vault-test"))
