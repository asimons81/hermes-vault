from __future__ import annotations

from pathlib import Path
import pytest

from hermes_vault import _platform
from hermes_vault.config import (
    AppSettings,
    get_settings,
    list_profiles,
    reset_active_profile,
    resolve_profile,
    set_active_profile,
    validate_profile_name,
)


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


def test_get_settings_no_profile_uses_base_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.delenv("HERMES_VAULT_PROFILE", raising=False)

    settings = get_settings()

    assert settings.profile_name == "default"
    assert settings.runtime_home == tmp_path
    assert settings.base_home == tmp_path
    assert settings.profile_source == "default"
    assert settings.profile_home_source == "env"
    assert settings.db_path == tmp_path / "vault.db"


def test_env_profile_uses_profiles_subdirectory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_PROFILE", "work")

    settings = get_settings()

    assert settings.profile_name == "work"
    assert settings.profile_source == "env"
    assert settings.runtime_home == tmp_path / "profiles" / "work"
    assert settings.db_path == tmp_path / "profiles" / "work" / "vault.db"
    assert settings.effective_policy_path == tmp_path / "profiles" / "work" / "policy.yaml"


def test_explicit_profile_beats_env_profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_PROFILE", "env-profile")

    settings = get_settings(profile="work")

    assert settings.profile_name == "work"
    assert settings.profile_source == "explicit"
    assert settings.runtime_home == tmp_path / "profiles" / "work"


def test_cli_context_profile_beats_env_profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_PROFILE", "env-profile")
    token = set_active_profile("cli-profile")
    try:
        settings = get_settings()
    finally:
        reset_active_profile(token)

    assert settings.profile_name == "cli-profile"
    assert settings.profile_source == "cli"
    assert settings.runtime_home == tmp_path / "profiles" / "cli-profile"


def test_default_profile_maps_to_base_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_PROFILE", "default")

    settings = get_settings()

    assert settings.profile_name == "default"
    assert settings.runtime_home == tmp_path


@pytest.mark.parametrize("name", ["", ".hidden", "profiles", "../work", "work/prod", "work..prod", "x" * 65])
def test_invalid_profile_names_are_rejected(name: str) -> None:
    with pytest.raises(ValueError):
        validate_profile_name(name)


def test_policy_env_overrides_selected_profile_policy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    policy_path = tmp_path / "shared-policy.yaml"
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))

    settings = get_settings(profile="work")

    assert settings.effective_policy_path == policy_path
    assert settings.policy_source == "env"


def test_list_profiles_returns_default_and_valid_children(tmp_path: Path) -> None:
    (tmp_path / "profiles" / "work").mkdir(parents=True)
    (tmp_path / "profiles" / "personal").mkdir(parents=True)
    (tmp_path / "profiles" / "default").mkdir(parents=True)
    (tmp_path / "profiles" / ".hidden").mkdir(parents=True)
    (tmp_path / "profiles" / "not-a-dir").write_text("skip", encoding="utf-8")

    names = [profile.name for profile in list_profiles(tmp_path)]

    assert names == ["default", "personal", "work"]


def test_resolve_profile_default_home_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HERMES_VAULT_HOME", raising=False)
    monkeypatch.delenv("HERMES_VAULT_PROFILE", raising=False)

    profile = resolve_profile()

    assert profile.name == "default"
    assert profile.profile_home == _platform.default_vault_home()
    assert profile.home_source == "default"
