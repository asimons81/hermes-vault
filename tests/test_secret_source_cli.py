from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from hermes_vault.cli import _hermes_group
from hermes_vault.crypto import profile_passphrase_env_name
from hermes_vault.vault import Vault


def _write_policy(path: Path, agent: str = "test-agent", service: str = "openai", *, get_env: bool = True) -> None:
    actions = "[get_env]" if get_env else "[metadata]"
    path.write_text(
        f"""
agents:
  {agent}:
    services:
      {service}:
        actions: {actions}
    max_ttl_seconds: 3600
    raw_secret_access: false
    ephemeral_env_only: true
""".lstrip(),
        encoding="utf-8",
    )


def _prepare_vault(monkeypatch, tmp_path: Path, *, secret: str = "sk-test-secret", service: str = "openai") -> Path:
    policy_path = tmp_path / "policy.yaml"
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
    Vault(tmp_path / "vault.db", tmp_path / "master_key_salt.bin", "test-passphrase").add_credential(
        service,
        secret,
        "api_key",
    )
    _write_policy(policy_path, service=service)
    return policy_path


def test_secret_source_fetch_returns_requested_env(monkeypatch, tmp_path: Path) -> None:
    _prepare_vault(monkeypatch, tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        _hermes_group,
        ["--no-banner", "secret-source", "fetch", "--agent", "test-agent", "--", "OPENAI_API_KEY=hv://openai"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["secrets"] == {"OPENAI_API_KEY": "sk-test-secret"}
    assert payload["errors"] == {}


def test_secret_source_fetch_missing_requested_env_is_ref_invalid(monkeypatch, tmp_path: Path) -> None:
    _prepare_vault(monkeypatch, tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        _hermes_group,
        ["--no-banner", "secret-source", "fetch", "--agent", "test-agent", "--", "NOT_OPENAI=hv://openai"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["ok"] is False
    assert payload["errors"]["NOT_OPENAI"]["kind"] == "REF_INVALID"


def test_secret_source_fetch_empty_value_is_omitted(monkeypatch, tmp_path: Path) -> None:
    _prepare_vault(monkeypatch, tmp_path, secret="")
    runner = CliRunner()

    result = runner.invoke(
        _hermes_group,
        ["--no-banner", "secret-source", "fetch", "--agent", "test-agent", "--", "OPENAI_API_KEY=hv://openai"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["secrets"] == {}
    assert payload["errors"]["OPENAI_API_KEY"]["kind"] == "EMPTY_VALUE"


def test_secret_source_fetch_policy_denial_is_auth_failed(monkeypatch, tmp_path: Path) -> None:
    policy_path = _prepare_vault(monkeypatch, tmp_path)
    _write_policy(policy_path, get_env=False)
    runner = CliRunner()

    result = runner.invoke(
        _hermes_group,
        ["--no-banner", "secret-source", "fetch", "--agent", "test-agent", "--", "OPENAI_API_KEY=hv://openai"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["errors"]["OPENAI_API_KEY"]["kind"] == "AUTH_FAILED"
    assert "sk-test-secret" not in result.output


def test_secret_source_fetch_malformed_ref_is_ref_invalid(monkeypatch, tmp_path: Path) -> None:
    _prepare_vault(monkeypatch, tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        _hermes_group,
        ["--no-banner", "secret-source", "fetch", "--agent", "test-agent", "--", "OPENAI_API_KEY=bad://openai"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["errors"]["OPENAI_API_KEY=bad://openai"]["kind"] == "REF_INVALID"


def test_secret_source_fetch_missing_passphrase_is_not_configured(monkeypatch, tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))
    monkeypatch.delenv("HERMES_VAULT_PASSPHRASE", raising=False)
    _write_policy(policy_path)
    runner = CliRunner()

    result = runner.invoke(
        _hermes_group,
        ["--no-banner", "secret-source", "fetch", "--agent", "test-agent", "--", "OPENAI_API_KEY=hv://openai"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["errors"]["__runtime__"]["kind"] == "NOT_CONFIGURED"


def test_profile_passphrase_env_name_matches_secret_source_runtime(monkeypatch, tmp_path: Path) -> None:
    profile = "work-profile"
    profile_env = profile_passphrase_env_name(profile)
    profile_home = tmp_path / "profiles" / profile
    profile_home.mkdir(parents=True)
    policy_path = profile_home / "policy.yaml"
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_PROFILE", profile)
    monkeypatch.setenv(profile_env, "profile-passphrase")
    monkeypatch.delenv("HERMES_VAULT_PASSPHRASE", raising=False)
    Vault(profile_home / "vault.db", profile_home / "master_key_salt.bin", "profile-passphrase").add_credential(
        "openai",
        "sk-profile-secret",
        "api_key",
    )
    _write_policy(policy_path)
    runner = CliRunner()

    result = runner.invoke(
        _hermes_group,
        ["--no-banner", "secret-source", "fetch", "--agent", "test-agent", "--", "OPENAI_API_KEY=hv://openai"],
    )

    assert result.exit_code == 0, result.output
    assert profile_env == "HERMES_VAULT_PASSPHRASE_WORK_PROFILE"
    payload = json.loads(result.output)
    assert payload["secrets"]["OPENAI_API_KEY"] == "sk-profile-secret"
