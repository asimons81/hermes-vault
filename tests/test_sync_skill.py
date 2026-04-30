from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from hermes_vault.cli import _hermes_group
from hermes_vault.models import AgentPolicy, PolicyConfig
from hermes_vault.policy import PolicyEngine
from hermes_vault.skillgen import SkillGenerator


@pytest.fixture
def cli_runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def policy_hermes() -> PolicyEngine:
    return PolicyEngine(
        PolicyConfig(
            agents={
                "hermes": AgentPolicy(
                    services=["openai", "github"],
                    raw_secret_access=False,
                    ephemeral_env_only=True,
                    max_ttl_seconds=1800,
                )
            }
        )
    )


def test_policy_hash_deterministic(policy_hermes: PolicyEngine) -> None:
    h1 = policy_hermes.compute_policy_hash()
    h2 = policy_hermes.compute_policy_hash()
    assert h1 == h2
    assert len(h1) == 64


def test_policy_hash_changes_on_different_config() -> None:
    p1 = PolicyEngine(
        PolicyConfig(
            agents={
                "hermes": AgentPolicy(
                    services=["openai"],
                    max_ttl_seconds=900,
                )
            }
        )
    )
    p2 = PolicyEngine(
        PolicyConfig(
            agents={
                "hermes": AgentPolicy(
                    services=["openai", "github"],
                    max_ttl_seconds=900,
                )
            }
        )
    )
    assert p1.compute_policy_hash() != p2.compute_policy_hash()


def test_generated_skill_contains_hash(policy_hermes: PolicyEngine, tmp_path: Path) -> None:
    gen = SkillGenerator(policy=policy_hermes, output_dir=tmp_path)
    path = gen.generate_for_agent("hermes")
    content = path.read_text(encoding="utf-8")
    assert "hv-policy-hash:" in content
    expected_hash = policy_hermes.compute_policy_hash()
    assert expected_hash in content


def test_sync_check_current(policy_hermes: PolicyEngine, tmp_path: Path) -> None:
    gen = SkillGenerator(policy=policy_hermes, output_dir=tmp_path)
    gen.generate_for_agent("hermes")
    result = gen.sync_skill("hermes", check=True)
    assert result["current"] is True
    assert result["policy_hash"] == result["skill_hash"]


def test_sync_check_stale_missing(policy_hermes: PolicyEngine, tmp_path: Path) -> None:
    gen = SkillGenerator(policy=policy_hermes, output_dir=tmp_path)
    result = gen.sync_skill("hermes", check=True)
    assert result["current"] is False
    assert result["skill_hash"] is None


def test_sync_check_stale_changed_policy(policy_hermes: PolicyEngine, tmp_path: Path) -> None:
    gen = SkillGenerator(policy=policy_hermes, output_dir=tmp_path)
    gen.generate_for_agent("hermes")

    modified = PolicyEngine(
        PolicyConfig(
            agents={
                "hermes": AgentPolicy(
                    services=["openai"],  # removed github
                    raw_secret_access=False,
                    ephemeral_env_only=True,
                    max_ttl_seconds=1800,
                )
            }
        )
    )
    gen2 = SkillGenerator(policy=modified, output_dir=tmp_path)
    result = gen2.sync_skill("hermes", check=True)
    assert result["current"] is False


def test_sync_write_regenerates(policy_hermes: PolicyEngine, tmp_path: Path) -> None:
    gen = SkillGenerator(policy=policy_hermes, output_dir=tmp_path)
    gen.generate_for_agent("hermes")

    modified = PolicyEngine(
        PolicyConfig(
            agents={
                "hermes": AgentPolicy(
                    services=["openai"],
                    raw_secret_access=False,
                    ephemeral_env_only=True,
                    max_ttl_seconds=900,
                )
            }
        )
    )
    gen2 = SkillGenerator(policy=modified, output_dir=tmp_path)
    result = gen2.sync_skill("hermes", write=True)
    assert result["current"] is True
    content = tmp_path / "hermes" / "SKILL.md"
    assert content.read_text(encoding="utf-8").count("openai, github") == 0
    assert "openai" in content.read_text(encoding="utf-8")


def test_sync_write_already_current(policy_hermes: PolicyEngine, tmp_path: Path) -> None:
    gen = SkillGenerator(policy=policy_hermes, output_dir=tmp_path)
    gen.generate_for_agent("hermes")
    result = gen.sync_skill("hermes", write=True)
    assert result["current"] is True


# ── CLI integration tests ───────────────────────────────────────────────

def _fake_build_services(policy: PolicyEngine):
    def _inner(prompt: bool = False):
        return object(), policy, object(), object()
    return _inner


def test_cli_sync_skill_check_current(
    cli_runner: CliRunner, policy_hermes: PolicyEngine, tmp_path: Path, monkeypatch
) -> None:
    skills_dir = tmp_path / "generated-skills"
    gen = SkillGenerator(policy=policy_hermes, output_dir=skills_dir)
    gen.generate_for_agent("hermes")
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(policy_hermes))
    result = cli_runner.invoke(_hermes_group, ["sync-skill", "--check"], catch_exceptions=False)
    assert result.exit_code == 0


def test_cli_sync_skill_check_stale(
    cli_runner: CliRunner, policy_hermes: PolicyEngine, tmp_path: Path, monkeypatch
) -> None:
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(policy_hermes))
    result = cli_runner.invoke(_hermes_group, ["sync-skill", "--check"], catch_exceptions=False)
    assert result.exit_code == 1
    assert "stale" in result.output.lower()


def test_cli_sync_skill_write(
    cli_runner: CliRunner, policy_hermes: PolicyEngine, tmp_path: Path, monkeypatch
) -> None:
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(policy_hermes))
    result = cli_runner.invoke(_hermes_group, ["sync-skill", "--write"], catch_exceptions=False)
    assert result.exit_code == 0
    skill_path = tmp_path / "generated-skills" / "hermes" / "SKILL.md"
    assert skill_path.exists()


def test_cli_sync_skill_print(
    cli_runner: CliRunner, policy_hermes: PolicyEngine, tmp_path: Path, monkeypatch
) -> None:
    skills_dir = tmp_path / "generated-skills"
    gen = SkillGenerator(policy=policy_hermes, output_dir=skills_dir)
    gen.generate_for_agent("hermes")
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(policy_hermes))
    result = cli_runner.invoke(_hermes_group, ["sync-skill", "--print"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "Never assume a service needs re-auth" in result.output


def test_cli_sync_skill_no_flag_exit_2(
    cli_runner: CliRunner, policy_hermes: PolicyEngine, tmp_path: Path, monkeypatch
) -> None:
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(policy_hermes))
    result = cli_runner.invoke(_hermes_group, ["sync-skill"], catch_exceptions=False)
    assert result.exit_code == 2


def test_cli_sync_skill_conflicting_flags(
    cli_runner: CliRunner, policy_hermes: PolicyEngine, tmp_path: Path, monkeypatch
) -> None:
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(policy_hermes))
    result = cli_runner.invoke(
        _hermes_group, ["sync-skill", "--check", "--write"], catch_exceptions=False
    )
    assert result.exit_code == 2


def test_skillgen_preserves_original_behavior(policy_hermes: PolicyEngine, tmp_path: Path) -> None:
    gen = SkillGenerator(policy=policy_hermes, output_dir=tmp_path)
    target = gen.generate_for_agent("hermes")
    content = target.read_text(encoding="utf-8")
    assert "Never assume a service needs re-auth" in content
    assert "openai, github" in content
    assert "Max TTL is 1800 seconds" in content
