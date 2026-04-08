from __future__ import annotations

from pathlib import Path

from hermes_vault.models import AgentPolicy, PolicyConfig
from hermes_vault.policy import PolicyEngine
from hermes_vault.skillgen import SkillGenerator


def test_skill_generator_outputs_contract(tmp_path: Path) -> None:
    policy = PolicyEngine(
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
    generator = SkillGenerator(policy=policy, output_dir=tmp_path)
    target = generator.generate_for_agent("hermes")
    content = target.read_text(encoding="utf-8")

    assert "Never assume a service needs re-auth" in content
    assert "openai, github" in content
    assert "Max TTL is 1800 seconds" in content

