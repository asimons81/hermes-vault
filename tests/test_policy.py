from __future__ import annotations

from pathlib import Path

from hermes_vault.models import AgentPolicy, PolicyConfig
from hermes_vault.policy import PolicyEngine


def test_policy_denies_unknown_agent() -> None:
    policy = PolicyEngine(PolicyConfig())
    allowed, reason = policy.can_access_service("pam", "google")
    assert allowed is False
    assert "not defined" in reason


def test_policy_caps_ttl() -> None:
    policy = PolicyEngine(
        PolicyConfig(agents={"hermes": AgentPolicy(services=["openai"], max_ttl_seconds=120)}))
    allowed, _, ttl = policy.enforce_ttl("hermes", 900)
    assert allowed is True
    assert ttl == 120


def test_policy_marks_plaintext_under_managed_path_as_violation() -> None:
    policy = PolicyEngine(PolicyConfig())
    severity, recommendation = policy.classify_plaintext_storage(Path.home() / ".hermes" / ".env")
    assert severity.value == "critical"
    assert "policy violation" in recommendation
