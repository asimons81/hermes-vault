from __future__ import annotations

from pathlib import Path

import yaml

from hermes_vault.models import (
    AgentPolicy,
    PolicyConfig,
    ServiceAction,
    ServicePolicyEntry,
)
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


def test_policy_normalizes_service_names() -> None:
    """Legacy service names like 'gmail' should normalize to 'google' in policy."""
    config = PolicyConfig(
        agents={
            "pam": AgentPolicy(
                services=["gmail", "google_docs"],
                max_ttl_seconds=900,
            )
        }
    )
    policy = PolicyEngine(config)
    agent = policy.get_agent_policy("pam")
    assert agent is not None
    assert "google" in agent.services
    assert "gmail" not in agent.services


def test_policy_can_access_service_normalizes_input() -> None:
    config = PolicyConfig(
        agents={
            "hermes": AgentPolicy(services=["openai"], max_ttl_seconds=900)
        }
    )
    policy = PolicyEngine(config)
    allowed, _ = policy.can_access_service("hermes", "Open_AI")
    assert allowed is True


# ── policy v2: can() action-aware checks ──────────────────


def test_can_allows_permitted_action_v2() -> None:
    config = PolicyConfig(
        agents={
            "dwight": AgentPolicy(
                services=["openai"],
                max_ttl_seconds=900,
            )
        }
    )
    # Manually set v2 service_actions
    agent = config.agents["dwight"]
    config = config.model_copy(
        update={
            "agents": {
                "dwight": agent.model_copy(
                    update={
                        "service_actions": {
                            "openai": ServicePolicyEntry(
                                actions=[ServiceAction.get_env, ServiceAction.verify],
                            )
                        }
                    }
                )
            }
        }
    )
    policy = PolicyEngine(config)

    allowed, reason = policy.can("dwight", "openai", "get_env")
    assert allowed is True
    assert "allowed" in reason


def test_can_denies_unpermitted_action_v2() -> None:
    config = PolicyConfig(
        agents={
            "dwight": AgentPolicy(
                services=["openai"],
                max_ttl_seconds=900,
            )
        }
    )
    agent = config.agents["dwight"]
    config = config.model_copy(
        update={
            "agents": {
                "dwight": agent.model_copy(
                    update={
                        "service_actions": {
                            "openai": ServicePolicyEntry(
                                actions=[ServiceAction.get_env, ServiceAction.verify],
                            )
                        }
                    }
                )
            }
        }
    )
    policy = PolicyEngine(config)

    allowed, reason = policy.can("dwight", "openai", "get_credential")
    assert allowed is False
    assert "not permitted" in reason


def test_can_legacy_allows_any_action() -> None:
    """Legacy policy (flat list) should allow any action on permitted services."""
    config = PolicyConfig(
        agents={
            "hermes": AgentPolicy(services=["openai"], max_ttl_seconds=900)
        }
    )
    policy = PolicyEngine(config)

    for action in ["get_credential", "get_env", "verify", "metadata"]:
        allowed, _ = policy.can("hermes", "openai", action)
        assert allowed is True, f"legacy should allow action {action}"


def test_can_denies_unknown_agent() -> None:
    policy = PolicyEngine(PolicyConfig())
    allowed, reason = policy.can("nobody", "openai", "get_env")
    assert allowed is False
    assert "not defined" in reason


def test_can_denies_unknown_service() -> None:
    config = PolicyConfig(
        agents={
            "hermes": AgentPolicy(services=["openai"], max_ttl_seconds=900)
        }
    )
    policy = PolicyEngine(config)
    allowed, reason = policy.can("hermes", "stripe", "get_env")
    assert allowed is False
    assert "not allowed" in reason


# ── policy v2: per-service TTL ────────────────────────────


def test_enforce_ttl_per_service_override() -> None:
    config = PolicyConfig(
        agents={
            "hermes": AgentPolicy(services=["openai"], max_ttl_seconds=1800)
        }
    )
    agent = config.agents["hermes"]
    config = config.model_copy(
        update={
            "agents": {
                "hermes": agent.model_copy(
                    update={
                        "service_actions": {
                            "openai": ServicePolicyEntry(
                                actions=list(ServiceAction),
                                max_ttl_seconds=300,
                            )
                        }
                    }
                )
            }
        }
    )
    policy = PolicyEngine(config)

    allowed, _, ttl = policy.enforce_ttl("hermes", 900, service="openai")
    assert allowed is True
    assert ttl == 300  # per-service cap wins


def test_enforce_ttl_service_cap_cannot_exceed_agent_cap() -> None:
    """Service max_ttl higher than agent max_ttl is capped by agent-level limit."""
    config = PolicyConfig(
        agents={
            "hermes": AgentPolicy(services=["openai"], max_ttl_seconds=600)
        }
    )
    agent = config.agents["hermes"]
    config = config.model_copy(
        update={
            "agents": {
                "hermes": agent.model_copy(
                    update={
                        "service_actions": {
                            "openai": ServicePolicyEntry(
                                actions=list(ServiceAction),
                                max_ttl_seconds=9999,  # absurdly high
                            )
                        }
                    }
                )
            }
        }
    )
    policy = PolicyEngine(config)

    allowed, _, ttl = policy.enforce_ttl("hermes", 9999, service="openai")
    assert allowed is True
    assert ttl == 600  # agent cap is the hard ceiling


def test_enforce_ttl_no_service_override_uses_agent_default() -> None:
    """When service has no per-service TTL, agent max_ttl applies."""
    config = PolicyConfig(
        agents={
            "hermes": AgentPolicy(services=["openai"], max_ttl_seconds=600)
        }
    )
    agent = config.agents["hermes"]
    config = config.model_copy(
        update={
            "agents": {
                "hermes": agent.model_copy(
                    update={
                        "service_actions": {
                            "openai": ServicePolicyEntry(
                                actions=list(ServiceAction),
                                max_ttl_seconds=None,
                            )
                        }
                    }
                )
            }
        }
    )
    policy = PolicyEngine(config)

    allowed, _, ttl = policy.enforce_ttl("hermes", 900, service="openai")
    assert allowed is True
    assert ttl == 600  # falls back to agent-level


# ── policy v2: YAML loading ──────────────────────────────


def test_v2_policy_loads_from_yaml(tmp_path: Path) -> None:
    policy_yaml = {
        "agents": {
            "dwight": {
                "services": {
                    "openai": {
                        "actions": ["get_credential", "get_env", "verify", "metadata"],
                        "max_ttl_seconds": 900,
                    },
                    "github": {
                        "actions": ["get_env", "verify"],
                    },
                },
                "raw_secret_access": False,
                "ephemeral_env_only": True,
                "max_ttl_seconds": 1800,
            }
        }
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(policy_yaml))

    policy = PolicyEngine.from_yaml(path)
    agent = policy.get_agent_policy("dwight")

    assert agent is not None
    assert "openai" in agent.services
    assert "github" in agent.services
    assert "openai" in agent.service_actions
    assert ServiceAction.get_credential in agent.service_actions["openai"].actions
    assert agent.service_actions["openai"].max_ttl_seconds == 900
    assert ServiceAction.get_credential not in agent.service_actions["github"].actions
    assert agent.service_actions["github"].max_ttl_seconds is None


def test_v2_policy_yaml_action_checks(tmp_path: Path) -> None:
    policy_yaml = {
        "agents": {
            "pam": {
                "services": {
                    "google": {
                        "actions": ["get_env", "verify", "metadata"],
                        "max_ttl_seconds": 600,
                    },
                },
                "max_ttl_seconds": 900,
            }
        }
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(policy_yaml))

    policy = PolicyEngine.from_yaml(path)

    allowed, _ = policy.can("pam", "google", "get_env")
    assert allowed is True

    allowed, reason = policy.can("pam", "google", "get_credential")
    assert allowed is False
    assert "not permitted" in reason

    # per-service TTL
    _, _, ttl = policy.enforce_ttl("pam", 900, service="google")
    assert ttl == 600


def test_legacy_policy_yaml_still_loads(tmp_path: Path) -> None:
    """v1 flat-list format must load and behave exactly as before."""
    policy_yaml = {
        "agents": {
            "hermes": {
                "services": ["openai", "github"],
                "raw_secret_access": False,
                "ephemeral_env_only": True,
                "max_ttl_seconds": 1800,
            }
        }
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(policy_yaml))

    policy = PolicyEngine.from_yaml(path)
    agent = policy.get_agent_policy("hermes")

    assert agent is not None
    assert "openai" in agent.services
    assert "github" in agent.services
    # Legacy agents get all actions in service_actions
    assert "openai" in agent.service_actions
    assert len(agent.service_actions["openai"].actions) == len(ServiceAction)
    # can() allows any action
    allowed, _ = policy.can("hermes", "openai", "get_credential")
    assert allowed is True
    allowed, _ = policy.can("hermes", "openai", "verify")
    assert allowed is True
    # can_access_service still works
    allowed, _ = policy.can_access_service("hermes", "openai")
    assert allowed is True


# ── migration helper ──────────────────────────────────────


def test_suggest_v2_migration_for_legacy_agent() -> None:
    config = PolicyConfig(
        agents={
            "hermes": AgentPolicy(services=["openai", "github"], max_ttl_seconds=1800)
        }
    )
    policy = PolicyEngine(config)
    suggestion = policy.suggest_v2_migration("hermes")

    assert suggestion is not None
    assert "openai" in suggestion
    assert "get_credential" in suggestion["openai"]["actions"]
    assert "get_env" in suggestion["openai"]["actions"]


def test_suggest_v2_migration_returns_none_for_v2_agent() -> None:
    config = PolicyConfig(
        agents={
            "dwight": AgentPolicy(services=["openai"], max_ttl_seconds=900)
        }
    )
    agent = config.agents["dwight"]
    config = config.model_copy(
        update={
            "agents": {
                "dwight": agent.model_copy(
                    update={
                        "service_actions": {
                            "openai": ServicePolicyEntry(
                                actions=[ServiceAction.get_env],  # restricted
                            )
                        }
                    }
                )
            }
        }
    )
    policy = PolicyEngine(config)
    assert policy.suggest_v2_migration("dwight") is None


def test_suggest_v2_migration_returns_none_for_unknown_agent() -> None:
    policy = PolicyEngine(PolicyConfig())
    assert policy.suggest_v2_migration("nobody") is None


# ── normalization ─────────────────────────────────────────


def test_v2_policy_normalizes_service_names() -> None:
    """v2 entries with non-canonical service names should normalise."""
    policy_yaml = {
        "agents": {
            "pam": {
                "services": {
                    "gmail": {
                        "actions": ["get_env"],
                    }
                },
                "max_ttl_seconds": 900,
            }
        }
    }
    path = Path("/tmp/_test_v2_norm.yaml")
    path.write_text(yaml.safe_dump(policy_yaml))

    policy = PolicyEngine.from_yaml(path)
    agent = policy.get_agent_policy("pam")
    assert agent is not None
    assert "google" in agent.services
    assert "gmail" not in agent.services
    assert "google" in agent.service_actions
