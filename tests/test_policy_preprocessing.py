"""Tests for _preprocess_policy — v2 YAML parsing internals and mixed-format scenarios."""

from __future__ import annotations

from pathlib import Path

import yaml

from hermes_vault.models import (
    AgentCapability,
    AgentPolicy,
    PolicyConfig,
    ServiceAction,
    ServicePolicyEntry,
)
from hermes_vault.policy import (
    PolicyEngine,
    _normalize_agent_services,
    _preprocess_policy,
)


# ── _preprocess_policy: v2 dict services → service_actions ────────────


def test_preprocess_converts_v2_dict_to_service_actions() -> None:
    raw = {
        "agents": {
            "dwight": {
                "services": {
                    "openai": {
                        "actions": ["get_credential", "get_env"],
                        "max_ttl_seconds": 600,
                    },
                },
                "max_ttl_seconds": 900,
            }
        }
    }
    processed = _preprocess_policy(raw)
    agent = processed["agents"]["dwight"]
    assert "service_actions" in agent
    sa = agent["service_actions"]
    assert isinstance(sa["openai"], ServicePolicyEntry)
    assert ServiceAction.get_credential in sa["openai"].actions
    assert ServiceAction.get_env in sa["openai"].actions
    assert ServiceAction.verify not in sa["openai"].actions
    assert sa["openai"].max_ttl_seconds == 600
    assert agent["services"] == ["openai"]


def test_preprocess_converts_capabilities_strings_to_enums() -> None:
    raw = {
        "agents": {
            "pam": {
                "services": ["google"],
                "capabilities": ["list_credentials", "scan_secrets"],
            }
        }
    }
    processed = _preprocess_policy(raw)
    agent = processed["agents"]["pam"]
    assert agent["capabilities"] == [
        AgentCapability.list_credentials,
        AgentCapability.scan_secrets,
    ]


def test_preprocess_passes_legacy_list_unchanged() -> None:
    raw = {
        "agents": {
            "hermes": {
                "services": ["openai", "github"],
                "max_ttl_seconds": 1800,
            }
        }
    }
    processed = _preprocess_policy(raw)
    agent = processed["agents"]["hermes"]
    assert "service_actions" not in agent  # left for _normalize_agent_services
    assert agent["services"] == ["openai", "github"]


# ── _normalize_agent_services ────────────────────────────────────────


def test_normalize_agent_services_builds_from_legacy_list() -> None:
    agent = AgentPolicy(
        services=["openai", "github"],
        max_ttl_seconds=900,
    )
    normalized = _normalize_agent_services(agent)
    assert "openai" in normalized.service_actions
    assert "github" in normalized.service_actions
    assert len(normalized.service_actions["openai"].actions) == len(ServiceAction)


def test_normalize_agent_services_returns_v2_unchanged() -> None:
    sa = {
        "openai": ServicePolicyEntry(
            actions=[ServiceAction.get_env, ServiceAction.verify],
            max_ttl_seconds=300,
        )
    }
    agent = AgentPolicy(
        services=["openai"],
        service_actions=sa,
        max_ttl_seconds=900,
    )
    normalized = _normalize_agent_services(agent)
    # Should already be v2 — service_actions entries unchanged
    assert normalized.service_actions["openai"].actions == sa["openai"].actions
    assert normalized.service_actions["openai"].max_ttl_seconds == 300


def test_normalize_agent_services_empty_services() -> None:
    agent = AgentPolicy(services=[], max_ttl_seconds=900)
    normalized = _normalize_agent_services(agent)
    assert normalized.service_actions == {}


# ── Mixed v1/v2 YAML in the same file ────────────────────────────────


def test_mixed_v1_v2_policy_loads(tmp_path: Path) -> None:
    """A single policy file can have v1 and v2 agents side by side."""
    policy_yaml = {
        "agents": {
            "hermes": {
                "services": ["openai", "github"],
                "raw_secret_access": False,
                "ephemeral_env_only": True,
                "max_ttl_seconds": 1800,
            },
            "dwight": {
                "services": {
                    "openai": {
                        "actions": ["get_credential", "get_env", "verify"],
                        "max_ttl_seconds": 900,
                    },
                    "github": {
                        "actions": ["get_env", "verify"],
                    },
                },
                "raw_secret_access": False,
                "ephemeral_env_only": True,
                "max_ttl_seconds": 1800,
            },
        }
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(policy_yaml))

    policy = PolicyEngine.from_yaml(path)

    # v1 agent: all actions allowed
    allowed, _ = policy.can("hermes", "openai", "get_credential")
    assert allowed is True
    allowed, _ = policy.can("hermes", "github", "delete")
    assert allowed is True

    # v2 agent: restricted actions
    allowed, _ = policy.can("dwight", "openai", "get_credential")
    assert allowed is True
    allowed, reason = policy.can("dwight", "openai", "delete")
    assert allowed is False
    assert "not permitted" in reason

    allowed, _ = policy.can("dwight", "github", "get_env")
    assert allowed is True
    allowed, _ = policy.can("dwight", "github", "get_credential")
    assert allowed is False


def test_mixed_v1_v2_policy_with_capabilities(tmp_path: Path) -> None:
    """v1 agent with implicit capabilities, v2 agent with explicit capabilities."""
    policy_yaml = {
        "agents": {
            "hermes": {
                "services": ["openai"],
                "max_ttl_seconds": 1800,
            },
            "pam": {
                "services": {
                    "google": {
                        "actions": ["get_env", "verify"],
                    },
                },
                "capabilities": ["list_credentials"],
                "max_ttl_seconds": 900,
            },
        }
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(policy_yaml))
    policy = PolicyEngine.from_yaml(path)

    # v1 agent: all capabilities
    allowed, _ = policy.can_capability("hermes", "list_credentials")
    assert allowed is True
    allowed, _ = policy.can_capability("hermes", "export_backup")
    assert allowed is True

    # v2 agent: restricted capabilities
    allowed, _ = policy.can_capability("pam", "list_credentials")
    assert allowed is True
    allowed, reason = policy.can_capability("pam", "export_backup")
    assert allowed is False
    assert "not granted" in reason
