"""Tests for VaultMutations — centralized audited mutation paths."""

from __future__ import annotations

from pathlib import Path

from hermes_vault.audit import AuditLogger
from hermes_vault.models import (
    AgentCapability,
    AgentPolicy,
    PolicyConfig,
    ServiceAction,
    ServicePolicyEntry,
    ALL_SERVICE_ACTIONS,
)
from hermes_vault.mutations import VaultMutations, OPERATOR_AGENT_ID
from hermes_vault.policy import PolicyEngine
from hermes_vault.vault import Vault


def _make_policy_with_actions(agent_id: str, services: dict[str, list[ServiceAction]] | None = None,
                               capabilities: list[AgentCapability] | None = None) -> PolicyEngine:
    """Build a policy engine with explicit per-service action lists."""
    if services is None:
        services = {}
    sa = {}
    svc_list = []
    for svc, actions in services.items():
        sa[svc] = ServicePolicyEntry(actions=actions)
        svc_list.append(svc)
    return PolicyEngine(
        PolicyConfig(
            agents={
                agent_id: AgentPolicy(
                    services=svc_list,
                    service_actions=sa,
                    capabilities=capabilities or [],
                    raw_secret_access=False,
                    ephemeral_env_only=True,
                    max_ttl_seconds=900,
                )
            }
        )
    )


def _make_legacy_policy(agent_id: str, services: list[str]) -> PolicyEngine:
    """Build a legacy policy (flat service list, no explicit action restrictions)."""
    return PolicyEngine(
        PolicyConfig(
            agents={
                agent_id: AgentPolicy(
                    services=services,
                    raw_secret_access=False,
                    ephemeral_env_only=True,
                    max_ttl_seconds=900,
                )
            }
        )
    )


# ── Operator path (bypasses policy, still audits) ───────────────────────


def test_operator_add_credential(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    policy = PolicyEngine(PolicyConfig())
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.add_credential(
        agent_id=OPERATOR_AGENT_ID,
        service="openai",
        secret="sk-test-123",
        credential_type="api_key",
        alias="default",
    )

    assert result.allowed is True
    assert result.record is not None
    assert result.record.service == "openai"
    assert result.action == "add_credential"

    # Verify it's in the vault
    records = vault.list_credentials()
    assert len(records) == 1
    assert records[0].service == "openai"


def test_operator_rotate_credential(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    vault.add_credential("openai", "sk-old", "api_key")
    policy = PolicyEngine(PolicyConfig())
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.rotate_credential(
        agent_id=OPERATOR_AGENT_ID,
        service_or_id="openai",
        new_secret="sk-new-456",
    )

    assert result.allowed is True
    assert result.record is not None
    assert result.record.service == "openai"
    assert result.action == "rotate_credential"


def test_operator_delete_credential(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    vault.add_credential("openai", "sk-old", "api_key")
    policy = PolicyEngine(PolicyConfig())
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.delete_credential(
        agent_id=OPERATOR_AGENT_ID,
        service_or_id="openai",
    )

    assert result.allowed is True
    assert result.metadata["credential_id"]
    assert result.action == "delete_credential"
    assert len(vault.list_credentials()) == 0


def test_operator_get_metadata(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    vault.add_credential("openai", "sk-test", "api_key")
    policy = PolicyEngine(PolicyConfig())
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.get_metadata(
        agent_id=OPERATOR_AGENT_ID,
        service_or_id="openai",
    )

    assert result.allowed is True
    assert result.record is not None
    assert result.record.service == "openai"
    assert result.record.encrypted_payload  # record still has encrypted payload


# ── Operator mutations produce audit entries ─────────────────────────────


def test_operator_add_audit_entry(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    policy = PolicyEngine(PolicyConfig())
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    mutations.add_credential(
        agent_id=OPERATOR_AGENT_ID,
        service="openai",
        secret="sk-test",
    )

    entries = audit.list_recent(limit=10)
    assert len(entries) == 1
    assert entries[0]["agent_id"] == OPERATOR_AGENT_ID
    assert entries[0]["action"] == "add_credential"
    assert entries[0]["decision"] == "allow"
    assert entries[0]["service"] == "openai"


def test_operator_delete_audit_entry(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    vault.add_credential("openai", "sk-test", "api_key")
    policy = PolicyEngine(PolicyConfig())
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    mutations.delete_credential(
        agent_id=OPERATOR_AGENT_ID,
        service_or_id="openai",
    )

    entries = audit.list_recent(limit=10)
    assert len(entries) == 1
    assert entries[0]["action"] == "delete_credential"
    assert entries[0]["decision"] == "allow"


# ── Agent path: policy enforcement ──────────────────────────────────────


def test_agent_add_denied_without_capability(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    policy = _make_policy_with_actions(
        "agent1",
        services={"openai": [ServiceAction.add_credential]},
        capabilities=[AgentCapability.list_credentials],  # has capabilities but not add_credential
    )
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.add_credential(
        agent_id="agent1",
        service="openai",
        secret="sk-test",
    )

    assert result.allowed is False
    assert "not granted" in result.reason


def test_agent_add_denied_without_service_action(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    policy = _make_policy_with_actions(
        "agent1",
        services={"openai": [ServiceAction.get_env]},  # no add_credential action
        capabilities=[AgentCapability.add_credential],
    )
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.add_credential(
        agent_id="agent1",
        service="openai",
        secret="sk-test",
    )

    assert result.allowed is False
    assert "not permitted" in result.reason


def test_agent_add_allowed_with_capability_and_action(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    policy = _make_policy_with_actions(
        "agent1",
        services={"openai": [ServiceAction.add_credential]},
        capabilities=[AgentCapability.add_credential],
    )
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.add_credential(
        agent_id="agent1",
        service="openai",
        secret="sk-test",
    )

    assert result.allowed is True
    assert result.record is not None


def test_agent_add_denied_for_unknown_agent(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    policy = PolicyEngine(PolicyConfig())
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.add_credential(
        agent_id="nobody",
        service="openai",
        secret="sk-test",
    )

    assert result.allowed is False
    assert "not defined in policy" in result.reason


def test_agent_rotate_denied_without_action(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    vault.add_credential("openai", "sk-old", "api_key")
    policy = _make_policy_with_actions(
        "agent1",
        services={"openai": [ServiceAction.get_env]},  # no rotate
    )
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.rotate_credential(
        agent_id="agent1",
        service_or_id="openai",
        new_secret="sk-new",
    )

    assert result.allowed is False
    assert "not permitted" in result.reason


def test_agent_rotate_allowed_with_action(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    vault.add_credential("openai", "sk-old", "api_key")
    policy = _make_policy_with_actions(
        "agent1",
        services={"openai": [ServiceAction.rotate]},
    )
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.rotate_credential(
        agent_id="agent1",
        service_or_id="openai",
        new_secret="sk-new",
    )

    assert result.allowed is True
    assert result.record is not None


def test_agent_delete_denied_without_action(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    vault.add_credential("openai", "sk-old", "api_key")
    policy = _make_policy_with_actions(
        "agent1",
        services={"openai": [ServiceAction.get_env]},  # no delete
    )
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.delete_credential(
        agent_id="agent1",
        service_or_id="openai",
    )

    assert result.allowed is False
    assert "not permitted" in result.reason


def test_agent_delete_allowed_with_action(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    vault.add_credential("openai", "sk-old", "api_key")
    policy = _make_policy_with_actions(
        "agent1",
        services={"openai": [ServiceAction.delete]},
    )
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.delete_credential(
        agent_id="agent1",
        service_or_id="openai",
    )

    assert result.allowed is True
    assert result.metadata["credential_id"]


def test_agent_metadata_denied_without_action(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    vault.add_credential("openai", "sk-test", "api_key")
    policy = _make_policy_with_actions(
        "agent1",
        services={"openai": [ServiceAction.get_env]},  # no metadata
    )
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.get_metadata(
        agent_id="agent1",
        service_or_id="openai",
    )

    assert result.allowed is False
    assert "not permitted" in result.reason


def test_agent_metadata_allowed_with_action(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    vault.add_credential("openai", "sk-test", "api_key")
    policy = _make_policy_with_actions(
        "agent1",
        services={"openai": [ServiceAction.metadata]},
    )
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.get_metadata(
        agent_id="agent1",
        service_or_id="openai",
    )

    assert result.allowed is True
    assert result.record is not None


# ── Legacy policy compatibility ─────────────────────────────────────────


def test_agent_legacy_policy_allows_all_actions(tmp_path: Path) -> None:
    """Legacy agent (flat service list) should allow all mutation actions."""
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    # Legacy policy has no explicit action restrictions
    policy = _make_legacy_policy("agent1", services=["openai"])
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    # add (legacy agents have implicit all capabilities)
    result = mutations.add_credential(
        agent_id="agent1",
        service="openai",
        secret="sk-test",
    )
    assert result.allowed is True

    # rotate
    result = mutations.rotate_credential(
        agent_id="agent1",
        service_or_id="openai",
        new_secret="sk-new",
    )
    assert result.allowed is True

    # delete
    result = mutations.delete_credential(
        agent_id="agent1",
        service_or_id="openai",
    )
    assert result.allowed is True


# ── Denial audit entries ────────────────────────────────────────────────


def test_denied_mutation_produces_audit_entry(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    policy = PolicyEngine(PolicyConfig())  # no agents defined
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.add_credential(
        agent_id="nobody",
        service="openai",
        secret="sk-test",
    )

    assert result.allowed is False
    entries = audit.list_recent(limit=10)
    assert len(entries) == 1
    assert entries[0]["decision"] == "deny"
    assert entries[0]["agent_id"] == "nobody"
    assert "not defined in policy" in entries[0]["reason"]


# ── Error handling ──────────────────────────────────────────────────────


def test_add_duplicate_returns_denied(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    vault.add_credential("openai", "sk-old", "api_key")
    policy = _make_legacy_policy("agent1", services=["openai"])
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.add_credential(
        agent_id="agent1",
        service="openai",
        secret="sk-new",
        alias="default",  # same as existing
    )

    assert result.allowed is False
    assert "already exists" in result.reason


def test_rotate_nonexistent_returns_denied(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    policy = _make_legacy_policy("agent1", services=["openai"])
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.rotate_credential(
        agent_id="agent1",
        service_or_id="nonexistent",
        new_secret="sk-new",
    )

    assert result.allowed is False
    assert "not found" in result.reason


def test_delete_nonexistent_returns_denied(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    policy = _make_legacy_policy("agent1", services=["openai"])
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.delete_credential(
        agent_id="agent1",
        service_or_id="nonexistent",
    )

    assert result.allowed is False
    assert "not found" in result.reason


# ── Service normalization ───────────────────────────────────────────────


def test_agent_add_normalizes_service_name(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    policy = _make_policy_with_actions(
        "agent1",
        services={"github": [ServiceAction.add_credential]},
        capabilities=[AgentCapability.add_credential],
    )
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    # Use legacy alias "GH" — should normalize to "github"
    result = mutations.add_credential(
        agent_id="agent1",
        service="GH",
        secret="ghp_xxx",
        credential_type="personal_access_token",
    )

    assert result.allowed is True
    assert result.record is not None
    assert result.record.service == "github"


# ── End-to-end: add → rotate → delete ──────────────────────────────────


def test_full_lifecycle_through_mutations(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    policy = _make_policy_with_actions(
        "agent1",
        services={"openai": ALL_SERVICE_ACTIONS},
        capabilities=[AgentCapability.add_credential],
    )
    audit = AuditLogger(tmp_path / "vault.db")
    mutations = VaultMutations(vault, policy, audit)

    # Add
    result = mutations.add_credential(
        agent_id="agent1",
        service="openai",
        secret="sk-v1",
    )
    assert result.allowed is True
    cred_id = result.record.id

    # Rotate
    result = mutations.rotate_credential(
        agent_id="agent1",
        service_or_id=cred_id,
        new_secret="sk-v2",
    )
    assert result.allowed is True

    # Metadata
    result = mutations.get_metadata(
        agent_id="agent1",
        service_or_id=cred_id,
    )
    assert result.allowed is True

    # Delete
    result = mutations.delete_credential(
        agent_id="agent1",
        service_or_id=cred_id,
    )
    assert result.allowed is True
    assert len(vault.list_credentials()) == 0

    # All 4 operations should have audit entries
    entries = audit.list_recent(limit=10)
    assert len(entries) == 4
    actions = [e["action"] for e in entries]
    # Entries are newest-first
    assert "delete_credential" in actions
    assert "get_metadata" in actions
    assert "rotate_credential" in actions
    assert "add_credential" in actions
    assert all(e["decision"] == "allow" for e in entries)
