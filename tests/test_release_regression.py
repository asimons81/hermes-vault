"""Regression tests for edge cases and release-readiness."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from hermes_vault.audit import AuditLogger
from hermes_vault.models import (
    AgentCapability,
    AgentPolicy,
    CredentialRecord,
    PolicyConfig,
    ServiceAction,
    ServicePolicyEntry,
)
from hermes_vault.policy import PolicyEngine
from hermes_vault.vault import Vault


# ── TTL enforcement edge cases ────────────────────────────────────────


def test_enforce_ttl_zero_rejected() -> None:
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "hermes": AgentPolicy(services=["openai"], max_ttl_seconds=900)
            }
        )
    )
    allowed, reason, ttl = policy.enforce_ttl("hermes", 0)
    assert allowed is False
    assert "greater than zero" in reason
    assert ttl == 0


def test_enforce_ttl_negative_rejected() -> None:
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "hermes": AgentPolicy(services=["openai"], max_ttl_seconds=900)
            }
        )
    )
    allowed, reason, ttl = policy.enforce_ttl("hermes", -1)
    assert allowed is False
    assert "greater than zero" in reason
    assert ttl == 0


def test_enforce_ttl_one_accepted() -> None:
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "hermes": AgentPolicy(services=["openai"], max_ttl_seconds=900)
            }
        )
    )
    allowed, _, ttl = policy.enforce_ttl("hermes", 1)
    assert allowed is True
    assert ttl == 1


# ── Backup round-trip through the full mutation path ──────────────────


def test_backup_round_trip_preserves_credentials(tmp_path: Path) -> None:
    """Export a backup from vault A, re-import into the same vault (replace mode)."""
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    vault.add_credential("openai", "sk-openai-key", "api_key", alias="primary")
    vault.add_credential("github", "ghp_pat_key", "personal_access_token", alias="work")
    vault.add_credential("google", "ya29.oauth", "oauth_access_token", alias="default")

    backup = vault.export_backup()

    assert backup["version"] == "hvbackup-v1"
    assert len(backup["credentials"]) == 3

    # Delete all, re-import from backup
    vault.delete("openai", alias="primary")
    vault.delete("github", alias="work")
    vault.delete("google", alias="default")
    assert len(vault.list_credentials()) == 0

    imported = vault.import_backup(backup)
    assert len(imported) == 3

    # Verify secrets survive the round-trip
    secret = vault.get_secret("openai")
    assert secret is not None
    assert secret.secret == "sk-openai-key"

    secret = vault.get_secret("github")
    assert secret is not None
    assert secret.secret == "ghp_pat_key"

    secret = vault.get_secret("google")
    assert secret is not None
    assert secret.secret == "ya29.oauth"


def test_backup_preserves_encrypted_payloads(tmp_path: Path) -> None:
    """Backup export/import preserves encrypted payload bytes (cross-vault with same key material)."""
    vault_a = Vault(tmp_path / "a.db", tmp_path / "a_salt.bin", "test-pass")
    vault_a.add_credential("openai", "sk-key", "api_key")

    backup = vault_a.export_backup()
    cred = backup["credentials"][0]
    original_payload = cred["encrypted_payload"]

    # Import into a fresh vault with same passphrase + same salt file
    # (encrypted payloads are keyed to salt+passphrase, so cross-vault requires same salt)
    import shutil
    shutil.copy(tmp_path / "a_salt.bin", tmp_path / "b_salt.bin")
    vault_b = Vault(tmp_path / "b.db", tmp_path / "b_salt.bin", "test-pass")
    imported = vault_b.import_backup(backup)

    assert len(imported) == 1
    # Payload is preserved exactly — vault_b can decrypt it with same key
    secret = vault_b.get_secret("openai")
    assert secret is not None
    assert secret.secret == "sk-key"


def test_backup_round_trip_preserves_aliases(tmp_path: Path) -> None:
    """Aliases and service names are preserved after backup/import."""
    vault_a = Vault(tmp_path / "a.db", tmp_path / "a_salt.bin", "test-pass")
    vault_a.add_credential("github", "ghp_work", "personal_access_token", alias="work")
    vault_a.add_credential("github", "ghp_personal", "personal_access_token", alias="personal")

    backup = vault_a.export_backup()
    vault_b = Vault(tmp_path / "b.db", tmp_path / "b_salt.bin", "test-pass")
    vault_b.import_backup(backup)

    records = vault_b.list_credentials()
    assert len(records) == 2
    aliases = {r.alias for r in records}
    assert aliases == {"work", "personal"}


def test_backup_rejects_wrong_version(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    with pytest.raises(ValueError, match="Unsupported backup version"):
        vault.import_backup({"version": "v0", "credentials": []})


# ── Audit entries for get_metadata ────────────────────────────────────


def test_operator_get_metadata_produces_audit_entry(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    vault.add_credential("openai", "sk-test", "api_key")
    policy = PolicyEngine(PolicyConfig())
    audit = AuditLogger(tmp_path / "vault.db")
    from hermes_vault.mutations import VaultMutations, OPERATOR_AGENT_ID
    mutations = VaultMutations(vault, policy, audit)

    mutations.get_metadata(agent_id=OPERATOR_AGENT_ID, service_or_id="openai")

    entries = audit.list_recent(limit=10)
    assert len(entries) == 1
    assert entries[0]["action"] == "get_metadata"
    assert entries[0]["decision"] == "allow"
    assert entries[0]["service"] == "openai"
    assert entries[0]["agent_id"] == OPERATOR_AGENT_ID


def test_denied_metadata_produces_audit_entry(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    vault.add_credential("openai", "sk-test", "api_key")
    policy = PolicyEngine(PolicyConfig())  # no agents defined
    audit = AuditLogger(tmp_path / "vault.db")
    from hermes_vault.mutations import VaultMutations
    mutations = VaultMutations(vault, policy, audit)

    result = mutations.get_metadata(agent_id="nobody", service_or_id="openai")
    assert result.allowed is False

    entries = audit.list_recent(limit=10)
    assert len(entries) == 1
    assert entries[0]["decision"] == "deny"
    assert entries[0]["action"] == "get_metadata"


# ── Service normalization in v2 policy YAML ───────────────────────────


def test_v2_policy_yaml_normalizes_aliases(tmp_path: Path) -> None:
    """Non-canonical service names in v2 format should normalize on load."""
    policy_yaml = {
        "agents": {
            "pam": {
                "services": {
                    "mini_max": {
                        "actions": ["get_env"],
                    },
                    "gh": {
                        "actions": ["verify"],
                    },
                },
                "max_ttl_seconds": 900,
            }
        }
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(policy_yaml))

    policy = PolicyEngine.from_yaml(path)
    agent = policy.get_agent_policy("pam")

    assert agent is not None
    assert "minimax" in agent.services
    assert "github" in agent.services
    assert "minimax" in agent.service_actions
    assert "github" in agent.service_actions


# ── Duplicate alias rejection ─────────────────────────────────────────


def test_add_duplicate_alias_different_service_allowed(tmp_path: Path) -> None:
    """Same alias on different services should be fine."""
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    vault.add_credential("openai", "sk-key", "api_key", alias="primary")
    vault.add_credential("github", "ghp-key", "personal_access_token", alias="primary")

    records = vault.list_credentials()
    assert len(records) == 2


def test_add_replace_existing_replaces_secret(tmp_path: Path) -> None:
    """replace_existing=True should overwrite the credential."""
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-pass")
    vault.add_credential("openai", "sk-old", "api_key")
    vault.add_credential("openai", "sk-new", "api_key", replace_existing=True)

    secret = vault.get_secret("openai")
    assert secret is not None
    assert secret.secret == "sk-new"

    # Only one record
    records = vault.list_credentials()
    assert len(records) == 1



