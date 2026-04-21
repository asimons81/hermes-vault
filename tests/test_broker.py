from __future__ import annotations

from pathlib import Path

from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.models import AgentCapability, AgentPolicy, PolicyConfig, VerificationCategory, VerificationResult
from hermes_vault.policy import PolicyEngine
from hermes_vault.vault import Vault


class StubVerifier:
    def verify(self, service: str, secret: str) -> VerificationResult:
        return VerificationResult(
            service=service,
            category=VerificationCategory.valid,
            success=True,
            reason="ok",
        )


def test_broker_enforces_policy_and_returns_env(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-secret-1234567890", "api_key")
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "dwight": AgentPolicy(
                    services=["openai"],
                    raw_secret_access=False,
                    ephemeral_env_only=True,
                    max_ttl_seconds=600,
                )
            }
        )
    )
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))
    decision = broker.get_ephemeral_env("openai", "dwight", ttl=900)

    assert decision.allowed is True
    assert decision.ttl_seconds == 600
    assert decision.env["OPENAI_API_KEY"] == "sk-secret-1234567890"


def test_broker_denies_raw_secret_when_env_only(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-secret-1234567890", "api_key")
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "dwight": AgentPolicy(
                    services=["openai"],
                    raw_secret_access=False,
                    ephemeral_env_only=True,
                )
            }
        )
    )
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))
    decision = broker.get_credential("openai", "test", "dwight")

    assert decision.allowed is False
    assert "ephemeral environment" in decision.reason


def test_broker_does_not_expose_raw_secret_in_metadata_when_allowed(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-sec...7890", "api_key")
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "hermes": AgentPolicy(
                    services=["openai"],
                    raw_secret_access=True,
                    ephemeral_env_only=False,
                )
            }
        )
    )
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))
    decision = broker.get_credential("openai", "test", "hermes")

    assert decision.allowed is True
    assert "secret" not in decision.metadata
    assert decision.metadata["credential_id"]


def test_broker_normalizes_service_on_env_request(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("github", "ghp_xxx", "personal_access_token")
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "hermes": AgentPolicy(
                    services=["github"],
                    raw_secret_access=False,
                    ephemeral_env_only=True,
                    max_ttl_seconds=900,
                )
            }
        )
    )
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))
    # Use legacy alias "GH" — should normalize to "github"
    decision = broker.get_ephemeral_env("GH", "hermes", ttl=900)
    assert decision.allowed is True
    assert "GITHUB_TOKEN" in decision.env


# ── agent capability gating ───────────────────────────────


def test_broker_list_denied_without_capability(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-test", "api_key")
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "pam": AgentPolicy(
                    services=["openai"],
                    capabilities=[AgentCapability.scan_secrets],  # no list_credentials
                    max_ttl_seconds=900,
                )
            }
        )
    )
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))
    result = broker.list_available_credentials("pam")
    assert result == []


def test_broker_list_allowed_with_capability(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-test", "api_key")
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "pam": AgentPolicy(
                    services=["openai"],
                    capabilities=[AgentCapability.list_credentials],
                    max_ttl_seconds=900,
                )
            }
        )
    )
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))
    result = broker.list_available_credentials("pam")
    assert len(result) == 1
    assert result[0]["service"] == "openai"


def test_broker_list_allowed_with_legacy_agent(tmp_path: Path) -> None:
    """Legacy agent (no capabilities field) should still list credentials."""
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-test", "api_key")
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "hermes": AgentPolicy(
                    services=["openai"],
                    max_ttl_seconds=900,
                )
            }
        )
    )
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))
    result = broker.list_available_credentials("hermes")
    assert len(result) == 1


def test_broker_list_denied_for_unknown_agent(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    policy = PolicyEngine(PolicyConfig())
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))
    result = broker.list_available_credentials("nobody")
    assert result == []
