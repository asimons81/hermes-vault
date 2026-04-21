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


# ── scan_secrets capability gating ────────────────────────


class StubScanner:
    """Minimal scanner stub that returns pre-set findings."""

    def __init__(self, findings: list | None = None) -> None:
        self._findings = findings or []
        self.scan_called_with = None

    def scan(self, paths=None):
        self.scan_called_with = paths
        return self._findings


def test_broker_scan_denied_without_capability(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
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
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"), scanner=StubScanner())
    decision = broker.scan_secrets("pam")
    assert decision.allowed is False
    assert "not granted" in decision.reason


def test_broker_scan_allowed_with_capability(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "pam": AgentPolicy(
                    services=["openai"],
                    capabilities=[AgentCapability.scan_secrets],
                    max_ttl_seconds=900,
                )
            }
        )
    )
    stub_scanner = StubScanner(findings=[])
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"), scanner=stub_scanner)
    decision = broker.scan_secrets("pam")
    assert decision.allowed is True
    assert decision.metadata["finding_count"] == 0
    assert stub_scanner.scan_called_with is None


def test_broker_scan_allowed_legacy_agent(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
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
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"), scanner=StubScanner())
    decision = broker.scan_secrets("hermes")
    assert decision.allowed is True


def test_broker_scan_denied_no_scanner(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
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
    decision = broker.scan_secrets("hermes")
    assert decision.allowed is False
    assert "scanner not available" in decision.reason


# ── export_backup capability gating ──────────────────────


def test_broker_export_denied_without_capability(tmp_path: Path) -> None:
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
    decision = broker.export_backup("pam")
    assert decision.allowed is False
    assert "not granted" in decision.reason


def test_broker_export_allowed_with_capability(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-test", "api_key")
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "pam": AgentPolicy(
                    services=["openai"],
                    capabilities=[AgentCapability.export_backup],
                    max_ttl_seconds=900,
                )
            }
        )
    )
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))
    decision = broker.export_backup("pam")
    assert decision.allowed is True
    assert "backup" in decision.metadata
    assert len(decision.metadata["backup"]["credentials"]) == 1


def test_broker_export_allowed_legacy_agent(tmp_path: Path) -> None:
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
    decision = broker.export_backup("hermes")
    assert decision.allowed is True
    assert "backup" in decision.metadata


# ── import_credentials capability gating ──────────────────


def test_broker_import_denied_without_capability(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "pam": AgentPolicy(
                    services=["openai"],
                    capabilities=[AgentCapability.export_backup],
                    max_ttl_seconds=900,
                )
            }
        )
    )
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))
    fake_backup = {"version": "hvbackup-v1", "credentials": []}
    decision = broker.import_credentials("pam", fake_backup)
    assert decision.allowed is False
    assert "not granted" in decision.reason


def test_broker_import_allowed_with_capability(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    # Export a backup from a fresh vault to get valid backup data
    vault.add_credential("openai", "sk-test", "api_key")
    backup = vault.export_backup()

    # Fresh vault for import target
    vault2 = Vault(tmp_path / "vault2.db", tmp_path / "salt2.bin", "test-passphrase")
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "pam": AgentPolicy(
                    services=["openai"],
                    capabilities=[AgentCapability.import_credentials],
                    max_ttl_seconds=900,
                )
            }
        )
    )
    broker = Broker(vault2, policy, StubVerifier(), AuditLogger(tmp_path / "vault2.db"))
    decision = broker.import_credentials("pam", backup)
    assert decision.allowed is True
    assert decision.metadata["imported_count"] == 1


def test_broker_import_allowed_legacy_agent(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-test", "api_key")
    backup = vault.export_backup()

    vault2 = Vault(tmp_path / "vault2.db", tmp_path / "salt2.bin", "test-passphrase")
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
    broker = Broker(vault2, policy, StubVerifier(), AuditLogger(tmp_path / "vault2.db"))
    decision = broker.import_credentials("hermes", backup)
    assert decision.allowed is True
    assert decision.metadata["imported_count"] == 1
