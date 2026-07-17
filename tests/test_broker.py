from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch


from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.models import (
    AgentCapability,
    AgentPolicy,
    Decision,
    CredentialRecord,
    CredentialStatus,
    LeaseStatus,
    PolicyConfig,
    ServiceAction,
    ServicePolicyEntry,
    VerificationCategory,
    VerificationResult,
    utc_now,
)
from hermes_vault.oauth.oauth_refresh import RefreshEngine
from hermes_vault.oauth.providers import OAuthProviderRegistry
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


class UnsupportedVerifier:
    def verify(self, service: str, secret: str) -> VerificationResult:
        return VerificationResult(
            service=service,
            category=VerificationCategory.unknown,
            success=False,
            reason="No provider-specific verifier is configured for this service.",
        )


def test_verify_supported_provider_updates_last_verified(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-test", "api_key")
    broker = Broker(vault, PolicyEngine(PolicyConfig()), StubVerifier(), AuditLogger(tmp_path / "vault.db"))

    decision = broker.verify_credential("openai")

    record = vault.list_credentials()[0]
    assert decision.allowed is True
    assert record.status == CredentialStatus.active
    assert record.last_verified_at is not None


def test_verify_unsupported_provider_does_not_update_last_verified(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("internal-tool", "secret", "api_key")
    broker = Broker(vault, PolicyEngine(PolicyConfig()), UnsupportedVerifier(), AuditLogger(tmp_path / "vault.db"))

    decision = broker.verify_credential("internal-tool")

    record = vault.list_credentials()[0]
    assert decision.allowed is False
    assert "No provider-specific verifier" in decision.reason
    assert record.status == CredentialStatus.unknown
    assert record.last_verified_at is None


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


def test_broker_denies_env_when_get_env_action_missing(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-secret-1234567890", "api_key")
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "dwight": AgentPolicy(
                    services=["openai"],
                    service_actions={
                        "openai": ServicePolicyEntry(actions=[ServiceAction.metadata]),
                    },
                    raw_secret_access=False,
                    ephemeral_env_only=True,
                )
            }
        )
    )
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))

    decision = broker.get_ephemeral_env("openai", "dwight", ttl=900)

    assert decision.allowed is False
    assert "get_env" in decision.reason


def test_broker_denies_aliasless_env_when_service_is_ambiguous(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-primary", "api_key", alias="primary")
    vault.add_credential("openai", "sk-admin", "api_key", alias="admin")
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "dwight": AgentPolicy(
                    services=["openai"],
                    service_actions={
                        "openai": ServicePolicyEntry(actions=[ServiceAction.get_env]),
                    },
                    raw_secret_access=False,
                    ephemeral_env_only=True,
                )
            }
        )
    )
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))

    decision = broker.get_ephemeral_env("openai", "dwight", ttl=900)

    assert decision.allowed is False
    assert "specify credential ID or service+alias" in decision.reason


def test_broker_explicit_alias_env_still_succeeds_when_service_has_multiple_aliases(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-primary", "api_key", alias="primary")
    vault.add_credential("openai", "sk-admin", "api_key", alias="admin")
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "dwight": AgentPolicy(
                    services=["openai"],
                    service_actions={
                        "openai": ServicePolicyEntry(actions=[ServiceAction.get_env]),
                    },
                    raw_secret_access=False,
                    ephemeral_env_only=True,
                )
            }
        )
    )
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))

    decision = broker.get_ephemeral_env("openai", "dwight", ttl=900, alias="primary")

    assert decision.allowed is True
    assert decision.env["OPENAI_API_KEY"] == "sk-primary"


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


def _make_lease_broker(
    tmp_path: Path,
    *,
    actions: dict[str, list[ServiceAction]] | None = None,
    max_ttl_seconds: int = 900,
    require_lease_for_env: bool = False,
    require_lease_purpose: bool = False,
) -> tuple[Vault, Broker]:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-openai", "api_key", alias="primary", scopes=["models.read"])
    vault.add_credential("github", "ghp-token", "personal_access_token", alias="work", scopes=["repo"])
    actions = actions or {
        "openai": [
            ServiceAction.get_env,
            ServiceAction.issue_lease,
            ServiceAction.list_leases,
            ServiceAction.show_lease,
            ServiceAction.renew_lease,
            ServiceAction.revoke_lease,
        ],
        "github": [
            ServiceAction.get_env,
            ServiceAction.issue_lease,
            ServiceAction.list_leases,
            ServiceAction.show_lease,
            ServiceAction.renew_lease,
            ServiceAction.revoke_lease,
        ],
    }
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "lease-agent": AgentPolicy(
                    services=list(actions.keys()),
                    service_actions={
                        service: ServicePolicyEntry(actions=service_actions)
                        for service, service_actions in actions.items()
                    },
                    max_ttl_seconds=max_ttl_seconds,
                    raw_secret_access=False,
                    ephemeral_env_only=True,
                    require_lease_for_env=require_lease_for_env,
                    require_lease_purpose=require_lease_purpose,
                )
            }
        )
    )
    audit = AuditLogger(tmp_path / "vault.db")
    broker = Broker(vault, policy, StubVerifier(), audit)
    return vault, broker


class TestLeaseBroker:
    def test_issue_lease_happy_path_with_policy_allow(self, tmp_path: Path) -> None:
        vault, broker = _make_lease_broker(tmp_path)

        decision = broker.issue_lease("lease-agent", "openai", 600, alias="primary", purpose="deploy", reason="ticket-1")

        assert decision.allowed is True
        assert decision.service == "openai"
        assert decision.ttl_seconds == 600
        assert decision.metadata["lease"]["purpose"] == "deploy"
        assert vault.get_lease(decision.metadata["lease"]["id"]) is not None

    def test_issue_lease_denied_by_policy(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(
            tmp_path,
            actions={"openai": [ServiceAction.list_leases, ServiceAction.show_lease]},
        )

        decision = broker.issue_lease("lease-agent", "openai", 600, alias="primary")

        assert decision.allowed is False
        assert "issue_lease" in decision.reason

    def test_issue_lease_denied_by_zero_ttl(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(tmp_path)

        decision = broker.issue_lease("lease-agent", "openai", 0, alias="primary")

        assert decision.allowed is False
        assert "greater than zero" in decision.reason

    def test_issue_lease_caps_ttl_to_policy_max(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(tmp_path, max_ttl_seconds=300)

        decision = broker.issue_lease("lease-agent", "openai", 600, alias="primary")

        assert decision.allowed is True
        assert decision.ttl_seconds == 300

    def test_issue_lease_denied_for_unknown_service(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(tmp_path)

        decision = broker.issue_lease("lease-agent", "nonexistent", 60)

        assert decision.allowed is False
        assert "not found" in decision.reason.lower()

    def test_issue_lease_records_audit_trail(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(tmp_path)

        decision = broker.issue_lease("lease-agent", "openai", 60, alias="primary")
        entries = broker.audit.list_recent(limit=5, action="issue_lease")

        assert decision.allowed is True
        assert entries[0]["decision"] == Decision.allow.value
        assert entries[0]["metadata"]["lease_id"] == decision.metadata["lease"]["id"]
        assert entries[0]["ttl_seconds"] == 60

    def test_list_leases_filters_mixed_visibility(self, tmp_path: Path) -> None:
        vault, broker = _make_lease_broker(
            tmp_path,
            actions={
                "openai": [ServiceAction.issue_lease, ServiceAction.list_leases, ServiceAction.show_lease],
                "github": [ServiceAction.issue_lease],
            },
        )
        openai = vault.resolve_credential("openai", alias="primary")
        github = vault.resolve_credential("github", alias="work")
        visible = vault.issue_lease(openai.id, agent_id="lease-agent", ttl_seconds=60)
        hidden = vault.issue_lease(github.id, agent_id="lease-agent", ttl_seconds=60)

        decision = broker.list_leases("lease-agent")

        assert decision.allowed is True
        assert [lease["id"] for lease in decision.metadata["leases"]] == [visible.id]
        assert hidden.id not in {lease["id"] for lease in decision.metadata["leases"]}

    def test_list_leases_supports_status_filter(self, tmp_path: Path) -> None:
        vault, broker = _make_lease_broker(tmp_path)
        lease = broker.issue_lease("lease-agent", "openai", 60, alias="primary").metadata["lease"]
        vault.revoke_lease(lease["id"], reason="done")

        decision = broker.list_leases("lease-agent", status=LeaseStatus.revoked)

        assert decision.allowed is True
        assert [item["id"] for item in decision.metadata["leases"]] == [lease["id"]]

    def test_show_lease_found_and_allowed(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(tmp_path)
        issued = broker.issue_lease("lease-agent", "openai", 60, alias="primary").metadata["lease"]

        decision = broker.show_lease("lease-agent", issued["id"])

        assert decision.allowed is True
        assert decision.metadata["lease"]["id"] == issued["id"]

    def test_show_lease_not_found(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(tmp_path)

        decision = broker.show_lease("lease-agent", "missing-lease")

        assert decision.allowed is False
        assert "not found" in decision.reason

    def test_show_lease_denied_by_policy(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(
            tmp_path,
            actions={"openai": [ServiceAction.issue_lease, ServiceAction.list_leases]},
        )
        lease = broker.issue_lease("lease-agent", "openai", 60, alias="primary")

        decision = broker.show_lease("lease-agent", lease.metadata["lease"]["id"])

        assert decision.allowed is False
        assert "show_lease" in decision.reason

    def test_renew_lease_happy_path(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(tmp_path)
        issued = broker.issue_lease("lease-agent", "openai", 60, alias="primary")

        decision = broker.renew_lease("lease-agent", issued.metadata["lease"]["id"], 300)

        assert decision.allowed is True
        assert decision.ttl_seconds == 300
        assert decision.metadata["lease"]["renew_count"] == 1

    def test_renew_lease_denied_by_policy(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(
            tmp_path,
            actions={"openai": [ServiceAction.issue_lease, ServiceAction.show_lease]},
        )
        lease = broker.issue_lease("lease-agent", "openai", 60, alias="primary")

        decision = broker.renew_lease("lease-agent", lease.metadata["lease"]["id"], 120)

        assert decision.allowed is False
        assert "renew_lease" in decision.reason

    def test_renew_lease_denied_by_ttl(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(tmp_path)
        lease = broker.issue_lease("lease-agent", "openai", 60, alias="primary")

        decision = broker.renew_lease("lease-agent", lease.metadata["lease"]["id"], 0)

        assert decision.allowed is False
        assert "greater than zero" in decision.reason

    def test_renew_lease_on_revoked_returns_deny(self, tmp_path: Path) -> None:
        vault, broker = _make_lease_broker(tmp_path)
        lease = broker.issue_lease("lease-agent", "openai", 60, alias="primary")
        vault.revoke_lease(lease.metadata["lease"]["id"], reason="done")

        decision = broker.renew_lease("lease-agent", lease.metadata["lease"]["id"], 60)

        assert decision.allowed is False
        assert "revoked" in decision.reason

    def test_revoke_lease_happy_path(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(tmp_path)
        lease = broker.issue_lease("lease-agent", "openai", 60, alias="primary")

        decision = broker.revoke_lease("lease-agent", lease.metadata["lease"]["id"], reason="cleanup")

        assert decision.allowed is True
        assert decision.metadata["lease"]["status"] == LeaseStatus.revoked.value
        assert decision.metadata["lease"]["reason"] == "cleanup"

    def test_revoke_lease_denied_by_policy(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(
            tmp_path,
            actions={"openai": [ServiceAction.issue_lease, ServiceAction.show_lease, ServiceAction.renew_lease]},
        )
        lease = broker.issue_lease("lease-agent", "openai", 60, alias="primary")

        decision = broker.revoke_lease("lease-agent", lease.metadata["lease"]["id"])

        assert decision.allowed is False
        assert "revoke_lease" in decision.reason

    def test_revoke_lease_on_already_revoked_returns_deny(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(tmp_path)
        lease = broker.issue_lease("lease-agent", "openai", 60, alias="primary")
        broker.revoke_lease("lease-agent", lease.metadata["lease"]["id"], reason="cleanup")

        decision = broker.revoke_lease("lease-agent", lease.metadata["lease"]["id"])

        assert decision.allowed is False
        assert "already been revoked" in decision.reason

    def test_get_env_denied_when_policy_requires_lease_without_active_lease(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(tmp_path, require_lease_for_env=True)

        decision = broker.get_ephemeral_env("openai", "lease-agent", ttl=600, alias="primary")

        assert decision.allowed is False
        assert "requires an active lease" in decision.reason
        assert decision.metadata["lease_required"] is True
        assert "sk-openai" not in str(decision.model_dump(mode="json"))

    def test_get_env_allowed_with_active_lease_and_lease_metadata(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(tmp_path, require_lease_for_env=True)
        lease = broker.issue_lease("lease-agent", "openai", 60, alias="primary", purpose="deploy").metadata["lease"]

        decision = broker.get_ephemeral_env("openai", "lease-agent", ttl=600, alias="primary")

        assert decision.allowed is True
        assert decision.ttl_seconds <= 60
        assert decision.metadata["lease_id"] == lease["id"]
        assert decision.metadata["lease_required"] is True

    def test_issue_lease_requires_specific_purpose_when_policy_requires_it(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(tmp_path, require_lease_purpose=True)

        decision = broker.issue_lease("lease-agent", "openai", 60, alias="primary", purpose="task")

        assert decision.allowed is False
        assert "specific lease purpose" in decision.reason

    def test_lease_checkout_issues_lease_and_returns_env(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(tmp_path, require_lease_for_env=True)

        decision = broker.lease_checkout(
            agent_id="lease-agent",
            service="openai",
            ttl_seconds=60,
            alias="primary",
            purpose="deploy",
        )

        assert decision.allowed is True
        assert decision.env["OPENAI_API_KEY"] == "sk-openai"
        assert decision.metadata["lease_checkout"]["lease_issued"] is True

    def test_request_access_persists_metadata_without_env(self, tmp_path: Path) -> None:
        vault, broker = _make_lease_broker(tmp_path, require_lease_for_env=True)

        decision = broker.request_access(
            agent_id="lease-agent",
            service="openai",
            alias="primary",
            action="get_env",
            purpose="deploy",
            requested_ttl_seconds=60,
        )

        assert decision.allowed is True
        assert decision.env == {}
        request = decision.metadata["request"]
        assert request["status"] == "pending"
        assert request["metadata"]["policy_explain"]["requires_lease"] is True
        assert vault.get_access_request(request["id"]) is not None
        assert "sk-openai" not in str(decision.model_dump(mode="json"))

    def test_approve_access_request_can_issue_lease(self, tmp_path: Path) -> None:
        _, broker = _make_lease_broker(tmp_path, require_lease_for_env=True)
        request = broker.request_access(
            agent_id="lease-agent",
            service="openai",
            alias="primary",
            action="get_env",
            purpose="deploy",
            requested_ttl_seconds=60,
        ).metadata["request"]

        decision = broker.approve_access_request(
            request["id"],
            reason="approved for deploy",
            issue_lease=True,
            ttl_seconds=60,
        )

        assert decision.allowed is True
        assert decision.metadata["request"]["status"] == "approved"
        assert decision.metadata["request"]["lease_id"]


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


# ── OAuth freshness helpers (inlined for test independence) ─────────────


class MockTokenEndpoint:
    """A programmable mock token endpoint for refresh flows.

    Usage:
        endpoint = MockTokenEndpoint(success_tokens={...})
        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
            ...
    """

    def __init__(
        self,
        success_tokens: dict | None = None,
        error_response: dict | None = None,
        status_code: int = 200,
        fail_count: int = 0,
    ):
        self.calls: list[dict] = []
        self.success_tokens = success_tokens or {
            "access_token": "new_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new_refresh_token",
            "scope": "openid email",
        }
        self.error_response = error_response
        self.status_code = status_code
        self.fail_count = fail_count
        self._call_count = 0

    def handler(self, url, data=None, headers=None, timeout=None, **kwargs):
        self._call_count += 1
        if isinstance(data, dict):
            parsed = data
        elif data:
            parsed = dict(p.split("=", 1) for p in data.split("&"))
        else:
            parsed = {}
        self.calls.append({"url": str(url), "data": parsed})

        mock_resp = MagicMock()
        if self._call_count <= self.fail_count:
            from requests import RequestException

            raise RequestException(f"Simulated failure #{self._call_count}")

        if self.error_response:
            mock_resp.ok = False
            mock_resp.status_code = self.status_code
            mock_resp.json.return_value = self.error_response
            mock_resp.text = str(self.error_response)
            return mock_resp

        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = self.success_tokens
        mock_resp.text = str(self.success_tokens)
        return mock_resp


def _add_credential(
    vault: Vault,
    service: str,
    secret: str,
    credential_type: str,
    alias: str = "default",
    expiry: datetime | None = None,
) -> CredentialRecord:
    rec = vault.add_credential(
        service=service,
        secret=secret,
        credential_type=credential_type,
        alias=alias,
        replace_existing=True,
    )
    if expiry is not None:
        vault.set_expiry(rec.id, expiry)
    return rec


def _seed_tokens(
    vault: Vault,
    service: str,
    expiry: datetime | None = None,
    access_alias: str = "default",
    refresh_alias: str = "refresh",
    refresh_secret: str = "old_refresh",
) -> None:
    if expiry is None:
        expiry = utc_now() - timedelta(seconds=10)
    _add_credential(
        vault, service, "old_access", "oauth_access_token",
        alias=access_alias, expiry=expiry,
    )
    vault.add_credential(
        service=service,
        secret=refresh_secret,
        credential_type="oauth_refresh_token",
        alias=refresh_alias,
        replace_existing=True,
    )


def _make_registry(tmp_path: Path) -> OAuthProviderRegistry:
    path = tmp_path / "providers.yaml"
    path.write_text(
        "providers:\n"
        "  openai:\n    name: OpenAI\n"
        "    authorization_endpoint: https://example.com/auth\n"
        "    token_endpoint: https://example.com/token\n"
    )
    return OAuthProviderRegistry(path)


def _oauth_policy(actions: list[ServiceAction] | None = None) -> PolicyEngine:
    if actions is None:
        actions = [ServiceAction.get_env, ServiceAction.rotate]
    return PolicyEngine(
        PolicyConfig(
            agents={
                "dwight": AgentPolicy(
                    services=["openai"],
                    service_actions={
                        "openai": ServicePolicyEntry(actions=actions),
                    },
                    max_ttl_seconds=900,
                )
            }
        )
    )


# ── OAuth freshness tests ──────────────────────────────────────────────


def test_get_ephemeral_env_api_key_unchanged_for_oauth_refresh(tmp_path: Path) -> None:
    """API-key credentials must produce no oauth_refresh metadata."""
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-sec...7890", "api_key")
    policy = _oauth_policy()
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))

    decision = broker.get_ephemeral_env("openai", "dwight", ttl=900)

    assert decision.allowed is True
    assert decision.env["OPENAI_API_KEY"] == "sk-sec...7890"
    # No oauth_refresh metadata for non-OAuth credentials
    assert "oauth_refresh" not in decision.metadata


def test_get_ephemeral_env_oauth_current_token_no_refresh(tmp_path: Path) -> None:
    """A current (non-expired) OAuth token must be returned as-is."""
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    future = utc_now() + timedelta(seconds=3600)
    _seed_tokens(vault, "openai", expiry=future)
    policy = _oauth_policy()
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))

    decision = broker.get_ephemeral_env("openai", "dwight", ttl=900, alias="default")

    assert decision.allowed is True
    assert decision.env["OPENAI_API_KEY"] == "old_access"
    assert decision.metadata.get("oauth_refresh") == {"refreshed": False}


def test_get_ephemeral_env_oauth_expired_refreshes_success(tmp_path: Path) -> None:
    """An expired OAuth token must be refreshed before handoff."""
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    past = utc_now() - timedelta(seconds=10)
    _seed_tokens(vault, "openai", expiry=past)

    registry = _make_registry(tmp_path)
    refresh_engine = RefreshEngine(vault=vault, registry=registry)
    policy = _oauth_policy()
    broker = Broker(
        vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"),
        refresh_engine=refresh_engine,
    )

    endpoint = MockTokenEndpoint(success_tokens={
        "access_token": "fresh_access",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "fresh_refresh",
        "scope": "openid",
    })

    with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
        decision = broker.get_ephemeral_env("openai", "dwight", ttl=900, alias="default")

    assert decision.allowed is True
    assert decision.metadata["oauth_refresh"]["refreshed"] is True
    assert decision.env["OPENAI_API_KEY"] == "fresh_access"

    # Verify the vault was actually updated
    re_record = vault.resolve_credential("openai", alias="default")
    re_secret = vault.get_secret(re_record.id)
    assert re_secret is not None
    assert re_secret.secret == "fresh_access"


def test_get_ephemeral_env_oauth_expired_no_refresh_token_denies(tmp_path: Path) -> None:
    """Expired OAuth token without a refresh token must be denied with a sanitised reason."""
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    past = utc_now() - timedelta(seconds=10)
    _add_credential(
        vault, "openai", "old_access", "oauth_access_token",
        alias="default", expiry=past,
    )
    # Deliberately no refresh token

    registry = _make_registry(tmp_path)
    refresh_engine = RefreshEngine(vault=vault, registry=registry)
    policy = _oauth_policy()
    broker = Broker(
        vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"),
        refresh_engine=refresh_engine,
    )

    decision = broker.get_ephemeral_env("openai", "dwight", ttl=900)

    assert decision.allowed is False
    assert "refresh token" in decision.reason.lower() or "Refresh token" in decision.reason
    # Verify it is NOT an OAuthProviderError — should be a clean string
    assert "OAuthProviderError" not in repr(decision.reason)
    # No raw token leaked
    assert "old_access" not in decision.reason


def test_get_ephemeral_env_oauth_refresh_fails_token_still_valid_returns_with_warning(tmp_path: Path) -> None:
    """Near-expiry token with failed refresh should still be returned (still valid)."""
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    near_expiry = utc_now() + timedelta(seconds=120)  # < OAUTH_REFRESH_MARGIN_SECONDS (300)
    _seed_tokens(vault, "openai", expiry=near_expiry)

    registry = _make_registry(tmp_path)
    refresh_engine = RefreshEngine(vault=vault, registry=registry)
    policy = _oauth_policy()
    broker = Broker(
        vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"),
        refresh_engine=refresh_engine,
    )

    endpoint = MockTokenEndpoint(
        error_response={"error": "invalid_grant", "error_description": "Token revoked"},
        status_code=400,
    )

    with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
        decision = broker.get_ephemeral_env("openai", "dwight", ttl=900, alias="default")

    assert decision.allowed is True
    assert decision.metadata["oauth_refresh"]["refreshed"] is False
    assert "error" in decision.metadata["oauth_refresh"]
    # Still returns the original token
    assert decision.env["OPENAI_API_KEY"] == "old_access"


def test_get_ephemeral_env_oauth_expired_refresh_fails_denies(tmp_path: Path) -> None:
    """Expired token whose refresh fails must be denied with sanitised message."""
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    past = utc_now() - timedelta(seconds=10)
    _seed_tokens(vault, "openai", expiry=past)

    registry = _make_registry(tmp_path)
    refresh_engine = RefreshEngine(vault=vault, registry=registry)
    policy = _oauth_policy()
    broker = Broker(
        vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"),
        refresh_engine=refresh_engine,
    )

    endpoint = MockTokenEndpoint(
        error_response={"error": "invalid_grant", "error_description": "Token revoked"},
        status_code=400,
    )

    with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
        decision = broker.get_ephemeral_env("openai", "dwight", ttl=900)

    assert decision.allowed is False
    assert decision.reason  # should have a sanitised reason
    # No raw token leaked
    assert "old_access" not in decision.reason
    assert "raw_response" not in str(decision.metadata)


def test_get_ephemeral_env_oauth_refresh_needs_rotate_permission(tmp_path: Path) -> None:
    """Expired token without rotate permission must be denied, mentioning policy."""
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    past = utc_now() - timedelta(seconds=10)
    _seed_tokens(vault, "openai", expiry=past)

    # Grant get_env but NOT rotate
    policy = _oauth_policy(actions=[ServiceAction.get_env])

    registry = _make_registry(tmp_path)
    refresh_engine = RefreshEngine(vault=vault, registry=registry)
    broker = Broker(
        vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"),
        refresh_engine=refresh_engine,
    )

    decision = broker.get_ephemeral_env("openai", "dwight", ttl=900, alias="default")

    assert decision.allowed is False
    assert "rotate" in decision.reason.lower() or "denied" in decision.reason.lower()
    assert decision.metadata.get("oauth_refresh", {}).get("refreshed") is False


def test_get_ephemeral_env_oauth_refresh_cooldown_respected(tmp_path: Path) -> None:
    """Multiple calls within cooldown must not re-hit the token endpoint."""
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    past = utc_now() - timedelta(seconds=10)
    _seed_tokens(vault, "openai", expiry=past)

    registry = _make_registry(tmp_path)
    refresh_engine = RefreshEngine(vault=vault, registry=registry)
    policy = _oauth_policy()
    broker = Broker(
        vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"),
        refresh_engine=refresh_engine,
    )

    endpoint = MockTokenEndpoint(success_tokens={
        "access_token": "cooldown_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "cooldown_refresh",
        "scope": "openid",
    })

    with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
        # First call — triggers refresh
        decision1 = broker.get_ephemeral_env("openai", "dwight", ttl=900, alias="default")
        assert decision1.allowed is True
        assert decision1.metadata["oauth_refresh"]["refreshed"] is True
        assert endpoint.calls is not None
        first_call_count = len(endpoint.calls)

        # Second call — within cooldown, should NOT trigger refresh
        decision2 = broker.get_ephemeral_env("openai", "dwight", ttl=900, alias="default")
        assert decision2.allowed is True
        # Should have a cooldown indicator OR no additional endpoint calls
        assert len(endpoint.calls) == first_call_count
        # The second call should return the already-refreshed token
        assert decision2.env["OPENAI_API_KEY"] == "cooldown_token"
