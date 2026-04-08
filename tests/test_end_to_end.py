from __future__ import annotations

from pathlib import Path

from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.models import AgentPolicy, PolicyConfig, VerificationCategory, VerificationResult
from hermes_vault.policy import PolicyEngine
from hermes_vault.vault import Vault


class NonAuthFailureVerifier:
    def verify(self, service: str, secret: str) -> VerificationResult:
        return VerificationResult(
            service=service,
            category=VerificationCategory.permission_scope_issue,
            success=False,
            reason="Provider rejected the request because the token lacks the required scope.",
        )


def test_end_to_end_non_auth_failure_is_not_reauth(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("github", "ghp_secret12345678901234567890", "personal_access_token")
    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "dwight": AgentPolicy(
                    services=["github"],
                    raw_secret_access=False,
                    ephemeral_env_only=True,
                    max_ttl_seconds=900,
                )
            }
        )
    )
    broker = Broker(vault, policy, NonAuthFailureVerifier(), AuditLogger(tmp_path / "vault.db"))

    env_decision = broker.get_ephemeral_env("github", "dwight", ttl=1800)
    assert env_decision.allowed is True
    assert env_decision.ttl_seconds == 900
    assert env_decision.env["GITHUB_TOKEN"].startswith("ghp_")

    verification = broker.verify_credential("github")
    assert verification.allowed is False
    assert verification.metadata["verification_result"]["category"] == VerificationCategory.permission_scope_issue.value
    assert "re-auth" not in verification.reason.lower()

