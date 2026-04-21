from __future__ import annotations

from datetime import datetime, timezone

from hermes_vault.audit import AuditLogger
from hermes_vault.models import AgentCapability, AccessLogRecord, BrokerDecision, CredentialStatus, Decision
from hermes_vault.policy import PolicyEngine
from hermes_vault.service_ids import get_env_var_map, normalize
from hermes_vault.verifier import Verifier
from hermes_vault.vault import Vault


class Broker:
    def __init__(
        self,
        vault: Vault,
        policy: PolicyEngine,
        verifier: Verifier,
        audit: AuditLogger,
    ) -> None:
        self.vault = vault
        self.policy = policy
        self.verifier = verifier
        self.audit = audit

    def get_credential(self, service: str, purpose: str, agent_id: str) -> BrokerDecision:
        service = normalize(service)
        allowed, reason = self.policy.allow_raw_secret_access(agent_id, service)
        if not allowed:
            return self._deny(agent_id, service, "get_credential", reason)
        record = self.vault.get_credential(service)
        if not record:
            return self._deny(agent_id, service, "get_credential", "credential not found in vault")
        return self._allow(
            agent_id,
            service,
            "get_credential",
            f"raw secret access allowed for purpose '{purpose}'",
            metadata={
                "credential_id": record.id,
                "service": record.service,
                "alias": record.alias,
                "credential_type": record.credential_type,
            },
        )

    def get_ephemeral_env(self, service: str, agent_id: str, ttl: int) -> BrokerDecision:
        service = normalize(service)
        allowed, reason = self.policy.can_access_service(agent_id, service)
        if not allowed:
            return self._deny(agent_id, service, "get_ephemeral_env", reason, ttl_seconds=ttl)
        ttl_ok, ttl_reason, effective_ttl = self.policy.enforce_ttl(agent_id, ttl, service=service)
        if not ttl_ok:
            return self._deny(agent_id, service, "get_ephemeral_env", ttl_reason, ttl_seconds=ttl)
        secret = self.vault.get_secret(service)
        if not secret:
            return self._deny(agent_id, service, "get_ephemeral_env", "credential not found in vault", ttl_seconds=effective_ttl)
        env_template = get_env_var_map(service)
        env = {key: value.format(secret=secret.secret) for key, value in env_template.items()}
        return self._allow(
            agent_id,
            service,
            "get_ephemeral_env",
            "ephemeral environment materialization approved",
            ttl_seconds=effective_ttl,
            env=env,
        )

    def verify_credential(self, service: str, alias: str | None = None) -> BrokerDecision:
        service = normalize(service)
        try:
            record = self.vault.resolve_credential(service, alias=alias)
        except KeyError:
            return BrokerDecision(
                allowed=False,
                service=service,
                agent_id="hermes-vault",
                reason="credential not found in vault",
            )
        except Exception as exc:
            return BrokerDecision(
                allowed=False,
                service=service,
                agent_id="hermes-vault",
                reason=str(exc),
            )
        secret = self.vault.get_secret(record.id)
        assert secret is not None
        result = self.verifier.verify(service, secret.secret)
        status = CredentialStatus.active if result.success else (
            CredentialStatus.invalid if result.category.value == "invalid_or_expired" else CredentialStatus.unknown
        )
        self.vault.update_status(record.id, status=status, verified_at=result.checked_at.isoformat())
        self.audit.record(
            AccessLogRecord(
                agent_id="hermes-vault",
                service=service,
                action="verify_credential",
                decision=Decision.allow,
                reason=result.reason,
                verification_result=result.category,
            )
        )
        return BrokerDecision(
            allowed=result.success,
            service=service,
            agent_id="hermes-vault",
            reason=result.reason,
            metadata={
                "credential_id": record.id,
                "alias": record.alias,
                "verification_result": result.model_dump(mode="json"),
            },
        )

    def list_available_credentials(self, agent_id: str) -> list[dict[str, str]]:
        # Gate on agent-level capability (non-service-scoped action).
        cap_ok, cap_reason = self.policy.can_capability(agent_id, AgentCapability.list_credentials)
        if not cap_ok:
            self._deny(agent_id, "n/a", "list_available_credentials", cap_reason)
            return []
        agent_policy = self.policy.get_agent_policy(agent_id)
        if not agent_policy:
            self._deny(agent_id, "n/a", "list_available_credentials", "agent is not defined in policy")
            return []
        allowed_services = set(agent_policy.services)
        records = self.vault.list_credentials()
        visible = [
            {
                "service": record.service,
                "alias": record.alias,
                "credential_type": record.credential_type,
                "status": record.status.value,
            }
            for record in records
            if record.service in allowed_services
        ]
        self.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service="*",
                action="list_available_credentials",
                decision=Decision.allow,
                reason="returned policy-filtered credential metadata",
            )
        )
        return visible

    def _allow(
        self,
        agent_id: str,
        service: str,
        action: str,
        reason: str,
        ttl_seconds: int | None = None,
        env: dict[str, str] | None = None,
        metadata: dict[str, object] | None = None,
    ) -> BrokerDecision:
        decision = BrokerDecision(
            allowed=True,
            service=service,
            agent_id=agent_id,
            reason=reason,
            ttl_seconds=ttl_seconds,
            env=env or {},
            metadata=metadata or {},
        )
        self.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service=service,
                action=action,
                decision=Decision.allow,
                reason=reason,
                ttl_seconds=ttl_seconds,
            )
        )
        return decision

    def _deny(
        self,
        agent_id: str,
        service: str,
        action: str,
        reason: str,
        ttl_seconds: int | None = None,
    ) -> BrokerDecision:
        self.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service=service,
                action=action,
                decision=Decision.deny,
                reason=reason,
                ttl_seconds=ttl_seconds,
            )
        )
        return BrokerDecision(
            allowed=False,
            service=service,
            agent_id=agent_id,
            reason=reason,
            ttl_seconds=ttl_seconds,
        )
