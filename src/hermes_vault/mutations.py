"""Centralized audited mutation paths for vault state changes.

All write/destructive operations on vault credentials flow through
``VaultMutations``.  Each method:

1. Normalizes the service ID.
2. Checks policy (skipped for the operator agent).
3. Performs the vault operation.
4. Writes a standardized audit entry.
5. Returns a ``MutationResult``.

Direct vault access remains available for low-level internals (key
management, backup internals, schema init), but callers that need
policy/audit semantics should always use this layer.
"""

from __future__ import annotations

from hermes_vault.audit import AuditLogger
from hermes_vault.models import (
    AccessLogRecord,
    AgentCapability,
    CredentialRecord,
    CredentialStatus,
    Decision,
    MutationResult,
    ServiceAction,
)
from hermes_vault.policy import PolicyEngine
from hermes_vault.service_ids import normalize
from hermes_vault.vault import Vault


# Special agent ID for operator CLI calls.
# Operator mutations skip policy checks but still produce audit entries.
OPERATOR_AGENT_ID = "operator"


class VaultMutations:
    """Policy-checked, audit-backed mutation service for vault credentials.

    Parameters
    ----------
    vault:
        The encrypted credential vault.
    policy:
        The policy engine for permission checks.
    audit:
        The audit logger for recording decisions.
    """

    def __init__(self, vault: Vault, policy: PolicyEngine, audit: AuditLogger) -> None:
        self.vault = vault
        self.policy = policy
        self.audit = audit

    def add_credential(
        self,
        agent_id: str,
        service: str,
        secret: str,
        credential_type: str = "api_key",
        alias: str = "default",
        imported_from: str | None = None,
        scopes: list[str] | None = None,
        replace_existing: bool = False,
    ) -> MutationResult:
        """Add a credential with policy check and audit."""
        service = normalize(service)

        if not self._is_operator(agent_id):
            # Agent must have the add_credential capability.
            cap_ok, cap_reason = self.policy.can_capability(
                agent_id, AgentCapability.add_credential
            )
            if not cap_ok:
                return self._record_mutation(
                    agent_id, service, "add_credential", False, cap_reason
                )
            # Service must be in agent's policy and allow add_credential action.
            svc_ok, svc_reason = self._check_service_action(
                agent_id, service, ServiceAction.add_credential
            )
            if not svc_ok:
                return self._record_mutation(
                    agent_id, service, "add_credential", False, svc_reason
                )

        try:
            record = self.vault.add_credential(
                service=service,
                secret=secret,
                credential_type=credential_type,
                alias=alias,
                imported_from=imported_from,
                scopes=scopes,
                replace_existing=replace_existing,
            )
        except Exception as exc:
            return self._record_mutation(
                agent_id, service, "add_credential", False, str(exc)
            )

        return self._record_mutation(
            agent_id,
            service,
            "add_credential",
            True,
            f"credential {record.id} added for service '{service}' alias '{alias}'",
            record=record,
        )

    def rotate_credential(
        self,
        agent_id: str,
        service_or_id: str,
        new_secret: str,
        alias: str | None = None,
    ) -> MutationResult:
        """Rotate a credential's secret with policy check and audit."""
        try:
            current = self.vault.resolve_credential(service_or_id, alias=alias)
        except KeyError:
            return self._record_mutation(
                agent_id,
                normalize(service_or_id),
                "rotate_credential",
                False,
                f"credential '{service_or_id}' not found",
            )

        service = current.service

        if not self._is_operator(agent_id):
            svc_ok, svc_reason = self._check_service_action(
                agent_id, service, ServiceAction.rotate
            )
            if not svc_ok:
                return self._record_mutation(
                    agent_id, service, "rotate_credential", False, svc_reason
                )

        try:
            updated = self.vault.rotate(service_or_id, new_secret, alias=alias)
        except Exception as exc:
            return self._record_mutation(
                agent_id, service, "rotate_credential", False, str(exc)
            )

        return self._record_mutation(
            agent_id,
            service,
            "rotate_credential",
            True,
            f"rotated credential for service '{service}' alias '{updated.alias}'",
            record=updated,
        )

    def delete_credential(
        self,
        agent_id: str,
        service_or_id: str,
        alias: str | None = None,
    ) -> MutationResult:
        """Delete a credential with policy check and audit."""
        try:
            current = self.vault.resolve_credential(service_or_id, alias=alias)
        except KeyError:
            return self._record_mutation(
                agent_id,
                normalize(service_or_id),
                "delete_credential",
                False,
                f"credential '{service_or_id}' not found",
            )

        service = current.service

        if not self._is_operator(agent_id):
            svc_ok, svc_reason = self._check_service_action(
                agent_id, service, ServiceAction.delete
            )
            if not svc_ok:
                return self._record_mutation(
                    agent_id, service, "delete_credential", False, svc_reason
                )

        record_id = current.id
        try:
            deleted = self.vault.delete(service_or_id, alias=alias)
        except Exception as exc:
            return self._record_mutation(
                agent_id, service, "delete_credential", False, str(exc)
            )

        if not deleted:
            return self._record_mutation(
                agent_id,
                service,
                "delete_credential",
                False,
                "delete returned False (credential may not exist)",
            )

        return self._record_mutation(
            agent_id,
            service,
            "delete_credential",
            True,
            f"deleted credential '{record_id}' for service '{service}'",
            metadata={"credential_id": record_id},
        )

    def get_metadata(
        self,
        agent_id: str,
        service_or_id: str,
        alias: str | None = None,
    ) -> MutationResult:
        """Fetch credential metadata (no raw secret) with policy check and audit."""
        try:
            record = self.vault.resolve_credential(service_or_id, alias=alias)
        except KeyError:
            return self._record_mutation(
                agent_id,
                normalize(service_or_id),
                "get_metadata",
                False,
                f"credential '{service_or_id}' not found",
            )

        service = record.service

        if not self._is_operator(agent_id):
            svc_ok, svc_reason = self._check_service_action(
                agent_id, service, ServiceAction.metadata
            )
            if not svc_ok:
                return self._record_mutation(
                    agent_id, service, "get_metadata", False, svc_reason
                )

        return self._record_mutation(
            agent_id,
            service,
            "get_metadata",
            True,
            f"metadata fetched for credential {record.id}",
            record=record,
        )

    # ── internals ──────────────────────────────────────────────────────────

    @staticmethod
    def _is_operator(agent_id: str) -> bool:
        return agent_id == OPERATOR_AGENT_ID

    def _check_service_action(
        self, agent_id: str, service: str, action: ServiceAction
    ) -> tuple[bool, str]:
        """Check both service membership and action permission."""
        return self.policy.can(agent_id, service, action)

    def _record_mutation(
        self,
        agent_id: str,
        service: str,
        action: str,
        allowed: bool,
        reason: str,
        record: CredentialRecord | None = None,
        metadata: dict | None = None,
    ) -> MutationResult:
        """Write the audit entry and build the result."""
        self.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service=service,
                action=action,
                decision=Decision.allow if allowed else Decision.deny,
                reason=reason,
            )
        )
        return MutationResult(
            allowed=allowed,
            service=service,
            agent_id=agent_id,
            action=action,
            reason=reason,
            record=record,
            metadata=metadata or {},
        )
