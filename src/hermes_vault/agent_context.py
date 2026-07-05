from __future__ import annotations

from typing import Any

from hermes_vault.models import LeaseStatus
from hermes_vault.policy import PolicyEngine
from hermes_vault.vault import Vault


AGENT_CONTEXT_VERSION = "agent-context-v1"


def build_agent_context(
    *,
    agent_id: str,
    vault: Vault,
    policy: PolicyEngine,
) -> dict[str, Any]:
    agent = policy.get_agent_policy(agent_id)
    data: dict[str, Any] = {
        "version": AGENT_CONTEXT_VERSION,
        "agent_id": agent_id,
        "policy_hash": policy.compute_policy_hash(),
        "defined": agent is not None,
        "services": [],
        "leases": [],
        "access_requests": [],
        "summary": {
            "service_count": 0,
            "active_lease_count": 0,
            "pending_request_count": 0,
        },
        "redaction_boundary": "metadata-only; no raw secrets, env values, encrypted payloads, or provider token responses",
    }
    if agent is None:
        data["recommended_next_step"] = "Define the agent in policy.yaml before requesting credential access."
        return data

    credential_by_service: dict[str, list[dict[str, Any]]] = {}
    for record in vault.list_credentials():
        if record.service not in agent.services:
            continue
        credential_by_service.setdefault(record.service, []).append(
            {
                "service": record.service,
                "alias": record.alias,
                "credential_type": record.credential_type,
                "status": record.status.value,
                "scopes": list(record.scopes),
                "tags": list(record.tags),
                "last_verified_at": record.last_verified_at.isoformat() if record.last_verified_at else None,
                "expiry": record.expiry.isoformat() if record.expiry else None,
                "crypto_version": record.crypto_version,
            }
        )

    services = []
    for service in agent.services:
        entry = agent.service_actions.get(service)
        actions = [action.value for action in entry.actions] if entry else []
        services.append(
            {
                "service": service,
                "actions": actions,
                "agent_max_ttl_seconds": agent.max_ttl_seconds,
                "service_max_ttl_seconds": entry.max_ttl_seconds if entry else None,
                "requires_lease_for_env": policy.require_lease_for_env(agent_id, service),
                "requires_lease_purpose": policy.require_lease_purpose(agent_id, service),
                "credentials": credential_by_service.get(service, []),
            }
        )

    leases = [
        lease.model_dump(mode="json")
        for lease in vault.list_leases(agent_id=agent_id)
    ]
    requests = [
        request.model_dump(mode="json")
        for request in vault.list_access_requests(agent_id=agent_id)
    ]
    data["services"] = services
    data["leases"] = leases
    data["access_requests"] = requests
    data["summary"] = {
        "service_count": len(services),
        "active_lease_count": sum(1 for lease in vault.list_leases(agent_id=agent_id) if lease.status is LeaseStatus.active),
        "pending_request_count": sum(1 for request in requests if request.get("status") == "pending"),
    }
    data["recommended_next_step"] = (
        "Use lease checkout or approve pending requests before env handoff where leases are required."
        if any(service["requires_lease_for_env"] for service in services)
        else "Use brokered env materialization for allowed services; do not handle raw secrets."
    )
    return data
