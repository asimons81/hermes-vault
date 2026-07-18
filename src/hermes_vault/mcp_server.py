"""MCP server transport for Hermes Vault.

Exposes brokered vault capabilities as MCP tools over stdio.
Tool calls use caller-supplied ``agent_id`` unless the server is bound
to an allowed-agent set with a default fallback.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import threading
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Resource, ResourceTemplate, TextContent, TextResourceContents, Tool
from pydantic import AnyUrl
from rich.console import Console

from hermes_vault import __version__
from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.config import get_settings
from hermes_vault.crypto import resolve_passphrase
from hermes_vault.health import run_health
from hermes_vault.models import AccessLogRecord, AgentCapability, CredentialSecret, Decision, ServiceAction
from hermes_vault.mutations import OPERATOR_AGENT_ID, VaultMutations
from hermes_vault.oauth.callback import CallbackServer
from hermes_vault.oauth.errors import sanitize_oauth_error_detail
from hermes_vault.oauth.exchange import TokenExchanger
from hermes_vault.oauth.flow import _store_oauth_tokens
from hermes_vault.oauth.oauth_refresh import RefreshEngine, refresh_alias_for
from hermes_vault.oauth.providers import OAuthProviderRegistry
from hermes_vault.oauth.readiness import provider_readiness
from hermes_vault.policy import PolicyEngine
from hermes_vault.policy_doctor import run_policy_doctor
from hermes_vault.scanner import Scanner
from hermes_vault.service_ids import normalize
from hermes_vault.verifier import Verifier
from hermes_vault.vault import Vault

logger = logging.getLogger("hermes_vault.mcp")

# ── tool schemas ───────────────────────────────────────────────────────────────

_TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "list_services": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "filter": {"type": "string", "description": "Optional substring filter on service names"},
        },
    },
    "get_credential_metadata": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "service": {"type": "string", "description": "Service name or credential ID"},
            "alias": {"type": "string", "description": "Optional alias for disambiguation"},
        },
        "required": ["service"],
    },
    "get_ephemeral_env": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "service": {"type": "string", "description": "Service name or credential ID"},
            "alias": {"type": "string", "description": "Optional alias for disambiguation"},
            "ttl_seconds": {"type": "integer", "description": "Optional TTL in seconds (subject to policy ceiling)"},
        },
        "required": ["service"],
    },
    "lease_issue": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "service": {"type": "string", "description": "Service name or credential ID"},
            "alias": {"type": "string", "description": "Optional alias for disambiguation"},
            "ttl_seconds": {"type": "integer", "description": "Lease duration in seconds"},
            "purpose": {"type": "string", "description": "Purpose of the lease"},
            "reason": {"type": "string", "description": "Optional human-readable reason"},
        },
        "required": ["service", "ttl_seconds"],
    },
    "lease_list": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "service": {"type": "string", "description": "Optional service filter"},
            "status": {"type": "string", "description": "Optional lease status filter"},
        },
    },
    "lease_show": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "lease_id": {"type": "string", "description": "Lease ID"},
        },
        "required": ["lease_id"],
    },
    "lease_renew": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "lease_id": {"type": "string", "description": "Lease ID"},
            "ttl_seconds": {"type": "integer", "description": "Renewal TTL in seconds"},
        },
        "required": ["lease_id", "ttl_seconds"],
    },
    "lease_revoke": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "lease_id": {"type": "string", "description": "Lease ID"},
            "reason": {"type": "string", "description": "Optional revocation reason"},
        },
        "required": ["lease_id"],
    },
    "verify_credential": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "service": {"type": "string", "description": "Service name or credential ID"},
            "alias": {"type": "string", "description": "Optional alias for disambiguation"},
        },
        "required": ["service"],
    },
    "rotate_credential": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "service": {"type": "string", "description": "Service name or credential ID"},
            "alias": {"type": "string", "description": "Optional alias for disambiguation"},
            "new_secret": {"type": "string", "description": "New secret value"},
        },
        "required": ["service", "new_secret"],
    },
    "scan_for_secrets": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "path": {"type": "string", "description": "Optional path to scan (defaults to ~/.hermes)"},
        },
    },
    "oauth_login": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "provider_id": {"type": "string", "description": "OAuth provider ID (e.g. google, github)"},
            "alias": {"type": "string", "description": "Credential alias (default: default)"},
            "scopes": {"type": "array", "items": {"type": "string"}, "description": "Optional OAuth scopes"},
            "port": {"type": "integer", "description": "Callback server port (0 = auto-assigned)"},
        },
        "required": ["provider_id"],
    },
    "oauth_device_login": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "provider_id": {"type": "string", "description": "OAuth provider ID with device-code support (e.g. google, github)"},
            "alias": {"type": "string", "description": "Credential alias (default: default)"},
            "scopes": {"type": "array", "items": {"type": "string"}, "description": "Optional OAuth scopes"},
            "timeout_seconds": {"type": "integer", "description": "Seconds to wait for user authorization before timing out"},
        },
        "required": ["provider_id"],
    },
    "oauth_provider_status": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "provider_id": {"type": "string", "description": "OAuth provider ID to inspect"},
        },
        "required": ["provider_id"],
    },
    "oauth_refresh": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "service": {"type": "string", "description": "Service name or credential ID"},
            "alias": {"type": "string", "description": "Optional alias for disambiguation"},
            "dry_run": {"type": "boolean", "description": "Simulate without updating vault"},
        },
        "required": ["service"],
    },
    "request_access": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "service": {"type": "string", "description": "Requested service"},
            "alias": {"type": "string", "description": "Requested alias"},
            "action": {"type": "string", "description": "Requested action"},
            "purpose": {"type": "string", "description": "Specific task purpose"},
            "ttl_seconds": {"type": "integer", "description": "Optional requested TTL"},
        },
        "required": ["service", "purpose"],
    },
    "policy_explain": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "service": {"type": "string", "description": "Service to explain"},
            "action": {"type": "string", "description": "Action to explain"},
            "ttl_seconds": {"type": "integer", "description": "Optional requested TTL"},
        },
        "required": ["service"],
    },
    "lease_checkout": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Optional agent identity; omitted only when MCP binding supplies a default"},
            "service": {"type": "string", "description": "Service name"},
            "alias": {"type": "string", "description": "Credential alias"},
            "ttl_seconds": {"type": "integer", "description": "Requested handoff TTL"},
            "purpose": {"type": "string", "description": "Lease purpose if a lease is issued"},
        },
        "required": ["service"],
    },
}


# ── broker lifecycle ───────────────────────────────────────────────────────────

_broker: Broker | None = None


def _build_broker(profile: str | None = None) -> Broker:
    """Initialise vault, policy, and broker — same rules as the CLI."""
    settings = get_settings(profile=profile)
    policy = PolicyEngine.from_yaml(settings.effective_policy_path)
    policy.write_default(settings.effective_policy_path)
    passphrase = resolve_passphrase(prompt=False, profile_name=settings.profile_name)
    vault = Vault(settings.db_path, settings.salt_path, passphrase)
    audit = AuditLogger(settings.db_path, master_key=vault.key)
    verifier = Verifier(plugin_dir=settings.verifier_plugin_dir)
    scanner = Scanner(settings, policy=policy)
    return Broker(vault=vault, policy=policy, verifier=verifier, audit=audit, scanner=scanner)


def _get_broker() -> Broker:
    """Return the cached broker, building lazily if needed (e.g. in tests)."""
    global _broker
    if _broker is None:
        _broker = _build_broker()
    return _broker


# ── helpers ────────────────────────────────────────────────────────────────────


def _json_text(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def _generate_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256)."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(128)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _generate_state() -> str:
    return secrets.token_urlsafe(32)


@dataclass(frozen=True)
class MCPBindingContext:
    requested_agent_id: str | None
    effective_agent_id: str | None
    binding_mode: str
    allowed_agents: tuple[str, ...]
    default_agent: str | None


def _normalize_agent_id(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _record_binding_denial(
    settings: Any,
    tool_name: str,
    requested_agent_id: str | None,
    reason: str,
) -> None:
    audit = AuditLogger(settings.db_path)
    allowed_agents = tuple(settings.mcp_allowed_agents or ())
    default_agent = settings.mcp_default_agent
    binding_mode = "bound" if allowed_agents else "unrestricted"
    audit.record(
        AccessLogRecord(
            agent_id=requested_agent_id or default_agent or "mcp-unbound",
            service="*",
            action=f"mcp_bind:{tool_name}",
            decision=Decision.deny,
            reason=reason,
            metadata={
                "tool_name": tool_name,
                "requested_agent_id": requested_agent_id,
                "effective_agent_id": default_agent if requested_agent_id is None else None,
                "mcp_binding_mode": binding_mode,
                "mcp_allowed_agents": list(allowed_agents),
                "mcp_default_agent": default_agent,
                "policy_decision": "not_evaluated",
            },
        )
    )


def _resolve_mcp_binding(
    settings: Any,
    arguments: dict[str, Any],
    tool_name: str,
) -> MCPBindingContext:
    requested_agent_id = _normalize_agent_id(arguments.get("agent_id"))
    allowed_agents = tuple(settings.mcp_allowed_agents or ())
    default_agent = _normalize_agent_id(settings.mcp_default_agent)

    if not allowed_agents:
        if requested_agent_id is None:
            raise ValueError("Missing required parameter: agent_id")
        return MCPBindingContext(
            requested_agent_id=requested_agent_id,
            effective_agent_id=requested_agent_id,
            binding_mode="unrestricted",
            allowed_agents=allowed_agents,
            default_agent=default_agent,
        )

    if requested_agent_id is not None:
        if requested_agent_id not in allowed_agents:
            reason = f"Denied: agent '{requested_agent_id}' is not allowed for this MCP server"
            _record_binding_denial(settings, tool_name, requested_agent_id, reason)
            raise ValueError(reason)
        return MCPBindingContext(
            requested_agent_id=requested_agent_id,
            effective_agent_id=requested_agent_id,
            binding_mode="bound",
            allowed_agents=allowed_agents,
            default_agent=default_agent,
        )

    if default_agent is not None:
        if default_agent not in allowed_agents:
            reason = f"Error: MCP default agent '{default_agent}' is not in the allowed agent set"
            _record_binding_denial(settings, tool_name, requested_agent_id, reason)
            raise ValueError(reason)
        return MCPBindingContext(
            requested_agent_id=None,
            effective_agent_id=default_agent,
            binding_mode="default_fallback",
            allowed_agents=allowed_agents,
            default_agent=default_agent,
        )

    reason = "Missing required parameter: agent_id"
    _record_binding_denial(settings, tool_name, requested_agent_id, reason)
    raise ValueError(reason)


def _generated_at() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resource_arguments(uri: Any) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(str(uri))
    query = urllib.parse.parse_qs(parsed.query)
    arguments: dict[str, Any] = {}
    if query.get("agent_id"):
        arguments["agent_id"] = query["agent_id"][0]
    if query.get("alias"):
        arguments["alias"] = query["alias"][0]
    if query.get("id"):
        arguments["id"] = query["id"][0]
    if query.get("service"):
        arguments["service"] = query["service"][0]
    if query.get("action"):
        arguments["action"] = query["action"][0]
    if query.get("ttl_seconds"):
        arguments["ttl_seconds"] = query["ttl_seconds"][0]
    if query.get("backup"):
        arguments["backup"] = query["backup"][0]
    return arguments


def _resource_key(uri: Any) -> str:
    parsed = urllib.parse.urlparse(str(uri))
    if parsed.scheme != "vault":
        raise ValueError(f"Unsupported resource URI: {uri}")
    if parsed.netloc == "services" and parsed.path not in ("", "/"):
        return "vault://services/{name}"
    if parsed.netloc == "leases" and parsed.path not in ("", "/"):
        return "vault://leases/{id}"
    if parsed.netloc in {"services", "health", "policy", "leases", "status", "agent-context", "policy-explain", "requests", "recovery", "audit-integrity"} and parsed.path in ("", "/"):
        return f"vault://{parsed.netloc}"
    raise ValueError(f"Unknown resource URI: {uri}")


def _resource_service_name(uri: Any) -> str | None:
    parsed = urllib.parse.urlparse(str(uri))
    if parsed.netloc != "services" or parsed.path in ("", "/"):
        return None
    return normalize(urllib.parse.unquote(parsed.path.lstrip("/")).replace(" ", "_"))


def _resource_lease_id(uri: Any) -> str | None:
    parsed = urllib.parse.urlparse(str(uri))
    if parsed.netloc != "leases" or parsed.path in ("", "/"):
        return None
    return urllib.parse.unquote(parsed.path.lstrip("/")).strip() or None


def _resolve_resource_binding(settings: Any, uri: Any, resource_key: str) -> MCPBindingContext:
    return _resolve_mcp_binding(
        settings,
        _resource_arguments(uri),
        f"resource:{resource_key}",
    )


def _json_resource(uri: Any, payload: dict[str, Any]) -> TextResourceContents:
    return TextResourceContents(
        uri=AnyUrl(str(uri)),
        mimeType="application/json",
        text=_json_text(payload),
    )


def _resource_error(uri: Any, error: str, agent_id: str | None = None) -> dict[str, Any]:
    return {
        "version": "vault-resource-error-v1",
        "resource": str(uri).split("?", 1)[0],
        "agent_id": agent_id,
        "error": error,
    }


def _record_resource_audit(
    broker: Broker,
    agent_id: str,
    action: str,
    decision: Decision,
    reason: str,
) -> None:
    broker.audit.record(
        AccessLogRecord(
            agent_id=agent_id,
            service="*",
            action=action,
            decision=decision,
            reason=reason,
        )
    )


def _service_metadata_payload(record: Any) -> dict[str, Any]:
    return record.model_dump(mode="json", exclude={"encrypted_payload"})


def _services_resource_payload(broker: Broker, binding: MCPBindingContext) -> dict[str, Any]:
    agent_id = binding.effective_agent_id or ""
    services = broker.list_available_credentials(agent_id)
    return {
        "version": "vault-services-v1",
        "generated_at": _generated_at(),
        "agent_id": agent_id,
        "binding_mode": binding.binding_mode,
        "count": len(services),
        "services": [
            {
                **service,
                "resource_uri": f"vault://services/{urllib.parse.quote(service['service'], safe='')}",
            }
            for service in services
        ],
    }


def _service_detail_resource_payload(uri: Any, broker: Broker, binding: MCPBindingContext) -> dict[str, Any]:
    agent_id = binding.effective_agent_id or ""
    service = _resource_service_name(uri)
    if service is None:
        raise ValueError(f"Missing service name in resource URI: {uri}")
    alias = _resource_arguments(uri).get("alias")

    allowed, reason = broker.policy.can(agent_id, service, ServiceAction.metadata)
    if not allowed:
        broker.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service=service,
                action="get_metadata",
                decision=Decision.deny,
                reason=reason,
            )
        )
        raise ValueError(reason)

    credentials: list[dict[str, Any]] = []
    if alias is not None:
        metadata_result = broker.get_metadata(agent_id, service, alias)
        if not metadata_result.allowed:
            raise ValueError(metadata_result.reason)
        if metadata_result.record is not None:
            credentials.append(_service_metadata_payload(metadata_result.record))
    else:
        records = [record for record in broker.vault.list_credentials() if record.service == service]
        for record in records:
            result = broker.get_metadata(agent_id, service, record.alias)
            if result.allowed and result.record is not None:
                credentials.append(_service_metadata_payload(result.record))
            elif not result.allowed:
                raise ValueError(result.reason)

    return {
        "version": "vault-service-v1",
        "generated_at": _generated_at(),
        "agent_id": agent_id,
        "binding_mode": binding.binding_mode,
        "service": service,
        "alias": alias,
        "count": len(credentials),
        "credentials": credentials,
    }


def _lease_metadata_payload(record: Any) -> dict[str, Any]:
    payload = record.model_dump(mode="json")
    payload.pop("metadata", None)
    payload["has_metadata"] = bool(record.metadata)
    return payload


def _leases_resource_payload(broker: Broker, binding: MCPBindingContext) -> dict[str, Any]:
    agent_id = binding.effective_agent_id or ""
    lease_list_result = broker.list_leases(agent_id)
    if not lease_list_result.allowed:
        raise ValueError(lease_list_result.reason)
    leases = [dict(lease) for lease in lease_list_result.metadata.get("leases", [])]
    return {
        "version": "vault-leases-v1",
        "generated_at": _generated_at(),
        "agent_id": agent_id,
        "binding_mode": binding.binding_mode,
        "count": len(leases),
        "leases": leases,
    }


def _lease_detail_resource_payload(uri: Any, broker: Broker, binding: MCPBindingContext) -> dict[str, Any]:
    agent_id = binding.effective_agent_id or ""
    lease_id = _resource_lease_id(uri)
    if lease_id is None:
        raise ValueError(f"Missing lease id in resource URI: {uri}")
    lease_show_result = broker.show_lease(agent_id, lease_id)
    if not lease_show_result.allowed:
        raise ValueError(lease_show_result.reason)
    lease = lease_show_result.metadata.get("lease") or {}
    return {
        "version": "vault-lease-v1",
        "generated_at": _generated_at(),
        "agent_id": agent_id,
        "binding_mode": binding.binding_mode,
        "lease": lease,
    }


def _health_resource_payload(broker: Broker, binding: MCPBindingContext) -> dict[str, Any]:
    agent_id = binding.effective_agent_id or ""
    cap_ok, cap_reason = broker.policy.can_capability(agent_id, AgentCapability.list_credentials)
    if not cap_ok:
        _record_resource_audit(broker, agent_id, "mcp_resource_health", Decision.deny, cap_reason)
        raise ValueError(cap_reason)
    agent_policy = broker.policy.get_agent_policy(agent_id)
    if agent_policy is None:
        reason = f"agent '{agent_id}' is not defined in policy"
        _record_resource_audit(broker, agent_id, "mcp_resource_health", Decision.deny, reason)
        raise ValueError(reason)

    _record_resource_audit(
        broker,
        agent_id,
        "mcp_resource_health",
        Decision.allow,
        "returned policy-scoped health snapshot",
    )
    payload = run_health(
        broker.vault,
        audit=broker.audit,
        verify_live=False,
        services=set(agent_policy.services),
    ).as_dict(exclude_none=False)
    payload.update({
        "agent_id": agent_id,
        "binding_mode": binding.binding_mode,
        "policy_scoped": True,
    })
    return payload


def _status_resource_payload(broker: Broker, binding: MCPBindingContext, settings: Any) -> dict[str, Any]:
    agent_id = binding.effective_agent_id or ""
    health = _health_resource_payload(broker, binding)
    agent_policy = broker.policy.get_agent_policy(agent_id)
    if agent_policy is None:
        raise ValueError(f"agent '{agent_id}' is not defined in policy")

    lease_result = broker.list_leases(agent_id)
    leases = list(lease_result.metadata.get("leases", [])) if lease_result.allowed else []
    policy_report = run_policy_doctor(
        settings.effective_policy_path,
        generated_skills_dir=settings.generated_skills_dir,
        strict=False,
    )

    next_steps: list[str] = []
    if health.get("findings"):
        next_steps.append("Run hermes-vault health locally and resolve the reported findings.")
    if policy_report.finding_count:
        next_steps.append("Run hermes-vault policy doctor locally and review policy drift.")
    days_since_backup = health.get("days_since_last_backup")
    backup_threshold = int(health.get("backup_threshold_days") or 30)
    if days_since_backup is None:
        next_steps.append("Create and verify a backup with hermes-vault backup and hermes-vault backup-verify.")
    elif int(days_since_backup) > backup_threshold:
        next_steps.append("Refresh backup coverage and run a restore dry-run.")

    # Audit integrity summary (metadata only).
    audit_integrity: dict[str, Any] = {"available": False}
    try:
        from hermes_vault.audit_integrity.service import AuditIntegrityService
        ai_service = AuditIntegrityService(broker.vault.db_path, broker.vault.key)
        ai_service.ensure_initialized()
        ai_result = ai_service.verify()
        audit_integrity = {
            "available": True,
            "status": ai_result.status.value,
            "reason_code": ai_result.reason_code,
            "verified_count": ai_result.verified_count,
            "legacy_count": ai_result.legacy_count,
            "checkpoint_status": ai_result.checkpoint_status.value,
        }
    except Exception:
        audit_integrity = {"available": False}

    if not next_steps:
        next_steps.append("Vault status is clean for this policy scope; continue using brokered env or leases.")

    return {
        "version": "vault-status-v1",
        "generated_at": _generated_at(),
        "agent_id": agent_id,
        "binding_mode": binding.binding_mode,
        "policy_scoped": True,
        "profile": {
            "name": settings.profile_name,
            "runtime_home": str(settings.runtime_home),
            "policy_path": str(settings.effective_policy_path),
            "mcp_binding_enabled": settings.mcp_binding_enabled,
        },
        "health": {
            "healthy": health.get("healthy"),
            "total_credentials": health.get("total_credentials"),
            "finding_count": len(health.get("findings", [])),
            "days_since_last_backup": days_since_backup,
            "backup_threshold_days": backup_threshold,
            "leases": health.get("leases", {}),
        },
        "policy": {
            "policy_hash": broker.policy.compute_policy_hash(),
            "service_count": len(agent_policy.services),
            "finding_count": policy_report.finding_count,
        },
        "leases": {
            "count": len(leases),
            "active": sum(1 for lease in leases if lease.get("status") == "active"),
            "expired": sum(1 for lease in leases if lease.get("status") == "expired"),
            "revoked": sum(1 for lease in leases if lease.get("status") == "revoked"),
        },
        "audit_integrity": audit_integrity,
        "next_steps": next_steps,
        "raw_secret_values_returned": False,
    }


def _policy_resource_payload(broker: Broker, binding: MCPBindingContext) -> dict[str, Any]:
    agent_id = binding.effective_agent_id or ""
    agent_policy = broker.policy.get_agent_policy(agent_id)
    if agent_policy is None:
        reason = f"agent '{agent_id}' is not defined in policy"
        _record_resource_audit(broker, agent_id, "mcp_resource_policy", Decision.deny, reason)
        raise ValueError(reason)

    _record_resource_audit(
        broker,
        agent_id,
        "mcp_resource_policy",
        Decision.allow,
        "returned effective-agent policy summary",
    )
    return {
        "version": "policy-summary-v1",
        "generated_at": _generated_at(),
        "agent_id": agent_id,
        "binding_mode": binding.binding_mode,
        "policy_hash": broker.policy.compute_policy_hash(),
        "services": agent_policy.services,
        "capabilities": [capability.value for capability in agent_policy.capabilities],
        "raw_secret_access": agent_policy.raw_secret_access,
        "ephemeral_env_only": agent_policy.ephemeral_env_only,
        "require_verification_before_reauth": agent_policy.require_verification_before_reauth,
        "max_ttl_seconds": agent_policy.max_ttl_seconds,
        "approval_required_services": agent_policy.approval_required_services,
        "service_actions": {
            service: {
                "actions": [action.value for action in entry.actions],
                "max_ttl_seconds": entry.max_ttl_seconds,
            }
            for service, entry in agent_policy.service_actions.items()
        },
    }


def _agent_context_resource_payload(broker: Broker, binding: MCPBindingContext) -> dict[str, Any]:
    agent_id = binding.effective_agent_id or ""
    from hermes_vault.agent_context import build_agent_context

    return build_agent_context(agent_id=agent_id, vault=broker.vault, policy=broker.policy)


def _policy_explain_resource_payload(uri: Any, broker: Broker, binding: MCPBindingContext) -> dict[str, Any]:
    agent_id = binding.effective_agent_id or ""
    args = _resource_arguments(uri)
    service = args.get("service")
    if not service:
        raise ValueError("Missing required query parameter: service")
    action = args.get("action") or "get_env"
    ttl_raw = args.get("ttl_seconds")
    ttl = int(ttl_raw) if ttl_raw is not None else None
    return broker.policy.explain(agent_id, service, action, requested_ttl=ttl)


def _requests_resource_payload(broker: Broker, binding: MCPBindingContext) -> dict[str, Any]:
    agent_id = binding.effective_agent_id or ""
    result = broker.list_access_requests(agent_id=agent_id)
    if not result.allowed:
        raise ValueError(result.reason)
    return {
        "version": "vault-requests-v1",
        "generated_at": _generated_at(),
        "agent_id": agent_id,
        "binding_mode": binding.binding_mode,
        "requests": result.metadata.get("requests", []),
    }


def _recovery_resource_payload(uri: Any, broker: Broker, binding: MCPBindingContext) -> dict[str, Any]:
    args = _resource_arguments(uri)
    backup = args.get("backup")
    if not backup:
        raise ValueError("Missing required query parameter: backup")
    from hermes_vault.recovery import run_recovery_drill

    report = run_recovery_drill(backup_path=backup, vault=broker.vault, policy=broker.policy)
    payload = report.as_dict(exclude_none=False)
    payload["agent_id"] = binding.effective_agent_id or ""
    payload["binding_mode"] = binding.binding_mode
    payload["raw_secret_values_returned"] = False
    return payload


def _audit_integrity_resource_payload(broker: Broker, binding: MCPBindingContext) -> dict[str, Any]:
    """Return metadata-only audit integrity status."""
    from hermes_vault.audit_integrity.service import AuditIntegrityService

    try:
        service = AuditIntegrityService(broker.vault.db_path, broker.vault.key)
        service.ensure_initialized()
        result = service.verify()
        return {
            "version": "audit-integrity-mcp-v1",
            "status": result.status.value,
            "reason_code": result.reason_code,
            "chain_version": result.chain_version,
            "verified_count": result.verified_count,
            "legacy_count": result.legacy_count,
            "first_verified_sequence": result.first_verified_sequence,
            "last_verified_sequence": result.last_verified_sequence,
            "checkpoint_status": result.checkpoint_status.value,
            "recommended_next_step": result.recommended_next_step,
            "verified_at": result.verified_at.isoformat() if result.verified_at else None,
        }
    except Exception as exc:
        return {
            "version": "audit-integrity-mcp-v1",
            "status": "error",
            "error": str(exc),
        }


def _preflight_tool_arguments(name: str, arguments: dict[str, Any]) -> str | None:
    if name in {"get_credential_metadata", "get_ephemeral_env", "verify_credential", "rotate_credential", "oauth_refresh", "request_access", "policy_explain", "lease_checkout"}:
        if _normalize_agent_id(arguments.get("service")) is None:
            return "Missing required parameter: service"
    if name == "request_access" and _normalize_agent_id(arguments.get("purpose")) is None:
        return "Missing required parameter: purpose"
    if name in {"lease_issue", "lease_list", "lease_show", "lease_renew", "lease_revoke"}:
        if name in {"lease_issue", "lease_renew"} and arguments.get("ttl_seconds") is None:
            return "Missing required parameter: ttl_seconds"
        if name in {"lease_show", "lease_renew", "lease_revoke"} and _normalize_agent_id(arguments.get("lease_id")) is None:
            return "Missing required parameter: lease_id"
    if name in {"oauth_login", "oauth_device_login", "oauth_provider_status"}:
        provider = _normalize_agent_id(arguments.get("provider_id") or arguments.get("provider"))
        if provider is None:
            return "Missing required parameter: provider_id" if name in {"oauth_device_login", "oauth_provider_status"} else "Missing required parameter: provider"
    return None


# ── OAuth state holder (per-process; browser/device login attempts use unique keys) ─────────

_pending_oauth: dict[str, dict[str, Any]] = {}


# ── server ─────────────────────────────────────────────────────────────────────

server = Server("hermes-vault", version=__version__)


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="list_services",
            description="List credentials visible to the agent, filtered by policy.",
            inputSchema=_TOOL_SCHEMAS["list_services"],
        ),
        Tool(
            name="get_credential_metadata",
            description="Fetch metadata for a credential. Raw secrets are never returned.",
            inputSchema=_TOOL_SCHEMAS["get_credential_metadata"],
        ),
        Tool(
            name="get_ephemeral_env",
            description="Materialise ephemeral environment variables for a service. Primary access pattern.",
            inputSchema=_TOOL_SCHEMAS["get_ephemeral_env"],
        ),
        Tool(
            name="lease_issue",
            description="Issue a credential lease for a service. Returns metadata only.",
            inputSchema=_TOOL_SCHEMAS["lease_issue"],
        ),
        Tool(
            name="lease_list",
            description="List visible leases for the effective agent. Returns metadata only.",
            inputSchema=_TOOL_SCHEMAS["lease_list"],
        ),
        Tool(
            name="lease_show",
            description="Show one lease by ID. Returns metadata only.",
            inputSchema=_TOOL_SCHEMAS["lease_show"],
        ),
        Tool(
            name="lease_renew",
            description="Renew a lease by ID. Returns metadata only.",
            inputSchema=_TOOL_SCHEMAS["lease_renew"],
        ),
        Tool(
            name="lease_revoke",
            description="Revoke a lease by ID. Returns metadata only.",
            inputSchema=_TOOL_SCHEMAS["lease_revoke"],
        ),
        Tool(
            name="verify_credential",
            description="Verify a credential against its provider.",
            inputSchema=_TOOL_SCHEMAS["verify_credential"],
        ),
        Tool(
            name="rotate_credential",
            description="Rotate a credential to a new secret value. Requires rotate permission.",
            inputSchema=_TOOL_SCHEMAS["rotate_credential"],
        ),
        Tool(
            name="scan_for_secrets",
            description="Scan filesystem paths for plaintext secrets.",
            inputSchema=_TOOL_SCHEMAS["scan_for_secrets"],
        ),
        Tool(
            name="oauth_login",
            description="Initiate PKCE OAuth login for a provider. Returns authorization URL.",
            inputSchema=_TOOL_SCHEMAS["oauth_login"],
        ),
        Tool(
            name="oauth_device_login",
            description="Initiate headless OAuth device-code login for a provider. Never returns raw tokens.",
            inputSchema=_TOOL_SCHEMAS["oauth_device_login"],
        ),
        Tool(
            name="oauth_provider_status",
            description="Report read-only OAuth provider readiness and safe next commands.",
            inputSchema=_TOOL_SCHEMAS["oauth_provider_status"],
        ),
        Tool(
            name="oauth_refresh",
            description="Trigger token refresh for a service using stored refresh token.",
            inputSchema=_TOOL_SCHEMAS["oauth_refresh"],
        ),
        Tool(
            name="request_access",
            description="Create a pending metadata-only access request. Does not return credentials.",
            inputSchema=_TOOL_SCHEMAS["request_access"],
        ),
        Tool(
            name="policy_explain",
            description="Explain why the effective agent can or cannot perform a service action.",
            inputSchema=_TOOL_SCHEMAS["policy_explain"],
        ),
        Tool(
            name="lease_checkout",
            description="Issue or reuse a lease and perform brokered env handoff through the same policy path.",
            inputSchema=_TOOL_SCHEMAS["lease_checkout"],
        ),
    ]


async def _default_agent_service_resources() -> list[Resource]:
    settings = get_settings()
    if not settings.mcp_default_agent:
        return []
    try:
        binding = _resolve_mcp_binding(settings, {}, "resource:list")
    except ValueError:
        return []
    try:
        services = _get_broker().list_available_credentials(binding.effective_agent_id or "")
    except Exception:
        logger.exception("Failed to resolve default-agent service resources")
        return []

    seen: set[str] = set()
    resources: list[Resource] = []
    for service in services:
        service_name = service.get("service")
        if not service_name or service_name in seen:
            continue
        seen.add(service_name)
        resources.append(
            Resource(
                name=f"vault-service-{service_name}",
                title=f"Hermes Vault service: {service_name}",
                uri=AnyUrl(f"vault://services/{urllib.parse.quote(service_name, safe='')}"),
                description=f"Metadata for policy-visible service '{service_name}'.",
                mimeType="application/json",
            )
        )
    return resources


@server.list_resources()
async def list_resources() -> list[Resource]:
    resources = [
        Resource(
            name="vault-status",
            title="Hermes Vault status",
            uri=AnyUrl("vault://status"),
            description="Consolidated policy-scoped vault status and safe next steps.",
            mimeType="application/json",
        ),
        Resource(
            name="vault-services",
            title="Hermes Vault services",
            uri=AnyUrl("vault://services"),
            description="Policy-scoped credential services visible to the effective agent.",
            mimeType="application/json",
        ),
        Resource(
            name="vault-health",
            title="Hermes Vault health",
            uri=AnyUrl("vault://health"),
            description="Policy-scoped read-only vault health summary. Does not perform live provider verification.",
            mimeType="application/json",
        ),
        Resource(
            name="vault-policy",
            title="Hermes Vault policy summary",
            uri=AnyUrl("vault://policy"),
            description="Sanitized policy summary for the effective agent only.",
            mimeType="application/json",
        ),
        Resource(
            name="vault-leases",
            title="Hermes Vault leases",
            uri=AnyUrl("vault://leases"),
            description="Policy-scoped lease inventory for the effective agent.",
            mimeType="application/json",
        ),
        Resource(
            name="vault-agent-context",
            title="Hermes Vault agent context",
            uri=AnyUrl("vault://agent-context"),
            description="Redacted manifest of effective-agent access, leases, and pending requests.",
            mimeType="application/json",
        ),
        Resource(
            name="vault-policy-explain",
            title="Hermes Vault policy explain",
            uri=AnyUrl("vault://policy-explain"),
            description="Policy explanation resource. Requires query parameters: service; optional action and ttl_seconds.",
            mimeType="application/json",
        ),
        Resource(
            name="vault-requests",
            title="Hermes Vault access requests",
            uri=AnyUrl("vault://requests"),
            description="Metadata-only access requests for the effective agent.",
            mimeType="application/json",
        ),
        Resource(
            name="vault-recovery",
            title="Hermes Vault recovery drill",
            uri=AnyUrl("vault://recovery"),
            description="Redacted recovery drill resource. Requires query parameter: backup.",
            mimeType="application/json",
        ),
        Resource(
            name="vault-audit-integrity",
            title="Hermes Vault audit integrity",
            uri=AnyUrl("vault://audit-integrity"),
            description="Metadata-only audit integrity status: status, chain version, checkpoint state, verified count.",
            mimeType="application/json",
        ),
    ]
    resources.extend(await _default_agent_service_resources())
    return resources


@server.list_resource_templates()
async def list_resource_templates() -> list[ResourceTemplate]:
    return [
        ResourceTemplate(
            name="vault-service-detail",
            title="Hermes Vault service metadata",
            uriTemplate="vault://services/{name}",
            description="Metadata for one policy-visible service. Optional query parameters: agent_id, alias.",
            mimeType="application/json",
        ),
        ResourceTemplate(
            name="vault-lease-detail",
            title="Hermes Vault lease metadata",
            uriTemplate="vault://leases/{id}",
            description="Metadata for one policy-visible lease. Optional query parameter: agent_id.",
            mimeType="application/json",
        ),
        ResourceTemplate(
            name="vault-policy-explain-query",
            title="Hermes Vault policy explain query",
            uriTemplate="vault://policy-explain?service={service}&action={action}",
            description="Explain an effective-agent service action. Optional query parameters: agent_id, ttl_seconds.",
            mimeType="application/json",
        ),
        ResourceTemplate(
            name="vault-recovery-query",
            title="Hermes Vault recovery drill query",
            uriTemplate="vault://recovery?backup={path}",
            description="Run a redacted recovery drill for a local backup path. Optional query parameter: agent_id.",
            mimeType="application/json",
        ),
    ]


@server.read_resource()
async def read_resource(uri: Any) -> Any:
    settings = get_settings()
    key = _resource_key(uri)
    try:
        binding = _resolve_resource_binding(settings, uri, key)
    except ValueError as exc:
        return [_json_resource(uri, _resource_error(uri, str(exc), agent_id=None))]

    broker = _get_broker()
    agent_id = binding.effective_agent_id or ""

    try:
        if key == "vault://services":
            payload = _services_resource_payload(broker, binding)
        elif key == "vault://services/{name}":
            payload = _service_detail_resource_payload(uri, broker, binding)
        elif key == "vault://health":
            payload = _health_resource_payload(broker, binding)
        elif key == "vault://status":
            payload = _status_resource_payload(broker, binding, settings)
        elif key == "vault://policy":
            payload = _policy_resource_payload(broker, binding)
        elif key == "vault://leases":
            payload = _leases_resource_payload(broker, binding)
        elif key == "vault://leases/{id}":
            payload = _lease_detail_resource_payload(uri, broker, binding)
        elif key == "vault://agent-context":
            payload = _agent_context_resource_payload(broker, binding)
        elif key == "vault://policy-explain":
            payload = _policy_explain_resource_payload(uri, broker, binding)
        elif key == "vault://requests":
            payload = _requests_resource_payload(broker, binding)
        elif key == "vault://recovery":
            payload = _recovery_resource_payload(uri, broker, binding)
        elif key == "vault://audit-integrity":
            payload = _audit_integrity_resource_payload(broker, binding)
        else:
            raise ValueError(f"Unknown resource URI: {uri}")
    except ValueError as exc:
        payload = _resource_error(uri, str(exc), agent_id=agent_id)

    return [_json_resource(uri, payload)]


@server.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    arguments = arguments or {}
    preflight_error = _preflight_tool_arguments(name, arguments)
    if preflight_error is not None:
        return [TextContent(type="text", text=f"Error: {preflight_error}")]

    settings = get_settings()
    try:
        binding = _resolve_mcp_binding(settings, arguments, name)
    except ValueError as exc:
        return [TextContent(type="text", text=f"Error: {sanitize_oauth_error_detail(exc)}")]

    broker = _get_broker()

    try:
        if name == "list_services":
            agent_id = binding.effective_agent_id or ""
            filter_str = arguments.get("filter")
            services = broker.list_available_credentials(agent_id)
            if filter_str:
                services = [s for s in services if filter_str.lower() in s["service"].lower()]
            return [TextContent(type="text", text=_json_text(services))]

        if name == "get_credential_metadata":
            agent_id = binding.effective_agent_id or ""
            service = arguments["service"]
            alias = arguments.get("alias")
            metadata_result = broker.get_metadata(agent_id, service, alias)
            if not metadata_result.allowed:
                return [TextContent(type="text", text=f"Denied: {metadata_result.reason}")]
            payload = (
                metadata_result.record.model_dump(mode="json", exclude={"encrypted_payload"})
                if metadata_result.record
                else metadata_result.metadata
            )
            return [TextContent(type="text", text=_json_text(payload))]

        if name == "get_ephemeral_env":
            agent_id = binding.effective_agent_id or ""
            service = arguments["service"]
            alias = arguments.get("alias")
            ttl = arguments.get("ttl_seconds")
            env_result = broker.get_ephemeral_env(service, agent_id, ttl or 900, alias=alias)
            if not env_result.allowed:
                return [TextContent(type="text", text=f"Denied: {env_result.reason}")]
            expires_at = None
            if env_result.ttl_seconds is not None:
                expires_at = (datetime.now(timezone.utc) + timedelta(seconds=env_result.ttl_seconds)).isoformat()
            return [TextContent(type="text", text=_json_text({
                "env": env_result.env,
                "ttl_seconds": env_result.ttl_seconds,
                "expires_at": expires_at,
                "metadata": env_result.metadata,
            }))]

        if name == "lease_issue":
            agent_id = binding.effective_agent_id or ""
            service = arguments["service"]
            alias = arguments.get("alias")
            ttl = arguments["ttl_seconds"]
            purpose = arguments.get("purpose") or "task"
            reason = arguments.get("reason")
            lease_issue_result = broker.issue_lease(agent_id, service, ttl, alias=alias, purpose=purpose, reason=reason)
            return [TextContent(type="text", text=_json_text(lease_issue_result.model_dump(mode="json")))]

        if name == "lease_list":
            agent_id = binding.effective_agent_id or ""
            service = arguments.get("service")
            status = arguments.get("status")
            lease_list_result = broker.list_leases(agent_id, service=service, status=status)
            return [TextContent(type="text", text=_json_text(lease_list_result.model_dump(mode="json")))]

        if name == "lease_show":
            agent_id = binding.effective_agent_id or ""
            lease_id = arguments["lease_id"]
            lease_show_result = broker.show_lease(agent_id, lease_id)
            return [TextContent(type="text", text=_json_text(lease_show_result.model_dump(mode="json")))]

        if name == "lease_renew":
            agent_id = binding.effective_agent_id or ""
            lease_id = arguments["lease_id"]
            ttl = arguments["ttl_seconds"]
            lease_renew_result = broker.renew_lease(agent_id, lease_id, ttl)
            return [TextContent(type="text", text=_json_text(lease_renew_result.model_dump(mode="json")))]

        if name == "lease_revoke":
            agent_id = binding.effective_agent_id or ""
            lease_id = arguments["lease_id"]
            reason = arguments.get("reason")
            lease_revoke_result = broker.revoke_lease(agent_id, lease_id, reason=reason)
            return [TextContent(type="text", text=_json_text(lease_revoke_result.model_dump(mode="json")))]

        if name == "verify_credential":
            agent_id = binding.effective_agent_id or ""
            service = arguments["service"]
            alias = arguments.get("alias")
            allowed, reason = broker.policy.can(agent_id, service, ServiceAction.verify)
            if not allowed:
                return [TextContent(type="text", text=f"Denied: {reason}")]
            verification_result = broker.verify_credential(service, alias=alias)
            return [TextContent(type="text", text=_json_text({
                "allowed": verification_result.allowed,
                "reason": verification_result.reason,
                "metadata": verification_result.metadata,
            }))]

        if name == "rotate_credential":
            agent_id = binding.effective_agent_id or ""
            service = arguments["service"]
            alias = arguments.get("alias")
            new_secret = arguments["new_secret"]
            result = broker.rotate_credential(agent_id, service, new_secret, alias=alias)
            if not result.allowed:
                return [TextContent(type="text", text=f"Denied: {result.reason}")]
            return [TextContent(type="text", text=_json_text({
                "allowed": result.allowed,
                "reason": result.reason,
                "metadata": result.metadata,
            }))]

        if name == "scan_for_secrets":
            agent_id = binding.effective_agent_id or ""
            path = arguments.get("path")
            paths = [path] if path else None
            scan_result = broker.scan_secrets(agent_id, paths)
            if not scan_result.allowed:
                return [TextContent(type="text", text=f"Denied: {scan_result.reason}")]
            return [TextContent(type="text", text=_json_text({
                "finding_count": scan_result.metadata.get("finding_count"),
                "findings": scan_result.metadata.get("findings"),
            }))]

        # ── OAuth: initiate PKCE login ───────────────────────────────────────
        if name == "oauth_login":
            return _handle_oauth_login(arguments, broker, binding.effective_agent_id or "")

        # ── OAuth: initiate device-code login ────────────────────────────────
        if name == "oauth_device_login":
            return _handle_oauth_device_login(arguments, broker, binding.effective_agent_id or "")

        # ── OAuth: provider readiness ────────────────────────────────────────
        if name == "oauth_provider_status":
            return _handle_oauth_provider_status(arguments)

        # ── OAuth: refresh token ─────────────────────────────────────────────
        if name == "oauth_refresh":
            return _handle_oauth_refresh(arguments, broker, binding.effective_agent_id or "")

        if name == "request_access":
            agent_id = binding.effective_agent_id or ""
            access_result = broker.request_access(
                agent_id=agent_id,
                service=arguments["service"],
                alias=arguments.get("alias") or "default",
                action=arguments.get("action") or "get_env",
                purpose=arguments["purpose"],
                requested_ttl_seconds=arguments.get("ttl_seconds"),
            )
            return [TextContent(type="text", text=_json_text(access_result.model_dump(mode="json")))]

        if name == "policy_explain":
            agent_id = binding.effective_agent_id or ""
            payload = broker.policy.explain(
                agent_id,
                arguments["service"],
                arguments.get("action") or "get_env",
                requested_ttl=arguments.get("ttl_seconds"),
            )
            return [TextContent(type="text", text=_json_text(payload))]

        if name == "lease_checkout":
            agent_id = binding.effective_agent_id or ""
            checkout_result = broker.lease_checkout(
                agent_id=agent_id,
                service=arguments["service"],
                alias=arguments.get("alias"),
                ttl_seconds=arguments.get("ttl_seconds") or 900,
                purpose=arguments.get("purpose") or "task",
            )
            if not checkout_result.allowed:
                return [TextContent(type="text", text=f"Denied: {checkout_result.reason}")]
            expires_at = None
            if checkout_result.ttl_seconds is not None:
                expires_at = (datetime.now(timezone.utc) + timedelta(seconds=checkout_result.ttl_seconds)).isoformat()
            return [TextContent(type="text", text=_json_text({
                "env": checkout_result.env,
                "ttl_seconds": checkout_result.ttl_seconds,
                "expires_at": expires_at,
                "metadata": checkout_result.metadata,
            }))]

        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except ValueError as exc:
        return [TextContent(type="text", text=f"Error: {sanitize_oauth_error_detail(exc)}")]
    except Exception as exc:
        logger.exception("Unhandled error in tool %s", name)
        return [TextContent(type="text", text=f"Internal error: {sanitize_oauth_error_detail(exc)}")]


# ── OAuth tool implementations ───────────────────────────────────────────────

def _handle_oauth_login(arguments: dict[str, Any], broker: Broker, agent_id: str) -> list[TextContent]:
    """Handle the oauth_login MCP tool call.

    1. Look up provider in registry
    2. Generate PKCE + state
    3. Start callback server in a background thread
    4. Return auth URL to the caller immediately
    5. Callback handler auto-exchanges code and stores tokens
    """
    # Accept both "provider" and "provider_id" for backwards-compat with tests
    provider_id = (arguments.get("provider_id") or arguments.get("provider") or "").strip().lower()
    alias = arguments.get("alias", "default") or "default"
    port = arguments.get("port", 0) or 0
    requested_scopes = arguments.get("scopes") or []

    if not provider_id:
        return [TextContent(type="text", text="Error: Missing required parameter: provider")]

    # Policy check — agent must be allowed to add credentials for this service
    allowed, reason = broker.policy.can(agent_id, provider_id, ServiceAction.add_credential)
    if not allowed:
        return [TextContent(type="text", text=f"Denied: {reason}")]

    try:
        settings = get_settings()
        registry = OAuthProviderRegistry(
            settings.runtime_home / "oauth-providers.yaml",
        )
    except Exception as exc:
        return [TextContent(type="text", text=f"Error: {sanitize_oauth_error_detail(exc)}")]

    provider = registry.get(provider_id)
    if provider is None:
        known = registry.list_providers()
        return [TextContent(type="text", text=_json_text({
            "success": False,
            "error": f"Unknown OAuth provider '{provider_id}'. Known providers: {known}",
        }))]

    # Client credentials
    client_id, client_secret = registry.get_client_credentials(provider)
    if provider.requires_client_id and not client_id:
        return [TextContent(type="text", text=_json_text({
            "success": False,
            "error": f"Provider '{provider_id}' requires a client_id. Set HERMES_VAULT_OAUTH_{provider_id.upper()}_CLIENT_ID.",
        }))]

    # PKCE + state
    code_verifier, code_challenge = _generate_pkce()
    state = _generate_state()

    # Start callback server
    callback_server = CallbackServer(port=port, timeout=120)
    actual_port = callback_server.start()
    redirect_uri = f"http://127.0.0.1:{actual_port}/callback"

    # Build authorization URL
    requested_scopes = requested_scopes if requested_scopes else provider.default_scopes
    scope_str = provider.scope_separator.join(requested_scopes)
    auth_params: dict[str, str] = {
        "response_type": "code",
        "client_id": client_id or "",
        "redirect_uri": redirect_uri,
        "scope": scope_str,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    for k, v in provider.extra_params.items():
        auth_params.setdefault(k, v)
    if not client_id and not provider.requires_client_id:
        auth_params.pop("client_id", None)

    auth_url = str(provider.authorization_endpoint) + "?" + urllib.parse.urlencode(auth_params)

    # Track pending login (so callback can validate state + exchange)
    # Include profile to prevent cross-profile OAuth collisions
    settings = get_settings()
    login_id = secrets.token_urlsafe(12)
    pending_key = f"browser:{settings.profile_name}:{provider_id}:{alias}:{login_id}"
    _pending_oauth[pending_key] = {
        "login_id": login_id,
        "state": state,
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
        "provider_id": provider_id,
        "alias": alias,
        "client_id": client_id,
        "client_secret": client_secret,
        "scopes": requested_scopes,
        "broker": broker,
        "profile_name": settings.profile_name,
    }

    # Attach auto-exchange handler onto CallbackServer's result mechanism.
    # Because CallbackServer uses class-level static state, we spin a
    # background thread that waits for the callback, then completes the flow.
    def _wait_and_exchange() -> None:
        try:
            result = callback_server.wait()
            _exchange_and_store(result, pending_key)
        except Exception:
            logger.exception("OAuth callback exchange failed for %s", pending_key)
        finally:
            _pending_oauth.pop(pending_key, None)

    thread = threading.Thread(target=_wait_and_exchange, daemon=True)
    thread.start()

    return [TextContent(type="text", text=_json_text({
        "success": True,
        "login_id": login_id,
        "authorization_url": auth_url,
        "redirect_uri": redirect_uri,
        "state": state,
        "message": f"Open the authorization_url in a browser for alias '{alias}'. Tokens will be stored automatically upon completion.",
    }))]


def _exchange_and_store(result: Any, pending_key: str) -> None:
    """Background-thread callback handler: exchanges code for tokens and stores them."""
    info = _pending_oauth.pop(pending_key, None)
    if info is None:
        logger.warning("OAuth callback for %s but no pending entry", pending_key)
        return

    broker = info["broker"]
    provider_id = info["provider_id"]

    # Build registry + provider — use the stored profile to avoid default fallback
    settings = get_settings(profile=info.get("profile_name"))
    registry = OAuthProviderRegistry(settings.runtime_home / "oauth-providers.yaml")
    provider = registry.get(provider_id)
    if provider is None:
        logger.error("Provider %s disappeared during OAuth flow", provider_id)
        return

    # Map CallbackResult fields
    if hasattr(result, "error") and result.error:
        if result.error == "timeout":
            logger.warning("OAuth callback timed out for %s", pending_key)
        elif result.error == "access_denied":
            logger.warning("OAuth authorization denied for %s", pending_key)
        else:
            logger.error("OAuth callback error for %s: %s", pending_key, result.error)
        return

    # Validate state — required, not optional
    if not hasattr(result, "state") or not result.state:
        logger.error("No state in callback for %s — possible CSRF", pending_key)
        return
    if not secrets.compare_digest(info["state"], result.state):
        logger.error("State mismatch for %s — possible CSRF", pending_key)
        return

    code = result.code if hasattr(result, "code") else None
    if not code:
        logger.error("No authorization code in callback for %s", pending_key)
        return

    # Exchange code for tokens
    try:
        exchanger = TokenExchanger(provider)
        token_response = exchanger.exchange(
            code=code,
            redirect_uri=info["redirect_uri"],
            code_verifier=info["code_verifier"],
            client_id=info["client_id"],
            client_secret=info["client_secret"],
        )
    except Exception:
        logger.exception("Token exchange failed for %s", pending_key)
        return

    # Store access token
    try:
        credential_secret = token_response.to_credential_secret(provider)
        mutations = VaultMutations(
            vault=broker.vault,
            policy=broker.policy,
            audit=broker.audit,
        )
        add_result = mutations.add_credential(
            agent_id=OPERATOR_AGENT_ID,
            service=provider.service_id,
            secret=credential_secret.secret,
            credential_type="oauth_access_token",
            alias=info["alias"],
            scopes=info["scopes"],
            metadata=credential_secret.metadata,
            replace_existing=True,
        )
        if not add_result.allowed:
            logger.error("Vault refused OAuth credential storage for %s: %s", pending_key, add_result.reason)
            return
        record = add_result.record
        assert record is not None

        # Set expiry if provided
        if token_response.expires_in is not None:
            expiry = datetime.now(timezone.utc) + timedelta(seconds=token_response.expires_in)
            broker.vault.set_expiry(record.id, expiry)

        # Store refresh token separately at an alias-scoped refresh record.
        if token_response.refresh_token:
            refresh_secret = CredentialSecret(
                secret=token_response.refresh_token,
                metadata={
                    "associated_access_token_alias": info["alias"],
                    "provider": provider.service_id,
                },
            )
            mutations.add_credential(
                agent_id=OPERATOR_AGENT_ID,
                service=provider.service_id,
                secret=refresh_secret.secret,
                credential_type="oauth_refresh_token",
                alias=refresh_alias_for(info["alias"]),
                scopes=info["scopes"],
                metadata=refresh_secret.metadata,
                replace_existing=True,
            )

        logger.info("OAuth login succeeded and stored for %s record=%s", pending_key, record.id)
    except Exception:
        logger.exception("Storing OAuth tokens failed for %s", pending_key)


def _handle_oauth_device_login(arguments: dict[str, Any], broker: Broker, agent_id: str) -> list[TextContent]:
    """Handle oauth_device_login by starting device-code polling in the background."""
    provider_id = (arguments.get("provider_id") or arguments.get("provider") or "").strip().lower()
    alias = arguments.get("alias", "default") or "default"
    requested_scopes = arguments.get("scopes") or []
    timeout_seconds = int(arguments.get("timeout_seconds") or 300)

    if not provider_id:
        return [TextContent(type="text", text="Error: Missing required parameter: provider_id")]

    allowed, reason = broker.policy.can(agent_id, provider_id, ServiceAction.add_credential)
    if not allowed:
        return [TextContent(type="text", text=f"Denied: {reason}")]

    try:
        settings = get_settings()
        registry = OAuthProviderRegistry(settings.runtime_home / "oauth-providers.yaml")
        provider = registry.get(provider_id)
        if provider is None:
            readiness = provider_readiness(registry, provider_id)
            return [TextContent(type="text", text=_json_text({
                "success": False,
                "error": f"Unknown OAuth provider '{provider_id}'. Known providers: {registry.list_providers()}",
                "provider_status": readiness.as_dict(),
            }))]
        if provider.device_authorization_endpoint is None:
            readiness = provider_readiness(registry, provider_id)
            return [TextContent(type="text", text=_json_text({
                "success": False,
                "error": f"Provider '{provider_id}' does not support device-code login.",
                "supported_providers": registry.list_device_code_providers(),
                "fallback_command": f"hermes-vault oauth login {provider_id} --alias {alias} --no-browser",
                "provider_status": readiness.as_dict(),
            }))]

        client_id, client_secret = registry.get_client_credentials(provider)
        if provider.requires_client_id and not client_id:
            readiness = provider_readiness(registry, provider_id)
            return [TextContent(type="text", text=_json_text({
                "success": False,
                "error": f"Provider '{provider_id}' requires a client_id. Set HERMES_VAULT_OAUTH_{provider_id.upper()}_CLIENT_ID.",
                "missing_env": readiness.missing_env,
                "provider_status": readiness.as_dict(),
            }))]

        scopes = requested_scopes if requested_scopes else provider.default_scopes
        scope_str = provider.scope_separator.join(scopes)
        exchanger = TokenExchanger(provider)
        device_response = exchanger.request_device_code(
            client_id=client_id or "",
            scope=scope_str,
            client_secret=client_secret,
            extra_params=getattr(provider, "device_extra_params", None) or None,
        )
        pending_key = f"device:{settings.profile_name}:{provider_id}:{alias}:{secrets.token_urlsafe(8)}"
        _pending_oauth[pending_key] = {
            "provider_id": provider_id,
            "alias": alias,
            "profile_name": settings.profile_name,
            "started_at": time.time(),
        }

        def _poll_and_store() -> None:
            poll_interval = max(1, device_response.interval or 5)
            deadline = time.monotonic() + timeout_seconds
            try:
                while True:
                    if time.monotonic() >= deadline:
                        logger.warning("MCP device login timed out for %s", pending_key)
                        return
                    poll = exchanger.poll_device_code(
                        device_code=device_response.device_code,
                        client_id=client_id or "",
                        client_secret=client_secret,
                    )
                    if poll.status == "success":
                        assert poll.token_response is not None
                        mutations = VaultMutations(vault=broker.vault, policy=broker.policy, audit=broker.audit)
                        with open(os.devnull, "w") as sink:
                            _store_oauth_tokens(
                                provider=provider,
                                alias=alias,
                                requested_scopes=scopes,
                                token_response=poll.token_response,
                                vault=broker.vault,
                                mutations=mutations,
                                console=Console(file=sink),
                            )
                        logger.info("MCP device login succeeded for %s", pending_key)
                        return
                    if poll.status == "slow_down":
                        poll_interval += poll.retry_after or 5
                    elif poll.status in {"access_denied", "expired_token"}:
                        logger.warning("MCP device login ended with %s for %s", poll.status, pending_key)
                        return
                    elif poll.status != "authorization_pending":
                        logger.warning("MCP device login failed with %s for %s", poll.status, pending_key)
                        return
                    time.sleep(min(poll_interval, max(0.1, deadline - time.monotonic())))
            except Exception:
                logger.exception("MCP device login polling failed for %s", pending_key)
            finally:
                _pending_oauth.pop(pending_key, None)

        threading.Thread(target=_poll_and_store, daemon=True).start()
        return [TextContent(type="text", text=_json_text({
            "success": True,
            "provider_id": provider_id,
            "alias": alias,
            "verification_uri": device_response.verification_uri,
            "verification_uri_complete": device_response.verification_uri_complete,
            "user_code": device_response.user_code,
            "expires_in": device_response.expires_in,
            "interval": device_response.interval,
            "pending_key": pending_key,
            "message": device_response.message or "Open verification_uri and enter user_code. Tokens will be stored automatically after approval.",
            "raw_tokens_returned": False,
        }))]
    except Exception as exc:
        return [TextContent(type="text", text=f"Error: {sanitize_oauth_error_detail(exc)}")]


def _handle_oauth_provider_status(arguments: dict[str, Any]) -> list[TextContent]:
    provider_id = (arguments.get("provider_id") or arguments.get("provider") or "").strip().lower()
    if not provider_id:
        return [TextContent(type="text", text="Error: Missing required parameter: provider_id")]
    settings = get_settings()
    registry = OAuthProviderRegistry(settings.runtime_home / "oauth-providers.yaml")
    report = provider_readiness(registry, provider_id)
    return [TextContent(type="text", text=_json_text(report.as_dict()))]


def _handle_oauth_refresh(arguments: dict[str, Any], broker: Broker, agent_id: str) -> list[TextContent]:
    """Handle the oauth_refresh MCP tool call."""
    service = arguments.get("service", "").strip().lower()
    alias = arguments.get("alias") or "default"
    dry_run = bool(arguments.get("dry_run", False))

    if not service:
        return [TextContent(type="text", text="Error: Missing required parameter: service")]

    # Refresh mutates stored OAuth tokens, so it requires rotate permission.
    allowed, reason = broker.policy.can(agent_id, service, ServiceAction.rotate)
    if not allowed:
        return [TextContent(type="text", text=f"Denied: {reason}")]

    try:
        engine = RefreshEngine(vault=broker.vault)
        engine.set_audit(broker.audit)
        attempt = engine.refresh(service=service, alias=alias, dry_run=dry_run)
        return [TextContent(type="text", text=_json_text({
            "success": attempt.success,
            "service": attempt.service,
            "alias": attempt.alias,
            "reason": sanitize_oauth_error_detail(attempt.reason),
            "new_access_token_preview": (attempt.new_access_token[:12] + "...") if attempt.new_access_token else None,
            "new_refresh_token_preview": (attempt.new_refresh_token[:12] + "...") if attempt.new_refresh_token else None,
            "access_token_rotated": bool(attempt.new_access_token),
            "refresh_token_rotated": bool(attempt.new_refresh_token),
            "expires_in": attempt.expires_in,
            "scopes": attempt.scopes,
            "retry_count": attempt.retry_count,
        }))]
    except Exception as exc:
        exc_str = str(exc).lower()
        if "no credential" in exc_str or "refresh token" in exc_str:
            return [TextContent(type="text", text=f"Error: No refresh token found for '{service}'. Use oauth_login to re-authenticate.")]
        return [TextContent(type="text", text=f"Error: {sanitize_oauth_error_detail(exc)}")]


# ── entrypoint ─────────────────────────────────────────────────────────────────

async def main() -> None:
    log_path = Path.home() / ".hermes" / "hermes-vault-data" / "mcp.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        filename=str(log_path),
    )
    global _broker
    _broker = _get_broker()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
