"""MCP server transport for Hermes Vault.

Exposes brokered vault capabilities as MCP tools over stdio.
All tool calls require an ``agent_id`` so that policy v2 enforcement
works unchanged.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.config import get_settings
from hermes_vault.crypto import resolve_passphrase
from hermes_vault.models import ServiceAction
from hermes_vault.mutations import VaultMutations
from hermes_vault.policy import PolicyEngine
from hermes_vault.scanner import Scanner
from hermes_vault.verifier import Verifier
from hermes_vault.vault import Vault

logger = logging.getLogger("hermes_vault.mcp")

# ── tool schemas ───────────────────────────────────────────────────────────────

_TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "list_services": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Agent identity for policy enforcement"},
            "filter": {"type": "string", "description": "Optional substring filter on service names"},
        },
        "required": ["agent_id"],
    },
    "get_credential_metadata": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Agent identity for policy enforcement"},
            "service": {"type": "string", "description": "Service name or credential ID"},
            "alias": {"type": "string", "description": "Optional alias for disambiguation"},
        },
        "required": ["agent_id", "service"],
    },
    "get_ephemeral_env": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Agent identity for policy enforcement"},
            "service": {"type": "string", "description": "Service name or credential ID"},
            "alias": {"type": "string", "description": "Optional alias for disambiguation"},
            "ttl_seconds": {"type": "integer", "description": "Optional TTL in seconds (subject to policy ceiling)"},
        },
        "required": ["agent_id", "service"],
    },
    "verify_credential": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Agent identity for policy enforcement"},
            "service": {"type": "string", "description": "Service name or credential ID"},
            "alias": {"type": "string", "description": "Optional alias for disambiguation"},
        },
        "required": ["agent_id", "service"],
    },
    "rotate_credential": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Agent identity for policy enforcement"},
            "service": {"type": "string", "description": "Service name or credential ID"},
            "alias": {"type": "string", "description": "Optional alias for disambiguation"},
            "new_secret": {"type": "string", "description": "New secret value"},
        },
        "required": ["agent_id", "service", "new_secret"],
    },
    "scan_for_secrets": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Agent identity for policy enforcement"},
            "path": {"type": "string", "description": "Optional path to scan (defaults to ~/.hermes)"},
        },
        "required": ["agent_id"],
    },
}


# ── broker lifecycle ───────────────────────────────────────────────────────────

_broker: Broker | None = None


def _build_broker() -> Broker:
    """Initialise vault, policy, and broker — same rules as the CLI."""
    settings = get_settings()
    policy = PolicyEngine.from_yaml(settings.effective_policy_path)
    policy.write_default(settings.effective_policy_path)
    passphrase = resolve_passphrase(prompt=False)
    vault = Vault(settings.db_path, settings.salt_path, passphrase)
    audit = AuditLogger(settings.db_path)
    verifier = Verifier()
    scanner = Scanner(settings, policy=policy)
    return Broker(vault=vault, policy=policy, verifier=verifier, audit=audit, scanner=scanner)


def _get_broker() -> Broker:
    """Return the cached broker, building lazily if needed (e.g. in tests)."""
    global _broker
    if _broker is None:
        _broker = _build_broker()
    return _broker


# ── helpers ────────────────────────────────────────────────────────────────────

def _require_agent_id(arguments: dict[str, Any]) -> str:
    agent_id = arguments.get("agent_id")
    if not agent_id:
        raise ValueError("Missing required parameter: agent_id")
    return agent_id


def _json_text(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


# ── server ─────────────────────────────────────────────────────────────────────

server = Server("hermes-vault", version="0.3.1")


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
    ]


@server.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    # Fast-fail on missing agent_id before expensive vault init
    if name in _TOOL_SCHEMAS and "agent_id" in _TOOL_SCHEMAS[name].get("required", []):
        if not arguments.get("agent_id"):
            return [TextContent(type="text", text="Error: Missing required parameter: agent_id")]

    broker = _get_broker()

    try:
        if name == "list_services":
            agent_id = _require_agent_id(arguments)
            filter_str = arguments.get("filter")
            services = broker.list_available_credentials(agent_id)
            if filter_str:
                services = [s for s in services if filter_str.lower() in s["service"].lower()]
            return [TextContent(type="text", text=_json_text(services))]

        if name == "get_credential_metadata":
            agent_id = _require_agent_id(arguments)
            service = arguments["service"]
            alias = arguments.get("alias")
            result = broker.get_metadata(agent_id, service, alias)
            if not result.allowed:
                return [TextContent(type="text", text=f"Denied: {result.reason}")]
            payload = (
                result.record.model_dump(mode="json", exclude={"encrypted_payload"})
                if result.record
                else result.metadata
            )
            return [TextContent(type="text", text=_json_text(payload))]

        if name == "get_ephemeral_env":
            agent_id = _require_agent_id(arguments)
            service = arguments["service"]
            alias = arguments.get("alias")
            ttl = arguments.get("ttl_seconds")
            result = broker.get_ephemeral_env(service, agent_id, ttl or 900, alias=alias)
            if not result.allowed:
                return [TextContent(type="text", text=f"Denied: {result.reason}")]
            expires_at = None
            if result.ttl_seconds is not None:
                from datetime import datetime, timezone, timedelta
                expires_at = (datetime.now(timezone.utc) + timedelta(seconds=result.ttl_seconds)).isoformat()
            return [TextContent(type="text", text=_json_text({
                "env": result.env,
                "ttl_seconds": result.ttl_seconds,
                "expires_at": expires_at,
            }))]

        if name == "verify_credential":
            agent_id = _require_agent_id(arguments)
            service = arguments["service"]
            alias = arguments.get("alias")
            allowed, reason = broker.policy.can(agent_id, service, ServiceAction.verify)
            if not allowed:
                return [TextContent(type="text", text=f"Denied: {reason}")]
            result = broker.verify_credential(service, alias=alias)
            return [TextContent(type="text", text=_json_text({
                "allowed": result.allowed,
                "reason": result.reason,
                "metadata": result.metadata,
            }))]

        if name == "rotate_credential":
            agent_id = _require_agent_id(arguments)
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
            agent_id = _require_agent_id(arguments)
            path = arguments.get("path")
            paths = [path] if path else None
            result = broker.scan_secrets(agent_id, paths)
            if not result.allowed:
                return [TextContent(type="text", text=f"Denied: {result.reason}")]
            return [TextContent(type="text", text=_json_text({
                "finding_count": result.metadata.get("finding_count"),
                "findings": result.metadata.get("findings"),
            }))]

        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except ValueError as exc:
        return [TextContent(type="text", text=f"Error: {exc}")]
    except Exception as exc:
        logger.exception("Unhandled error in tool %s", name)
        return [TextContent(type="text", text=f"Internal error: {exc}")]


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
