"""MCP server transport for Hermes Vault.

Exposes brokered vault capabilities as MCP tools over stdio.
All tool calls require an ``agent_id`` so that policy v2 enforcement
works unchanged.
"""

from __future__ import annotations

"""MCP server transport for Hermes Vault.

Exposes brokered vault capabilities as MCP tools over stdio.
All tool calls require an ``agent_id`` so that policy v2 enforcement
works unchanged.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.config import get_settings
from hermes_vault.crypto import resolve_passphrase
from hermes_vault.models import CredentialSecret, CredentialStatus, ServiceAction
from hermes_vault.mutations import OPERATOR_AGENT_ID, VaultMutations
from hermes_vault.oauth.callback import CallbackServer
from hermes_vault.oauth.errors import OAuthProviderError
from hermes_vault.oauth.exchange import TokenExchanger
from hermes_vault.oauth.oauth_refresh import RefreshEngine
from hermes_vault.oauth.providers import OAuthProviderRegistry
from hermes_vault.policy import PolicyEngine
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
    "oauth_login": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Agent identity for policy enforcement"},
            "provider_id": {"type": "string", "description": "OAuth provider ID (e.g. google, github)"},
            "alias": {"type": "string", "description": "Credential alias (default: default)"},
            "scopes": {"type": "array", "items": {"type": "string"}, "description": "Optional OAuth scopes"},
            "port": {"type": "integer", "description": "Callback server port (0 = auto-assigned)"},
        },
        "required": ["agent_id", "provider_id"],
    },
    "oauth_refresh": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Agent identity for policy enforcement"},
            "service": {"type": "string", "description": "Service name or credential ID"},
            "alias": {"type": "string", "description": "Optional alias for disambiguation"},
            "dry_run": {"type": "boolean", "description": "Simulate without updating vault"},
        },
        "required": ["agent_id", "service"],
    },
}
        "type": "object",
        "properties": {
            "provider": {"type": "string", "description": "OAuth provider ID (e.g. google, github, openai)"},
            "alias": {"type": "string", "description": "Vault alias for the stored credential. Defaults to 'default'"},
            "scopes": {"type": "array", "items": {"type": "string"}, "description": "Optional list of requested scopes"},
            "agent_id": {"type": "string", "description": "Agent identity for policy enforcement"},
        },
        "required": ["provider", "agent_id"],
    },
    "oauth_refresh": {
        "type": "object",
        "properties": {
            "service": {"type": "string", "description": "Service name to refresh (e.g. google, github)"},
            "alias": {"type": "string", "description": "Alias of the access token to refresh. Defaults to 'default'"},
            "agent_id": {"type": "string", "description": "Agent identity for policy enforcement"},
        },
        "required": ["service", "agent_id"],
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


# ── OAuth helpers ──────────────────────────────────────────────────────────────

# In-memory store for PKCE login flows initiated via MCP.
# Key: (provider_id, alias), Value: (code_verifier, state, callback_url)
_oauth_flows: dict[tuple[str, str], dict[str, Any]] = {}

# Default timeout for the ephemeral callback server (seconds).
_OAUTH_CALLBACK_TIMEOUT = 120


def _get_registry() -> OAuthProviderRegistry:
    """Load the OAuth provider registry from the default path."""
    settings = get_settings()
    return OAuthProviderRegistry(settings.runtime_home / "oauth-providers.yaml")


async def _tool_oauth_login(arguments: dict[str, Any], broker: Broker) -> list[TextContent]:
    """Initiate a PKCE OAuth login flow.

    Returns an authorization URL that the caller (e.g. Hermes in an MCP
    session) should open in a browser.  Tokens are stored in the vault upon
    successful callback.
    """
    agent_id = arguments.get("agent_id")
    if not agent_id:
        return [TextContent(type="text", text="Error: Missing required parameter: agent_id")]
    provider_id = arguments.get("provider")
    if not provider_id:
        return [TextContent(type="text", text="Error: Missing required parameter: provider")]
    alias = arguments.get("alias") or "default"
    requested_scopes = arguments.get("scopes") or []

    # Agent must have add_credential permission for this service
    allowed, reason = broker.policy.can(agent_id, provider_id, "add_credential")
    if not allowed:
        return [TextContent(type="text", text=f"Denied: {reason}")]

    # Load provider config
    registry = _get_registry()
    provider = registry.get(provider_id)
    if provider is None:
        known = registry.list_providers()
        return [TextContent(type="text", text=f"Error: Unknown provider '{provider_id}'. Known: {', '.join(known) or 'none'}")]

    # Resolve client credentials
    client_id, client_secret = registry.get_client_credentials(provider)
    if provider.requires_client_id and not client_id:
        return [TextContent(type="text", text=f"Error: Provider '{provider_id}' requires a client_id. "
            f"Set HERMES_VAULT_OAUTH_{provider_id.upper()}_CLIENT_ID.")]

    # Generate PKCE
    pkce = PKCEGenerator()
    code_verifier = pkce.generate_verifier()
    code_challenge = pkce.generate_challenge(code_verifier)
    state = secrets.token_urlsafe(32)

    # Start ephemeral callback server
    try:
        server = CallbackServer(port=0, timeout=_OAUTH_CALLBACK_TIMEOUT)
        actual_port = server.start()
    except Exception as exc:
        logger.exception("Failed to start callback server")
        return [TextContent(type="text", text=f"Error: Failed to start callback server: {exc}")]

    redirect_uri = f"http://127.0.0.1:{actual_port}/callback"

    # Build authorization URL
    scopes = requested_scopes if requested_scopes else provider.default_scopes
    scope_str = provider.scope_separator.join(scopes)
    auth_params: dict[str, str] = {
        "response_type": "code",
        "client_id": client_id or "",
        "redirect_uri": redirect_uri,
        "scope": scope_str,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    for key, value in provider.extra_params.items():
        auth_params.setdefault(key, value)
    if not client_id and not provider.requires_client_id:
        auth_params.pop("client_id", None)

    auth_url = str(provider.authorization_endpoint) + "?" + urllib.parse.urlencode(auth_params)

    # Store flow state keyed by (provider, alias)
    flow_key = (provider_id, alias)
    _oauth_flows[flow_key] = {
        "code_verifier": code_verifier,
        "state": state,
        "server": server,
        "provider": provider,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
        "scopes": scopes,
        "agent_id": agent_id,
        "alias": alias,
    }

    # Spawn a background thread to await the callback and store tokens.
    thread = threading.Thread(
        target=_await_oauth_callback,
        args=(flow_key, broker.vault),
        daemon=True,
    )
    thread.start()

    return [TextContent(type="text", text=_json_text({
        "authorization_url": auth_url,
        "redirect_uri": redirect_uri,
        "provider": provider_id,
        "alias": alias,
        "message": (
            f"Please open the authorization_url in your browser. "
            f"After authorization, tokens will be stored in the vault under alias '{alias}'."
        ),
    }))]


def _await_oauth_callback(flow_key: tuple[str, str], vault: Vault) -> None:
    """Background thread: waits for callback, exchanges code for tokens, stores in vault."""
    flow = _oauth_flows.get(flow_key)
    if flow is None:
        logger.error("OAuth flow not found for key %s", flow_key)
        return
    server: CallbackServer = flow["server"]
    try:
        result = server.wait()
    except Exception as exc:
        logger.exception("Error waiting for OAuth callback")
        _oauth_flows.pop(flow_key, None)
        return

    # Handle errors
    if result.error == "timeout":
        logger.warning("OAuth callback timed out for %s", flow_key)
        _oauth_flows.pop(flow_key, None)
        return
    if result.error == "access_denied":
        logger.warning("OAuth denied by user/provider for %s", flow_key)
        _oauth_flows.pop(flow_key, None)
        return
    if result.error:
        logger.error("OAuth callback error for %s: %s -- %s", flow_key, result.error, result.error_description or "")
        _oauth_flows.pop(flow_key, None)
        return

    # Validate state
    if result.state != flow["state"]:
        logger.error("OAuth state mismatch for %s", flow_key)
        _oauth_flows.pop(flow_key, None)
        return

    if not result.code:
        logger.error("No authorization code in callback for %s", flow_key)
        _oauth_flows.pop(flow_key, None)
        return

    provider = flow["provider"]
    try:
        exchanger = TokenExchanger(provider)
        token_response = exchanger.exchange(
            code=result.code,
            redirect_uri=flow["redirect_uri"],
            code_verifier=flow["code_verifier"],
            client_id=flow["client_id"],
            client_secret=flow["client_secret"],
        )
    except (OAuthNetworkError, OAuthProviderError, Exception) as exc:
        logger.exception("Token exchange failed for %s", flow_key)
        _oauth_flows.pop(flow_key, None)
        return

    # Build mutations and store
    try:
        from hermes_vault.config import get_settings
        settings = get_settings()
        policy = PolicyEngine.from_yaml(settings.effective_policy_path)
        audit = AuditLogger(settings.db_path)
        mutations = VaultMutations(vault=vault, policy=policy, audit=audit)

        credential_secret = token_response.to_credential_secret(provider)
        mutation_result = mutations.add_credential(
            agent_id=OPERATOR_AGENT_ID,
            service=provider.service_id,
            secret=credential_secret.secret,
            credential_type="oauth_access_token",
            alias=flow["alias"],
            scopes=flow["scopes"],
            replace_existing=True,
        )
        if not mutation_result.allowed:
            logger.error("Vault refused credential storage: %s", mutation_result.reason)
            _oauth_flows.pop(flow_key, None)
            return

        record = mutation_result.record
        assert record is not None

        # Set expiry
        from datetime import datetime, timedelta, timezone
        if token_response.expires_in is not None:
            expiry = datetime.now(timezone.utc) + timedelta(seconds=token_response.expires_in)
            vault.set_expiry(record.id, expiry)

        # Store refresh token separately at alias "refresh"
        if token_response.refresh_token:
            refresh_secret = CredentialSecret(
                secret=token_response.refresh_token,
                metadata={
                    "associated_access_token_alias": flow["alias"],
                    "provider": provider.service_id,
                },
            )
            mutations.add_credential(
                agent_id=OPERATOR_AGENT_ID,
                service=provider.service_id,
                secret=refresh_secret.secret,
                credential_type="oauth_refresh_token",
                alias="refresh",
                scopes=flow["scopes"],
                replace_existing=True,
            )

        logger.info(
            "Stored OAuth credential %s for %s alias '%s'",
            record.id, provider.service_id, flow["alias"],
        )
    except Exception:
        logger.exception("Failed to store OAuth tokens for %s", flow_key)
    finally:
        _oauth_flows.pop(flow_key, None)


async def _tool_oauth_refresh(arguments: dict[str, Any], broker: Broker) -> list[TextContent]:
    """Refresh an OAuth access token for a service."""
    agent_id = arguments.get("agent_id")
    if not agent_id:
        return [TextContent(type="text", text="Error: Missing required parameter: agent_id")]
    service = arguments.get("service")
    if not service:
        return [TextContent(type="text", text="Error: Missing required parameter: service")]
    alias = arguments.get("alias") or "default"

    # Agent must have rotate permission to refresh tokens
    allowed, reason = broker.policy.can(agent_id, service, "rotate")
    if not allowed:
        return [TextContent(type="text", text=f"Denied: {reason}")]

    try:
        engine = RefreshEngine(vault=broker.vault)
        attempt = engine.refresh(service, alias=alias, dry_run=False)
    except RefreshTokenMissingError as exc:
        return [TextContent(type="text", text=f"Error: {exc} — re-authentication required. Use oauth_login.")]
    except KeyError as exc:
        return [TextContent(type="text", text=f"Error: {exc} — re-authentication required. Use oauth_login.")]
    except OAuthProviderError as exc:
        return [TextContent(type="text", text=f"Error: Provider rejected refresh: {exc}")]
    except OAuthNetworkError as exc:
        return [TextContent(type="text", text=f"Error: Network failure during refresh: {exc}")]
    except Exception as exc:
        logger.exception("Unhandled error during oauth_refresh")
        return [TextContent(type="text", text=f"Internal error: {exc}")]

    if not attempt.success:
        return [TextContent(type="text", text=f"Error: Refresh failed — {attempt.reason}")]

    return [TextContent(type="text", text=_json_text({
        "success": True,
        "service": attempt.service,
        "alias": attempt.alias,
        "new_access_token_truncated": (
            attempt.new_access_token[:10] + "..."
            if attempt.new_access_token and len(attempt.new_access_token) > 10
            else attempt.new_access_token
        ),
        "new_refresh_token": "rotated" if attempt.new_refresh_token else "unchanged",
        "expires_in": attempt.expires_in,
        "scopes": attempt.scopes,
        "retry_count": attempt.retry_count,
    }))]


# ── server ─────────────────────────────────────────────────────────────────────

server = Server("hermes-vault", version="0.5.0")


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
        Tool(
            name="oauth_login",
            description="Initiate a PKCE OAuth login flow for a provider. Returns an authorization URL to open in a browser.",
            inputSchema=_TOOL_SCHEMAS["oauth_login"],
        ),
        Tool(
            name="oauth_refresh",
            description="Refresh an OAuth access token for a service using its stored refresh token.",
            inputSchema=_TOOL_SCHEMAS["oauth_refresh"],
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

        if name == "oauth_login":
            return await _tool_oauth_login(arguments, broker)

        if name == "oauth_refresh":
            return await _tool_oauth_refresh(arguments, broker)

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
