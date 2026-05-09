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
from mcp.types import TextContent, Tool

from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.config import get_settings
from hermes_vault.crypto import resolve_passphrase
from hermes_vault.models import AccessLogRecord, CredentialSecret, CredentialStatus, Decision, ServiceAction
from hermes_vault.mutations import OPERATOR_AGENT_ID, VaultMutations
from hermes_vault.oauth.callback import CallbackServer
from hermes_vault.oauth.errors import OAuthProviderError
from hermes_vault.oauth.exchange import TokenExchanger
from hermes_vault.oauth.oauth_refresh import RefreshEngine, refresh_alias_for
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


def _preflight_tool_arguments(name: str, arguments: dict[str, Any]) -> str | None:
    if name in {"get_credential_metadata", "get_ephemeral_env", "verify_credential", "rotate_credential"}:
        if _normalize_agent_id(arguments.get("service")) is None:
            return "Missing required parameter: service"
    if name == "oauth_login":
        provider = _normalize_agent_id(arguments.get("provider_id") or arguments.get("provider"))
        if provider is None:
            return "Missing required parameter: provider"
    if name == "oauth_refresh":
        if _normalize_agent_id(arguments.get("service")) is None:
            return "Missing required parameter: service"
    return None


# ── OAuth state holder (per-process, not thread-safe across multiple concurrent logins) ─────────

_pending_oauth: dict[str, dict[str, Any]] = {}


# ── server ─────────────────────────────────────────────────────────────────────

server = Server("hermes-vault", version="0.7.2")


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
            description="Initiate PKCE OAuth login for a provider. Returns authorization URL.",
            inputSchema=_TOOL_SCHEMAS["oauth_login"],
        ),
        Tool(
            name="oauth_refresh",
            description="Trigger token refresh for a service using stored refresh token.",
            inputSchema=_TOOL_SCHEMAS["oauth_refresh"],
        ),
    ]


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
        return [TextContent(type="text", text=f"Error: {exc}")]

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
            agent_id = binding.effective_agent_id or ""
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
            agent_id = binding.effective_agent_id or ""
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
            result = broker.scan_secrets(agent_id, paths)
            if not result.allowed:
                return [TextContent(type="text", text=f"Denied: {result.reason}")]
            return [TextContent(type="text", text=_json_text({
                "finding_count": result.metadata.get("finding_count"),
                "findings": result.metadata.get("findings"),
            }))]

        # ── OAuth: initiate PKCE login ───────────────────────────────────────
        if name == "oauth_login":
            return _handle_oauth_login(arguments, broker, binding.effective_agent_id or "")

        # ── OAuth: refresh token ─────────────────────────────────────────────
        if name == "oauth_refresh":
            return _handle_oauth_refresh(arguments, broker, binding.effective_agent_id or "")

        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except ValueError as exc:
        return [TextContent(type="text", text=f"Error: {exc}")]
    except Exception as exc:
        logger.exception("Unhandled error in tool %s", name)
        return [TextContent(type="text", text=f"Internal error: {exc}")]


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
        return [TextContent(type="text", text=f"Error: {exc}")]

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
    pending_key = f"{provider_id}:{alias}"
    _pending_oauth[pending_key] = {
        "state": state,
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
        "provider_id": provider_id,
        "alias": alias,
        "client_id": client_id,
        "client_secret": client_secret,
        "scopes": requested_scopes,
        "broker": broker,
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

    # Build registry + provider again (lightweight)
    settings = get_settings()
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
    except Exception as exc:
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
            "reason": attempt.reason,
            "new_access_token_preview": (attempt.new_access_token[:12] + "...") if attempt.new_access_token else None,
            "new_refresh_token_preview": (attempt.new_refresh_token[:12] + "...") if attempt.new_refresh_token else None,
            "expires_in": attempt.expires_in,
            "scopes": attempt.scopes,
            "retry_count": attempt.retry_count,
        }))]
    except Exception as exc:
        exc_str = str(exc).lower()
        if "no credential" in exc_str or "refresh token" in exc_str:
            return [TextContent(type="text", text=f"Error: No refresh token found for '{service}'. Use oauth_login to re-authenticate.")]
        return [TextContent(type="text", text=f"Error: {exc}")]


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
