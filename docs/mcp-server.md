# Hermes Vault MCP Server Documentation

## Overview

Hermes Vault exposes its full credential-management surface as an MCP (Model Context Protocol) server. When registered as a managed MCP server inside Hermes, agents can discover and call vault tools alongside built-in tools like `terminal`, `read_file`, etc.

Tool calls normally use caller-supplied `agent_id`. In v0.7.0, the server can also be launched with an allowed-agent binding so a known default agent is used when the host omits `agent_id`.

## Registration in Hermes

Add Hermes Vault to `~/.hermes/config.yaml` under the `mcp_servers` key:

```yaml
mcp_servers:
  hermes-vault:
    command: "python"
    args: ["-m", "hermes_vault.mcp_server"]
```

If Hermes Vault is installed in a dedicated virtual environment, use the absolute path:

```yaml
mcp_servers:
  hermes-vault:
    command: "/home/tony/projects/hermes-vault/.venv/bin/python"
    args: ["-m", "hermes_vault.mcp_server"]
```

**Auto-start behavior:** Hermes discovers and connects to all `mcp_servers` at process startup. No manual step is required. If the server fails to connect, Hermes retries with exponential backoff up to 5 times.

Optional deployment binding:

```bash
export HERMES_VAULT_MCP_ALLOWED_AGENTS='hermes,claude-desktop'
export HERMES_VAULT_MCP_DEFAULT_AGENT='claude-desktop'
hermes-vault mcp
```

When the binding env vars are set, the server denies any `agent_id` outside the allowed set before policy evaluation. When they are not set, `agent_id` remains required on every MCP tool call or MCP resource read.

## Caller Identity

The MCP server uses the caller's supplied `agent_id` unless the deployment provides an allowed-agent binding plus a default agent. In bound mode, the default agent is used only when the host omits `agent_id`.

This is a deployment guardrail, not strong authentication. Policy still decides what the effective agent may do once identity is resolved.

MCP resource reads receive only a URI, not JSON tool arguments. In unbound mode, include identity in the query string, for example `vault://services?agent_id=hermes`. In bound mode, set both `HERMES_VAULT_MCP_ALLOWED_AGENTS` and `HERMES_VAULT_MCP_DEFAULT_AGENT` so bare resource URIs such as `vault://services` resolve to the configured default agent.

## Available MCP Resources

Resources are read-only, metadata-only context. They never return raw secrets, encrypted payloads, or brokered environment variable values. Use tools for active operations like env materialization, live verification, OAuth, rotation, and scanning.

| Resource URI | Description | Policy scope |
|--------------|-------------|--------------|
| `vault://services` | Lists credential services visible to the effective agent. | Requires `list_credentials`; returns only services in the effective agent policy. |
| `vault://services/{name}` | Returns safe metadata for one service. Optional query params: `agent_id`, `alias`. | Requires `metadata` action on the requested service. |
| `vault://health` | Returns a no-live-verify health snapshot. | Requires `list_credentials`; counts and findings are limited to services in the effective agent policy. |
| `vault://policy` | Returns the effective agent's sanitized policy summary. | Returns only that agent's services, capabilities, TTL settings, approval-required services, and service actions. |

Examples:

```text
vault://services?agent_id=hermes
vault://services/github?agent_id=hermes
vault://services/github?agent_id=hermes&alias=work
vault://health?agent_id=hermes
vault://policy?agent_id=hermes
```

In a bound deployment with a default agent, the same resources can be read without the `agent_id` query:

```text
vault://services
vault://services/github
vault://health
vault://policy
```

Resource responses use `application/json`. Authorization and binding denials are returned as JSON content with `version: "vault-resource-error-v1"` so clients can parse them consistently.

## Available MCP Tools

Once registered, tools are prefixed as `mcp_hermes_vault_*`:

| Tool | Description |
|------|-------------|
| `mcp_hermes_vault_list_services` | List credentials visible to the agent, filtered by policy |
| `mcp_hermes_vault_get_credential_metadata` | Fetch metadata (no raw secrets) |
| `mcp_hermes_vault_get_ephemeral_env` | Materialise ephemeral env vars for a service |
| `mcp_hermes_vault_lease_issue` | Issue a time-bound access lease |
| `mcp_hermes_vault_lease_list` | List leases visible to the agent |
| `mcp_hermes_vault_lease_show` | Show a specific lease |
| `mcp_hermes_vault_lease_renew` | Renew a lease's TTL |
| `mcp_hermes_vault_lease_revoke` | Revoke a lease |
| `mcp_hermes_vault_verify_credential` | Verify a credential against its provider |
| `mcp_hermes_vault_rotate_credential` | Rotate to a new secret (requires `rotate` permission) |
| `mcp_hermes_vault_scan_for_secrets` | Scan filesystem paths for plaintext secrets |
| `mcp_hermes_vault_oauth_login` | Initiate PKCE OAuth login |
| `mcp_hermes_vault_oauth_device_login` | Initiate headless device-code OAuth login without returning tokens |
| `mcp_hermes_vault_oauth_provider_status` | Report provider readiness and safe next commands |
| `mcp_hermes_vault_oauth_refresh` | Trigger refresh for a stored OAuth token |

### `get_ephemeral_env`

The `get_ephemeral_env` tool materialises ephemeral environment variables for a service. The response now includes a `metadata` field alongside `env`, `ttl_seconds`, and `expires_at`.

**Arguments:**
- `agent_id` (required unless the server is bound to an allowed-agent set with a configured default) --- Identity for policy enforcement
- `service` (required) --- Service name
- `alias` (optional) --- Credential alias, default `default`
- `ttl_seconds` (optional) --- TTL for the ephemeral environment, default 300

**Response shape:**
```json
{
  "content": [
    {
      "type": "text",
      "text": "{\n  \"env\": {\"OPENAI_API_KEY\": \"sk-...\"},\n  \"ttl_seconds\": 300,\n  \"expires_at\": \"2026-06-15T18:30:00Z\",\n  \"metadata\": {\n    \"oauth_refresh\": {\n      \"refreshed\": false,\n      \"reason\": \"Token is still fresh (expires in 3500s)\"\n    }\n  }\n}"
    }
  ]
}
```

The `metadata` field may contain `oauth_refresh` with the following structure:
- `refreshed` (bool or null): `true` if the token was refreshed, `false` if still fresh, `null` for non-OAuth credentials
- `reason` (string): Human-readable explanation of the refresh decision

When a near-expiry OAuth token is successfully refreshed, `oauth_refresh.refreshed` is `true`. When the token is hard-expired and refresh fails, the request is denied with a policy reason and no raw tokens are exposed.

## OAuth Tools

### `oauth_login`

Initiates a PKCE login flow for a given provider and returns an authorization URL. The callback server runs in the background -- the user opens the URL in a browser and tokens are stored automatically upon completion.

**Arguments:**
- `agent_id` (required unless the server is bound to an allowed-agent set with a configured default) --- Identity for policy enforcement
- `provider_id` (required) --- Provider ID (e.g. `google`, `github`, `openai`)
- `alias` (optional) --- Credential alias, default `default`
- `scopes` (optional) --- List of OAuth scopes (falls back to provider defaults)
- `port` (optional) --- Callback port (0 = auto-assigned)

**Response:**
```json
{
  "success": true,
  "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
  "redirect_uri": "http://127.0.0.1:PORT/callback",
  "state": "nonce",
  "message": "Open the authorization_url in a browser for alias 'default'. Tokens will be stored automatically upon completion."
}
```

**Policy requirement:** The calling agent must have `add_credential` permission on the provider service.

**Prerequisites:**
- The provider must be defined in `~/.hermes/oauth-providers.yaml`
- Environment variables like `HERMES_VAULT_OAUTH_<PROVIDER>_CLIENT_ID` must be set if the provider requires a client ID

### `oauth_device_login`

Initiates device-code login for providers with a device authorization endpoint. The tool returns the verification URL, user code, and pending key immediately, starts polling in the background, and stores tokens automatically after the user approves the provider prompt. Raw access tokens, refresh tokens, device codes, and provider token responses are never returned through MCP.

**Arguments:**
- `agent_id` (required unless the server is bound to an allowed-agent set with a configured default) --- Identity for policy enforcement
- `provider_id` (required) --- Provider ID with device-code support, for example `google` or `github`
- `alias` (optional) --- Credential alias, default `default`
- `scopes` (optional) --- List of OAuth scopes, falls back to provider defaults
- `timeout_seconds` (optional) --- How long the background poller waits for user approval

**Response:**
```json
{
  "success": true,
  "provider_id": "google",
  "alias": "work",
  "verification_uri": "https://example.com/device",
  "verification_uri_complete": "https://example.com/device?user_code=ABCD-EFGH",
  "user_code": "ABCD-EFGH",
  "expires_in": 600,
  "interval": 5,
  "pending_key": "device:default:google:work:...",
  "raw_tokens_returned": false
}
```

**Policy requirement:** The calling agent must have `add_credential` permission on the provider service.

**Prerequisites:** The provider must define `device_authorization_endpoint` and any required client ID or client secret env vars must be set.

### `oauth_provider_status`

Reports OAuth provider readiness without starting login, polling, refresh, or token exchange.

**Arguments:**
- `agent_id` (required unless the server is bound to an allowed-agent set with a configured default) --- Identity for binding enforcement
- `provider_id` (required) --- Provider ID to inspect

**Response:**
```json
{
  "provider": "google",
  "configured": false,
  "supports_pkce": true,
  "supports_device_code": true,
  "missing_env": ["HERMES_VAULT_OAUTH_GOOGLE_CLIENT_ID"],
  "default_scopes": ["openid", "email"],
  "findings": ["missing_required_env"],
  "recommended_commands": [
    "hermes-vault oauth login google --alias work --headless",
    "hermes-vault oauth device-login google --alias work"
  ]
}
```

**Security boundary:** The response is metadata-only. It never returns raw tokens, device codes, client secrets, provider token responses, encrypted payloads, or vault secret values.

### `oauth_refresh`

Triggers an automatic token refresh for a service using its stored refresh token. Vault is updated atomically and the attempt is audited.

**Arguments:**
- `agent_id` (required unless the server is bound to an allowed-agent set with a configured default) --- Identity for policy enforcement
- `service` (required) --- Service name
- `alias` (optional) --- Credential alias, default `default`
- `dry_run` (optional) --- Simulate without writing to vault

**Response:**
```json
{
  "success": true,
  "service": "google",
  "alias": "default",
  "reason": "Token refreshed successfully",
  "new_access_token_preview": "ya29.a0Af...",
  "new_refresh_token_preview": "1//04d...",
  "expires_in": 3600,
  "scopes": ["openid", "email"],
  "retry_count": 1
}
```

**Policy requirement:** The calling agent must have `rotate` permission on the service.

**Prerequisites:**
- An `oauth_access_token` must exist for the service+alias
- A paired `oauth_refresh_token` must exist in the vault. New records use the deterministic alias `refresh:<alias>`; legacy alias `refresh` remains readable during migration.

## v0.19.0 Agent Control Plane

v0.19.0 adds metadata-first control-plane surfaces for hosts that need to understand access before materializing it. These tools and resources reuse the same broker, policy, lease, and audit paths as the CLI and dashboard.

Resources:

- `vault://agent-context?agent_id=<agent>` returns a redacted manifest of policy services, credential metadata, active leases, and access requests for one agent.
- `vault://policy-explain?agent_id=<agent>&service=<service>&action=<action>&ttl_seconds=<ttl>` returns the shared policy explanation payload.
- `vault://requests?agent_id=<agent>` lists access requests visible for the agent.
- `vault://recovery?backup=<path>` runs a redacted recovery drill for a local backup path.
- `vault://leases/{id}` remains the lease detail resource.

Tools:

- `request_access` creates a durable metadata-only access request with purpose and optional requested TTL.
- `policy_explain` returns the same allow/deny explanation used by the CLI and dashboard.
- `lease_checkout` reuses or issues a lease, then materializes env through the existing broker path.

Security boundary:

- Resources never return raw secret values, raw OAuth tokens, provider responses, encrypted payloads, vault databases, or salt files.
- `lease_checkout` can return env material because it is an access-materialization tool, not a passive resource. It remains policy-gated and audited through the broker.
- Bound MCP deployments should still set `HERMES_VAULT_MCP_ALLOWED_AGENTS` and `HERMES_VAULT_MCP_DEFAULT_AGENT` so the host cannot silently impersonate arbitrary agents.

## Tool Naming in Hermes

MCP tools are auto-registered by Hermes with the convention:

```
mcp_{server_name}_{tool_name}
```

For Hermes Vault, this becomes:
- `mcp_hermes_vault_oauth_login`
- `mcp_hermes_vault_oauth_device_login`
- `mcp_hermes_vault_oauth_refresh`
- `mcp_hermes_vault_list_services`
- etc.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "MCP SDK not available" | `mcp` Python package not installed | `pip install mcp` in the venv |
| "Unknown OAuth provider" | Provider not in `oauth-providers.yaml` | Add it or use a known provider |
| "Provider requires client_id" | Missing env var | Set `HERMES_VAULT_OAUTH_<PROVIDER>_CLIENT_ID` |
| "No refresh token found" | No `refresh:<alias>` record exists yet | Run `oauth_login` first or run `oauth normalize` on older vaults |
| "Denied:" | Policy blocks the agent | Add the service/action to the agent's policy |
| "Denied: agent 'X' is not allowed for this MCP server" | The caller identity is outside `HERMES_VAULT_MCP_ALLOWED_AGENTS` | Use an allowed agent or change the binding env vars |
| "Missing required parameter: agent_id" | Unbound server mode still requires caller identity for tools and resources | Supply `agent_id`, or launch the server with a default agent binding |
| Resource returns `vault-resource-error-v1` | A resource binding or policy check failed | Read the JSON `error` field and adjust `agent_id`, binding env vars, or policy |
| Callback times out | User didn't complete browser auth within 120s | Retry login |
| State mismatch | CSRF attack or stale callback | Retry login with fresh state |
