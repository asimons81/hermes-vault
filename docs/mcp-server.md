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

When the binding env vars are set, the server denies any `agent_id` outside the allowed set before policy evaluation. When they are not set, `agent_id` remains required on every MCP tool call.

## Caller Identity

The MCP server uses the caller's supplied `agent_id` unless the deployment provides an allowed-agent binding plus a default agent. In bound mode, the default agent is used only when the host omits `agent_id`.

This is a deployment guardrail, not strong authentication. Policy still decides what the effective agent may do once identity is resolved.

## Available MCP Tools

Once registered, tools are prefixed as `mcp_hermes_vault_*`:

| Tool | Description |
|------|-------------|
| `mcp_hermes_vault_list_services` | List credentials visible to the agent, filtered by policy |
| `mcp_hermes_vault_get_credential_metadata` | Fetch metadata (no raw secrets) |
| `mcp_hermes_vault_get_ephemeral_env` | Materialise ephemeral env vars for a service |
| `mcp_hermes_vault_verify_credential` | Verify a credential against its provider |
| `mcp_hermes_vault_rotate_credential` | Rotate to a new secret (requires `rotate` permission) |
| `mcp_hermes_vault_scan_for_secrets` | Scan filesystem paths for plaintext secrets |
| `mcp_hermes_vault_oauth_login` | **NEW** Initiate PKCE OAuth login |
| `mcp_hermes_vault_oauth_refresh` | **NEW** Trigger refresh for a stored OAuth token |

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

**Policy requirement:** The calling agent must have access to the service (via `can_access_service`).

**Prerequisites:**
- An `oauth_access_token` must exist for the service+alias
- A paired `oauth_refresh_token` must exist in the vault. New records use the deterministic alias `refresh:<alias>`; legacy alias `refresh` remains readable during migration.

## Tool Naming in Hermes

MCP tools are auto-registered by Hermes with the convention:

```
mcp_{server_name}_{tool_name}
```

For Hermes Vault, this becomes:
- `mcp_hermes_vault_oauth_login`
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
| "Missing required parameter: agent_id" | Unbound server mode still requires caller identity | Supply `agent_id`, or launch the server with a default agent binding |
| Callback times out | User didn't complete browser auth within 120s | Retry login |
| State mismatch | CSRF attack or stale callback | Retry login with fresh state |
