# Hermes Vault MCP Server Integration

This document describes how to register `hermes-vault` as a managed MCP server inside Hermes Agent so that MCP-aware tools (e.g. `oauth_login`, `oauth_device_login`, `oauth_refresh`) are available to the agent.

## Prerequisites

- Hermes Vault installed and on your PATH (e.g. `pip install -e .` from the repo root).
- Hermes Agent >= 2025-05 (MCP stdio server support).
- A vault already initialized (run `hermes-vault add <service>` at least once so the DB exists).

## 1. Add hermes-vault to Hermes config

Edit `~/.hermes/config.yaml` and add an entry under `mcp_servers`:

```yaml
mcp_servers:
  hermes-vault:
    command: python
    args:
      - -m
      - hermes_vault.mcp_server
    enabled: true
```

If you installed into a specific virtual environment, use the absolute Python path instead, e.g.:

```yaml
mcp_servers:
  hermes-vault:
    command: /home/tony/projects/hermes-vault/.venv/bin/python
    args:
      - -m
      - hermes_vault.mcp_server
    enabled: true
```

## 2. How it works (auto-start)

When Hermes loads, it reads `mcp_servers` from `config.yaml`.  Any server with `enabled: true` is started automatically via stdio transport.  Hermes discovers the tools and resources exposed by the server and makes them available to the agent loop.

`hermes-vault` exposes the following MCP tools:

| Tool | Description |
|------|-------------|
| `list_services` | List credentials visible to the agent, filtered by policy. |
| `get_credential_metadata` | Fetch metadata for a credential (no raw secret). |
| `get_ephemeral_env` | Materialise ephemeral environment variables for a service. |
| `verify_credential` | Verify a credential against its provider. |
| `rotate_credential` | Rotate a credential to a new secret value. |
| `scan_for_secrets` | Scan filesystem paths for plaintext secrets. |
| `oauth_login` | Initiate a PKCE OAuth login flow for a provider. |
| `oauth_device_login` | Initiate a browserless device-code OAuth flow without returning raw tokens. |
| `oauth_refresh` | Refresh an OAuth access token using a stored refresh token. |

`hermes-vault` also exposes read-only MCP resources:

| Resource | Description |
|----------|-------------|
| `vault://services` | Policy-scoped service inventory for the effective agent. |
| `vault://services/{name}` | Safe metadata for one visible service. Optional query params: `agent_id`, `alias`. |
| `vault://health` | Policy-scoped health snapshot with `verified_live: false`. |
| `vault://policy` | Sanitized policy summary for the effective agent only. |

Resources are context, tools are actions. Read resources to understand available services, health, and policy boundaries. Call tools when you need to materialize env vars, verify providers live, refresh OAuth, rotate credentials, or scan files.

For bare resource URIs, bind the MCP server to a default policy agent:

```yaml
mcp_servers:
  hermes-vault:
    command: /home/tony/.local/hermes-vault-venv/bin/hermes-vault
    args:
      - mcp
    enabled: true
    env:
      HERMES_VAULT_HOME: /home/tony/.hermes/hermes-vault-data
      HERMES_VAULT_MCP_ALLOWED_AGENTS: hermes
      HERMES_VAULT_MCP_DEFAULT_AGENT: hermes
```

Without a default binding, include identity in the URI query, for example `vault://services?agent_id=hermes`.

## 3. Verifying registration

After adding the config entry, start a new Hermes session and run:

```bash
hermes mcp list
```

You should see `hermes-vault` listed with its transport (`python -m hermes_vault.mcp_server`) and discovered capabilities.

To test the OAuth tools specifically, ask Hermes:

> "Use the hermes-vault MCP tool oauth_login for provider google with alias work."

Hermes should call the tool and return an authorization URL. For headless first login, ask:

> "Use the hermes-vault MCP tool oauth_device_login for provider google with alias work."

Hermes should return a verification URL and user code, not raw OAuth tokens.

To inspect readiness without starting login, ask:

> "Use the hermes-vault MCP tool oauth_provider_status for provider google."

Hermes should return missing environment variables, provider capabilities, and safe next commands only.

## 4. Policy considerations

`oauth_login`, `oauth_device_login`, and `oauth_refresh` require policy permissions:

- `oauth_login` requires `add_credential` action on the target service.
- `oauth_device_login` requires `add_credential` action on the target service.
- `oauth_refresh` requires `rotate` action on the target service.

If the agent is denied, the tool returns a policy denial message.

## 5. Architecture notes

- The MCP server uses **stdio transport** (no TCP port), so it runs in-process with Hermes.
- The `oauth_login` tool spawns an ephemeral HTTP callback server on localhost (OS-assigned ephemeral port) and returns an `authorization_url` to the caller.
- A background thread awaits the OAuth callback, exchanges the code for tokens, and stores them in the vault atomically.
- The `oauth_device_login` tool returns verification instructions immediately, polls in the background, and stores tokens after approval without returning raw token material.
- The `oauth_refresh` tool uses the existing `RefreshEngine` (proactive expiry detection + exponential backoff) to update tokens in-place.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `hermes mcp list` doesn't show hermes-vault | Check that `command` points to the correct Python binary and that `hermes_vault.mcp_server` is importable. |
| OAuth login times out | Ensure the browser can reach `127.0.0.1`. The ephemeral port is printed in the URL. |
| Device login says provider unsupported | Use `oauth_login`/`--no-browser` or configure a provider with `device_authorization_endpoint`. |
| Policy denial on oauth_login or oauth_device_login | Add `add_credential` to the agent's policy for the provider service. |
| Refresh fails with "no refresh token" | Re-run `oauth_login` or `oauth_device_login`, then retry refresh after the provider issues a refresh token. |
