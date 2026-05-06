# Hermes Vault MCP Server Integration

This document describes how to register `hermes-vault` as a managed MCP server inside Hermes Agent so that MCP-aware tools (e.g. `oauth_login`, `oauth_refresh`) are available to the agent.

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

When Hermes loads, it reads `mcp_servers` from `config.yaml`.  Any server with `enabled: true` is started automatically via stdio transport.  Hermes discovers the tools exposed by the server and makes them available to the agent loop.

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
| `oauth_refresh` | Refresh an OAuth access token using a stored refresh token. |

## 3. Verifying registration

After adding the config entry, start a new Hermes session and run:

```bash
hermes mcp list
```

You should see `hermes-vault` listed with its transport (`python -m hermes_vault.mcp_server`) and tool count.

To test the OAuth tools specifically, ask Hermes:

> "Use the hermes-vault MCP tool oauth_login for provider google with alias work."

Hermes should call the tool and return an authorization URL.

## 4. Policy considerations

Both `oauth_login` and `oauth_refresh` require policy permissions:

- `oauth_login` requires `add_credential` action on the target service.
- `oauth_refresh` requires `rotate` action on the target service.

If the agent is denied, the tool returns a policy denial message.

## 5. Architecture notes

- The MCP server uses **stdio transport** (no TCP port), so it runs in-process with Hermes.
- The `oauth_login` tool spawns an ephemeral HTTP callback server on localhost (OS-assigned ephemeral port) and returns an `authorization_url` to the caller.
- A background thread awaits the OAuth callback, exchanges the code for tokens, and stores them in the vault atomically.
- The `oauth_refresh` tool uses the existing `RefreshEngine` (proactive expiry detection + exponential backoff) to update tokens in-place.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `hermes mcp list` doesn't show hermes-vault | Check that `command` points to the correct Python binary and that `hermes_vault.mcp_server` is importable. |
| OAuth login times out | Ensure the browser can reach `127.0.0.1`. The ephemeral port is printed in the URL. |
| Policy denial on oauth_login | Add `add_credential` to the agent's policy for the provider service. |
| Refresh fails with "no refresh token" | Re-run `oauth_login` -- the provider may not have issued a refresh token. |
