# Operator Guide

## Setup

1. Install the package.
2. Set `HERMES_VAULT_PASSPHRASE`.
3. Run `hermes-vault list` once to initialize the runtime layout and default policy.
4. Edit `~/.hermes/hermes-vault-data/policy.yaml` for the real agent allowlists.
5. Back up both `vault.db` and `master_key_salt.bin` together. Losing the salt makes the vault unreadable.

## Recommended First Run

```bash
hermes-vault scan --path ~/.hermes
hermes-vault import --from-env ~/.hermes/.env
hermes-vault verify --all
hermes-vault generate-skill --all-agents
```

## Policy Notes

- Policy is deny by default
- Keep `raw_secret_access: false` unless there is a concrete operational reason
- Keep `require_verification_before_reauth: true`
- Keep TTLs short for sub-agents
- Use `plaintext_migration_paths` only for short-lived cutovers
- Treat plaintext under `managed_paths` as a policy violation unless explicitly exempted

## Agent Capabilities

Some actions are not scoped to a single service.  These are controlled by the
`capabilities` field on each agent in `policy.yaml`.

| Capability | Controls |
|---|---|
| `list_credentials` | `broker list` — enumerate credentials the agent may access |
| `scan_secrets` | `scan` — scan the filesystem for plaintext secrets |
| `export_backup` | `backup` — export an encrypted backup of the vault |
| `import_credentials` | `import` — add credentials from env files or JSON |

**Backward compatibility:** if an agent has no `capabilities` field (or an
empty list), all capabilities are implicitly granted.  This preserves existing
policies without modification.

When `capabilities` is explicitly set, only the listed capabilities are allowed.
For example, an agent with `capabilities: [list_credentials]` can enumerate
credentials but cannot run scans or exports.

### Example — restrict capabilities

```yaml
agents:
  pam:
    services:
      google:
        actions: [get_env, verify, metadata]
    capabilities: [list_credentials, scan_secrets]
```

In this configuration, `pam` can list available credentials and scan for
plaintext secrets, but cannot export backups or import new credentials.

## MCP Setup

Hermes Vault can expose the broker through the Model Context Protocol (MCP) so that compatible hosts (Claude Desktop, Cursor, etc.) can request credentials programmatically.

### Running the MCP server

```bash
hermes-vault mcp
```

The server uses stdio transport and reads `HERMES_VAULT_PASSPHRASE` from the environment.

### Connecting from Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or the equivalent config path for your host:

```json
{
  "mcpServers": {
    "hermes-vault": {
      "command": "hermes-vault",
      "args": ["mcp"],
      "env": {
        "HERMES_VAULT_PASSPHRASE": "your-passphrase"
      }
    }
  }
}
```

### Agent registration for MCP

Every MCP tool call requires an `agent_id`. Register agents in `policy.yaml` just like CLI sub-agents:

```yaml
agents:
  claude-desktop:
    services:
      openai:
        actions: [get_env, verify, metadata]
      supabase:
        actions: [get_env]
    capabilities: [list_credentials]
    max_ttl_seconds: 3600
    raw_secret_access: false
    ephemeral_env_only: true
```

The MCP server applies the same policy checks as the CLI broker.

### MCP troubleshooting

- **"Missing required parameter: agent_id"** — Every MCP tool call must include `agent_id`. The host does not pass identity automatically.
- **"Denied: agent 'X' is not defined in policy"** — Add the agent to `policy.yaml` and restart the MCP server.
- **"Denied: action 'Y' not permitted on service 'Z'"** — Add the action to the agent's service entry in policy.
- **Server fails to start** — Ensure `HERMES_VAULT_PASSPHRASE` is set in the environment passed to the MCP server process.

## Update Command

Check for updates safely:

```bash
hermes-vault update --check
```

Perform a guarded update (only for supported install methods):

```bash
hermes-vault update
```

Supported install methods: `pip`, `pipx`, `uv tool`. Unsupported methods (editable installs, unknown) receive exact manual instructions instead of auto-update.

## Canonical Service IDs

Hermes Vault uses canonical service IDs internally.  When you `add`, `import`, or reference a service in policy, the name is normalized automatically:

| Canonical ID | Recognized aliases |
|---|---|
| `openai` | `open_ai`, `open-ai` |
| `anthropic` | `anthropic_ai` |
| `github` | `gh`, `github_pat` |
| `google` | `gmail`, `google_docs`, `google_drive`, `google_oauth` |
| `minimax` | `mini_max`, `mini-max` |
| `supabase` | `supa`, `supabase_db` |
| `telegram` | — |
| `netlify` | — |
| `generic` | `bearer`, `token` |

Custom service names (anything not in the table above) are preserved as-is.  Use lowercase for new entries.

## Troubleshooting

### "No passphrase available"

- Export `HERMES_VAULT_PASSPHRASE`
- Or run a command that prompts interactively, such as `add` or `import`

### "Vault database exists but salt file is missing"

- Restore `master_key_salt.bin` from backup
- Do not generate a new salt for an existing database
- If the salt is lost, the existing encrypted vault records are not recoverable

### "Credential not found in vault"

- Import or add the credential first
- Stop relying on filesystem discovery

### "Verification returned network failure"

- Do not tell the agent to re-auth
- Check connectivity and provider reachability first

### "Verification returned permission or scope issue"

- Do not tell the agent to re-auth
- Check scopes, app permissions, and provider authorization details instead

### "MiniMax verification endpoint is not configured"

- Set `HERMES_VAULT_MINIMAX_VERIFY_URL` before running `hermes-vault verify minimax`
- Point it at an operator-validated authenticated GET endpoint that returns `200` for valid credentials and `401` or `403` for invalid ones
- If you are testing an OpenAI-compatible MiniMax deployment, `/v1/models` is a candidate endpoint to validate, not an assumed contract

### "Broker denied access"

- Read the exact denial reason
- Update policy only if the service should genuinely be available to that agent
- If the denial says "not permitted on service", the agent's policy v2 entry is missing that action
- If the denial says "capability not granted", the agent needs the capability in its policy

### "Ambiguous: Service has N credentials"

- The service has multiple credentials under different aliases
- Use `--alias` to target the specific one: `hermes-vault rotate github --alias work`
- Or use the credential ID from `hermes-vault list`
- This error prevents accidentally operating on the wrong credential

### "Not found: credential"

- The credential does not exist in the vault
- Check `hermes-vault list` to see what's actually stored
- Import or add the credential first
- Make sure you're using the correct canonical service name (e.g. `openai` not `open_ai`)

### "Denied: capability not granted"

- The agent's policy has an explicit `capabilities` list that does not include this action
- Add the capability to the agent's policy, or remove the `capabilities` field to grant all (backward compatible)
- Capabilities: `list_credentials`, `scan_secrets`, `export_backup`, `import_credentials`, `add_credential`

### "Denied: action not permitted on service"

- The agent's policy v2 entry for this service does not include the requested action
- Add the action to the service's `actions` list in the agent's policy
- Or switch the agent to legacy format (flat service list) to allow all actions

## Safe Operating Defaults

- Scan and import first
- Verify before any re-auth recommendation
- Use broker env materialization for tasks
- Keep audit records for false-auth troubleshooting
- Treat generated skills as review artifacts unless you explicitly install them

## Credential Selectors

Most CLI commands that target an existing credential accept a **credential selector** — a positional argument that resolves to exactly one credential. Three forms are supported:

| Selector | Example | When it works |
|---|---|---|
| **credential ID** (UUID) | `hermes-vault rotate a1b2c3d4-...` | Always — exact match |
| **service + `--alias`** | `hermes-vault rotate github --alias work` | Always — exact match |
| **service only** | `hermes-vault rotate openai` | Only when exactly one credential exists for that service |

### When service-only is ambiguous

If you have multiple credentials for the same service (e.g. `github` with aliases `work` and `personal`), using just the service name will fail:

```
$ hermes-vault rotate github
Ambiguous: Service 'github' has 2 credentials — specify credential ID or service+alias
Use --alias or provide the credential ID.
```

Fix it by adding `--alias` or using the credential ID from `hermes-vault list`.

### Commands that use selectors

- `show-metadata <target> [--alias ALIAS]`
- `rotate <target> --secret SECRET [--alias ALIAS]`
- `delete <target> --yes [--alias ALIAS]`
- `verify <target> [--alias ALIAS]` or `verify --all`

### Commands that accept service names only

These commands accept a service name (normalized to canonical ID) and don't require alias disambiguation:

- `add <service> --secret SECRET [--alias ALIAS]` — adds a new credential
- `broker get <service> --agent AGENT` — fetches a credential via policy
- `broker env <service> --agent AGENT` — materializes ephemeral env vars

Service names are normalized automatically (see [Canonical Service IDs](#canonical-service-ids) above).

## Audit Log Query

Query the audit log to trace credential access, denials, and mutations:

  hermes-vault audit
  hermes-vault audit --agent dwight --since 7d
  hermes-vault audit --service openai --decision deny --format json
  hermes-vault audit --since 2026-01-01 --until 2026-03-01

Use --since with a relative value (7d, 30d) or an ISO date (YYYY-MM-DD).
Use --decision allow or --decision deny to filter by access decision.
Use --format json for machine-readable output.

## Credential Status

Inspect credential health across the vault:

  hermes-vault status
  hermes-vault status --stale 7d
  hermes-vault status --invalid
  hermes-vault status --expiring 30d --format json

Credentials with no last_verified_at are always stale.
Credentials with no expiry set are never shown by --expiring.
Filters can be combined: hermes-vault status --stale 7d --invalid

## Expiry Metadata

Set or clear expiry dates for credentials to track renewal windows:

  hermes-vault set-expiry openai --alias primary --days 90
  hermes-vault set-expiry github --alias work --date 2026-07-01
  hermes-vault clear-expiry openai --alias primary

Use --days for a relative deadline (N days from today) or --date for an
absolute date. Both commands write audit entries. Expiry dates are
preserved through backup and restore.

## OAuth Setup and Token Lifecycle

Hermes Vault supports OAuth 2.0 with PKCE for providers that support it. The flow is entirely local -- no cloud intermediary, no hosted redirect URI required.

### Provider registration

Providers are stored in `~/.hermes/hermes-vault-data/oauth-providers.yaml`. The file is created automatically with built-in defaults (`google`, `github`, `openai`) on first use. You can add custom providers by editing the YAML directly.

A provider entry looks like this:

```yaml
providers:
  myprovider:
    name: "MyProvider"
    authorization_endpoint: "https://myprovider.com/oauth/authorize"
    token_endpoint: "https://myprovider.com/oauth/token"
    default_scopes:
      - "api"
    scope_separator: " "
    use_pkce: true
    extra_params:
      access_type: "offline"
    requires_client_id: true
    requires_client_secret: false
```

### Client credentials via environment variables

Providers that require a `client_id` (or `client_secret`) read it from environment variables at runtime:

```
HERMES_VAULT_OAUTH_<PROVIDER>_CLIENT_ID
HERMES_VAULT_OAUTH_<PROVIDER>_CLIENT_SECRET
```

For example: `HERMES_VAULT_OAUTH_GOOGLE_CLIENT_ID` and `HERMES_VAULT_OAUTH_GITHUB_CLIENT_SECRET`.

### Login flow

1.  `hermes-vault oauth login <provider> [--alias NAME] [--scope SCOPE ...] [--no-browser]`
2.  The CLI generates a PKCE code_verifier + code_challenge and a CSRF state nonce.
3.  An ephemeral callback server starts on `127.0.0.1:0` (OS-assigned port).
4.  The browser is opened with the authorization URL (or the URL is printed if `--no-browser`).
5.  The user completes consent in the browser.
6.  The provider callback hits the local server with `?code=...&state=...`.
7.  The CLI validates state with timing-safe comparison, then POSTs the code to the token endpoint.
8.  On success, the access token is stored as `oauth_access_token` and the refresh token as `oauth_refresh_token` with alias `"refresh"`.
9.  If the provider returns `expires_in`, an expiry timestamp is set automatically.

### Token lifecycle and refresh

Access tokens have a limited lifespan (typically 1 hour for Google, configurable by provider). The refresh token lives in the vault separately and is used to obtain new access tokens without browser re-authentication.

Refresh commands:

```bash
# Refresh a single service
hermes-vault oauth refresh google --alias work

# Refresh all expired or nearly-expired tokens
hermes-vault oauth refresh --all

# Dry-run: see what would be refreshed without updating vault
hermes-vault oauth refresh google --dry-run

# Custom proactive margin (default: 300s = 5 minutes before expiry)
hermes-vault oauth refresh --all --margin 600
```

The refresh engine:

- Scans all `oauth_access_token` credentials for expiry.
- A token is considered "expired" when it's past its expiry or within `margin` seconds of it.
- POSTs to the provider's token endpoint with `grant_type=refresh_token`.
- Retries transient network errors up to 3 times with exponential backoff (2s, 4s, 8s).
- Updates both tokens atomically in a single SQLite transaction.
- Records every attempt (success or failure) in the audit log.
- Provider-side refresh token rotation is supported; the engine preserves a `rotation_counter` and optional `family_id`.

### MCP OAuth tools

When Hermes Vault is registered as an MCP server inside Hermes Agent, the `oauth_login` and `oauth_refresh` tools are available to agents:

- `oauth_login` returns an authorization URL and starts a background callback thread. The agent opens the URL, completes consent, and tokens are stored automatically.
- `oauth_refresh` triggers the same refresh engine described above, returning the result to the agent.

Both tools require policy permissions (`add_credential` for login, service access for refresh).