# Operator Guide

## Setup

1. Install the package.
2. Set `HERMES_VAULT_PASSPHRASE`.
3. Run `hermes-vault list` once to initialize the vault layout and default policy.
4. Edit `~/.hermes/hermes-vault-data/policy.yaml` for the real agent allowlists.
5. Back up both `vault.db` and `master_key_salt.bin` together. Losing the salt makes the vault unreadable.

## Recommended First Run

```bash
hermes-vault scan --path ~/.hermes
hermes-vault import --from-env ~/.hermes/.env --dry-run
hermes-vault import --from-env ~/.hermes/.env
hermes-vault verify --all
hermes-vault generate-skill --all-agents
```

### Env import preview and mapping

Always preview large `.env` imports before mutating the vault:

```bash
hermes-vault import --from-env ~/.hermes/.env --dry-run
```

The preview lists importable and skipped env vars without opening or writing the vault. Known service hints and safe suffixes (`*_API_KEY`, `*_TOKEN`, `*_AUTH_TOKEN`, `*_ACCESS_TOKEN`) are imported automatically. Unknown names are skipped with a reason and a `--map` hint.

Use `--map` for intentional custom names:

```bash
hermes-vault import --from-env ~/.hermes/.env --map CUSTOM_VENDOR_TOKEN=custom-vendor:personal_access_token
hermes-vault import --from-env ~/.hermes/.env --map DATABASE_URL=postgres:connection_url
```

`NEXT_PUBLIC_*` public config stays skipped. Broad DB URLs, passwords, app secrets, JWT secrets, and session secrets also stay skipped unless explicitly mapped. With `--redact-source`, Hermes Vault comments only successfully imported lines and reports how many skipped lines were left unchanged. `--dry-run --redact-source` does not modify the source file.

## From `.env` to a real agent workflow

If you start with a normal `.env`, this is the real path from “we have some secrets on disk” to “Hermes is using them safely”:

1. Scan for plaintext secrets

   ```bash
   hermes-vault scan --path ~/.hermes
   ```

2. Preview the import before anything changes

   ```bash
   hermes-vault import --from-env ~/.hermes/.env --dry-run
   ```

3. Import the approved entries into the vault

   ```bash
   hermes-vault import --from-env ~/.hermes/.env
   ```

4. Generate the agent skill contract

   ```bash
   hermes-vault generate-skill --all-agents
   ```

5. Review the generated skill

   - Generated skills are written under `~/.hermes/hermes-vault-data/generated-skills/<agent>/SKILL.md`
   - The skill embeds a policy hash, so drift is detectable
   - Treat it as a review artifact until you explicitly install it into the live Hermes skill directory

6. Wire Hermes to the vault runtime

   - `HERMES_VAULT_HOME=~/.hermes/hermes-vault-data`
   - `HERMES_VAULT_POLICY=~/.hermes/hermes-vault-data/policy.yaml`
   - If Hermes is loading the vault through MCP, add `hermes-vault` to `~/.hermes/config.yaml` under `mcp_servers`

What happens next is the important bit, and this is where the setup stops being abstract:

- `policy.yaml` decides which agent can access which services
- the vault runtime home holds the encrypted database and generated skill artifacts
- the skill tells the agent how to behave around credentials
- broker calls hand out ephemeral env vars instead of raw secrets

This is the concrete runtime path, not a vague `config.yml` hand wave.

## Why this is better

This setup gives you a few hard wins:

- **Less plaintext sprawl**
  - Secrets stop living in random files
  - Imported values land in one vault

- **Scoped access**
  - An agent can get `github` without also getting `google`
  - Access is service-bound, not vibes-bound

- **Short-lived exposure**
  - Agents get ephemeral env vars instead of raw secret dumps
  - TTLs keep the blast radius small

- **Easy rotation**
  - Update one vault entry instead of hunting down stale copies
  - Revoke once, stop it everywhere

- **Fewer auth headaches**
  - The skill tells the agent to verify before claiming re-auth
  - No guessing because some stale `.env` copy got left behind

## Concrete examples

- **GitHub**
  - Give the agent access to `github`
  - It gets brokered env for the task, not your whole shell state
  - Good for repo ops, PR work, and automation without spraying tokens everywhere

- **OpenAI**
  - Allow the coding agent to use `openai`
  - Keep it out of workspace or infrastructure creds
  - One model key, one policy entry, no cross-contamination

- **Google**
  - Let a workspace agent use `google`
  - Keep that credential separate from the rest of the stack
  - Rotate or revoke it without touching unrelated services

The point isn't “more files.” The point is one canonical secret source, one policy file, and one contract that tells the agent how to use them safely.

## Multiple Profiles

If you run multiple agents, don't jam everything into one catch-all profile. Split by job:

- **default**, the fallback profile, keep it boring and low-privilege
- **coder**, the profile that can build, test, and hit the services needed to ship code
- **auditor**, the profile that can inspect, verify, and scan, but shouldn't need broad mutation rights

These aren't special modes. They're separate agent IDs with separate policy entries and generated skill contracts. That keeps permission boundaries obvious.

A simple shape looks like this:

```yaml
agents:
  default:
    services:
      github:
        actions: [metadata, verify]
    capabilities: [list_credentials]
    max_ttl_seconds: 300
    ephemeral_env_only: true
    raw_secret_access: false

  coder:
    services:
      github:
        actions: [metadata, get_env, verify]
      openai:
        actions: [get_env]
      google:
        actions: [get_env]
    capabilities: [list_credentials, import_credentials]
    max_ttl_seconds: 900
    ephemeral_env_only: true
    raw_secret_access: false

  auditor:
    services:
      github:
        actions: [metadata, verify]
      google:
        actions: [metadata, verify]
    capabilities: [list_credentials, scan_secrets]
    max_ttl_seconds: 300
    ephemeral_env_only: true
    raw_secret_access: false
```

Use the narrowest profile that still gets the job done. If an auditor can verify the thing, don't hand it mutation rights just because it's convenient. If the coder only needs `github` and `openai`, don't give it every other service in the vault.

## MCP Server Option

MCP is useful, but it isn't the default path for everything.

### Use MCP when

- You want Hermes to request credentials from inside the agent loop
- You want tool discovery and credential access to feel native
- You want the same policy gate without shell glue around every call

### Stick with the CLI when

- You're doing setup, imports, backups, recovery, or one-off admin work
- You want the fewest moving parts
- You don't need Hermes to broker the request in real time

### Pros

- **Tighter agent integration**
  - Hermes can call the vault directly instead of bouncing through shell steps
- **Cleaner ergonomics**
  - Tool discovery is automatic, and the agent asks for exactly what it needs
- **Good for bounded automation**
  - If the work lives inside Hermes, MCP is usually the straightest path

### Cons

- **More moving parts**
  - You now care about `~/.hermes/config.yaml`, MCP startup, and connection state
- **`agent_id` is not strong auth by itself**
  - It only becomes meaningful when the server is bound to an allowed-agent set
- **Bigger debug surface**
  - If the server won't start or the connection drops, the agent loses the path
- **Overkill for basic admin work**
  - If you're importing a `.env` or doing a restore drill, the CLI is simpler

Bottom line: use MCP when you want Hermes to operate as an in-loop client of the vault. Use the CLI when you want the boring, explicit path that is easier to audit and harder to screw up.

## Maintenance

`hermes-vault maintain` is the v0.7.0 scheduled run for token refresh and vault hygiene. It combines proactive OAuth refresh, health checks, stale-verification checks, and backup-age warnings in one report.

```bash
hermes-vault maintain --dry-run
hermes-vault maintain
hermes-vault maintain --print-systemd
```

- `--dry-run` reports what would be refreshed or warned about without mutating tokens.
- `--format json` is useful for cron, systemd timers, and log aggregation.
- Exit code `0` means the maintenance run completed cleanly.
- Exit code `1` means warnings or refresh failures were found.
- Exit code `2` means invalid arguments.
- `print-systemd` is the safer way to generate a timer/service example when you want to inspect the unit before installation.

## Dashboard

`hermes-vault dashboard` starts the local Hermes Vault Console.

```bash
hermes-vault dashboard
hermes-vault dashboard --no-open
hermes-vault dashboard --port 8765
```

The dashboard binds to `127.0.0.1`, generates a random tokenized launch URL, and serves packaged static assets from the installed Python package. Use the printed URL from the current launch; old URLs expire when the process exits.

The console is for daily operator inspection: health, credential inventory, policy findings, audit activity, MCP binding status, backup posture, and safe operational actions. It is not a hosted vault or a policy editor.

Safe v0.8.0 actions include:

- Run health
- Run policy doctor
- Verify one credential or all credentials
- Refresh OAuth tokens
- Run maintenance dry-run or maintenance
- Verify a backup file
- Run restore dry-run

Unsafe or out-of-scope actions stay in the CLI and require the existing explicit flags or workflows. The dashboard does not expose raw secrets, encrypted payloads, credential editing, policy editing, cloud sync, remote access, raw restore, credential deletion, master-key rotation, or plaintext export.

Release visual QA should cover desktop and mobile widths, the first-run vault-door intro, bundled brand asset loading, text overflow, and control overlap before publishing a dashboard build.

## Policy Notes

- Policy is deny by default
- Keep `raw_secret_access: false` unless there is a concrete operational reason
- Keep `require_verification_before_reauth: true`
- Keep TTLs short for sub-agents
- Use `plaintext_migration_paths` only for short-lived cutovers
- Treat plaintext under `managed_paths` as a policy violation unless explicitly exempted

## Policy Doctor

`hermes-vault policy doctor` inspects `policy.yaml` before runtime failures show up.

```bash
hermes-vault policy doctor
hermes-vault policy doctor --strict
```

It flags:

- Unknown service IDs
- Unknown actions or capabilities
- Legacy agents that still rely on implicit all-capability grants
- `raw_secret_access: true`
- Long TTLs for MCP-facing agents
- OAuth-capable agents missing `add_credential` or `rotate` for refresh
- Stale generated skills whose policy hash no longer matches

Use `--strict` in CI or pre-deploy checks when you want the command to fail on high-risk findings.

## Agent Capabilities

Some actions aren't service-scoped. They are controlled by the
`capabilities` field on each agent in `policy.yaml`.

| Capability | Controls |
|---|---|
| `list_credentials` | `broker list` — enumerate credentials the agent may access |
| `scan_secrets` | `scan` — scan the filesystem for plaintext secrets |
| `export_backup` | `backup` — export an encrypted backup of the vault |
| `import_credentials` | `import` — add credentials from env files or JSON |

**Backward compatibility:** If an agent has no `capabilities` field, all capabilities are implicitly granted for backward compatibility.

When `capabilities` is explicitly set, only the listed capabilities are allowed.
For example, an agent with `capabilities: [list_credentials]` can enumerate credentials but cannot run scans or exports.

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

Hermes Vault can expose the broker through the Model Context Protocol (MCP) so that compatible hosts like Claude Desktop and Cursor can request credentials programmatically.

### Running the MCP server

```bash
hermes-vault mcp
```

The server uses stdio transport and reads `HERMES_VAULT_PASSPHRASE` from the environment.

If you want to bind the MCP process to a known agent set, also export:

```bash
export HERMES_VAULT_MCP_ALLOWED_AGENTS='hermes,claude-desktop'
export HERMES_VAULT_MCP_DEFAULT_AGENT='claude-desktop'
```

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

If the MCP server is started without an allowed-agent binding, every tool call requires a caller-supplied `agent_id`. When `HERMES_VAULT_MCP_ALLOWED_AGENTS` is set and `HERMES_VAULT_MCP_DEFAULT_AGENT` names one of the allowed agents, the host may omit `agent_id` and the server will use that default.

Register agents in `policy.yaml` just like CLI sub-agents:

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

Important: `agent_id` is caller-supplied identity unless the deployment binds the server to an allowed-agent set. Do not treat a bare `agent_id` as strong authentication.

### MCP troubleshooting

- **"Missing required parameter: agent_id"**: The MCP server is running in unrestricted mode and the host did not supply `agent_id`, or the deployment did not configure a default agent.
- **"Denied: agent 'X' is not defined in policy"**: Add the agent to `policy.yaml` and restart the MCP server.
- **"Denied: agent 'X' is not allowed for this MCP server"**: Add the agent to `HERMES_VAULT_MCP_ALLOWED_AGENTS` or use one of the allowed agents.
- **"Error: MCP default agent 'X' is not in the allowed agent set"**: Fix the env vars so the default agent is one of the allowed agents.
- **"Denied: action 'Y' not permitted on service 'Z'"**: Add the action to the agent's service entry in policy.
- **"Server fails to start"**: Ensure `HERMES_VAULT_PASSPHRASE` is set in the environment passed to the MCP server process.

## Update Command

Check for updates safely:

```bash
hermes-vault update --check
```

Perform a guarded update (only for supported install methods):

```bash
hermes-vault update
```

Auto-update is supported for `pipx` and `uv tool` installs. Standard `pip`/venv installs, editable installs, and unknown environments receive exact manual instructions instead of auto-update.

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

## OAuth Storage and Pairing

v0.7.0 tightens the OAuth record model so refresh tokens can be paired safely across multiple aliases.

- Access-token metadata is sanitized. Keep only provider-safe fields such as `token_type`, `provider`, `issued_at`, `expires_at`, and `scopes`.
- Refresh tokens are stored separately under the deterministic alias `refresh:<alias>`.
- Legacy records that still use alias `refresh` are still readable, but normalization rewrites them into the alias-scoped form.
- `oauth normalize` is the migration command operators should run after upgrading older vaults.

Example pairing:

```bash
hermes-vault oauth login google --alias work
hermes-vault oauth login google --alias personal
hermes-vault oauth normalize
hermes-vault oauth refresh google --alias work
hermes-vault oauth refresh google --alias personal
```

This avoids refresh-token collisions when one operator stores multiple identities for the same provider.

## Backup Verification and Drill

v0.7.0 adds a non-mutating recovery drill so operators can prove a backup is usable before an incident.

```bash
hermes-vault backup-verify --input ~/vault-backup.json
hermes-vault restore --dry-run --input ~/vault-backup.json
```

The verification/drill path should confirm:

- Backup format is valid
- Salt compatibility is intact
- The passphrase can decrypt the payload
- Record counts match expectations
- Audit data is present when included in the backup

Keep `vault.db` and `master_key_salt.bin` together in backup procedures. A verified backup is only useful if you can restore it with the matching salt.

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
8.  On success, the access token is stored as `oauth_access_token` and the refresh token as `oauth_refresh_token` with alias `refresh:<alias>`.
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

When Hermes Vault is registered as an MCP server inside Hermes Agent, agents can use `oauth_login` and `oauth_refresh`:

- `oauth_login` returns an authorization URL and starts a background callback thread. The agent opens the URL, completes consent, and tokens are stored automatically.
- `oauth_refresh` triggers the same refresh engine described above, returning the result to the agent.

Both tools require policy permissions (`add_credential` for login, `rotate` for refresh).
