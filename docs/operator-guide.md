# Operator Guide

## Setup

1. Install the package.
2. Set `HERMES_VAULT_PASSPHRASE`.
3. Run `hermes-vault list` once to initialize the vault layout and default policy.
4. Edit `~/.hermes/hermes-vault-data/policy.yaml` for the real agent allowlists.
5. Back up both `vault.db` and `master_key_salt.bin` together. Losing the salt makes the vault unreadable.

## v0.20.0 secret-source startup runbook

Hermes Vault now materializes mapped startup credentials through the standalone
Hermes Secret Source plugin. Use this when Hermes needs explicit env vars at
process startup, not when the agent is already in-loop.

```bash
hermes-vault --no-banner secret-source fetch --agent hermes --ttl 900 --format json -- \
  OPENAI_API_KEY=hv://openai \
  GITHUB_TOKEN=hv://github?alias=work
```

```yaml
secrets:
  sources: [hermes_vault]
  hermes_vault:
    enabled: true
    binary: hermes-vault
    agent: hermes
    ttl_seconds: 900
    timeout_seconds: 30
    home: ~/.hermes/hermes-vault-data
    policy: ~/.hermes/hermes-vault-data/policy.yaml
    env:
      OPENAI_API_KEY: hv://openai
      GITHUB_TOKEN: hv://github?alias=work
```

- Keep `HERMES_VAULT_PASSPHRASE` available to the Hermes startup process. The
  plugin protects it from being overwritten by any secret source.
- Use only mapped `hv://service` and `hv://service?alias=name` refs. No bulk
  export, no background refresh, and no write-back.
- The fetch path is non-interactive, uses `run_secret_cli()`, and keeps partial
  success as warnings instead of failing the whole startup when at least one
  usable secret is returned.
- Empty values are omitted. If zero usable secrets remain, the fetch result is
  an error with a structured `error_kind`.
- The first Hermes process that installs or discovers the plugin may not use it
  until the next Hermes process starts because plugin discovery happens after
  startup env loading.
- MCP remains the in-loop control plane for agent actions. Secret Source is only
  for bootstrap credentials.

## v0.19.0 agent-control-plane runbook

This release makes agent access explainable, requestable, lease-bound, and recoverable without exposing raw secrets:

```bash
hermes-vault policy explain hermes openai --action get_env --ttl 600
hermes-vault policy simulate --agent hermes --service openai --actions get_env,verify,metadata
hermes-vault request access openai --agent hermes --purpose "release verification" --ttl 600
hermes-vault request list --status pending
hermes-vault request approve <request-id> --issue-lease --ttl 600
hermes-vault lease checkout openai --agent hermes --purpose "release verification" --ttl 600
hermes-vault agent context hermes --format json
hermes-vault recovery drill --backup ~/vault-backup.json --format json
hermes-vault incident bundle --output ~/hv-incident.zip --since 24h
```

- `policy explain` is the first stop when an agent is denied or when a new workflow is being designed. It shows action permission, TTL, raw-secret boundary, lease requirement, and a safe next step.
- `request access` creates a durable, metadata-only request. `request approve --issue-lease` can turn an approved request into a time-bound lease without bypassing the broker.
- `lease checkout` reuses or issues a lease, then materializes env through the existing policy and broker path.
- `agent context` returns a redacted manifest of services, credential metadata, leases, and access requests for one agent.
- `recovery drill` combines backup verification, restore dry-run, metadata diff, and policy hash into one proof report.
- `incident bundle` writes a redacted zip with audit slices, policy summary, health, leases, requests, and runtime metadata. It excludes vault databases, salts, encrypted payloads, raw secrets, provider responses, and env files.
- Dashboard Command Center exposes agent context, policy explain, access requests, approval decisions, and recovery drills through the same local-only token-guarded boundary.
- MCP exposes the same control-plane surfaces with `request_access`, `policy_explain`, `lease_checkout`, `vault://agent-context`, `vault://policy-explain`, `vault://requests`, and `vault://recovery`.

## v0.18.0 operator-workflow convergence runbook

This release makes the console and MCP surfaces better at answering "what should I do next?" without exposing secrets:

```bash
hermes-vault dashboard --no-open
hermes-vault mcp
hermes-vault diff --against ~/vault-backup.json --format json
```

- Dashboard Onboarding Preview wraps `bootstrap --dry-run` for redacted env import planning. It does not import credentials or redact source files from the browser.
- Dashboard Recovery Hub can verify a backup, run restore dry-run, and diff current metadata against a backup from one local view.
- Credential, lease, and audit dashboard tables now support client-side search, status filters, and sorting for larger vaults.
- MCP `vault://status?agent_id=<agent>` returns policy-scoped health, lease, backup, policy, profile, and safe next-step metadata. It never returns raw secret values.
- Dashboard vault-key validation now checks every credential record, so late-record decrypt failures are visible before secret-backed actions run.

## v0.16.0 access-lifecycle release runbook

This release turns access into a lease lifecycle. Use these commands when you want bounded access, a reusable policy baseline, and a quick cleanup path:

```bash
hermes-vault policy pack list
hermes-vault policy pack show coder
hermes-vault lease issue openai --agent hermes --ttl 600
hermes-vault lease list --agent hermes
hermes-vault lease revoke lease-123 --agent hermes --reason "task complete"
```

- `policy pack` gives canonical starting policy files instead of hand-editing YAML from scratch.
- `lease issue` creates a time-bound access record.
- `lease list`, `lease show`, `lease renew`, and `lease revoke` are the operator lifecycle tools.
- Dashboard and MCP surfaces show lifecycle metadata but never raw secret values.

## v0.17.0 lease-assurance runbook

This release makes the lease lifecycle observable and maintainable, not just invocable:

```bash
hermes-vault health --format json
hermes-vault maintain --dry-run --cleanup-leases
hermes-vault maintain --cleanup-leases
hermes-vault policy doctor
hermes-vault diff --against ~/vault-backup.json --format json
```

- `health` now includes `leases.active`, `leases.expired`, `leases.revoked`, and `leases.total`.
- `maintain --cleanup-leases` revokes expired leases only. Active leases are left alone, and repeated runs stay safe.
- `policy doctor` now warns when an agent can issue leases without `get_env` or `get_credential`, and when it can revoke leases without `issue_lease`.
- `diff` now shows lease additions, removals, and changes so backup comparisons include access drift, not just credential drift.

## v0.14.0 Windows-native release runbook

This release is about keeping the vault healthy on its own after credentials already exist. Use the tools in this order when you want the honest picture:

```bash
hermes-vault status
hermes-vault health --verify-live --service openai
hermes-vault maintain --dry-run
hermes-vault policy doctor
hermes-vault backup-verify --input ~/vault-backup.json
hermes-vault restore --dry-run --input ~/vault-backup.json
hermes-vault rotate-master-key
```

- `status` is the freshness readout.
- `health` is the current operator posture, and `--verify-live` checks a real provider when you need it.
- `maintain` runs the scheduled refresh plus health loop, but it doesn't prove recoverability on its own.
- `policy doctor` catches drift, legacy grants, stale generated skills, and other lifecycle paper cuts.
- `backup-verify` and `restore --dry-run` are the recovery proof path. Backup age is a clue, not evidence.
- `rotate-master-key` is the deliberate rekey path, not a maintenance shortcut.

## Recommended First Run

```bash
hermes-vault bootstrap --from-env ~/.hermes/.env --agent hermes --dry-run
hermes-vault bootstrap --from-env ~/.hermes/.env --agent hermes
hermes-vault verify --all
hermes-vault policy doctor
hermes-vault generate-skill --all-agents
```

### First Safe Agent bootstrap

`hermes-vault bootstrap` is the guided path from a normal `.env` to safe agent access. The dry-run report lists importable and skipped env vars, policy-doctor summary, generated skill contract path, broker-env next command, and MCP config snippet. It does not print secret values and does not mutate the vault or source file.

```bash
hermes-vault bootstrap --from-env ~/.hermes/.env --agent hermes --dry-run --json
hermes-vault bootstrap --from-env ~/.hermes/.env --agent hermes
```

Use `--map` for intentional custom names:

```bash
hermes-vault bootstrap --from-env ~/.hermes/.env --map CUSTOM_VENDOR_TOKEN=custom-vendor:personal_access_token
hermes-vault bootstrap --from-env ~/.hermes/.env --map DATABASE_URL=postgres:connection_url
```

`NEXT_PUBLIC_*` public config stays skipped. Broad DB URLs, passwords, app secrets, JWT secrets, and session secrets also stay skipped unless explicitly mapped. With `--redact-source`, Hermes Vault comments only successfully imported lines and reports how many skipped lines were left unchanged. `--dry-run --redact-source` does not modify the source file.

### Env import preview and mapping

The lower-level importer remains available when you only want import behavior without the wider First Safe Agent report:

```bash
hermes-vault import --from-env ~/.hermes/.env --dry-run
hermes-vault import --from-env ~/.hermes/.env --map CUSTOM_VENDOR_TOKEN=custom-vendor:personal_access_token
```

## From `.env` to a real agent workflow

If you start with a normal `.env`, the fastest safe path is now the bootstrap command:

1. Preview the full flow before anything changes

   ```bash
   hermes-vault bootstrap --from-env ~/.hermes/.env --agent hermes --dry-run --json
   ```

2. Import the approved entries into the encrypted vault

   ```bash
   hermes-vault bootstrap --from-env ~/.hermes/.env --agent hermes
   ```

3. Generate the agent skill contract

   ```bash
   hermes-vault generate-skill --all-agents
   ```

4. Review the generated skill

   - Generated skills are written under `~/.hermes/hermes-vault-data/generated-skills/<agent>/SKILL.md`
   - The skill embeds a policy hash, so drift is detectable
   - Treat it as a review artifact until you explicitly install it into the live Hermes skill directory

5. Wire Hermes to the vault runtime

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

## Unattended OAuth refresh

When an agent already has an OAuth access token and matching `refresh:<alias>` record, use `hermes-vault oauth refresh <service> --alias <alias>` or `hermes-vault maintain` for non-interactive renewal. Those paths require `rotate` permission on the service, use the stored refresh token instead of opening a browser, and fail closed if the provider refuses renewal or the refresh token is missing. `policy doctor` will flag the gap and suggest the `rotate` action when an agent should be allowed to refresh.

Before first login, check provider readiness:

```bash
hermes-vault oauth doctor google
hermes-vault oauth doctor google --format json
```

For browserless first login, use device-code auth directly or the headless shortcut:

```bash
hermes-vault oauth device-login google --alias work
hermes-vault oauth login google --alias work --headless
```

`--headless` only works for providers with a device authorization endpoint. Providers without device-code support fail closed and suggest `--no-browser`, which remains the manual browser callback fallback.

### Remote browser fallback for callback login

For a remote shell where the vault runs on a host without a browser, keep using `--no-browser` with an explicit callback port and forward that port from your local machine:

On the remote host:

```bash
hermes-vault oauth login google --alias work --no-browser --port 8765
```

On your local machine:

```bash
ssh -L 8765:127.0.0.1:8765 <host>
```

Open the printed authorization URL in your local browser. The provider callback to `127.0.0.1:8765` travels through the SSH tunnel to the remote callback server. This is still remote-browser-to-callback plumbing. If you need true browserless first login, use `hermes-vault oauth device-login`; that's the separate device-code flow.

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

## Hermes Secret Source Plugin

Use the Secret Source plugin when Hermes needs provider env vars during process
startup, before in-loop MCP tools are available. Copy
`plugins/hermes-vault-secret-source/` to `~/.hermes/plugins/hermes-vault/` and
configure explicit mappings:

```yaml
secrets:
  sources: [hermes_vault]
  hermes_vault:
    enabled: true
    binary: hermes-vault
    agent: hermes
    ttl_seconds: 900
    home: ~/.hermes/hermes-vault-data
    env:
      OPENAI_API_KEY: hv://openai
      GITHUB_TOKEN: hv://github?alias=work
```

The Hermes process still needs `HERMES_VAULT_PASSPHRASE` or the matching
profile passphrase env var so the local vault can be opened. Keep provider
secrets out of `.env`; leave only the Vault bootstrap/config vars there.

V1 is intentionally narrow: mapped refs only, no bulk export, no refresh,
no write-back, and no mid-session secret API. Empty values are skipped instead
of returned, and partial success reports warnings for skipped refs.

## Maintenance

`hermes-vault maintain` is the scheduled run for token refresh and vault hygiene. It combines proactive OAuth refresh, health checks, stale-verification checks, and backup-age warnings in one report.

```bash
hermes-vault maintain --dry-run
hermes-vault maintain
hermes-vault maintain --print-schedule
```

- `--dry-run` reports what would be refreshed or warned about without mutating tokens.
- `--format json` is useful for cron, systemd timers, and log aggregation.
- Exit code `0` means the maintenance run completed cleanly.
- Exit code `1` means warnings or refresh failures were found.
- Exit code `2` means invalid arguments.
- `--print-schedule` is the safer way to generate a systemd or Windows Task Scheduler example when you want to inspect the unit before installation. `--print-systemd` remains available as a compatibility alias.

## Dashboard

`hermes-vault dashboard` starts the local Hermes Vault Console introduced in v0.8.0 and expanded through v0.20.0. Use it for daily operator visibility, policy explanation, request review, and bounded checks. Use the CLI for setup, imports, backups, policy edits, credential mutation, destructive recovery, release work, and any operation where you want an explicit command transcript.

```bash
hermes-vault dashboard
hermes-vault dashboard --no-open
hermes-vault dashboard --port 8765
hermes-vault dashboard --ttl-seconds 3600
```

Launch behavior:

1. The server binds to `127.0.0.1` by default, and non-local dashboard hosts are rejected.
2. A random session token is generated for that process and printed in the launch URL.
3. API requests need either the launch URL token or the same token passed through the standard bearer authorization header.
4. The token expires after the configured TTL and also dies when the process exits.
5. The UI is served from static assets packaged with the installed Python package. If the dashboard opens but assets are missing, verify the wheel or editable install includes `hermes_vault/dashboard_static/`.

The console is for health, credential inventory, policy findings, audit activity, MCP binding status, operations, and recovery posture. It is not a hosted vault, raw-secret viewer, policy editor, or remote admin plane.

Safe dashboard actions include:

- Run health
- Run policy doctor
- Verify one credential or all credentials
- Run OAuth refresh dry-run
- Run maintenance dry-run
- Verify a backup file
- Run restore dry-run
- Explain a policy decision
- Load a redacted agent context manifest
- Create, approve, or deny an access request
- Run a recovery drill

The dashboard forces OAuth refresh and maintenance to dry-run-only even if a client posts `dry_run=false`. Live OAuth refresh and live maintenance remain CLI-only:

```bash
hermes-vault oauth refresh google --alias work
hermes-vault maintain
```

The dashboard responses redact raw secret and token material, and they do not expose encrypted payloads. Credential editing, policy editing, cloud sync, remote access, destructive restore, credential deletion, master-key rotation, and plaintext export stay out of the dashboard surface.

### Reading dashboard health and status

Treat the dashboard as a triage surface, then confirm anything sensitive through the CLI before mutating state.

- **Healthy/ok** means the command completed and found no high-risk finding in that view.
- **Warning/stale/expiring** means an operator should inspect age, expiry, or backup posture before a scheduled run.
- **Invalid/denied/error** means don't rotate, delete, refresh, or re-auth on instinct. Check the exact reason, policy entry, audit trail, and provider reachability first.
- **Empty vault** can be normal on a new runtime, but confirm `HERMES_VAULT_HOME`, passphrase source, and policy path before importing credentials.
- **MCP binding status** describes the local MCP process configuration. It doesn't replace `policy.yaml`, and a caller-supplied `agent_id` isn't strong identity by itself.

### Handling policy findings

Run policy doctor from the dashboard for a quick view. Use the CLI when applying changes:

```bash
hermes-vault policy doctor
hermes-vault policy doctor --strict
```

Review each finding before editing `policy.yaml`. Long TTLs, `raw_secret_access: true`, stale generated skills, and OAuth refresh permission gaps can all be intentional in narrow cases, but they should be written down and reviewed. Regenerate and review skills after policy changes:

```bash
hermes-vault generate-skill --all-agents
```

### Checks before sensitive credential operations

Before live refresh, rotation, deletion, import with source redaction, restore, or master-key work:

1. Confirm the runtime home and policy path are the intended ones.
2. Run a dry-run or read-only command first where available.
3. Check the audit log for recent failures or unexpected access.
4. Verify the target selector is unambiguous, especially when a service has multiple aliases.
5. Confirm the latest backup includes both `vault.db` and `master_key_salt.bin`.
6. Prefer provider verification and scope review before telling an agent to re-auth.

Release visual QA should cover desktop and mobile widths, the first-run vault-door intro, bundled brand asset loading, text overflow, and control overlap before publishing a dashboard build.

### Recovery posture basics

Recovery is boring by design: keep the encrypted database and salt together, prove backups before an incident, and use dry-runs before restore.

```bash
hermes-vault backup --output ~/vault-backup.json
hermes-vault backup-verify --input ~/vault-backup.json
hermes-vault restore --dry-run --input ~/vault-backup.json
```

A backup that can't decrypt with the current passphrase and matching `master_key_salt.bin` isn't useful. Don't generate a new salt for an existing vault database; restore the matching salt from backup instead.

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
| `list_credentials` | `broker list`, enumerate credentials the agent may access |
| `scan_secrets` | `scan`, scan the filesystem for plaintext secrets |
| `export_backup` | `backup`, export an encrypted backup of the vault |
| `import_credentials` | `import`, add credentials from env files or JSON |

**Backward compatibility:** If an agent has no `capabilities` field, all capabilities are implicitly granted for backward compatibility.

When `capabilities` is explicitly set, only the listed capabilities are allowed.
For example, an agent with `capabilities: [list_credentials]` can enumerate credentials but cannot run scans or exports.

### Example: restrict capabilities

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
| `telegram` | None |
| `netlify` | None |
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

## OAuth Freshness at Handoff

v0.15.0 introduces automatic OAuth token freshness at broker handoff. When an agent requests an ephemeral environment, near-expiry OAuth tokens are refreshed before delivery — reducing stale-token failures in agent workflows.

### What changed for operators

- `hermes-vault broker env <service> --agent <agent>` now includes `oauth_refresh` metadata in its JSON output, showing whether the token was refreshed (`true`), still fresh (`false`), or had no expiry (`null`).
- Agents that should receive live-refreshed OAuth tokens at handoff need the `rotate` action in their policy v2 entry for that service.

### Policy requirement

Live OAuth refresh requires the existing `rotate` service action. The `get_env` action alone does NOT authorize vault mutation. If an agent only has `get_env` and the OAuth token is hard-expired, the broker denies the request with a clear policy reason.

Example policy entry with refresh permission:

```yaml
agents:
  my-agent:
    services:
      google:
        actions: [get_env, rotate]   # rotate needed for live refresh at handoff
    max_ttl_seconds: 900
```

### How to verify

Run `hermes-vault broker env <service> --agent <agent>` and inspect the `oauth_refresh` metadata:

```json
{
  "allowed": true,
  "service": "google",
  "agent_id": "my-agent",
  "env": { "GOOGLE_API_KEY": "..." },
  "oauth_refresh": {
    "refreshed": true,
    "reason": "Token was expired; successfully refreshed"
  }
}
```

### Failure scenarios

| Scenario | Behavior |
|----------|----------|
| Token is far from expiry | Passes through untouched; `oauth_refresh.refreshed = false` |
| Token near expiry, refresh succeeds | Refreshed token delivered; `oauth_refresh.refreshed = true` |
| Token hard-expired, refresh fails | Request denied with clean error; `oauth_refresh.refreshed = false` and failure reason |
| Near-expiry, refresh fails | Warning returned but existing token still delivered (agent may still succeed) |
| Agent lacks `rotate` permission | Policy denial with reason about missing `rotate` action |
| Non-OAuth credential | `oauth_refresh.refreshed = null` (no-op) |

### Dashboard boundary

Dashboard OAuth refresh remains dry-run-only. Live token mutation at handoff is exclusive to CLI and MCP broker paths.

## Backup Verification and Drill

v0.14.0 makes the platform split explicit: `maintain` still covers refresh + health only, but the release also brings Windows-native support and DPAPI-backed master-key protection. Use `policy doctor` for drift diagnosis, then `backup-verify` and `restore --dry-run` to prove recovery before calling the vault fully assured.

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

### Custom OpenAI-Compatible Endpoints Verification

Hermes Vault supports a generic, environment-driven OpenAI-compatible verifier for custom or unknown services.

- Define the environment variable `HERMES_VAULT_VERIFY_URL_<SERVICE>` to specify the verification URL for that service.
- The service name is normalized: hyphens (`-`), dots (`.`), and spaces (` `) are translated to underscores (`_`), and the name is uppercased.
  - For service `deepseek` -> `HERMES_VAULT_VERIFY_URL_DEEPSEEK`
  - For service `fireworks` -> `HERMES_VAULT_VERIFY_URL_FIREWORKS`
  - For service `custom-provider` -> `HERMES_VAULT_VERIFY_URL_CUSTOM_PROVIDER`
- The endpoint is expected to be an OpenAI-compatible `/v1/models`-style endpoint.
- Hermes Vault will send a GET request with the vaulted credential as the bearer token (`Authorization: Bearer <token>`).
- **Security Warning**: Ensure that the configured URL is trusted and provider-controlled, as the vault will send the decrypted bearer token to it.

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

Most CLI commands that target an existing credential accept a **credential selector**, a positional argument that resolves to exactly one credential. Three forms are supported:

| Selector | Example | When it works |
|---|---|---|
| **credential ID** (UUID) | `hermes-vault rotate a1b2c3d4-...` | Always, exact match |
| **service + `--alias`** | `hermes-vault rotate github --alias work` | Always, exact match |
| **service only** | `hermes-vault rotate openai` | Only when exactly one credential exists for that service |

### When service-only is ambiguous

If you have multiple credentials for the same service (e.g. `github` with aliases `work` and `personal`), using just the service name will fail:

```
$ hermes-vault rotate github
Ambiguous: Service 'github' has 2 credentials. Specify credential ID or service+alias
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

- `add <service> --secret SECRET [--alias ALIAS]`: adds a new credential
- `broker get <service> --agent AGENT`: fetches a credential via policy
- `broker env <service> --agent AGENT`: materializes ephemeral env vars

Service names are normalized automatically (see [Canonical Service IDs](#canonical-service-ids) above).

## Audit Log Query

Query the audit log to trace credential access, denials, and mutations:

```bash
hermes-vault audit
hermes-vault audit --agent dwight --since 7d
hermes-vault audit --service openai --decision deny --format json
hermes-vault audit --since 2026-01-01 --until 2026-03-01
```

Use `--since` with a relative value (`7d`, `30d`) or an ISO date (`YYYY-MM-DD`).
Use `--decision allow` or `--decision deny` to filter by access decision.
Use `--format json` for machine-readable output.

## Credential Status

Inspect credential health across the vault:

```bash
hermes-vault status
hermes-vault status --stale 7d
hermes-vault status --invalid
hermes-vault status --expiring 30d --format json
hermes-vault status --stale 7d --invalid
```

Credentials with no `last_verified_at` are classified as stale.
Credentials with no expiry set are omitted by `--expiring`.
Filters can be combined.

## Expiry Metadata

Set or clear expiry dates for credentials to track renewal windows:

```bash
hermes-vault set-expiry openai --alias primary --days 90
hermes-vault set-expiry github --alias work --date 2026-07-01
hermes-vault clear-expiry openai --alias primary
```

Use `--days` for a relative deadline (N days from today) or `--date` for an
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

Run `hermes-vault oauth doctor <provider>` after setting these values to confirm readiness without starting a login or token exchange.

### Login flow

Browser callback login:

1.  `hermes-vault oauth login <provider> [--alias NAME] [--scope SCOPE ...] [--no-browser]`
2.  The CLI generates a PKCE code_verifier + code_challenge and a CSRF state nonce.
3.  An ephemeral callback server starts on `127.0.0.1:0` (OS-assigned port).
4.  The browser is opened with the authorization URL (or the URL is printed if `--no-browser`).
5.  The user completes consent in the browser.
6.  The provider callback hits the local server with `?code=...&state=...`.
7.  The CLI validates state with timing-safe comparison, then POSTs the code to the token endpoint.
8.  On success, the access token is stored as `oauth_access_token` and the refresh token as `oauth_refresh_token` with alias `refresh:<alias>`.
9.  If the provider returns `expires_in`, an expiry timestamp is set automatically.

Headless device-code login on supported providers:

1.  `hermes-vault oauth login <provider> --headless` or `hermes-vault oauth device-login <provider>`
2.  The CLI asks the provider for a device/user code.
3.  The operator opens the verification URL and enters the user code.
4.  The CLI polls until the provider approves, denies, expires, or times out.
5.  On success, tokens are stored with the same vault record shape as browser callback login.

### Token lifecycle and refresh

Access tokens have a limited lifespan (typically 1 hour for Google, configurable by provider). The refresh token lives in the vault separately and is used to obtain new access tokens without browser re-authentication.

Refresh commands:

```bash
# Refresh a single service
hermes-vault oauth refresh google --alias work
hermes-vault health --verify-live --service google

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

When Hermes Vault is registered as an MCP server inside Hermes Agent, agents can use `oauth_login`, `oauth_device_login`, and `oauth_refresh`:

- `oauth_login` returns an authorization URL and starts a background callback thread. The operator opens the URL, completes browser consent, and tokens are stored automatically.
- `oauth_device_login` returns a verification URL and user code, starts background polling, and stores tokens after approval. It does not return raw access tokens, refresh tokens, or provider device codes.
- `oauth_refresh` triggers the same refresh engine described above, returning the result to the agent.

The login tools require `add_credential`; refresh requires `rotate`.
