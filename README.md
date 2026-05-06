# Hermes Vault

Hermes Vault is a local-first credential broker and encrypted vault for Hermes agents. It scans for risky plaintext secrets, stores credentials locally, verifies them before re-auth claims, and generates skill contracts that keep agents on the same workflow.

![Hermes Vault CLI banner](assets/hermes-vault.png)

## What It Does

- Scans Hermes-relevant files for plaintext secrets, duplicates, and insecure permissions
- Encrypts credentials in a local SQLite-backed vault
- Brokers access with per-agent policy and ephemeral environment materialization
- Verifies credentials before any re-auth recommendation
- Generates `SKILL.md` files for Hermes agents and sub-agents

## Install

Released CLI installs are safest with an isolated tool manager:

```bash
uv tool install git+https://github.com/asimons81/hermes-vault.git@vX.Y.Z
pipx install git+https://github.com/asimons81/hermes-vault.git@vX.Y.Z
```

For local development, use `uv` or editable `pip`:

```bash
uv sync --extra dev
```

Or with pip:

```bash
python3 -m pip install -e .[dev]
```

Hermes Vault targets Python 3.11+.

## Update

Check for the latest tagged release without changing the environment:

```bash
hermes-vault update --check
```

Apply a guarded update:

```bash
hermes-vault update
```

`hermes-vault update` currently auto-updates only for `pipx` and `uv tool` installs. Editable/dev installs, generic `pip` installs, and unknown environments receive an explicit manual command instead of an automatic mutation.

## Quick Start

```bash
export HERMES_VAULT_PASSPHRASE='choose-a-strong-local-passphrase'
hermes-vault --help
hermes-vault scan --path ~/.hermes
hermes-vault import --from-env ~/.hermes/.env
hermes-vault verify --all
hermes-vault generate-skill --all-agents
```

Default runtime state lives in `~/.hermes/hermes-vault-data`.

## MCP Server

Hermes Vault exposes the broker as an MCP (Model Context Protocol) server so that compatible hosts can request credentials programmatically.

```bash
hermes-vault mcp
```

Configure your MCP host (Claude Desktop, Cursor, etc.) to run:

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

All MCP tool calls require an `agent_id`. The same policy.yaml that gates CLI access also gates MCP access.

### MCP Tools

| Tool | Description | Policy Gate |
|---|---|---|
| `list_services` | List credentials visible to the agent | `capability:list_credentials` |
| `get_credential_metadata` | Fetch credential metadata (no secrets) | `can_read(service)` |
| `get_ephemeral_env` | Materialise ephemeral env vars | `can_env(service)` |
| `verify_credential` | Verify a credential against its provider | `can_verify(service)` |
| `rotate_credential` | Rotate a credential to a new secret | `can_rotate(service)` |
| `scan_for_secrets` | Scan filesystem for plaintext secrets | `capability:scan_secrets` |
| `oauth_login` | Initiate PKCE OAuth login (returns auth URL) | `capability:add_credential` |
| `oauth_refresh` | Refresh an OAuth access token using stored refresh token | `action:rotate` |

Raw secrets are **never** transmitted over MCP. The default access pattern is `get_ephemeral_env`.

### OAuth via MCP

Hermes Vault can broker OAuth logins so agents never handle raw passwords. `oauth_login` returns an authorization URL and spins up a callback server -- open the URL in a browser, and tokens are stored automatically. `oauth_refresh` renews tokens proactively before expiry. See [docs/mcp-server.md](docs/mcp-server.md) for full tool schemas.

## Common Commands

```bash
hermes-vault scan
hermes-vault update --check
hermes-vault import --from-env ~/.hermes/.env
hermes-vault add openai --alias primary
hermes-vault list
hermes-vault verify openai
hermes-vault broker env openai --agent dwight --ttl 900
hermes-vault audit --agent dwight --since 7d
hermes-vault status
hermes-vault status --stale 7d
hermes-vault status --invalid
hermes-vault set-expiry openai --alias primary --days 90
hermes-vault clear-expiry openai --alias primary
hermes-vault verify --all --format table
hermes-vault verify --all --report ~/.hermes/hermes-vault-data/reports/verify-latest.json
hermes-vault health
hermes-vault health --format json
hermes-vault sync-skill --check
hermes-vault backup --metadata-only --output ~/meta-backup.json
hermes-vault diff --against ~/meta-backup.json
hermes-vault rotate-master-key
hermes-vault oauth login google --alias work
hermes-vault oauth refresh google --alias work
hermes-vault oauth providers
```

## What's New in 0.6.0 — OAuth PKCE and Token Auto-Refresh

### OAuth PKCE login
`hermes-vault oauth login <provider>` initiates a browser-based PKCE login flow. Tokens are stored in the vault automatically. Supports `--no-browser`, custom `--scope`, and `--alias`. Built-in providers: `google`, `github`, `openai`. Custom providers can be added via YAML.

### Token auto-refresh engine
`hermes-vault oauth refresh <service>` detects expired or nearly-expired access tokens (default 5-minute proactive margin) and refreshes them using stored refresh tokens. Supports `--all`, `--dry-run`, and configurable `--margin`. Exponential backoff with configurable `max_retries`.

### MCP OAuth tools
`oauth_login` and `oauth_refresh` are available as MCP tools when Hermes Vault is registered as an MCP server. Agents can initiate logins and trigger refresh without touching raw tokens.

### Provider registry
OAuth providers are configured in `~/.hermes/hermes-vault-data/oauth-providers.yaml`. The file seeds itself with baked-in defaults on first use. Add custom providers without code changes.

### Security invariants preserved
No raw tokens in logs. No browser state leaked. CSRF-protected via timing-safe state comparison. Refresh tokens are stored separately from access tokens. Atomic vault updates via SQLite transactions.

## What's New in 0.5.0 — Health, Governance, and Key Rotation

### Vault health command
`hermes-vault health` runs a read-only check across stale/invalid/expired credentials
and backup age. Exit codes: 0 = healthy, 1 = warnings found. JSON and markdown output.

### Master-key rotation
`hermes-vault rotate-master-key` re-encrypts every credential under a new passphrase
with atomic rollback. Creates an encrypted pre-rotation backup by default.

### Skill sync with policy hashing
`hermes-vault sync-skill --check` / `--write` / `--print` keeps the
`hermes-vault-access` SKILL.md in sync with current policy. Generated skills embed
a SHA-256 policy hash so stale detection is deterministic.

### Metadata-only backup and vault diff
`hermes-vault backup --metadata-only` exports metadata without encrypted payloads.
`hermes-vault diff --against <path>` compares current vault against a backup.

### Governance warnings
Expiry and backup reminders appear in broker `get_ephemeral_env` decision metadata
under `warnings[]`. Configurable via `HERMES_VAULT_EXPIRY_WARNING_DAYS` and
`HERMES_VAULT_BACKUP_REMINDER_DAYS`. Never expose raw secrets.

## What's New in 0.4.0 — Credential Observability

### Audit query CLI
hermes-vault audit with --agent, --service, --action, --decision,
--since/--until (relative or ISO date), --format table|json, --limit.

### Credential status CLI
hermes-vault status with --stale Nd, --invalid, --expiring Nd,
--format table|json. Credentials with no last_verified_at are always stale.

### Expiry metadata commands
hermes-vault set-expiry (--days N or --date YYYY-MM-DD) and
hermes-vault clear-expiry. Both write audit entries. Expiry round-trips
through backup and restore.

### Verification report output
hermes-vault verify --all now accepts --format table and --report PATH.
Default JSON-to-stdout behavior is unchanged.

### Security invariants preserved
No secrets in audit, status, or verification output. No background
processes. No auto-rotation. No cloud sync.

## What's New in 0.2.0

### Canonical Service IDs

All service names are normalized to canonical IDs automatically. `open_ai`, `open-ai` → `openai`; `gmail`, `google_docs` → `google`; `gh` → `github`. See [docs/operator-guide.md](docs/operator-guide.md) for the full alias table.

### Deterministic Credential Selectors

Commands that target a credential accept three forms:

- **credential ID** (UUID) — always exact
- **service + `--alias`** — always exact
- **service only** — works only when exactly one credential exists for that service

If you have multiple credentials for the same service (e.g. `github` with aliases `work` and `personal`), the CLI fails with an `Ambiguous` error and asks for `--alias` or the credential ID.

Commands that use selectors: `verify`, `rotate`, `delete`, `show-metadata`.

### Policy v2

Policy now supports per-service action permissions:

```yaml
agents:
  dwight:
    services:
      openai:
        actions: [get_credential, get_env, verify, metadata]
        max_ttl_seconds: 900
      github:
        actions: [get_env, verify, metadata]
    max_ttl_seconds: 900
```

Legacy flat-list format (`services: [openai, github]`) still works and grants all actions.

### Agent Capabilities

Non-service-scoped actions are gated by agent-level capabilities:

| Capability | Controls |
|---|---|
| `list_credentials` | `broker list` |
| `scan_secrets` | `scan` |
| `export_backup` | `backup` |
| `import_credentials` | `import` |

If `capabilities` is omitted from an agent's policy, all capabilities are implicitly granted (backward compatible).

### Centralized Mutation Paths

All write/destructive operations (add, rotate, delete, metadata) flow through `VaultMutations` — a centralized, policy-checked, audited mutation layer. The operator CLI path skips policy checks but still produces audit entries.

## Configuration

```bash
export HERMES_VAULT_HOME=~/.hermes/hermes-vault-data
export HERMES_VAULT_POLICY=~/.hermes/hermes-vault-data/policy.yaml
export HERMES_VAULT_NO_BANNER=1
```

If you need a starting policy, copy `policy.example.yaml` into the runtime home and edit the agent allowlists there.

## Notes

- The master key is derived at runtime from `HERMES_VAULT_PASSPHRASE`
- A separate local salt file is stored beside the vault database
- If the database exists but the salt is missing, Hermes Vault fails closed instead of silently re-keying the vault
- Generated skills are review artifacts unless you explicitly install them

## More Detail

See [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md), [docs/credential-lifecycle.md](docs/credential-lifecycle.md), [docs/operator-guide.md](docs/operator-guide.md), [docs/migration-0.1-to-0.2.md](docs/migration-0.1-to-0.2.md), [docs/migration-0.5-to-0.6.md](docs/migration-0.5-to-0.6.md), and [docs/update-workflow.md](docs/update-workflow.md).
