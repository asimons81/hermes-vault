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
