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

- Set `HERMES_VAULT_MINIMAX_VERIFY_URL` before running `hermes-vault verify --service minimax`
- Point it at an operator-validated authenticated GET endpoint that returns `200` for valid credentials and `401` or `403` for invalid ones
- If you are testing an OpenAI-compatible MiniMax deployment, `/v1/models` is a candidate endpoint to validate, not an assumed contract

### "Broker denied access"

- Read the exact denial reason
- Update policy only if the service should genuinely be available to that agent

## Safe Operating Defaults

- Scan and import first
- Verify before any re-auth recommendation
- Use broker env materialization for tasks
- Keep audit records for false-auth troubleshooting
- Treat generated skills as review artifacts unless you explicitly install them
