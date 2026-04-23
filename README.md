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

## Common Commands

```bash
hermes-vault scan
hermes-vault update --check
hermes-vault import --from-env ~/.hermes/.env
hermes-vault add openai --alias primary
hermes-vault list
hermes-vault verify openai
hermes-vault broker env openai --agent dwight --ttl 900
```

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

See [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md), [docs/credential-lifecycle.md](docs/credential-lifecycle.md), [docs/operator-guide.md](docs/operator-guide.md), [docs/migration-0.1-to-0.2.md](docs/migration-0.1-to-0.2.md), and [docs/update-workflow.md](docs/update-workflow.md).
