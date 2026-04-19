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

Recommended with `uv`:

```bash
uv sync --extra dev
```

Or with pip:

```bash
python3 -m pip install -e .[dev]
```

Hermes Vault targets Python 3.11+.

## Quick Start

```bash
export HERMES_VAULT_PASSPHRASE='choose-a-strong-local-passphrase'
hermes-vault --help
hermes-vault scan --path ~/.hermes
hermes-vault verify --all
hermes-vault generate-skill --all-agents
```

Default runtime state lives in `~/.hermes/hermes-vault-data`.

## Common Commands

```bash
hermes-vault scan
hermes-vault import --from-env ~/.hermes/.env
hermes-vault add openai --alias primary
hermes-vault list
hermes-vault verify --service openai
hermes-vault broker env openai --agent dwight --ttl 900
```

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

See [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md), [docs/credential-lifecycle.md](docs/credential-lifecycle.md), and [docs/operator-guide.md](docs/operator-guide.md).
