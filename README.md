# Hermes Vault

Hermes Vault is a Hermes-native, local-first credential security and access system. It replaces flaky ad hoc credential discovery with one deterministic broker that scans for bad secret storage, encrypts credentials locally, enforces per-agent policy, verifies credentials before re-auth claims, and generates skill contracts that teach Hermes sub-agents the correct workflow.

## Why This Exists

Hermes sub-agents should not decide authentication state by poking around `.env` files, shell configs, notes, or random state files. That behavior creates false "needs re-auth" reports, duplicate sources of truth, and leaked secrets in logs.

Hermes Vault fixes that by making one broker the canonical credential authority:

- Scan Hermes-relevant locations for plaintext secrets, duplicates, bad permissions, and risky storage patterns
- Encrypt credentials in a local SQLite-backed vault
- Materialize brokered access deterministically, with ephemeral environment injection preferred over raw secret output
- Enforce least-privilege per-agent policy
- Verify credentials before any agent reports that re-auth is required
- Generate SKILL.md files that teach Hermes and sub-agents the correct credential contract

## Key Handling

- The master key is passphrase-derived at runtime from `HERMES_VAULT_PASSPHRASE` or an interactive prompt
- A separate local salt file is stored beside the vault database
- If the database exists but the salt is missing, Hermes Vault fails closed instead of silently re-keying the vault
- Vault state lives in `~/.hermes/hermes-vault-data` by default with restrictive file permissions

## Local-First Security Model

- Hermes-only, no OpenClaw integration
- Local encrypted storage only
- No cloud sync
- No browser UI
- No web service requirement
- No raw secret logging
- No raw secret printing in normal CLI flows

## V1 Limitations

- Single-operator design
- Limited provider-specific verification adapters
- No full master-key rotation workflow yet
- No automatic plaintext secret removal
- Ephemeral env materialization is CLI/broker oriented, not yet process-supervision aware
- Generated skills are review artifacts unless explicitly installed

## Install

```bash
cd /home/tony/.hermes/hermes-vault
python3 -m pip install -e .[dev]
```

Set a passphrase for encryption operations:

```bash
export HERMES_VAULT_PASSPHRASE='choose-a-strong-local-passphrase'
```

Optional runtime overrides:

```bash
export HERMES_VAULT_HOME=~/.hermes/hermes-vault-data
export HERMES_VAULT_POLICY=~/.hermes/hermes-vault-data/policy.yaml
```

## Command Examples

```bash
hermes-vault scan
hermes-vault scan --path ~/.hermes --format json
hermes-vault import --from-env ~/.hermes/.env
hermes-vault add openai --alias primary
hermes-vault list
hermes-vault show-metadata openai
hermes-vault verify --service openai
hermes-vault verify --all
hermes-vault broker list --agent hermes
hermes-vault broker env openai --agent dwight --ttl 900
hermes-vault generate-skill --agent hermes
hermes-vault generate-skill --all-agents
```

Scanner output is intentionally pattern-based: it ignores comment-only example lines, and placeholder-looking strings that do not match provider-shaped detector patterns are not reported as findings.

## Why Brokered Access Beats Ad Hoc Discovery

- One source of truth instead of duplicate secrets across files
- Policy-controlled access instead of whatever an agent can find on disk
- Deterministic verification before re-auth recommendations
- Better auditability for false auth claims
- Less secret sprawl in notes, logs, and memory

## Source Of Truth Policy

- Temporary plaintext migration is allowed only by explicit policy
- Plaintext secrets under managed Hermes paths are policy violations unless exempted
- Imported credentials should become the canonical source of truth
- Split-brain state is treated as a defect, not a normal operating mode

## Generated Skills

Generated skill files are meant to be reviewed first and can be installed into live Hermes skill directories only by operator choice. The contract is explicit:

1. Identify the required service.
2. Request brokered access through Hermes Vault.
3. Attempt the task using brokered access.
4. If access fails, run Hermes Vault verification.
5. Report re-auth only when verification explicitly shows invalid or expired credentials.
6. Otherwise report the verified failure category such as network, endpoint, scope, or configuration.

## Layout

```text
hermes-vault/
├─ README.md
├─ pyproject.toml
├─ policy.example.yaml
├─ src/hermes_vault/
├─ skills/
├─ tests/
└─ docs/
```

See [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md), [docs/credential-lifecycle.md](docs/credential-lifecycle.md), and [docs/operator-guide.md](docs/operator-guide.md) for the deeper design.
