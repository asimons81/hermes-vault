# Hermes Secret Source Plugin

Hermes Vault can act as an official Hermes Secret Source plugin for startup
credential materialization. This is separate from the MCP server: MCP is for
in-loop agent tools, while the Secret Source plugin resolves configured env vars
before Hermes reads provider credentials.

## Install

Copy the standalone plugin package:

```bash
mkdir -p ~/.hermes/plugins/hermes-vault
cp -R plugins/hermes-vault-secret-source/* ~/.hermes/plugins/hermes-vault/
```

Install Hermes Vault so `hermes-vault` is on the PATH visible to Hermes.

## Configure Hermes

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

Each `env` entry is explicit: the key is the environment variable Hermes should
receive, and the value is a Hermes Vault ref.

Supported refs:

```text
hv://openai
hv://github?alias=work
```

## Bootstrap Environment

The Hermes process still needs enough bootstrap environment to open the local
vault:

```bash
export HERMES_VAULT_PASSPHRASE='your-local-passphrase'
export HERMES_VAULT_HOME=~/.hermes/hermes-vault-data
```

For profiles, use the same profile passphrase variable that Hermes Vault uses,
for example `HERMES_VAULT_PASSPHRASE_WORK` for profile `work`.

`HERMES_VAULT_PASSPHRASE` is protected and cannot be overwritten by this plugin.

## Contract Boundaries

- `fetch()` never prompts.
- `fetch()` never mutates `os.environ`.
- The plugin uses Hermes `run_secret_cli()` with argv lists, never `shell=True`.
- Empty values are omitted and never applied.
- Partial success stays successful: skipped refs become warnings.
- If no usable secret resolves, the plugin returns a machine-readable error.
- V1 is mapped-only: no bulk export, no background refresh, no write-back, no
  mid-session secret API.

## Migration From Plain `.env`

1. Import existing credentials into Hermes Vault.
2. Remove provider credentials from the Hermes startup `.env`.
3. Keep only Vault bootstrap/config vars, such as `HERMES_VAULT_PASSPHRASE`.
4. Add explicit `secrets.hermes_vault.env` mappings.
5. Confirm policy grants the configured `agent` the `get_env` action.

Plugin discovery happens after Hermes' first dotenv load in the process that
discovers the plugin. Subsequent Hermes child processes and sessions can use
the source.
