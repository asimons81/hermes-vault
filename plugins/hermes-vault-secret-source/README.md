# Hermes Vault Secret Source Plugin

This plugin lets Hermes Agent resolve explicit startup environment variables
from Hermes Vault.

It is intentionally small:

- mapped mode only
- `hv://service` and `hv://service?alias=name` refs only
- no bulk export
- no rotation or refresh
- no write-back
- no mid-session API

## Install

Copy this directory to:

```text
~/.hermes/plugins/hermes-vault/
```

Hermes Vault must also be installed so the `hermes-vault` executable is
available to Hermes.

## Configure

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
    env:
      OPENAI_API_KEY: hv://openai
      GITHUB_TOKEN: hv://github?alias=work
```

Keep `HERMES_VAULT_PASSPHRASE` in the process environment that starts Hermes.
For profiles, use Hermes Vault's profile-specific passphrase env var.

The plugin protects `HERMES_VAULT_PASSPHRASE` and the active profile passphrase
env var from being overwritten by any secret source.

## Behavior

The plugin calls:

```bash
hermes-vault --no-banner secret-source fetch --agent hermes --ttl 900 --format json -- OPENAI_API_KEY=hv://openai
```

It returns a Hermes `FetchResult`; Hermes itself applies values to
`os.environ` according to Secret Source precedence rules.

Empty values are omitted and never returned as secrets. If at least one mapped
secret resolves successfully, other skipped refs become warnings. If no usable
secret resolves, the plugin reports a machine-readable error kind.
