# Migration Notes: 0.6.0 to 0.7.0

## Overview

Version 0.7.0 keeps the vault database, encryption format, salt handling, and backup format compatible with 0.6.0. Existing credentials continue to work after upgrade.

The main migration work is operational: normalize older OAuth records, review policy drift, and add scheduled maintenance if you want Hermes Vault to refresh and check itself continuously.

## What Changed

### 1. Version bump

`pyproject.toml`, package `__version__`, MCP server metadata, and lockfile package metadata now report version `0.7.0`.

**Action required:** None.

### 2. Maintenance command

`hermes-vault maintain` combines OAuth refresh, health checks, stale-verification checks, and backup-age warnings in one scheduled-safe command.

```bash
hermes-vault maintain
hermes-vault maintain --dry-run
hermes-vault maintain --format json
hermes-vault maintain --print-systemd
```

**Action required:** Optional. Use this instead of hand-rolled refresh cron jobs if you want one recurring operator check.

### 3. OAuth storage normalization

Refresh tokens are now paired by access-token alias. New records use aliases like `refresh:work` instead of the v0.6 legacy alias `refresh`.

Run the normalizer after upgrading if you used OAuth in 0.6.0:

```bash
hermes-vault oauth normalize
hermes-vault oauth normalize --write
```

The command is dry-run by default. It removes token-bearing metadata from OAuth access-token payloads and renames legacy refresh-token aliases only when the pairing is unambiguous.

**Action required:** Recommended for operators with existing OAuth records.

### 4. Policy doctor

`hermes-vault policy doctor` inspects policy shape, legacy grants, risky `raw_secret_access`, service/action drift, OAuth readiness, and generated skill drift.

```bash
hermes-vault policy doctor
hermes-vault policy doctor --strict
hermes-vault policy doctor --format json
```

**Action required:** Recommended before release rollout and in CI/scheduled checks.

### 5. MCP agent binding

The MCP server can be launched with deployment-time allowed-agent binding:

```bash
export HERMES_VAULT_MCP_ALLOWED_AGENTS=hermes,gemmy
export HERMES_VAULT_MCP_DEFAULT_AGENT=hermes
```

When configured, tool calls without `agent_id` use the default agent only if it is allowed. Explicit caller IDs are still checked against the allow-list.

**Action required:** Optional. Use this for MCP hosts that cannot reliably pass caller identity.

### 6. Backup verification and restore drill

Backups can now be verified without restore, and restore semantics can be drilled without mutating the live vault:

```bash
hermes-vault backup-verify --input ~/vault-backup.json
hermes-vault restore --dry-run --input ~/vault-backup.json
```

**Action required:** Recommended for operators relying on local backup recovery.

## What Did Not Change

- Vault database format remains compatible
- Encryption format remains `aesgcm-v1`
- Salt file handling is unchanged
- Backup format remains `hvbackup-v1`
- Existing API-key and PAT credentials are unchanged
- Existing MCP tools remain available
- Legacy OAuth refresh alias `refresh` remains readable during migration

## Migration Checklist

- [ ] Upgrade Hermes Vault to 0.7.0
- [ ] Run `hermes-vault oauth normalize` to preview OAuth storage changes
- [ ] Run `hermes-vault oauth normalize --write` if the preview is safe
- [ ] Run `hermes-vault policy doctor`
- [ ] Run `hermes-vault backup-verify --input <backup-file>` against a recent backup
- [ ] Run `hermes-vault restore --dry-run --input <backup-file>` before relying on the backup
- [ ] Replace older refresh-only cron jobs with `hermes-vault maintain` if desired
- [ ] Configure `HERMES_VAULT_MCP_ALLOWED_AGENTS` and `HERMES_VAULT_MCP_DEFAULT_AGENT` if your MCP host omits `agent_id`
