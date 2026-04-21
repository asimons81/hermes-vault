# Migration Notes: 0.1.0 → 0.2.0

## Overview

Version 0.2.0 hardens the Hermes Vault contract surface. There are no breaking changes to the vault database schema or encryption format — existing vaults from 0.1.0 work without migration. The changes are in policy format, CLI behavior, and internal mutation paths.

## What Changed

### 1. Canonical Service IDs

All service references are now normalized to canonical IDs automatically. You do not need to update existing vault records — the vault already normalizes on read and write.

**Action required:** None for existing data. If your `.env` or policy files use legacy names like `open_ai`, `gmail`, or `gh`, they will continue to work. The canonical names (`openai`, `google`, `github`) are what gets stored.

### 2. Deterministic Credential Selectors

CLI commands that target an existing credential now require deterministic resolution:

- **UUID** — always works, exact match
- **service + `--alias`** — always works, exact match
- **service only** — works only when exactly one credential exists for that service

If you have multiple credentials for the same service under different aliases, `hermes-vault rotate github` will now fail with an `Ambiguous` error. Use `hermes-vault rotate github --alias work` or `hermes-vault rotate <credential-id>` instead.

**Action required:** None if you only have one credential per service. If you have aliases, use `--alias` or credential IDs.

### 3. CLI: `verify` Command Positional Target

The `verify` command no longer uses `--service` as a flag. The service is now a positional argument:

```bash
# Old (0.1.0)
hermes-vault verify --service openai

# New (0.2.0)
hermes-vault verify openai
hermes-vault verify github --alias work
hermes-vault verify a1b2c3d4-...  # by credential ID
hermes-vault verify --all          # verify everything
```

**Action required:** Update any scripts or aliases that use `verify --service`.

### 4. Policy v2 Format

Policy now supports per-service action permissions in a new dict format:

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

**Backward compatible:** The legacy flat-list format still works and grants all actions on all listed services. You can mix v1 and v2 agents in the same `policy.yaml`.

**Action required:** None. Adopt v2 format when you need to restrict actions per service.

### 5. Agent Capabilities

Non-service-scoped actions (list, scan, export, import) are now gated by agent-level capabilities:

```yaml
agents:
  pam:
    services:
      google:
        actions: [get_env, verify, metadata]
    capabilities: [list_credentials, scan_secrets]
```

**Backward compatible:** If `capabilities` is omitted, all capabilities are implicitly granted.

**Action required:** None. Add `capabilities` to restrict what agents can do outside of per-service actions.

### 6. Centralized Mutation Paths

All write/destructive operations now flow through a centralized `VaultMutations` layer. This means:

- Every mutation (add, rotate, delete, metadata) produces an audit entry
- Agent mutations are checked against policy before execution
- Operator CLI mutations skip policy checks but still produce audit entries

**Action required:** None. This is an internal improvement. Audit logs are now more comprehensive.

### 7. Version Bump

`pyproject.toml` and `__init__.py` now report version `0.2.0`.

## What Did NOT Change

- Vault database schema (SQLite table structure is unchanged)
- Encryption format (AES-GCM with PBKDF2-HMAC-SHA256, version `aesgcm-v1`)
- Salt file format and handling
- Runtime layout (`~/.hermes/hermes-vault-data`)
- Environment variable names (`HERMES_VAULT_PASSPHRASE`, etc.)
- Backup format (`hvbackup-v1`)
