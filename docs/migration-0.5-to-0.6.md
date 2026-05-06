# Migration Notes: 0.5.0 → 0.6.0

## Overview

Version 0.6.0 adds OAuth PKCE login and token auto--refresh. Existing vaults, credentials, and policies from 0.5.0 work without migration. The new features are opt--in -- you only use them when you run `hermes-vault oauth login`.

## What Changed

### 1. Version bump

`pyproject.toml` and `__init__.py` now report version `0.6.0`.

**Action required:** None. This is cosmetic.

### 2. OAuth PKCE login (`hermes-vault oauth login`)

A new CLI sub--command initiates browser-based OAuth login with PKCE. Tokens are stored in the vault automatically after the user completes consent in the browser.

```bash
# Log in to Google
hermes-vault oauth login google --alias work --scope openid --scope email

# Log in without auto-opening browser
hermes-vault oauth login github --alias personal --no-browser
```

**Prerequisites:**
- For providers that require a `client_id`, set `HERMES_VAULT_OAUTH_<PROVIDER>_CLIENT_ID` before running the command.
- The provider must be registered in the OAuth provider registry (see below).

**Action required:** None unless you want to use OAuth. API-key and personal-access-token workflows are unchanged.

### 3. Token auto-refresh (`hermes-vault oauth refresh`)

A new CLI sub--command refreshes expired or near-expiry OAuth access tokens using stored refresh tokens.

```bash
# Refresh a single service
hermes-vault oauth refresh google --alias work

# Refresh all expired/near-expiry tokens
hermes-vault oauth refresh --all

# Dry-run: see what would refresh without updating vault
hermes-vault oauth refresh google --dry-run
```

**Action required:** None unless you have OAuth tokens stored. Existing API-key credentials are unaffected.

### 4. OAuth provider registry

A new YAML file seeds itself automatically on first use:

```
~/.hermes/hermes-vault-data/oauth-providers.yaml
```

Built-in defaults include `google`, `github`, and `openai`. You can add custom providers by appending entries to this file -- no code changes required.

**Action required:** None. The file is created automatically when the first OAuth command runs.

### 5. MCP OAuth tools

When Hermes Vault is registered as an MCP server, two new tools are available:

- `mcp_hermes_vault_oauth_login` -- returns an authorization URL, background callback server handles token storage
- `mcp_hermes_vault_oauth_refresh` -- triggers the refresh engine and returns structured results

**Action required:** None. Existing MCP tools are unchanged. The new tools appear automatically when the MCP server restarts.

### 6. New credential types

OAuth tokens are stored with these `credential_type` values:

- `oauth_access_token` -- the bearer token used for API calls
- `oauth_refresh_token` -- the long-lived refresh token stored separately under alias `"refresh"`

**Action required:** None if you do not use OAuth. Existing credentials keep their original types.

## What Did NOT Change

- Vault database schema (new columns were not added; tokens are stored in existing `credentials` table)
- Encryption format (AES-GCM with PBKDF2-HMAC-SHA256, version `aesgcm-v1`)
- Salt file format and handling
- Runtime layout (`~/.hermes/hermes-vault-data`)
- Environment variable names (`HERMES_VAULT_PASSPHRASE`, etc.)
- Policy format (new permissions may be needed for OAuth actions; see below)
- Backup format (`hvbackup-v1`)
- MCP tool schemas for existing tools

## Policy considerations for OAuth

If you use OAuth via the MCP server or broker, ensure agent policies include the right actions:

### For `oauth_login` (via MCP)

The agent needs `add_credential` on the provider service:

```yaml
agents:
  my-agent:
    services:
      google:
        actions: [get_env, verify, metadata, add_credential]
```

### For `oauth_refresh` (via MCP)

The agent needs `can_access_service` on the provider service (this is implicit if the service is listed in the agent's policy).

### For brokered access after OAuth login

Once an OAuth token is stored, the agent accesses it the same way as any other credential -- `get_env`, `get_credential`, etc. -- with the same policy gates.

## Migration checklist for operators using OAuth

- [ ] Set `HERMES_VAULT_OAUTH_<PROVIDER>_CLIENT_ID` (and `_CLIENT_SECRET`) if the provider requires it
- [ ] Run `hermes-vault oauth providers` to confirm the provider is registered
- [ ] Add `add_credential` action to agent policies for services that will use `oauth_login`
- [ ] Run `hermes-vault oauth login <provider>` and complete browser consent
- [ ] Verify tokens stored with `hermes-vault list`
- [ ] (Optional) Set up a cron job to run `hermes-vault oauth refresh --all` periodically
- [ ] (Optional) Add `oauth_access_token` to `credential_type` filters in status/health queries if you track expiry
