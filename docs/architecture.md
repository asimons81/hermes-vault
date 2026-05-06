# Hermes Vault Architecture

## Summary

Hermes Vault is a local-first Python project that centralizes credential scanning, secure storage, brokered access, policy enforcement, verification, auditing, and skill generation for Hermes and Hermes sub-agents.

## Major Components

### `scanner.py`

- Walks Hermes-relevant paths
- Detects plaintext secrets via pluggable patterns from `detectors.py`
- Flags insecure file permissions through `permissions.py`
- Fingerprints secrets to find duplicates without storing raw values

### `vault.py`

- Stores encrypted credential payloads in SQLite
- Keeps metadata separate from raw secret material
- Supports add, list, show metadata, rotate, delete, and import workflows
- Deterministic credential targeting: UUID, service+alias, or service-only (when unambiguous)
- Raises `AmbiguousTargetError` when service-only matches multiple credentials

### `mutations.py`

- Centralized mutation service layer for all write/destructive operations
- Enforces policy checks (agent capability + service action) before mutations
- Writes standardized audit entries for every mutation (allow and deny)
- Operator path (``agent_id="operator"``) skips policy checks but still audits
- Used by the Broker for agent-facing mutations and by the CLI for operator-facing mutations

### `crypto.py`

- Uses PBKDF2-HMAC-SHA256 to derive a master key from a local passphrase
- Uses AES-GCM for authenticated encryption of per-record payloads
- Stores versioned crypto metadata on records for future migration support

### `policy.py`

- Loads deny-by-default YAML policy
- Enforces service allowlists, raw secret access settings, env-only access, and TTL ceilings
- Policy v2: per-service action permissions (get_credential, get_env, verify, metadata, add_credential, rotate, delete)
- Agent-level capabilities for non-service-scoped actions (list_credentials, scan_secrets, export_backup, import_credentials)
- Backward compatible with legacy flat-list service format
- Normalizes all service names to canonical IDs on load

### `broker.py`

- Canonical credential access layer
- Applies policy before access decisions
- Preferentially materializes ephemeral environment variables instead of returning raw secrets
- Routes mutations (add, rotate, delete, metadata) through ``VaultMutations`` for policy and audit
- Records broker decisions in `audit.py`

### `verifier.py`

- Provider-specific verification adapters
- Classifies outcomes into valid, invalid/expired, network failure, endpoint misconfiguration, permission/scope issue, rate limit, or unknown

### `skillgen.py`

- Generates SKILL.md contracts that enforce the Hermes Vault access workflow
- Keeps sub-agents from freelancing credential discovery

### `mcp_server.py`

- Stdio-based MCP server using the official Python MCP SDK
- Exposes brokered capabilities as MCP tools: list_services, get_credential_metadata, get_ephemeral_env, verify_credential, rotate_credential, scan_for_secrets
- **New in 0.6.0:** `oauth_login` initiates PKCE login and returns an authorization URL. A background thread spawns a callback server, waits for the browser redirect, exchanges the code for tokens, and stores them in the vault atomically.
- **New in 0.6.0:** `oauth_refresh` triggers the `RefreshEngine` to proactively or on-demand refresh expired access tokens.
- Every tool call requires `agent_id` -- policy enforcement reuses the existing broker and VaultMutations layers
- Raw secrets are never transmitted over MCP; the default access pattern is ephemeral env materialization
- Loads the same vault, policy, and crypto configuration as the CLI
- OAuth tool implementations reuse the same PKCE generation, state validation, token exchange, and vault storage as the CLI `LoginFlow`

### `oauth/` subsystem

New in 0.6.0. The OAuth package is self-contained and does not depend on CLI code:

| Module | Responsibility |
|---|---|
| `pkce.py` | Generates S256 code_verifier and code_challenge per RFC 7636 |
| `state.py` | Generates cryptographically random state nonces and validates them with timing-safe `secrets.compare_digest` |
| `callback.py` | Ephemeral `HTTPServer` on `127.0.0.1`, port 0. Handles exactly one `/callback` GET, extracts `code`, `state`, and `error`, then signals the waiting thread. Suppresses HTTP access logging. |
| `providers.py` | YAML-backed registry of OAuth identity providers. Seeds built-in defaults (`google`, `github`, `openai`) on first use. Reads `client_id`/`client_secret` from `HERMES_VAULT_OAUTH_<PROVIDER>_CLIENT_ID/SECRET` env vars. |
| `exchange.py` | POSTs authorization codes to the provider token endpoint and parses JSON (or URL-encoded) responses. Builds `CredentialSecret` from the token data. |
| `flow.py` | High-level `LoginFlow` orchestrator: coordinates PKCE, callback server, browser open, state validation, token exchange, and vault storage. Sets expiry automatically if `expires_in` is returned. |
| `oauth_refresh.py` | `RefreshEngine`: detects expired/near-expiry access tokens, POSTs `grant_type=refresh_token` to the provider, retries transient failures with exponential backoff, and updates vault atomically. Preserves refresh-token rotation metadata. Logs every attempt. |
| `errors.py` | Typed exception hierarchy for OAuth flow failures: `OAuthTimeoutError`, `OAuthDeniedError`, `OAuthStateMismatchError`, `OAuthNetworkError`, `OAuthProviderError`, `OAuthMissingClientIdError`, `RefreshTokenMissingError`, `RefreshTokenExpiredError`. |

## Runtime Layout

Default runtime state lives outside the project tree at `~/.hermes/hermes-vault-data`:

- `vault.db`
- `policy.yaml`
- `master_key_salt.bin`
- `generated-skills/`
- **`oauth-providers.yaml`** (new in 0.6.0)

This keeps repository code separate from live secrets and operator state.

## Security Posture

- Local-first only
- Raw secrets encrypted at rest
- No normal CLI path prints raw secrets
- No secret logging in audit records
- Broker and verifier make re-auth decisions explicit instead of speculative
- MCP transport is a thin wrapper: all policy enforcement reuses the broker; no parallel authority
- Raw secrets are never transmitted over MCP -- only ephemeral environment materialization
- **OAuth-specific:**
  - CSRF protection via randomly-generated state parameter validated with timing-safe comparison
  - PKCE mitigates authorization-code interception (even without a confidential client)
  - Callback server binds to `127.0.0.1` only and accepts exactly one request
  - No raw tokens in HTTP handler logs (access logging is suppressed)
  - Refresh tokens stored under a separate record with alias `"refresh"` (not co-mingled with access tokens)
  - Atomic vault update: both access and refresh tokens update in a single SQLite transaction
  - Exponential backoff on transient refresh failures prevents thundering-herb against provider endpoints

## Extension Points

- Add new detector patterns in `detectors.py`
- Add new provider verifiers in `verifier.py`
- Extend broker env mappings in `broker.py`
- Add policy fields in `models.py` and `policy.py`
- Add new MCP tools in `mcp_server.py` (must require `agent_id` and route through broker)
- **Add OAuth providers without code changes by editing `oauth-providers.yaml`**
- Adjust refresh engine parameters (`proactive_margin_seconds`, `max_retries`, `base_backoff_seconds`) via constructor or caller

