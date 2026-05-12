# Hermes Vault Architecture

## Summary

Hermes Vault is a local-first Python project that centralizes credential scanning, secure storage, brokered access, policy enforcement, verification, auditing, maintenance, and skill generation for Hermes and Hermes sub-agents.

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

### `policy_doctor.py`

- Reads `policy.yaml` without mutating it
- Flags unknown services, unknown capabilities, risky secret access, and stale generated skills
- Produces suggested YAML patches for least-privilege remediation

### `maintenance.py`

- Composes OAuth refresh and health checks into a single scheduled-safe run
- Emits a structured maintenance report with refresh results, health findings, and a recommended exit code
- Records an audit entry for each run without exposing secret material

### `dashboard.py`

- Serves the local Hermes Vault Console through `hermes-vault dashboard`
- Binds to `127.0.0.1` by default; v0.8.0 rejects non-local dashboard hosts
- Generates an ephemeral browser-session token and guards all `/api/*` endpoints with the token
- Serves bundled static frontend assets from `hermes_vault/dashboard_static/` in the installed Python package
- Resolves static paths under the dashboard asset root before reading files, and falls back to `index.html` only for app routes
- Exposes JSON views for health, credentials, policy, audit, MCP binding, session status, and safe operator actions
- Reuses existing service-layer functions for health, policy doctor, verification, OAuth refresh, maintenance, backup verification, and restore dry-run
- Sanitizes dashboard responses so browser JSON doesn't include raw secrets, raw OAuth access or refresh tokens, or encrypted payloads
- Forces OAuth refresh and maintenance to dry-run-only from the dashboard in v0.8.0
- Treats brand media as packaged static assets; no image/video generation runs inside the dashboard process
- Keeps destructive or high-risk operations outside the dashboard surface

### `mcp_server.py`

- Stdio-based MCP server using the official Python MCP SDK
- Exposes brokered capabilities as MCP tools: list_services, get_credential_metadata, get_ephemeral_env, verify_credential, rotate_credential, scan_for_secrets
- **New in 0.6.0:** `oauth_login` initiates PKCE login and returns an authorization URL. A background thread spawns a callback server, waits for the browser redirect, exchanges the code for tokens, and stores them in the vault atomically.
- **New in 0.6.0:** `oauth_refresh` triggers the `RefreshEngine` to proactively or on-demand refresh expired access tokens.
- Every tool call uses caller-supplied `agent_id` unless the server is launched with `HERMES_VAULT_MCP_ALLOWED_AGENTS` and `HERMES_VAULT_MCP_DEFAULT_AGENT`
- Bound MCP deployments deny agent IDs outside the allowed set before policy evaluation and audit the binding decision separately
- MCP access defaults to policy-gated ephemeral env materialization rather than direct raw-secret handling
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
| `exchange.py` | POSTs authorization codes to the provider token endpoint and parses JSON (or URL-encoded) responses. Builds `CredentialSecret` from the token data with sanitized metadata only. |
| `flow.py` | High-level `LoginFlow` orchestrator: coordinates PKCE, callback server, browser open, state validation, token exchange, and vault storage. Stores access-token metadata separately from the refresh token and sets expiry automatically if `expires_in` is returned. |
| `oauth_refresh.py` | `RefreshEngine`: detects expired/near-expiry access tokens, POSTs `grant_type=refresh_token` to the provider, retries transient failures with exponential backoff, and updates vault atomically. Uses alias-scoped refresh pairing (`refresh:<alias>`) with a legacy fallback for older records. Logs every attempt. |
| `errors.py` | Typed exception hierarchy for OAuth flow failures: `OAuthTimeoutError`, `OAuthDeniedError`, `OAuthStateMismatchError`, `OAuthNetworkError`, `OAuthProviderError`, `OAuthMissingClientIdError`, `RefreshTokenMissingError`, `RefreshTokenExpiredError`. |

## Runtime Layout

Default runtime state lives outside the project tree at `~/.hermes/hermes-vault-data`:

- `vault.db`
- `policy.yaml`
- `master_key_salt.bin`
- `generated-skills/`
- **`oauth-providers.yaml`** (new in 0.6.0)

This keeps repository code separate from live secrets and operator state.

## Dashboard Server Boundary

The v0.8.0 dashboard is a local browser session over a Python `ThreadingHTTPServer`, not a new credential authority.

### Local server and static assets

`hermes-vault dashboard` builds one `DashboardContext` from the same settings, vault, policy, broker, verifier, and audit logger used by the CLI. `create_dashboard_server()` accepts `127.0.0.1` and `localhost` only; attempts to create a dashboard server for a non-local host raise an error in v0.8.0.

The server serves static files from the installed package's `hermes_vault/dashboard_static/` directory. Request paths are resolved and checked against that static root before bytes are read. Missing asset paths return `404`; application routes fall back to `index.html` so the packaged single-page console can render.

### Token-guarded browser session

Each server process gets a random URL-safe session token. API requests under `/api/` must provide that token either through the launch URL or through the standard bearer authorization header. The token has a TTL, defaults to 3600 seconds, and disappears when the dashboard process exits. This is a local session guard for the operator's browser, not a replacement for OS account security, disk encryption, vault passphrase handling, or `policy.yaml`.

### Dashboard-to-core interaction path

The browser never opens the vault directly. The interaction path is:

1. Browser loads packaged static assets from the local dashboard server.
2. Browser calls token-guarded `/api/*` JSON endpoints.
3. `DashboardAPI` builds or reuses a local context.
4. Actions call existing core services: health, policy doctor, broker verification, OAuth refresh engine, maintenance, backup verification, and restore dry-run.
5. Those services continue to use the same vault, policy, crypto, verifier, and audit layers as the CLI.

This keeps policy enforcement and audit semantics in the core modules instead of creating a parallel dashboard-specific trust path.

### Redaction and non-exposure boundary

Dashboard credential inventory serializes metadata fields such as service, alias, credential type, status, scopes, timestamps, expiry, and crypto version. It doesn't serialize decrypted secret values or encrypted payload bytes.

OAuth and maintenance responses are sanitized before they reach the browser. Raw OAuth access tokens, raw refresh tokens, provider token responses, and vault encrypted payloads are out of the dashboard JSON contract. Verification exceptions are reduced to bounded error metadata instead of provider or stack output that might contain sensitive material.

### Dry-run action boundary

Dashboard actions are intentionally narrower than the CLI. Health, policy doctor, credential verification, backup verification, and restore dry-run are available. OAuth refresh and maintenance are forced to `dry_run=True` server-side in v0.8.0, even if a client sends `dry_run=false`.

Live OAuth refresh, live maintenance, credential add/import/rotate/delete, policy editing, destructive restore, master-key rotation, plaintext export, cloud sync, and remote binding remain CLI-only or out of scope for this release. Expanding that boundary requires Hermes/Tony review before release.

## Security Posture

- Local-first only
- Raw secrets encrypted at rest
- No normal CLI path prints raw secrets
- No secret logging in audit records
- Broker and verifier make re-auth decisions explicit instead of speculative
- MCP transport is a thin wrapper: all policy enforcement reuses the broker; no parallel authority
- MCP access defaults to policy-gated ephemeral environment materialization rather than direct raw-secret handling
- v0.7.0 adds maintenance, policy doctor, OAuth normalization, and backup verification/drill without changing the local-first storage model
- v0.8.0 adds the local dashboard as a token-guarded localhost operator surface; it is not a remote service or a raw-secret UI
- Dashboard visual polish is a release concern only when bundled assets, responsive layouts, and first-run intro behavior pass smoke checks
- **OAuth-specific:**
  - CSRF protection via randomly-generated state parameter validated with timing-safe comparison
  - PKCE mitigates authorization-code interception (even without a confidential client)
  - Callback server binds to `127.0.0.1` only and accepts exactly one request
  - No raw tokens in HTTP handler logs (access logging is suppressed)
  - Access-token metadata is sanitized and excludes raw token material
  - Refresh tokens stored under a separate alias-scoped record (`refresh:<alias>`) with legacy fallback for migration
  - Atomic vault update: both access and refresh tokens update in a single SQLite transaction
  - Exponential backoff on transient refresh failures prevents thundering-herd against provider endpoints
  - Backup verification/drill proves decryptability without mutating the live vault

## Extension Points

- Add new detector patterns in `detectors.py`
- Add new provider verifiers in `verifier.py`
- Extend broker env mappings in `broker.py`
- Add policy fields in `models.py` and `policy.py`
- Add new MCP tools in `mcp_server.py` (must route through broker and respect optional MCP binding)
- **Add OAuth providers without code changes by editing `oauth-providers.yaml`**
- Adjust refresh engine parameters (`proactive_margin_seconds`, `max_retries`, `base_backoff_seconds`) via constructor or caller
