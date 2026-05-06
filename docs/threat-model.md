# Hermes Vault Threat Model

## Goals

Reduce false auth failures, secret sprawl, and uncontrolled credential access in Hermes and persistent sub-agents.

## Threats Addressed

### Plaintext secrets left on disk

- Scanner detects likely secrets in `.env`, config, shell, JSON, YAML, TOML, INI, and text files
- Plaintext under managed Hermes paths is treated as a policy violation unless explicitly exempted or under a time-limited migration allowance
- Findings include recommendations to import and remove plaintext copies

### Duplicated secrets causing source-of-truth confusion

- Scanner fingerprints secrets and flags duplicate appearances across files

### Agents reading secrets they do not need

- Broker enforces per-agent service access
- Policy defaults to ephemeral env materialization instead of raw secret access

### False "needs re-auth" claims

- Verifier provides explicit outcome categories
- Generated skills require verification before re-auth recommendations

### Leaked secrets in logs or exceptions

- Redaction helpers scrub common secret formats
- Audit logs omit raw secret values

### Stale credentials treated as active

- Verification updates record status and last verified timestamp

### Insecure file permissions

- Scanner flags group/world-readable or writable secret locations

### Operator mistakes during debugging

- CLI prints metadata, not plaintext credentials
- Deletion requires explicit `--yes`

### Vault corruption or lockout

- SQLite is simple to back up locally
- Crypto metadata is versioned
- Passphrase and salt handling are separated from repo code
- If the vault database exists but the salt is missing, Hermes Vault fails closed instead of regenerating a salt and breaking decryption

### Split-brain credential state

- Duplicate credentials are flagged as source-of-truth conflicts
- Operators are expected to consolidate plaintext and imported copies into a single canonical vault record
- Long-lived plaintext duplicates under managed Hermes paths are not considered acceptable steady state

## Residual Risks

### Audit and status visibility

Without a query interface, audit logs accumulated but were not actionable.
v0.4.0 adds the audit and status commands so operators can inspect access
history and credential health. Audit entries never contain secrets.

- Local compromise of the operator account still threatens the vault
- V1 does not yet implement full key rotation or automated backup/restore tooling
- MiniMax verification is still configuration-dependent and not yet a fully opinionated default adapter
- Provider verification depends on network reachability and stable provider endpoints

## MCP Threat Model

### What an attacker with MCP host access can do

- Request any MCP tool call with any `agent_id` they know or guess
- If the agent is registered in policy, the attacker gains whatever that agent is authorized to do
- If the agent is not registered, all requests are denied

### What an attacker with MCP host access cannot do

- Extract raw secrets -- the MCP server only returns ephemeral env materialization or metadata
- Bypass policy -- all tool calls route through the broker, which applies the same policy checks as the CLI
- Mutate the vault without policy authorization -- rotate, scan, and other destructive operations require explicit action permissions
- Access the vault without `HERMES_VAULT_PASSPHRASE` -- the MCP server fails closed if the passphrase is not available

### Operator mitigations

- Register only the minimum set of agents and actions needed for each MCP host
- Use short TTLs for ephemeral env materialization
- Keep `raw_secret_access: false` for all MCP-facing agents
- Restart the MCP server after policy changes -- the server loads policy at startup
- Do not share `agent_id` values across untrusted hosts

## OAuth Threat Model

### Threats addressed

#### Authorization code interception

Mitigation: PKCE S256 is required for every login flow. The `code_verifier` is generated locally and never transmitted over untrusted channels. Even if an attacker intercepts the authorization code, they cannot exchange it without the verifier.

#### CSRF / state fixation attacks

Mitigation: A cryptographically random `state` parameter is generated for each login attempt. The callback handler validates the returned `state` with `secrets.compare_digest` (timing-safe). The stored state is cleared immediately after validation (single-use). State is held in memory only, not persisted to disk.

#### Token leakage in logs or process output

Mitigation: The callback server suppresses HTTP access logging to avoid leaking `code` and `state` in standard logs. Token exchange responses are stored directly in the vault; access tokens and refresh tokens are never printed to stdout except as truncated previews (first 12 chars + `...`). MCP `oauth_refresh` returns only token previews in its response.

#### Refresh token theft

Mitigation: Refresh tokens are stored as separate vault records under alias `"refresh"`, isolated from access tokens. Vault is encrypted at rest with AES-GCM. SQLite journal mode means unencrypted tokens are not written to the filesystem outside the encrypted payload. The refresh engine updates tokens atomically in a single transaction.

#### Replay of refresh requests

Mitigation: Each refresh POST uses the provider-issued refresh token. If the provider rotates refresh tokens (returning a new one), the engine stores the new token and increments a `rotation_counter` in metadata. An attacker replaying an old refresh request would be rejected by the provider. Family ID tracking preserves token lineage across rotations.

#### Thundering-herd against provider endpoints

Mitigation: The refresh engine uses exponential backoff (default base 2s, doubling per retry) on transient network failures. This limits retry pressure against provider token endpoints. Maximum retry count is configurable (default 3).

#### Browser callback spoofing

Mitigation: The callback server binds to `127.0.0.1` only and listens on an OS-assigned ephemeral port. It handles exactly one GET request, then shuts down. A malicious local process windowing an attacker-controlled callback would need to know the exact port, state, and timing to intercept.

### Residual risks

- Browser interaction is still required for initial login -- phishing-resistant flows (e.g., passkey-based OAuth) are not yet supported
- Provider revocation of refresh tokens is handled gracefully (the engine raises `RefreshTokenExpiredError`), but re-authentication is operator-initiated, not automatic
- Compromise of the operator's local machine (outside the vault) still grants access to the browser session used for OAuth consent
- No support for device-code flow -- headless servers without display/browsers cannot use `oauth_login` without an operator manually running the CLI
- The MCP `oauth_login` flow uses a process-level `_pending_oauth` dictionary for state tracking. Concurrent login attempts for the same provider+alias are not isolated and will overwrite each other
