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
- v0.7.0 adds backup verification and restore drills so operators can prove a backup is readable before an incident, but the salt still has to be stored with the vault

### Split-brain credential state

- Duplicate credentials are flagged as source-of-truth conflicts
- Operators are expected to consolidate plaintext and imported copies into a single canonical vault record
- Long-lived plaintext duplicates under managed Hermes paths are not considered acceptable steady state

### Unreviewed agent access

- v0.19.0 adds policy explanation before access, so operators and agents can inspect why a request would be allowed or denied without decrypting a credential
- Access requests are durable metadata records; requesting access does not grant access or return env material
- Approval and denial decisions are audited, and approved requests can optionally issue a lease through the existing broker path
- Lease-required policies fail closed when no active lease exists for the agent, service, and alias
- Purpose-required policies reject generic or empty lease purposes, reducing unexplained access windows

### Incident evidence leaking secrets

- v0.19.0 incident bundles are metadata-only archives
- Bundles include audit slices, policy hash, health, leases, requests, and runtime metadata
- Bundles exclude vault databases, salts, encrypted payloads, raw secrets, provider responses, and env files
- Recovery drills prove backup decryptability and restore posture without mutating the live vault or exporting raw credentials

## Residual Risks

### Audit and status visibility

Without a query interface, audit logs accumulated but were not actionable.
v0.4.0 adds the audit and status commands so operators can inspect access
history and credential health. Audit entries never contain secrets.

- Local compromise of the operator account still threatens the vault
- v0.7.0 improves recovery confidence with backup verification/drill, but it does not remove the need for operator discipline around the salt file, passphrase, and local machine security
- MiniMax verification is still configuration-dependent and not yet a fully opinionated default adapter
- Provider verification depends on network reachability and stable provider endpoints

## MCP Threat Model

### What an attacker with MCP host access can do

- Request any MCP tool call with any `agent_id` they know or guess when the server is running in unrestricted mode
- If the deployment exposes `HERMES_VAULT_MCP_ALLOWED_AGENTS` and `HERMES_VAULT_MCP_DEFAULT_AGENT`, the attacker can only act as an allowed agent
- If the agent is registered in policy, the attacker gains whatever that agent is authorized to do
- If the agent is not registered, all requests are denied

### What an attacker with MCP host access cannot do

- Extract raw secrets -- the MCP server only returns ephemeral env materialization or metadata
- Bypass policy -- all tool calls route through the broker, which applies the same policy checks as the CLI
- Widen authority through an out-of-band `agent_id` when the server is bound to an allowed agent set
- Mutate the vault without policy authorization -- rotate, scan, and other destructive operations require explicit action permissions
- Access the vault without `HERMES_VAULT_PASSPHRASE` -- the MCP server fails closed if the passphrase is not available

### Operator mitigations

- Register only the minimum set of agents and actions needed for each MCP host
- Use `HERMES_VAULT_MCP_ALLOWED_AGENTS` and `HERMES_VAULT_MCP_DEFAULT_AGENT` for any host that should not be able to claim arbitrary identities
- Use short TTLs for ephemeral env materialization
- Keep `raw_secret_access: false` for all MCP-facing agents
- Restart the MCP server after policy changes -- the server loads policy at startup
- Do not treat `agent_id` as authentication by itself
- Do not share `agent_id` values across untrusted hosts

## Secret Source Plugin Threat Model

The Hermes Secret Source plugin is a startup-time env materialization path, not
a new credential authority. It shells out through Hermes `run_secret_cli()` to
`hermes-vault secret-source fetch` with argv lists and stdin closed. It never
uses `shell=True`, never mutates `os.environ`, and never returns empty strings
as credentials.

The subprocess environment is allowlisted to Vault bootstrap/session/config vars
such as `HERMES_VAULT_PASSPHRASE`, `HERMES_VAULT_HOME`, `HERMES_VAULT_POLICY`,
`HERMES_VAULT_PROFILE`, and `HERMES_VAULT_DPAPI`. `PATH` and platform basics
are handled by Hermes' shared helper, not treated as auth env vars by the
plugin. `HERMES_VAULT_PASSPHRASE` is protected, never fetched as a secret, and
partial success remains a warning-only condition as long as at least one usable
credential was returned.

Residual risk: any Hermes process that can read the Vault bootstrap passphrase
and has policy access for the configured `agent` can materialize the mapped
env vars at startup. Mitigate this by using the narrowest agent policy and
explicit mappings only.

## OAuth Threat Model

### Threats addressed

#### Authorization code interception

Mitigation: PKCE S256 is required for every login flow. The `code_verifier` is generated locally and never transmitted over untrusted channels. Even if an attacker intercepts the authorization code, they cannot exchange it without the verifier.

#### CSRF / state fixation attacks

Mitigation: A cryptographically random `state` parameter is generated for each login attempt. The callback handler validates the returned `state` with `secrets.compare_digest` (timing-safe). The stored state is cleared immediately after validation (single-use). State is held in memory only, not persisted to disk.

#### Token leakage in logs or process output

Mitigation: The callback server suppresses HTTP access logging to avoid leaking `code` and `state` in standard logs. Token exchange responses are stored directly in the vault with sanitized metadata only. Device-code flows return the user-facing `user_code` and verification URL but never return the provider `device_code`. Access tokens and refresh tokens are never printed to stdout except as truncated previews (first 12 chars + `...`). MCP `oauth_device_login` never returns raw token material, and MCP `oauth_refresh` returns only token previews in its response.

#### Refresh token theft

Mitigation: Refresh tokens are stored as separate vault records under alias `refresh:<alias>`, isolated from access tokens, with a legacy fallback only for migration. Vault is encrypted at rest with AES-GCM. SQLite journal mode means unencrypted tokens are not written to the filesystem outside the encrypted payload. The refresh engine updates tokens atomically in a single transaction.

#### Replay of refresh requests

Mitigation: Each refresh POST uses the provider-issued refresh token. If the provider rotates refresh tokens (returning a new one), the engine stores the new token and increments a `rotation_counter` in metadata. An attacker replaying an old refresh request would be rejected by the provider. Family ID tracking preserves token lineage across rotations.

#### Thundering-herd against provider endpoints

Mitigation: The refresh engine uses exponential backoff (default base 2s, doubling per retry) on transient network failures. This limits retry pressure against provider token endpoints. Maximum retry count is configurable (default 3).

#### Browser callback spoofing

Mitigation: The callback server binds to `127.0.0.1` only and listens on an OS-assigned ephemeral port. It handles exactly one GET request, then shuts down. A malicious local process windowing an attacker-controlled callback would need to know the exact port, state, and timing to intercept.

#### Backup verification and drill

Mitigation: `backup-verify` and `restore --dry-run` prove the archive is structurally valid and decryptable without mutating the live vault. They reduce the chance of discovering a broken backup during recovery, but they do not protect against a lost passphrase, missing salt file, or host compromise after verification.

### OAuth Refresh-at-Handoff Threat Model

v0.15.0 introduces automatic OAuth token refresh at broker/MCP handoff. This adds new threat vectors:

#### Silent vault mutation from a read-looking command

Risk: A `get_ephemeral_env` call looks like a read operation to operators auditing the system, but it can silently mutate the vault by refreshing a near-expiry OAuth token.

Mitigation: Live refresh requires the `rotate` service action permission. An agent with only `get_env` cannot trigger vault mutation. Policy separation ensures read-only grants remain read-only.

#### Provider rate-limit abuse

Risk: Rapid repeated `get_ephemeral_env` calls for the same credential could hammer the provider's token endpoint, triggering rate-limit blocks.

Mitigation: A 30-second per-credential cooldown prevents repeated refresh attempts within a single handoff sequence. The existing exponential backoff in the `RefreshEngine` provides additional protection for retries.

#### Stale token delivery after refresh failure

Risk: When a near-expiry token fails to refresh, the broker could silently deliver a stale token that the agent then fails to use, creating confusing failures.

Mitigation: The broker treats hard-expired tokens as fail-closed: if the token is past expiry and refresh cannot recover it, the request is denied with a clean error. Near-expiry tokens that fail refresh still deliver the existing token with a warning in `oauth_refresh` metadata.

#### Summary

| Risk | Severity | Mitigation |
|------|----------|------------|
| Vault mutation from read call | Medium | Require `rotate` permission for live refresh |
| Provider rate-limit abuse | Low | 30s per-credential cooldown + exponential backoff |
| Stale token delivery | Low | Fail-closed for hard-expired tokens |

### Residual risks

- Initial login can use browser PKCE or device-code flow for providers that support it. Device-code support removes the local browser requirement, but the operator still has to approve the login in a provider-controlled browser or device prompt.
- `oauth refresh` and `maintain` can renew access tokens unattended once a refresh token exists, but they do not remove the need to protect the local machine.
- Compromise of the operator's local machine (outside the vault) still grants access to browser sessions and device-code approval flows used for OAuth consent
- The MCP `oauth_login` flow uses a process-level `_pending_oauth` dictionary for state tracking. `oauth_device_login` also stores pending device-login state in process memory. Concurrent login attempts for the same provider+alias should be treated as operator-coordinated, not fully isolated automation.
