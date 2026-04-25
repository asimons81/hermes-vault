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

- Extract raw secrets — the MCP server only returns ephemeral env materialization or metadata
- Bypass policy — all tool calls route through the broker, which applies the same policy checks as the CLI
- Mutate the vault without policy authorization — rotate, scan, and other destructive operations require explicit action permissions
- Access the vault without `HERMES_VAULT_PASSPHRASE` — the MCP server fails closed if the passphrase is not available

### Operator mitigations

- Register only the minimum set of agents and actions needed for each MCP host
- Use short TTLs for ephemeral env materialization
- Keep `raw_secret_access: false` for all MCP-facing agents
- Restart the MCP server after policy changes — the server loads policy at startup
- Do not share `agent_id` values across untrusted hosts
