# Hermes Vault Architecture for Contributors

Hermes Vault is a local-first credential broker. Its job is to find risky plaintext secrets, store credentials encrypted at rest, enforce per-agent policy before access, materialize short-lived environment variables, verify credentials, and expose safe operator views through the CLI, MCP, and local dashboard.

This page is a contributor map. For the release-oriented architecture and lifecycle narrative, see `docs/architecture.md` and `docs/credential-lifecycle.md`.

## System boundaries

- Runtime state lives outside the repository, usually in `~/.hermes/hermes-vault-data`.
- Secret payloads are encrypted in SQLite and decrypted only inside trusted local service paths.
- Browser dashboard responses, audit logs, status output, and generated docs must not contain raw secrets.
- MCP is a thin transport over the broker and policy engine. It is not a second credential authority.
- Dashboard actions are intentionally narrower than CLI actions and stay localhost/token guarded.

## Start-here module map

| Area | Primary modules | Purpose |
|---|---|---|
| CLI entry point | `src/hermes_vault/cli.py` | Typer commands for operator workflows |
| Configuration | `src/hermes_vault/config.py` | Resolve vault home, policy path, passphrase, and runtime paths |
| Models | `src/hermes_vault/models.py` | Pydantic data contracts for credentials, policy, audit, and reports |
| Crypto | `src/hermes_vault/crypto.py` | Key derivation and AES-GCM payload encryption |
| Vault storage | `src/hermes_vault/vault.py` | SQLite persistence, encrypted payload storage, selectors, metadata |
| Mutations | `src/hermes_vault/mutations.py` | Central write/destructive operation layer with policy and audit |
| Policy | `src/hermes_vault/policy.py` | Agent capabilities, per-service actions, TTLs, canonical service IDs |
| Broker | `src/hermes_vault/broker.py` | Agent-facing access decisions and ephemeral env materialization |
| Audit | `src/hermes_vault/audit.py` | Durable metadata-only allow/deny/action records |
| Scanner | `src/hermes_vault/scanner.py`, `detectors.py`, `permissions.py` | Plaintext secret and permission findings |
| Verifier | `src/hermes_vault/verifier.py` | Provider-specific validity checks and failure classification |
| Health/status | `src/hermes_vault/health.py`, `status` paths in CLI | Stale, invalid, expired, and backup posture reporting |
| Backup/diff | `src/hermes_vault/backup.py`, `diff.py` | Backup, restore, verification, and metadata diff workflows |
| Policy doctor | `src/hermes_vault/policy_doctor.py` | Read-only policy drift and least-privilege findings |
| Skill generation | `src/hermes_vault/skillgen.py` | Agent-facing SKILL.md contracts from policy |
| MCP server | `src/hermes_vault/mcp_server.py` | stdio MCP tool bridge into broker/policy workflows |
| OAuth | `src/hermes_vault/oauth/` | PKCE login, token exchange, refresh, normalization, provider registry |
| Dashboard | `src/hermes_vault/dashboard.py`, `dashboard_static/` | Local console server and packaged frontend assets |
| Updates | `src/hermes_vault/update.py` | Guarded install update checks and supported update paths |

## Core data flows

### Scan to finding

1. CLI resolves scan paths and ignore rules.
2. `scanner.py` walks candidate files.
3. `detectors.py` applies service-aware patterns and records fingerprints instead of raw values.
4. `permissions.py` adds file-mode findings where relevant.
5. Results are rendered as table, JSON, or report output without exposing secret values.

### Import/add to vault write

1. CLI parses an explicit add or env import request.
2. Input is normalized into `CredentialSecret`/record models.
3. Writes go through `VaultMutations` or the operator write path that still audits.
4. `vault.py` encrypts payloads with keys from `crypto.py` and stores metadata separately.
5. `audit.py` records allow/deny/action metadata without secret material.

### Broker env request

1. Caller asks for `broker env <service> --agent <agent> --ttl <seconds>` or an equivalent MCP tool.
2. `broker.py` canonicalizes service naming and asks `policy.py` whether the agent can get env material for that service.
3. TTL is capped by policy.
4. The vault decrypts only the selected credential payload needed for env materialization.
5. Broker returns a bounded env dict plus decision metadata and records an audit entry.

### MCP tool request

1. MCP host calls a tool in `mcp_server.py`.
2. Bound-agent checks apply first when `HERMES_VAULT_MCP_ALLOWED_AGENTS` is configured.
3. The MCP layer passes service, alias, agent, and options into broker/mutation/service functions.
4. Policy, vault, verifier, and audit behavior stays in the core modules.
5. The response is serialized as MCP content without raw secret leakage except for intentional ephemeral env materialization.

### Dashboard request

1. `hermes-vault dashboard` binds to `127.0.0.1` or `localhost` and creates an expiring session token.
2. Browser loads packaged static assets from `hermes_vault/dashboard_static/`.
3. Browser calls token-guarded `/api/*` endpoints.
4. `dashboard.py` invokes existing service-layer functions for health, policy doctor, verification, OAuth dry-run, maintenance dry-run, backup verify, and restore dry-run.
5. Responses are sanitized before they reach the browser.

### OAuth login/refresh

1. `oauth/providers.py` resolves provider metadata from built-ins or YAML config.
2. `oauth/pkce.py` and `oauth/state.py` create verifier/challenge and CSRF state.
3. `oauth/callback.py` listens on localhost for the provider redirect.
4. `oauth/exchange.py` exchanges codes or refresh tokens with provider endpoints.
5. `oauth/flow.py` and `oauth/oauth_refresh.py` write sanitized metadata and token payloads through vault mutation paths.

## Rules of the road

- Do not add new raw-secret display paths.
- Do not log decrypted values, provider token responses, passphrases, or encrypted payload bytes.
- Do not bypass `VaultMutations` for agent-facing writes.
- Do not make MCP resolve credential aliases before broker/policy checks.
- Do not add dashboard live mutations unless the security boundary is explicitly reviewed.
- Do not make dashboard bind to a public interface.
- Do not put real credentials in tests or docs.
- Do not make tests depend on the operator's real vault home.

## Extension recipes

### Add a verifier

1. Add or extend a provider adapter in `verifier.py`.
2. Classify failures as invalid/expired, network failure, endpoint misconfiguration, permission/scope issue, rate limit, or unknown.
3. Add mocked tests in `tests/test_verifier.py` or a focused verifier test file.
4. Update docs and issue labels if the provider becomes a first-class supported service.

### Add a secret detector

1. Add a pattern or detector helper in `detectors.py`.
2. Ensure findings fingerprint secrets and do not expose raw values.
3. Add scanner/detector tests with fake values only.
4. Update docs if the detector changes public scan behavior.

### Add an MCP tool

1. Keep the MCP layer thin in `mcp_server.py`.
2. Reuse broker, mutation, verifier, OAuth, or service-layer functions.
3. Gate access through policy or existing capabilities.
4. Add tests that call the MCP handler directly.
5. Update `docs/mcp-server.md` and README tool tables.

### Add a CLI command

1. Add the Typer command in `cli.py`.
2. Put business logic in a reusable module, not only in command-body code.
3. Use structured models for machine-readable output.
4. Add CLI tests with temporary vault homes.
5. Update README/operator docs and changelog when behavior is user-facing.

### Add a dashboard endpoint/action

1. Confirm the action belongs in the dashboard. Prefer read-only or dry-run operations.
2. Reuse existing service-layer functions.
3. Sanitize every response before JSON serialization.
4. Keep token checks on `/api/*` endpoints.
5. Add dashboard API tests and UI smoke evidence for visible changes.
6. Update docs and screenshots using fake/demo credentials only.

## Test orientation

The test suite lives in `tests/` and is organized by domain. Run the full suite before submitting changes:

```bash
python -m pytest tests/ -q
```

For local manual tests, set `HERMES_VAULT_HOME` to a temporary directory and use fake secrets only.
