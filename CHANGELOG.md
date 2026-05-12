# Changelog

## 0.8.0 -- Hermes Vault Console Release

### Added

- **Local dashboard** (`hermes-vault dashboard`) -- token-guarded Hermes Vault Console served from packaged assets on `127.0.0.1`.
- **Dashboard views** -- operator surfaces for health, credential inventory, policy findings, audit activity, MCP binding, operations, and recovery posture.
- **Safe dashboard actions** -- health, policy doctor, credential verification, OAuth refresh dry-run, maintenance dry-run, backup verification, and restore dry-run through existing service-layer workflows.
- **Brand assets** -- bundled console brand media for the vault-door intro and local dashboard experience.

### Changed

- OAuth refresh and maintenance are dry-run-only from the dashboard in v0.8.0. Live execution remains available through the CLI.
- Dashboard static assets are packaged as Python package data so installed wheel and source distributions can serve the console without remote assets.

### Security

- Dashboard URLs use a per-process launch token and localhost binding.
- Dashboard JSON serializes credential metadata only and redacts raw secret, raw OAuth token, provider token response, and encrypted payload material from browser-facing responses.
- Credential editing, policy editing, destructive restore, cloud sync, remote binding, plaintext export, and master-key rotation remain outside the dashboard surface.

### Release QA

- Desktop and mobile visual smoke checks cover the packaged dashboard, first-run intro path, bundled asset loading, text overflow, and control overlap.
- Package QA verifies the wheel and sdist include `hermes_vault/dashboard_static/` assets.

## 0.7.2 -- Env Import Idempotency Follow-up

### Changed

- Repeated `.env` imports now compare the incoming secret against the stored `(service, alias)` pair first, report `Already imported` when unchanged, and update in place when the secret changed.

## 0.7.1 -- Env Import UX Hotfix

### Added

- `hermes-vault import --from-env` now supports `--dry-run` previews that show importable and skipped env vars without opening or mutating the vault.
- `--map ENV_NAME=service:credential_type` can be repeated to explicitly import custom names, DB URLs, passwords, or app secrets when the operator chooses to map them.
- Common AI/dev env hints now cover OpenRouter, FAL, Replicate, ElevenLabs, Resend, Tavily, Brave Search, Cloudflare, Vercel, Hugging Face, Groq, xAI, Gemini, Google API keys, Perplexity, and SerpAPI.

### Changed

- Unknown env vars are reported as skipped with clear reasons and `--map` hints instead of silently disappearing.
- Safe suffix inference imports `*_API_KEY`, `*_TOKEN`, `*_AUTH_TOKEN`, and `*_ACCESS_TOKEN` names as service-specific credentials.
- `--redact-source` now reports how many skipped env lines were left unchanged and still redacts only successfully imported lines.

### Security

- Public client config such as `NEXT_PUBLIC_*`, broad DB URLs, passwords, JWT/session/app secrets, and unknown names remain conservative skips unless explicitly mapped.

## 0.7.0 -- Operational Autonomy Release

### Added

- **Maintenance orchestration** (`hermes-vault maintain`) -- scheduled-safe OAuth refresh, health checks, stale-verification checks, backup-age warnings, JSON/table output, dry-run mode, and systemd helper output via `--print-systemd`.
- **Policy doctor** (`hermes-vault policy doctor`) -- read-only policy inspection for least-privilege drift, risky grants, unknown actions/capabilities, stale generated skills, and OAuth readiness gaps. Supports `--strict` for automation.
- **OAuth normalization** (`hermes-vault oauth normalize`) -- dry-run-by-default migration for v0.6 OAuth records, including sanitized token metadata and alias-scoped refresh-token pairing.
- **MCP allowed-agent binding** -- `HERMES_VAULT_MCP_ALLOWED_AGENTS` and `HERMES_VAULT_MCP_DEFAULT_AGENT` can bind a server instance to a known agent set when hosts omit caller identity.
- **Backup verification and restore drill** -- `hermes-vault backup-verify --input <backup-file>` and `hermes-vault restore --dry-run --input <backup-file>` validate decryptability and recovery shape without mutating the live vault.
- **Audit metadata** -- audit records can carry structured metadata for maintenance, backup verification, and restore drill events without exposing secrets.

### Changed

- OAuth refresh tokens are now stored under deterministic alias-scoped records such as `refresh:work`, with legacy `refresh` fallback during migration.
- OAuth access-token metadata is sanitized to provider-safe fields such as provider, token type, issue/expiry timestamps, and scopes.
- Documentation now covers v0.7.0 operator workflows, MCP binding, OAuth normalization, and recovery proof.
- `pyproject.toml`, package `__version__`, MCP server metadata, and lockfile package metadata now report `0.7.0`.

### Security

- MCP binding reduces reliance on caller-supplied `agent_id` in known deployment topologies.
- OAuth normalization removes token-bearing metadata such as raw token responses from access-token records.
- Backup verification and dry-run restore prove encrypted backup readability before an incident while leaving the live vault unchanged.
- Maintenance and recovery events are audited without logging raw secrets.

## 0.6.0 -- OAuth PKCE and Token Auto-Refresh Release

### Added

- **OAuth PKCE login** (`hermes-vault oauth login <provider>`) -- browser-based PKCE login flow with built-in providers (`google`, `github`, `openai`) and custom provider support via YAML. Tokens stored automatically. Supports `--alias`, `--scope`, `--no-browser`, `--port`, and `--timeout`.
- **Token auto-refresh engine** (`hermes-vault oauth refresh <service>`) -- detects expired or near-expiry access tokens (default proactive margin 300s) and refreshes using stored refresh tokens. Supports `--all`, `--dry-run`, and configurable `--margin`. Exponential backoff with configurable `max_retries` (default 3) and `base_backoff_seconds` (default 2s).
- **OAuth provider registry** (`hermes-vault/oauth/providers.py`) -- YAML-backed registry at `~/.hermes/hermes-vault-data/oauth-providers.yaml`. Seeds built-in defaults automatically. Reads `client_id`/`client_secret` from `HERMES_VAULT_OAUTH_<PROVIDER>_CLIENT_ID/SECRET` env vars.
- **MCP OAuth tools** -- `oauth_login` and `oauth_refresh` exposed as MCP tools. `oauth_login` returns an authorization URL and completes the flow in a background thread. `oauth_refresh` triggers the `RefreshEngine` and returns structured results including token previews.
- **Full OAuth package** under `src/hermes_vault/oauth/`: `pkce.py` (RFC 7636 S256), `state.py` (CSRF nonce generation/validation), `callback.py` (ephemeral HTTP server), `exchange.py` (token endpoint POST), `flow.py` (orchestrator), `oauth_refresh.py` (RefreshEngine), `errors.py` (typed exceptions), `providers.py` (registry).
- **OAuth CLI commands** -- `hermes-vault oauth login`, `hermes-vault oauth refresh`, `hermes-vault oauth providers`.
- **Provider-side refresh-token rotation support** -- the RefreshEngine preserves `rotation_counter` and optional `family_id` metadata when a provider returns a new refresh token.
- **MCP integration docs** -- `docs/mcp-server.md` and `docs/mcp-integration.md` updated with OAuth tool schemas, troubleshooting, and architecture notes.

### Changed

- `pyproject.toml` version bumped to `0.6.0`.
- `docs/architecture.md` updated with OAuth module descriptions and security posture.
- `docs/operator-guide.md` updated with OAuth setup, provider registration, token lifecycle, and MCP OAuth tool usage.
- `docs/threat-model.md` updated with OAuth-specific threats and mitigations.
- `README.md` updated with v0.6.0 Whats New section, MCP tool table additions, and common commands.

### Security

- CSRF protection via timing-safe state comparison (`secrets.compare_digest`).
- PKCE S256 required for all flows -- authorization-code interception is mitigated even without a confidential client.
- Callback server binds to `127.0.0.1` only, suppresses HTTP access logging, and accepts exactly one request.
- Refresh tokens stored as separate vault records (alias `"refresh"`) with metadata linking to the access token alias.
- Atomic vault updates -- both access and refresh tokens update in a single SQLite transaction.
- Exponential backoff on transient refresh failures prevents retry storms.
- No raw tokens in stdout/logs except as truncated previews in MCP responses.
- Audit log records every OAuth event (login callback, refresh attempt) without exposing secrets.

## 0.5.0 -- Health, Governance, and Key Rotation Release

### Added

- **Vault health command** (`hermes-vault health`) — read-only health check that
  inspects credential staleness, expiry, invalid status, and backup age in a single
  pass. Composes existing vault status/verification/expiry logic. Outputs structured
  JSON or markdown reports. Exit codes: 0 = healthy, 1 = warnings, 2 = error.
- **Master-key rotation** (`hermes-vault rotate-master-key`) — derives a new master
  key from a new passphrase and re-encrypts every credential atomically. Creates an
  encrypted pre-rotation backup by default. Requires `--skip-backup-dangerous` to
  bypass. Writes an audit event on success.
- **Sync-skill command** (`hermes-vault sync-skill`) — checks or regenerates the
  `hermes-vault-access` SKILL.md from the current policy. Skills now embed a
  SHA-256 policy hash for deterministic stale detection. Supports `--check`,
  `--write`, and `--print`. Exit code 0 = current, 1 = stale.
- **Metadata-only backup** (`hermes-vault backup --metadata-only`) — exports
  credential metadata without encrypted payloads, safe for diff/inspection.
- **Backup with audit** (`hermes-vault backup --include-audit`) — includes audit
  log entries in the backup file.
- **Vault diff command** (`hermes-vault diff --against <path>`) — compares current
  vault metadata against a backup file. Shows added, removed, and changed
  credentials. Never exposes secrets. Accepts both full and metadata-only backups.
- **Governance warnings** in broker `get_ephemeral_env` decisions — expiry warnings
  when credentials are within `HERMES_VAULT_EXPIRY_WARNING_DAYS` (default 7) and
  backup reminders when the last backup exceeds `HERMES_VAULT_BACKUP_REMINDER_DAYS`
  (default 30). Warnings live in `metadata.warnings[]` and never contain raw secrets.
- **Configurable thresholds** via environment variables:
  `HERMES_VAULT_EXPIRY_WARNING_DAYS`, `HERMES_VAULT_BACKUP_REMINDER_DAYS`

### Changed

- `vault.export_backup()` now accepts `metadata_only` parameter to exclude
  encrypted payloads.
- `vault.import_backup()` rejects metadata-only backups with a clear error.
- `SkillGenerator` now embeds a policy hash (`<!-- hv-policy-hash: ... -->`) in
  generated skills for stale detection.
- `PolicyEngine` gains `compute_policy_hash()` for deterministic policy hashing.
- `AppSettings` gains `expiry_warning_days`, `backup_reminder_days`, and
  `governance_warnings_enabled` properties from env vars.

### Security

- Master-key rotation is atomic: if any credential fails re-encryption, the entire
  operation rolls back.
- Pre-rotation encrypted backups are created by default before key rotation.
- Metadata-only backups and diff never expose encrypted payloads or raw secrets.
- Governance warnings never leak raw secrets — only metadata (days-until-expiry,
  days-since-backup).

## 0.4.0 — Credential Observability Release

### Added

- **Audit query CLI** (`hermes-vault audit`) — query access logs with filters:
  --agent, --service, --action, --decision, --since/--until (relative or ISO date),
  --format table|json, --limit. Always ordered newest-first. Empty results exit 0.
- **Credential status CLI** (`hermes-vault status`) — inspect credential health:
  --stale Nd (not verified in N days), --invalid (invalid/expired status),
  --expiring Nd (expiring within N days), --format table|json. Credentials with
  last_verified_at=null are always stale. Target + filters work together.
- **Expiry metadata commands** (`hermes-vault set-expiry` / `clear-expiry`) —
  operator-controlled expiry tracking via --days N or --date YYYY-MM-DD.
  Both write audit entries. Expiry round-trips through backup/restore.
- **Verification report output** — `verify --all` now accepts --format table
  and --report PATH. Default JSON-to-stdout behavior is unchanged.
  --report writes stable JSON with parent-dir creation and chmod 0600.

### Changed

- Audit log gains indexes on agent_id, service, and timestamp
  (`CREATE IF NOT EXISTS` — no migration needed).
- Credentials table gains indexes on status, last_verified_at, and expiry
  (`CREATE IF NOT EXISTS` — no migration needed).

### Security

- No secret values appear in audit log entries, status output, or verification
  reports. encrypted_payload is never included in any JSON output.
- No background processes, no daemon, no auto-rotation.

## 0.3.1 — MCP Hotfix Release

### Fixed

- **MCP alias handling** — `get_ephemeral_env` now resolves aliases inside the broker after the policy gate, preventing UUID-vs-name policy mismatches that could cause incorrect denials
- **MCP metadata leak** — `get_credential_metadata` now excludes `encrypted_payload` from responses; raw encrypted bytes are no longer exposed over stdio
- **MCP `expires_at`** — `get_ephemeral_env` now computes and returns a real `expires_at` ISO timestamp instead of `null`
- **Policy model strictness** — `AgentPolicy` and `PolicyConfig` now reject unknown fields (`extra="forbid"`), preventing silent misconfiguration when operators use outdated field names
- **Docs/examples field names** — `docs/operator-guide.md` and test fixtures corrected to use `max_ttl_seconds` and `ephemeral_env_only`, matching the actual model schema
- **MCP server initialization** — broker is cached as a singleton via `_get_broker()` instead of rebuilding on every tool call
- **MCP transport safety** — logging redirected to `~/.hermes/hermes-vault-data/mcp.log` instead of `stderr`, preventing JSON-RPC framing corruption

## 0.3.0 — MCP Server Release

### Added

- **MCP server transport** (`hermes-vault mcp`) — stdio-based MCP server using the official Python MCP SDK
- **MCP tool surface** — 6 tools exposed: `list_services`, `get_credential_metadata`, `get_ephemeral_env`, `verify_credential`, `rotate_credential`, `scan_for_secrets`
- **Agent identity propagation** — every MCP tool call requires `agent_id`; policy v2 enforcement works unchanged through the broker
- **Update command family** (`hermes-vault update --check`, `hermes-vault update`) — install-method detection, guarded auto-update for pip/pipx/uv tool, safe refusal with manual instructions for unsupported methods
- `mcp` dependency in `pyproject.toml`

### Changed

- README updated with MCP server section, tool reference table, and update command reference
- `docs/architecture.md` updated with MCP transport layer description
- `docs/operator-guide.md` updated with MCP setup instructions, agent registration workflow, and troubleshooting
- `docs/threat-model.md` updated with MCP threat model and operator mitigations

### Security

- Raw secrets are never transmitted over MCP — only ephemeral environment materialization and metadata
- All MCP tool calls route through the existing broker and VaultMutations layers — no parallel policy authority

## 0.2.0 — Contract Hardening Release

### Added

- Policy v2 with per-service action permissions and legacy compatibility
- Canonical service IDs across vault, broker, policy, and scan/import flows
- Deterministic credential targeting for alias and multi-credential scenarios
- Centralized audited mutation paths for add, rotate, delete, metadata, and verification-related updates
- Agent-level capabilities for non-service-scoped actions
- CLI alignment with canonical service IDs, deterministic selectors, and policy v2

### Changed

- Expanded test suite and release documentation for the 0.2.0 contract

## 0.1.0 — Initial Release

### Added

- Local encrypted vault (SQLite-backed, PBKDF2 + AES-GCM)
- CLI for scan, import, add, list, verify, rotate, delete, backup, restore
- Secret scanner with pluggable detectors and permission checks
- Credential verifier with provider-specific adapters
- Backup and restore for vault portability
- Skill generation for Hermes agent contracts
