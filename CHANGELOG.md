# Changelog

## 0.21.0 -- Audit Assurance (unreleased)

### Added

- Signed audit-integrity chains with deterministic canonical serialization, HKDF-derived Ed25519 evidence signatures, and versioned integrity records.
- Durable authenticated checkpoints with signature verification, write-lock coordination, and explicit operator-only lifecycle (establish, advance, recover).
- Legacy migration anchoring with non-destructive, idempotent v0.20→v0.21 transition.
- Read-only verification result model with explicit healthy, legacy, incomplete, and failed states.
- **`hvbackup-v2`** backup format including audit integrity evidence, segments, checkpoint, and verification summary.
- v2 backup verification with structural consistency checks and key compatibility validation.
- Transactional restore with staged database and checkpoint replacement, rollback evidence, and audited operator restore event.
- **CLI commands**: `audit-verify`, `audit-checkpoint` (show/establish/advance/recover), `audit-export --with-integrity`.
- **Dashboard endpoints**: `GET /api/audit-integrity`, `POST /api/audit-integrity/verify`.
- **MCP resources**: `vault://audit-integrity` metadata-only resource, integrity summary in `vault://status`.
- Sanitized integrity summaries in incident bundles and recovery reports.
- Master-key rotation segments with predecessor chain continuity.
- Full Linux and Windows test matrix with 800+ passing tests.

### Security boundaries

- Private signing material is derived only in memory and is neither stored nor exported.
- Integrity-key material is never logged, serialized, or environment-placed.
- Checkpoint reset, advancement, and recovery remain explicit and operator-only (require `--yes`).
- Verification is read-only across CLI, dashboard, and MCP surfaces.
- Secret Source and MCP credential authority are unchanged.
- Pre-v0.21 audit history is preserved and readable but was not retrospectively protected.
- Local integrity verification is not third-party attestation.

### Compatibility

- v0.20 vaults open without destructive migration; legacy audit rows become anchored.
- Interrupted migration is safe to retry.
- `hvbackup-v1` backups remain fully restorable (classified as legacy).
- Metadata-only backups are non-restorable.
- Windows and POSIX behavior uses the existing platform abstraction.
- DPAPI-backed and passphrase-backed vaults provide the same audit-integrity behavior.
- No automatic downgrade is guaranteed after protected audit entries are written.

### Added

- Standalone Hermes Secret Source plugin under `plugins/hermes-vault-secret-source/`.
- Non-interactive `hermes-vault secret-source fetch` endpoint for mapped, read-only startup env materialization.
- Secret Source CLI, plugin, conformance, and fake-CLI contract tests.
- Explicit startup mapping support for `ENV_VAR=hv://service` and `ENV_VAR=hv://service?alias=name` refs.

### Changed

- Version surfaces now report `0.20.0` in `pyproject.toml`, `src/hermes_vault/__init__.py`, and site release copy.
- README, operator docs, threat model, plugin docs, and site copy now present Secret Source as startup-only while MCP remains the in-loop agent control plane.
- The plugin keeps `HERMES_VAULT_PASSPHRASE` protected, omits empty values, and keeps partial success as warnings instead of hard failures.

### Verification

- Focused suites: `python -m pytest tests/test_secret_source_cli.py plugins/hermes-vault-secret-source/tests tests/test_cli.py tests/test_broker.py tests/test_config.py tests/test_redaction.py -q --tb=short`
- Full release validation: `python -m pytest -q --tb=short`
- Upstream Hermes conformance: `tests.secret_sources.conformance.SecretSourceConformance` against the installed Hermes Agent package
- Manual smoke: isolated vault startup fetches for missing passphrase, valid mapped secret, alias ref, empty secret, denied policy, malformed ref, and closed-stdin no-prompt behavior

### Added

- Explainable policy decisions through `hermes-vault policy explain`, `policy simulate`, dashboard policy explain, MCP `policy_explain`, and `vault://policy-explain`.
- Lease-enforced env handoffs with opt-in `require_lease_for_env` and `require_lease_purpose` policy fields, broker-side lease reuse, `lease checkout`, MCP `lease_checkout`, and metadata showing the lease boundary.
- Operator access-request workflow across vault persistence, broker audit, CLI `request access/list/show/approve/deny`, dashboard Approval Inbox, MCP `request_access`, and `vault://requests`.
- Agent context manifests through `hermes-vault agent context`, dashboard Agent Context, and MCP `vault://agent-context`; responses are metadata-only and include redaction boundaries.
- Recovery and incident evidence upgrades with `recovery drill`, dashboard Recovery Drill, MCP `vault://recovery`, and redacted `incident bundle` archives.
- Dashboard Command Center for agent context, policy explain, access requests, approval decisions, and recovery drills.

### Fixed

- `maintain` now accepts the clearer `--print-schedule` alias while preserving `--print-systemd` compatibility.
- Windows CLI help no longer crashes when Rich renders service-normalization help in legacy code pages.
- MCP asyncio tests use `asyncio.run`, removing the release-regression deprecation warning.
- The example policy file is plain ASCII again and documents v0.19 lease enforcement fields.
- Incident bundle live generation now calls health with the supported argument set.

### Changed

- Version surfaces now report `0.19.0` in `pyproject.toml`, `src/hermes_vault/__init__.py`, and MCP server metadata.
- README, operator docs, MCP docs, and site copy now present Agent Control Plane as the current release.

### Verification

- Focused suites: `uv run python -m pytest tests/test_policy.py tests/test_broker.py tests/test_cli.py tests/test_mcp_server.py tests/test_dashboard.py -q --tb=short`
- Full release validation: `uv run python -m pytest tests/ -q --tb=short`
- Build validation: `uv run --with build python -m build`

## 0.18.0 -- Operator Workflow Convergence

### Added

- Dashboard Onboarding Preview action for dry-run bootstrap/import summaries, including redacted import counts, skipped entries, policy doctor summary, skill next step, and MCP config snippet.
- Dashboard Recovery Hub diff support, pairing metadata-only backup drift with backup verification and restore dry-run.
- Client-side dashboard search, status filters, and sorting for credential, lease, and audit tables.
- MCP `vault://status` resource for policy-scoped health, lease, backup, policy, profile, and safe next-step metadata.
- Release readiness and roadmap artifacts for the v0.18.0 release train.

### Fixed

- Dashboard overview now renders the lease metric returned by the backend.
- Dashboard vault-key validation now checks all credential records instead of only the first sample.
- MCP browser OAuth logins now include unique `login_id` values so concurrent same-provider/same-alias attempts do not collide.
- Current dashboard UI and host-binding errors no longer refer to stale v0.8 operational copy.

### Changed

- Version surfaces now report `0.18.0` in `pyproject.toml`, `src/hermes_vault/__init__.py`, and `uv.lock`.
- The public site and README now present Operator Workflow Convergence as the current release.

### Verification

- Focused dashboard/MCP regression suite: `uv run pytest tests/test_dashboard.py tests/test_mcp_server.py -q --tb=short`

## 0.17.0 -- Lease Assurance

### Added

- Full lease lifecycle backfill across vault, broker, MCP, CLI, backup/recovery, release regression, health, maintenance, policy doctor, and diff coverage.
- Lease-aware health reporting with active, expired, revoked, and total lease counts in CLI, JSON, and MCP health surfaces.
- Lease-aware maintenance with `--cleanup-leases` for idempotent expired-lease revocation during scheduled runs.
- Lease-focused policy doctor warnings for agents that can issue leases without access materialization rights or revoke leases without issue authority.
- Lease drift reporting in backup diff output, including added, removed, and changed lease state.

### Changed

- Broker and CLI lease flows now use the real method contracts end-to-end, including correct broker argument wiring and metadata-safe deny responses for MCP lease tools.
- Vault lease renewal now allows expired leases to be renewed from the current time, and double-revocation now fails closed with a clear error.
- Version surfaces now report `0.17.0` in `pyproject.toml` and `src/hermes_vault/__init__.py`.

### Verification

- Full test suite: `uv run pytest tests/ -q`
- Import check: `uv run python -c "import hermes_vault; print(hermes_vault.__version__)"`

## 0.16.0 -- Agent Access Lifecycle

### Added

- Lease lifecycle support: agents and operators can issue, list, inspect, renew, and revoke time-bound leases over credential access.
- Policy pack templates: reusable starter packs now provide a coherent policy baseline for operator and agent workflows.
- Dashboard and MCP surfacing: lease metadata is visible through the local dashboard and MCP server without exposing raw secrets.

### Changed

- Release closeout: version surfaces now report `0.16.0` in `pyproject.toml`, `src/hermes_vault/__init__.py`, `src/hermes_vault/mcp_server.py`, and `uv.lock`.
- README release notes now describe the Agent Access Lifecycle release at the top of the document.

### Verification

- Full `uv run pytest` passed after the lease, policy-pack, and release-surface updates.

## 0.15.1 -- EvoLink Provider Support

### Added

- EvoLink provider support: `evolink` is now a canonical service ID, env-name hints recognize `EVOLINK_API_KEY`, and provider verification has a direct EvoLink models check.
- Release closeout: version surfaces now report `0.15.1` in `pyproject.toml`, `src/hermes_vault/__init__.py`, and `src/hermes_vault/mcp_server.py`.

### Changed

- README release notes now describe the EvoLink patch release instead of repeating the prior OAuth freshness story as the latest release.

### Verification

- Targeted release regression tests passed for the EvoLink-related surfaces and release version assertions.

## 0.15.0 -- Agent OAuth Freshness

### Added

- Agent OAuth Freshness: broker/MCP env handoff auto-refreshes near-expiry OAuth tokens before the credential reaches the agent, reducing stale-token failures.
- New `oauth_refresh` metadata field in `BrokerDecision` surfaced through CLI and MCP responses, enabling agent-visible freshness status.
- Refresh cooldown of 30 seconds per credential prevents provider rate-limit abuse from repeated handoffs.
- Sanitized failure handling: expired + unrecoverable OAuth tokens are denied with a clean error — no raw token leakage.
- Policy gate: live refresh requires the existing `rotate` service action permission; `get_env` alone does not authorize vault mutation.
- CLI `broker env` JSON output now includes `oauth_refresh` metadata.
- MCP `get_ephemeral_env` response includes a `metadata` field with `oauth_refresh` status.

### Changed

- Dashboard live refresh remains dry-run-only; live token mutation is CLI-only.
- Version surfaces now report `0.15.0` in `pyproject.toml`, `src/hermes_vault/__init__.py`, and `src/hermes_vault/mcp_server.py`.

### Verification

- Full test suite: 687 passed, 1 skipped (includes 8 broker, 2 CLI, and 2 MCP OAuth freshness tests, plus policy and audit verification tests).

## 0.14.0 -- Native Windows + DPAPI Master-Key Protection

### Added

- DPAPI-based master-key wrapping on Windows, opt-in via `HERMES_VAULT_DPAPI=1` and the new `pywin32` extra. Backward compatible: existing vaults continue to use the legacy passphrase-only path with no migration.
- New `_platform.py` abstraction layer that centralizes every OS-dependent call site (default vault home, default scan roots, file permissions, durable writes, command formatting, browser opening, DPAPI availability) so Windows behavior is consistent and POSIX behavior is unchanged.
- New `docs/windows.md` install, path, CLI, OAuth, backup, scheduled-maintenance, security, and known-limitations guide for Windows users.
- New `tests/test_platform.py` covers Windows code paths via `monkeypatch` of `_is_windows` and `_platform.dpapi_available`, matching the existing test idiom.
- New `tests/test_dpapi.py` covers lazy import failure, DPAPI protect/unprotect roundtrip, Windows monkeypatch, non-Windows no-op, mixed passphrase + DPAPI, and the legacy-vault migration path (20 new test cases).
- Constructor opt-in via `HERMES_VAULT_DPAPI=1` with stderr warning and legacy fallback when DPAPI is unavailable.
- Rotation uses format-agnostic read plus a DPAPI-aware write path.
- Magic-header detection (`b"HVDP"`) so legacy 16-byte salt vaults continue to work without intervention.

### Changed

- `src/hermes_vault/crypto.py` gained the `load_or_create_master_key(salt_path, passphrase, *, enable_dpapi=True)` wrapper that auto-detects the on-disk format and raises a clear error when DPAPI is requested but unavailable.
- `src/hermes_vault/vault.py` constructor and `rotate-master-key` path now wrap the master key with DPAPI on Windows when enabled.
- `src/hermes_vault/_platform.py` is the single source of truth for platform behavior. `dpapi_available()` is the only public DPAPI helper.
- `pyproject.toml` adds a `[windows]` optional extra declaring `pywin32`.
- `docs/windows.md` "Known Limitations" table now lists DPAPI as supported when `pywin32` is installed, with the passphrase still required.
- Version surfaces now report `0.14.0` in `pyproject.toml`, `src/hermes_vault/__init__.py`, `src/hermes_vault/mcp_server.py`, and `uv.lock`.

### Verification

- Full test suite: 676 passed, 0 failed (656 baseline + 20 new DPAPI tests).
- All CLI commands cited in the new Windows docs were checked against `python -m hermes_vault.cli --help`.
- DPAPI is opt-in and the legacy passphrase path is exercised on every test run for backward-compat assurance.

## 0.13.0 -- Credential Lifecycle & Recovery

### Added

- A top-level 0.13.0 release framing in the README so the product story now opens with lifecycle and recovery instead of older auth-readiness language.
- A lifecycle and recovery runbook in the operator guide that separates freshness checks, live health verification, scheduled maintenance, policy drift review, and recovery proof.

### Changed

- `maintain` now says it only covers refresh + health and points operators to `policy doctor`, `backup-verify`, and `restore --dry-run` for the missing assurance.
- `maintain` is documented as lifecycle assurance, not as a substitute for backup verification or restore drills.
- Recovery guidance now treats `backup-verify` and `restore --dry-run` as the proof path, and backup age as a warning, not proof.
- README and operator guide now frame Hermes Vault v0.13.0 as the lifecycle and recovery release.
- Policy doctor wording keeps refresh permissions separate from rotation expectations instead of blurring them together.
- Architecture and credential-lifecycle notes now match the new release story.
- Version surfaces now report `0.13.0` in `pyproject.toml`, `src/hermes_vault/__init__.py`, `src/hermes_vault/mcp_server.py`, and `uv.lock`.

### Verification

- Full test suite passed with `uv run pytest`.
- Updated docs were checked against the shipped `maintain`, `policy doctor`, `backup-verify`, `restore --dry-run`, and `rotate-master-key` surfaces.

## 0.12.1 -- Security Hardening Patch

### Changed

- `maintain --format json` and MCP OAuth refresh responses now replace raw refreshed OAuth tokens with short previews and rotation booleans.
- Broker environment materialization now requires the `get_env` action for policy v2 agents while preserving legacy service-list policy behavior.
- Aliasless broker environment requests now fail closed when a service has multiple matching credentials.

### Security

- OAuth provider errors are sanitized before they can reach exception messages, audit reasons, MCP responses, CLI output, or maintenance reports.
- Master-key rotation now writes a durable salt-rotation journal and recovers deterministically if interrupted after database re-encryption.
- Secret scanning now includes common token-bearing dotfiles and reports large secret-like files as warning findings instead of skipping them silently.

### Verification

- Full release validation passed with `uv run pytest` on the 0.12.1 release candidate.
- Version surfaces now report `0.12.1` in `pyproject.toml`, `src/hermes_vault/__init__.py`, `src/hermes_vault/mcp_server.py`, and `uv.lock`.

## 0.12.0 -- Auth Confidence

### Added

- `hermes-vault oauth doctor [provider] --format table|json` reports provider readiness, PKCE support, device-code support, missing required env vars, default scopes, findings, and safe next commands without token exchange.
- `hermes-vault health --verify-live --service <name>` runs metadata-only provider verification findings for a narrow auth surface before handing credentials to an agent.
- MCP now exposes `oauth_provider_status` so agents can inspect provider readiness without receiving raw tokens, device codes, client secrets, or vault secrets.

### Changed

- OAuth device-login failures now include supported providers, missing env var names, provider status metadata, and safe fallback commands.
- Packaged OAuth defaults now consistently mark Google and GitHub as device-code-capable.
- README, operator docs, MCP docs, architecture notes, and site copy now describe the current browserless first-login and auth-readiness surface.
- Version surfaces now report `0.12.0` in `pyproject.toml`, `src/hermes_vault/__init__.py`, and `src/hermes_vault/mcp_server.py`.

### Security

- Auth readiness outputs are metadata-only and never include raw credentials, OAuth token responses, client secrets, device codes, encrypted payloads, or vault secret values.
- Health JSON output is now machine-readable without the decorative banner prefix.

### Release Ops

- Site release copy and dashboard screenshots were refreshed, with a deploy guardrail script for the Hermes Vault static site.

## 0.11.0 -- First Safe Agent

### Added

- `hermes-vault bootstrap` guides operators from a plaintext `.env` into redacted import preview, encrypted vault import, policy-doctor summary, generated skill contract next steps, broker-env next command, and an MCP config snippet.
- `hermes-vault oauth login <provider> --headless` routes supported providers through the existing device-code flow while keeping `--no-browser` as browser callback fallback.
- MCP now exposes `oauth_device_login` so agent-in-the-loop onboarding can initiate device-code login without a callback browser.

### Changed

- Quick-start docs now lead with the First Safe Agent flow instead of a loose scan/import command chain.
- Version surfaces now report `0.11.0` in `pyproject.toml`, `src/hermes_vault/__init__.py`, and `src/hermes_vault/mcp_server.py`.

### Security

- Bootstrap JSON and human output are redacted by design and never include secret values.
- MCP device login returns user authorization instructions and pending state only. Raw OAuth access tokens, refresh tokens, and provider token responses are never returned through MCP.
- `--dry-run` bootstrap does not mutate the vault or source `.env`; `--redact-source` only comments out lines that were successfully imported.

## 0.10.1 -- Device-Code Login Follow-up

### Added

- `hermes-vault oauth device-login <provider>` adds a no-browser OAuth device-code flow for supported providers, so headless operators can complete first login without a local callback browser.
- Device-code support now threads through the CLI and OAuth exchange layer, including provider capability checks and token polling.

### Changed

- Version surfaces now report `0.10.1` in `pyproject.toml`, `src/hermes_vault/__init__.py`, and `src/hermes_vault/mcp_server.py`.

## 0.10.0 -- Unattended OAuth and Custom Verifiers

### Added

- Generic custom verifiers now work through `HERMES_VAULT_VERIFY_URL_<SERVICE>` environment variables, so any OpenAI-compatible endpoint can verify a service without writing a plugin.
- `hermes-vault oauth refresh <service>` now handles unattended OAuth renewal from the paired `refresh:<alias>` record and fails closed if renewal cannot succeed.
- `hermes-vault maintain` can batch refresh and health checks for scheduled-safe operator runs.

### Changed

- Refresh policy guidance now points OAuth-capable agents to the existing `rotate` permission instead of a hypothetical refresh-specific action.
- Version surfaces now report `0.10.0` in `pyproject.toml`, `src/hermes_vault/__init__.py`, and `src/hermes_vault/mcp_server.py`.

### Security

- Browserless renewal does not expose raw access or refresh tokens in docs, dashboard, or MCP outputs.

## 0.9.0 -- Profile, Verifier, and MCP Expansion

### Added

- **Credential tags and notes** -- top-level tags and notes now persist through encryption, schema migration, CLI add/import/list/metadata paths, dashboard views, MCP metadata, and backup round-trips.
- **MCP resources** -- `vault://services`, `vault://services/{name}`, `vault://health`, and `vault://policy` expose read-only broker and health data without raw secrets or encrypted payloads.
- **Verifier plugins** -- file-based YAML verifier plugins and entry-point discovery extend provider verification while preserving the existing broker compatibility path.
- **Multi-vault profiles** -- profile-aware home resolution isolates pending OAuth state, verifier plugin directories, and CLI/dashboard/MCP flows across vault profiles.
- **Community onboarding docs** -- CONTRIBUTING guidance, issue templates, PR template, and architecture docs now give contributors a clearer path into the repo.

### Changed

- Version surfaces now report `0.9.0` in `pyproject.toml`, `src/hermes_vault/__init__.py`, and `src/hermes_vault/mcp_server.py`.
- Current release validation passed the full pytest suite and import check before the version bump was recorded.


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
