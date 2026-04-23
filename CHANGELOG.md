# Changelog

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
