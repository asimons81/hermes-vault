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
- Every tool call requires `agent_id` — policy enforcement reuses the existing broker and VaultMutations layers
- Raw secrets are never transmitted over MCP; the default access pattern is ephemeral env materialization
- Loads the same vault, policy, and crypto configuration as the CLI

## Runtime Layout

Default runtime state lives outside the project tree at `~/.hermes/hermes-vault-data`:

- `vault.db`
- `policy.yaml`
- `master_key_salt.bin`
- `generated-skills/`

This keeps repository code separate from live secrets and operator state.

## Security Posture

- Local-first only
- Raw secrets encrypted at rest
- No normal CLI path prints raw secrets
- No secret logging in audit records
- Broker and verifier make re-auth decisions explicit instead of speculative
- MCP transport is a thin wrapper: all policy enforcement reuses the broker; no parallel authority
- Raw secrets are never transmitted over MCP — only ephemeral environment materialization

## Extension Points

- Add new detector patterns in `detectors.py`
- Add new provider verifiers in `verifier.py`
- Extend broker env mappings in `broker.py`
- Add policy fields in `models.py` and `policy.py`
- Add new MCP tools in `mcp_server.py` (must require `agent_id` and route through broker)

