# Hermes Vault v0.7.0 Roadmap

## Release Theme

**Operational autonomy without expanding trust.**

v0.6.0 gave Hermes Vault OAuth PKCE login, refresh-token storage, and MCP OAuth tools. v0.7.0 should make those capabilities safe to run continuously: fewer manual refresh chores, better lifecycle handling, tighter MCP identity assumptions, and clearer operator remediation when credentials drift.

The release should not chase cloud sync, hosted vaults, team sharing, or broad UI work. Hermes Vault's advantage is still local-first credential control for agents. v0.7.0 should make that control durable under real daily use.

## Strategic Direction

Hermes Vault should become the local credential control plane for Hermes agents:

- Agents request capabilities, not secrets.
- Operators see policy, health, expiry, and audit drift before failures.
- OAuth tokens refresh before they interrupt work.
- MCP hosts cannot silently widen their authority.
- Recovery paths are explicit, tested, and documented.

In practical terms: v0.7.0 should move Hermes Vault from "secure broker with OAuth support" to "self-maintaining local credential broker."

## Priority Epics

### 1. Token Lifecycle Supervisor

Build a first-class refresh/maintenance workflow around OAuth tokens.

Scope:

- Add `hermes-vault maintain` or `hermes-vault lifecycle` command that runs:
  - OAuth refresh for expiring tokens.
  - health checks.
  - backup-age checks.
  - stale verification checks.
- Add `--dry-run`, `--format json`, and human table output.
- Add exit codes suitable for cron/systemd.
- Add generated cron/systemd snippets:
  - `hermes-vault maintain --print-systemd`
- Record lifecycle runs in audit without storing secrets.

Acceptance criteria:

- An operator can schedule one command and know tokens are refreshed before expiry.
- Failed refresh attempts produce actionable reasons: network, provider rejection, missing refresh token, missing client credentials, policy denial.
- The command is safe to run repeatedly.
- No background daemon is required for v0.7.0.

Why this matters:

v0.6.0 documents cron as optional, but refresh is only useful if it happens before agents fail. A supervised command gives autonomy without introducing a persistent daemon or cloud component.

### 2. OAuth Storage Cleanup and Pairing Hardening

Tighten the token model now that OAuth is no longer experimental.

Scope:

- Stop duplicating `refresh_token` in access-token metadata.
- Stop storing full `raw_response` if it contains token material.
- Store only sanitized provider metadata:
  - `token_type`
  - `expires_at`
  - `issued_at`
  - `scopes`
  - `provider`
  - safe provider fields only.
- Add explicit access/refresh pairing helpers instead of relying only on alias `"refresh"`.
- Support multiple OAuth aliases per provider without refresh-token collision.
  - Current convention uses `service=google, alias=refresh`, which is not enough if `google:work` and `google:personal` both exist.
  - v0.7.0 should pair refresh tokens by access-token alias, for example `refresh:work`, or by metadata-backed lookup.
- Add cleanup/migration command:
  - `hermes-vault oauth normalize`
  - dry-run shows records that would be rewritten.

Acceptance criteria:

- New OAuth logins do not store token material redundantly.
- Existing v0.6.0 OAuth records remain usable.
- Multiple aliases for the same OAuth provider can refresh independently.
- Tests cover old-format records and new-format records.

Why this matters:

The v0.6.0 review already identified redundant token storage. More importantly, refresh aliasing will become a real operational bug as soon as one operator has multiple Google/GitHub identities.

### 3. MCP Session Identity and Authorization Tightening

Reduce the risk of MCP hosts spoofing arbitrary `agent_id` values.

Scope:

- Add optional MCP server config that binds a process/host registration to an allowed agent ID set.
- Support environment-level server identity:
  - `HERMES_VAULT_MCP_ALLOWED_AGENTS=hermes,claude-desktop`
  - `HERMES_VAULT_MCP_DEFAULT_AGENT=claude-desktop`
- Deny MCP calls whose `agent_id` is outside the allowed set before policy evaluation.
- Add audit fields that distinguish:
  - requested `agent_id`
  - MCP server identity/config profile
  - policy decision.
- Update docs to stop implying `agent_id` alone is strong identity.

Acceptance criteria:

- A compromised MCP host cannot simply claim a more privileged `agent_id` if the server was launched with an allowed-agent binding.
- Backward compatibility remains: unrestricted MCP mode still works when no binding env vars are set.
- Denials are visible in audit.

Why this matters:

The current policy model is strong after identity is accepted, but MCP identity is caller-provided. v0.7.0 should make deployment-time identity binding available without requiring a full auth protocol.

### 4. Policy Doctor and Least-Privilege Migration

Make policy problems diagnosable before runtime failures.

Scope:

- Add `hermes-vault policy doctor`.
- Validate:
  - unknown service IDs.
  - unknown actions/capabilities.
  - legacy agents with implicit all-capabilities grants.
  - agents with `raw_secret_access: true`.
  - long TTLs for MCP-facing agents.
  - OAuth-capable agents missing `add_credential` or `rotate` for refresh.
  - stale generated skills by policy hash.
- Add `--strict` mode for CI.
- Add optional remediation output:
  - "suggested YAML patch" text, not automatic mutation by default.

Acceptance criteria:

- Operators can run one command and see concrete policy risks.
- CI can fail on strict policy violations.
- Existing legacy policies remain supported but visibly warned.

Why this matters:

Hermes Vault has gained enough policy surface that misconfiguration is now more likely than missing features. A policy doctor preserves the deny-by-default posture while reducing operator friction.

### 5. Recovery and Backup Drill

Move backup from "available" to "proven restorable."

Scope:

- Add `hermes-vault backup-verify --input <backup-file>`.
- Add `hermes-vault restore --dry-run --input <backup-file>`.
- Validate:
  - backup format.
  - salt compatibility.
  - decryptability with current passphrase.
  - record counts.
  - audit inclusion.
- Add safer operator guidance around where `vault.db` and `master_key_salt.bin` must be stored together.

Acceptance criteria:

- An operator can verify a backup without overwriting the live vault.
- Health can include "last verified backup" separately from "last created backup."
- Tests cover corrupted backup, wrong passphrase, missing salt, and metadata-only incompatibility.

Why this matters:

v0.5.0 added backup governance. v0.7.0 should close the loop by proving recovery works before an incident.

## Secondary Candidates

These are useful, but should not displace the priority epics unless implementation is cheap.

- Device-code OAuth flow for headless machines.
- More provider verification adapters, especially for Google/GitHub OAuth scopes.
- `hermes-vault oauth revoke` to mark access and refresh tokens invalid after provider-side revocation.
- `hermes-vault audit summarize` for weekly operator review.
- Better scanner remediation plans that group duplicates by canonical service.
- Shell completion and packaging polish.

## Explicit Non-Goals for v0.7.0

- Hosted cloud vault.
- Multi-user/team sync.
- Remote secret sharing.
- Long-running daemon by default.
- GUI dashboard.
- Raw-secret MCP transport.
- Automatic destructive policy rewrites.

These would change the threat model too much for a minor release after OAuth.

## Suggested Milestone Plan

### Milestone 1: Design Locks

- Decide token pairing strategy for multiple aliases.
- Decide command name: `maintain`, `lifecycle`, or `doctor`.
- Define MCP allowed-agent environment variables.
- Define backup verification report schema.

Exit criteria:

- Design notes added to `docs/architecture.md` or a dedicated design doc.
- Tests listed for each chosen behavior.

### Milestone 2: OAuth Lifecycle Core

- Implement sanitized token metadata.
- Implement alias-safe refresh-token pairing.
- Implement compatibility path for v0.6.0 token records.
- Implement lifecycle/maintenance dry-run.

Exit criteria:

- Existing OAuth tests pass.
- New tests prove multi-alias refresh works.
- `maintain --dry-run --json` works without mutating the vault.

### Milestone 3: Operator Guardrails

- Add policy doctor.
- Add MCP allowed-agent binding.
- Add lifecycle audit records.
- Add docs for scheduled maintenance.

Exit criteria:

- Policy doctor flags risky legacy policy without breaking it.
- MCP calls outside configured allowed agents are denied and audited.
- Operator guide includes systemd/cron examples.

### Milestone 4: Recovery Proof

- Add backup verify/drill.
- Add health integration for verified backups.
- Add release regression tests.
- Update migration docs from 0.6.0 to 0.7.0.

Exit criteria:

- Full test suite passes.
- Migration doc covers OAuth record normalization.
- Changelog and README clearly explain v0.7.0.

## Release Bar

v0.7.0 should ship only if:

- OAuth multi-alias refresh is safe.
- Lifecycle maintenance can be scheduled without leaking secrets.
- MCP identity binding is available and documented.
- Policy doctor catches common privilege mistakes.
- Backup verification proves recoverability.
- Backward compatibility with v0.6.0 vaults is tested.

## Recommended Cut Line

If scope needs to shrink, keep these:

1. OAuth storage cleanup and multi-alias refresh pairing.
2. Lifecycle maintenance command.
3. MCP allowed-agent binding.
4. Policy doctor minimal version.

Device-code OAuth remains deferred. Backup verification and dry-run restore are included in the v0.7.0 release scope.
