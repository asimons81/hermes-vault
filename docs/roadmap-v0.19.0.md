# Hermes Vault v0.19.0 Roadmap

- **Release**: v0.19.0 -- Agent Control Plane
- **Status**: Implemented release plan
- **Date**: 2026-07-05

## Executive Summary

v0.18.0 made Hermes Vault easier to operate. v0.19.0 makes it harder to misuse.

The release goal is to turn Hermes Vault from a local encrypted credential broker into a local-first agent access control plane: explainable policy, lease-backed credential handoffs, operator approvals, redacted incident evidence, profile-aware recovery drills, and a dashboard that answers "what can this agent do, why, for how long, and what should I approve next?"

This is not a cloud service release. It does not turn the dashboard into a remote admin panel, does not add raw-secret viewing, and does not create a second authority path around the broker. CLI, MCP, dashboard, policy, audit, and backup behavior must all converge on the same local trust model.

## Shipped Scope

v0.19.0 ships the Agent Control Plane across CLI, MCP, dashboard, policy, broker, vault persistence, tests, and release docs:

- Explainable policy via CLI, dashboard, MCP tool, and MCP resource.
- Lease-required env materialization with purpose enforcement and broker lease checkout.
- Durable access requests with approve/deny lifecycle and optional lease issuance.
- Redacted agent-context manifests for per-agent review.
- Recovery drills and incident bundles for metadata-only operational evidence.
- Dashboard Command Center for the new operator workflows.
- Plain-ASCII policy example with v0.19 lease fields.
- Scheduler template alias `--print-schedule` while preserving `--print-systemd`.

## Baseline Snapshot

Observed on `master` at `e76336c feat(release): ship Hermes Vault v0.18.0`.

- Version surfaces report `0.18.0` in `pyproject.toml`, package `__version__`, and MCP server metadata.
- Full test suite passes: `761 passed, 1 skipped, 1 warning`.
- v0.18.0 delivered dashboard onboarding preview, recovery diff drills, searchable tables, exhaustive vault-key validation, MCP OAuth login isolation, and MCP `vault://status`.
- The repo has untracked local files/directories: `.hermes/`, `IDEA.md`, and `docs/roadmap-v0.17.0.md`. Do not fold those into v0.19.0 unless intentionally reviewed.
- Known polish debt visible from inspection:
  - `policy.example.yaml` contains mojibake box-drawing/comment text and is harder to trust as copy-paste starter policy.
  - `docs/operator-guide.md` has some mojibake punctuation in older sections.
  - `maintain --print-systemd` is documented as the Windows Task Scheduler template command, but the option name is Linux-shaped.
  - CLI subgroup help for lease subcommands is terse.
  - Full test suite emits an asyncio deprecation warning from MCP tests.
  - README dashboard screenshots still point to the v0.8.0 screenshot set, while the dashboard has grown substantially since then.

## Release Thesis

Hermes Vault already stores secrets safely. v0.19.0 should govern agent access safely.

The product promise for v0.19.0:

> Before an agent receives a credential, Hermes Vault can explain the policy decision, bind the access to a lease, record an audit trail, show the operator a redacted approval view, and prove the vault can recover if something goes sideways.

## Non-Negotiable Security Boundaries

- Raw secrets, raw OAuth access tokens, refresh tokens, provider responses, encrypted payload bytes, and vault database files never appear in CLI reports, MCP resources, dashboard JSON, logs, audit exports, or docs.
- Dashboard remains localhost-only, token-guarded, and metadata-only.
- MCP remains broker-backed and policy-gated. It must not gain a parallel permission model.
- Live credential mutation remains CLI-first unless a dashboard action is explicitly approved as local-only, bounded, audited, and narrower than the existing CLI.
- Lease and approval features must degrade safely: deny or require operator action rather than silently falling back to broad access.
- Update checks stay read-only under `update --check`.
- Tests must use fake credentials and temporary `HERMES_VAULT_HOME` directories.

## Pillar 1: Explainable Policy Engine

### Goal

Make policy decisions inspectable before an agent hits a denial or receives access.

### Features

- `hermes-vault policy explain <agent> <service> --action <action>`
  - Shows allow/deny decision, matched service policy, inherited TTL ceiling, required capability/action, raw-secret boundary, ephemeral-env requirement, lease requirement, and recommended remediation.
  - Supports `--format table|json`.
  - Never decrypts or touches credential payloads.
- `hermes-vault policy simulate --agent <agent> --service <service> --actions get_env,verify`
  - Batch dry-run decisions for planned agent workflows.
  - Returns an exit code suitable for CI and release checks.
- `policy doctor` upgrades:
  - Flag legacy flat-list agents as migration warnings.
  - Flag lease-capable agents that lack an explicit TTL ceiling.
  - Flag `rotate` grants that exist only to support OAuth freshness and recommend a narrower future permission if implemented.
  - Flag policy entries that name services with no matching credential, and credentials with no policy path.
- Safe remediation output:
  - Suggested YAML patch snippets stay comments/reports only.
  - No automatic policy write in v0.19.0 unless guarded behind a separate explicit `--write` command and tests.

### Acceptance Criteria

- New policy explanation tests cover allow, deny, legacy policy, missing capability, missing service action, TTL cap, lease-required access, and unknown service.
- Dashboard and MCP reuse the same policy explanation serializer instead of duplicating decision logic.

## Pillar 2: Lease-Enforced Agent Handoffs

### Goal

Move leases from observable lifecycle objects to enforceable access boundaries.

### Features

- Optional policy field: `require_lease_for_env: true`.
  - When enabled for an agent or service, broker `get_env` denies unless an active, unexpired lease exists for the agent/service/alias.
  - Lease enforcement applies consistently to CLI broker calls and MCP `get_ephemeral_env`.
- `hermes-vault lease checkout <service> --agent <agent>`
  - Issues or reuses a valid lease, then materializes ephemeral env in one audited flow.
  - Uses the narrower of requested TTL, lease TTL, service TTL, and agent TTL.
- Lease purpose hardening:
  - Require or strongly warn on empty/generic lease purposes when policy sets `require_lease_purpose: true`.
  - Add purpose search/filtering to CLI and dashboard surfaces.
- Lease audit correlation:
  - Broker decisions include `lease_id` metadata when a lease authorizes access.
  - Audit query can filter by `--lease <id>`.

### Acceptance Criteria

- Expired, revoked, wrong-agent, wrong-service, and wrong-alias leases fail closed.
- Non-lease policies keep current behavior for backward compatibility.
- Backup, restore dry-run, diff, status, health, dashboard, and MCP status all include lease enforcement metadata without exposing secrets.

## Pillar 3: Local Approval Queue

### Goal

Give operators a safe way to review agent access requests without inventing a hosted control plane.

### Features

- `hermes-vault request access <service> --agent <agent> --action get_env --purpose "..."`
  - Creates an audit-backed pending request object with metadata only.
  - No credential is decrypted when the request is created.
- `hermes-vault request list|show|approve|deny`
  - Approval may issue a lease, grant a one-time handoff, or return a suggested policy change, depending on request type.
  - Denial records a reason for future audit.
- Dashboard Approval Inbox:
  - Local-only review of pending access requests.
  - Approve/deny actions are metadata-only until approval triggers a lease issuance through the existing mutation path.
  - No dashboard credential add/import/rotate/delete.
- MCP request tool:
  - Agents can request access without receiving access.
  - MCP approval remains out of band; the operator approves through CLI or local dashboard.

### Acceptance Criteria

- Approval objects survive process restarts.
- Approval actions are audited.
- Dashboard approval endpoints reject non-local hosts, require token auth, sanitize responses, and never return raw secrets.
- MCP request creation works in bound and unbound agent modes.

## Pillar 4: Agent Context Packs

### Goal

Replace ad hoc "what can I use?" agent context with deterministic, redacted access manifests.

### Features

- `hermes-vault agent context <agent> --format markdown|json`
  - Produces a redacted manifest: visible services, permitted actions, TTL ceilings, lease requirements, provider readiness, stale/invalid/expiring metadata, and safe next commands.
  - Embeds policy hash and generated timestamp.
- MCP resource: `vault://agent-context?agent_id=<agent>`.
  - Same serializer as CLI.
  - No env materialization and no raw secret values.
- Generated skill integration:
  - `generate-skill` can include or link to an agent context pack.
  - `sync-skill --check` detects stale policy hash and stale context hash separately.

### Acceptance Criteria

- Context packs are deterministic for stable input.
- Tests prove no encrypted payload, secret preview, token preview, raw provider response, or env value appears in context output.

## Pillar 5: Recovery Drill Automation

### Goal

Make recovery proof routine, profile-aware, and auditable.

### Features

- `hermes-vault recovery drill --backup <path> --format table|json`
  - Composes backup verification, restore dry-run, metadata diff, lease diff, salt compatibility, profile path check, and policy hash check.
  - Emits a single redacted pass/fail report.
- `maintain --recovery-drill --backup <path>`
  - Optional scheduled-safe drill mode.
  - Dry-run first-class; live mutation remains out of scope.
- Recovery readiness score in `health`, dashboard, and MCP status:
  - Backup age.
  - Last verified backup.
  - Last restore dry-run.
  - Last recovery drill.
  - Salt compatibility.

### Acceptance Criteria

- Drill reports never include encrypted payload bytes or raw secret material.
- Missing salt, incompatible profile, metadata-only backup, unreadable backup, and decrypt failure each produce distinct findings.
- Dashboard Recovery Hub uses the same drill report serializer.

## Pillar 6: Redacted Incident Bundle

### Goal

Let an operator package enough evidence to debug access incidents without leaking credentials.

### Features

- `hermes-vault incident bundle --since 24h --output <path>`
  - Produces a redacted archive or directory with:
    - audit events
    - policy summary and hash
    - health/status findings
    - lease/request timeline
    - MCP binding summary
    - version and platform metadata
    - dashboard-disabled proof that no browser JSON is required
  - Excludes vault database, salt, encrypted payloads, raw secrets, provider responses, and `.env` contents.
- `--agent`, `--service`, `--lease`, and `--request` filters.
- `--dry-run` prints the manifest of files that would be included.

### Acceptance Criteria

- Bundle tests scan generated output for known fake secrets and token-like material.
- File permissions are restrictive on POSIX and best-effort checked on Windows.
- Bundle output is useful for GitHub issues without asking users to paste local secrets.

## Pillar 7: Dashboard Command Center

### Goal

Turn the dashboard into a local operator cockpit for explain, approve, lease, and recover workflows.

### Features

- Agent detail view:
  - Visible services, allowed actions, TTL ceilings, lease requirements, stale generated skill/context status.
- Policy Explain panel:
  - Calls the same explain serializer as CLI.
- Approval Inbox:
  - Request list, details, approve/deny with reason.
- Lease Board:
  - Active/expired/revoked lanes, renewal warnings, purpose search, audit correlation.
- Recovery Drill panel:
  - Single drill action and drill history.
- Fresh screenshot set for v0.19.0 docs and site.

### Acceptance Criteria

- Browser QA at desktop and mobile widths for all new panels.
- Token expiry, invalid vault key, missing static assets, and profile switch behavior remain covered.
- No nested-card sprawl or text overflow in dense table states.

## Pillar 8: MCP Resource Expansion

### Goal

Give agents rich read-only context and safe request creation without broadening credential access.

### Resources

- `vault://agent-context`
- `vault://policy-explain`
- `vault://requests`
- `vault://recovery`
- `vault://leases/{id}`

### Tools

- `request_access`
- `policy_explain`
- Optional: `lease_checkout`, only if it routes through the same lease enforcement and broker path as CLI.

### Acceptance Criteria

- Every resource/tool supports bound-agent mode and unbound explicit `agent_id`.
- Error envelopes use stable `version` fields.
- MCP test coverage includes denial, missing identity, bound identity, and redaction checks.

## Pillar 9: Provider and Import Intelligence

### Goal

Reduce setup friction without loosening import safety.

### Features

- Provider catalog report:
  - Built-in canonical services, env hints, verifier availability, OAuth support, device-code support, custom verifier env var names.
- Import preview v2:
  - Confidence levels for env mapping.
  - Collision detection against existing service/alias records.
  - Suggested aliases for multi-account providers.
  - Safer skip reasons for database URLs, JWT secrets, session secrets, and public config.
- Policy pack upgrades:
  - Add lease-enforced `coder`, `auditor`, `browser-operator`, and `release-manager` packs.
  - Include comments that match current capabilities/actions.

### Acceptance Criteria

- Existing import behavior remains conservative.
- New hints do not auto-import broad secrets unless explicitly mapped.
- Policy packs pass policy-doctor without warnings except documented intentional warnings.

## Required Bug Fixes and Hardening

These should land before or alongside the feature pillars:

- Clean encoding/mojibake in `policy.example.yaml`, `docs/operator-guide.md`, and any older README sections touched by v0.19.0.
- Rename or supplement `maintain --print-systemd` with a platform-neutral scheduler template command, while keeping the old flag as a compatibility alias.
- Add meaningful help text for lease subcommands and any new request/policy/recovery commands.
- Fix the MCP asyncio deprecation warning in tests.
- Refresh dashboard screenshots and site copy so the public docs no longer look anchored to v0.8.0.
- Add a release-regression check that every version surface, roadmap, README "What's New", changelog, and site copy agree on `0.19.0`.
- Audit dashboard/API sanitizers after adding approvals, requests, policy explain, and recovery drills.
- Verify package data includes any new dashboard assets.

## Implementation Order

1. **Foundation**
   - Policy explain serializer.
   - Lease enforcement model and tests.
   - Request/approval storage model.
   - Shared redaction assertions.

2. **CLI First**
   - `policy explain`, `policy simulate`.
   - `lease checkout`.
   - `request access/list/show/approve/deny`.
   - `recovery drill`.
   - `incident bundle`.

3. **MCP Second**
   - Add read-only resources and request creation.
   - Add optional `lease_checkout` only after CLI broker behavior is locked.

4. **Dashboard Third**
   - Agent detail, approval inbox, lease board, explain panel, recovery drill panel.
   - Reuse CLI/core serializers.

5. **Docs, Site, and Release Readiness**
   - README top release story.
   - Operator runbook.
   - MCP docs.
   - Threat model additions.
   - Fresh screenshots.
   - Release readiness report.

## Test Plan

Targeted suites:

```bash
uv run python -m pytest tests/test_policy.py tests/test_policy_doctor.py -q
uv run python -m pytest tests/test_broker.py tests/test_mutations.py tests/test_vault.py -q
uv run python -m pytest tests/test_cli.py tests/test_mcp_server.py -q
uv run python -m pytest tests/test_dashboard.py -q
uv run python -m pytest tests/test_backup_recovery.py tests/test_diff.py tests/test_health.py tests/test_maintenance.py -q
uv run python -m pytest tests/test_release_regression.py -q
```

Full release gate:

```bash
$env:PYTHONIOENCODING = "utf-8"
uv run python -m pytest tests/ -q --tb=short
uv run --with build python -m build
```

Manual QA:

- Temporary `HERMES_VAULT_HOME` with fake credentials only.
- CLI policy explain and lease checkout transcripts.
- MCP resource smoke check in bound and unbound modes.
- Dashboard desktop and mobile browser QA.
- Package install smoke for dashboard static assets.
- Windows PowerShell smoke for scheduler template, path quoting, and recovery drill.

## Release Artifacts

- `docs/roadmap-v0.19.0.md`
- `release-readiness/v0.19.0/readiness-report.md`
- `CHANGELOG.md` entry for `0.19.0`
- README top release story and command examples
- `docs/operator-guide.md` v0.19.0 runbook
- `docs/mcp-server.md` resource/tool updates
- `docs/threat-model.md` additions for approvals, lease enforcement, incident bundles, and recovery drills
- Fresh dashboard screenshots under `docs/assets/v0.19.0-dashboard/`
- Site copy and deploy verification

## Out of Scope

- Hosted/cloud control plane.
- Remote dashboard binding.
- Raw-secret dashboard viewer.
- Automatic policy rewrites without explicit operator command.
- Auto-publishing releases from the CLI.
- Destructive restore from dashboard.
- Replacing passphrase/DPAPI with external KMS.
- Syncing vault data to third-party storage.

## Definition of Done

v0.19.0 is ready when:

- An operator can answer, with one command or one dashboard view: what can this agent access, why, for how long, and under which lease or approval?
- Brokered env handoff can be made lease-enforced without breaking existing policies.
- Agents can request access without receiving access.
- A recovery drill produces one redacted, actionable result.
- An incident bundle can be attached to a bug report without leaking secrets.
- CLI, MCP, dashboard, docs, tests, and release site all describe the same safety boundary.
- Full tests and package build pass from a clean checkout with fake credentials only.
