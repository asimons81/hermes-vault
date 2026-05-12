# Hermes Vault v0.8.0 Dashboard Roadmap

## Release Theme

**A cinematic local operator console without expanding trust.**

v0.7.0 made Hermes Vault self-maintaining enough for daily use. v0.8.0 adds a local dashboard so operators can understand vault health, policy drift, audit activity, MCP binding, OAuth lifecycle, and recovery posture without stitching CLI reports together.

The dashboard is intentionally not a hosted vault, password manager, or policy editor. It is a local control room for the existing credential control plane.

## Product Direction

- Command: `hermes-vault dashboard`
- Runtime: local Python HTTP server on `127.0.0.1`
- Access guard: random launch URL token
- UI: bundled web app served from package assets
- First-run feel: premium vault-door intro, then fast daily console
- Safe actions only: health, policy doctor, verify, OAuth refresh, backup verify, restore dry-run, maintenance dry-run/run
- Brand assets are bundled release assets, not remote dependencies or runtime generation

No raw secret reveal, remote binding, cloud sync, credential editing, policy editing, or destructive recovery in v0.8.0.

## Implementation Milestones

### 1. Dashboard Server Foundation

- Add `hermes-vault dashboard`
- Serve packaged static assets locally
- Add token-guarded JSON endpoints
- Reuse existing Vault, Broker, Health, Policy Doctor, Maintenance, Backup, and OAuth refresh services
- Exclude encrypted payloads and raw secrets from all responses

### 2. Console UI

- Build Overview, Credentials, Policy, Audit, Operations, MCP, and Recovery surfaces
- Prioritize dense, scannable operator workflows
- Include safe action states for pending, success, denial, and failure
- Keep daily UI crisp and fast after the first-run intro

### 3. Brand Asset Sprint

- Generate 3-5 branded vault-door directions with the latest official GPT Image model available
- Select one direction and convert it into app-ready bitmap/SVG references
- Use Remotion for launch/video/brand asset generation, not as dashboard runtime
- Commit only release-ready exported assets that render locally from the packaged console

### 4. Packaging and Verification

- Include dashboard assets in source and wheel builds
- Add tests for token enforcement, localhost-only binding, secret-free responses, and safe actions
- Add visual smoke checks for desktop and mobile widths before release
- Verify the selected brand direction does not obscure controls, text, or data at supported viewport widths

### 5. Documentation and Release Polish

- Document dashboard launch, tokenized local access, and daily operator usage
- Document the safe-action boundary and explicitly excluded capabilities
- Capture visual QA expectations for desktop/mobile, first-run intro, text overflow, and asset rendering
- Keep README, operator guide, architecture notes, changelog, and this roadmap aligned

## Hermes Kanban Breakdown

- **HV-0801 Dashboard architecture**: server command, local binding, token model, endpoint map
- **HV-0802 Dashboard API**: overview, credentials, policy, audit, MCP, and action endpoints
- **HV-0803 Console shell**: navigation, layout, responsive structure, dark operator palette
- **HV-0804 Brand sprint**: GPT Image vault-door directions, selected identity, exported assets
- **HV-0805 Inventory and health views**: metrics, findings, credential table, verify action
- **HV-0806 Policy and audit views**: doctor findings, agent summary, timeline
- **HV-0807 Operations views**: maintenance, OAuth refresh, backup verify, restore dry-run
- **HV-0808 Packaging**: package data, install verification, docs
- **HV-0809 Security tests**: token guard, no raw secret output, localhost-only behavior
- **HV-0810 Visual QA**: desktop/mobile screenshots, intro animation, text overflow checks
- **HV-0811 Release docs**: operator usage, architecture boundary, changelog, release checklist

## Acceptance Criteria

- `hermes-vault dashboard --no-open` prints a tokenized local URL and serves the console.
- API calls without a valid token return 401.
- Credential responses never include `encrypted_payload` or raw secret values.
- Safe actions work through existing service-layer functions.
- The first-run vault-door animation is skippable by time and does not block normal operation.
- The package includes all dashboard assets.
- Visual QA covers desktop and mobile widths, confirms asset loading, and checks for text/control overlap.
