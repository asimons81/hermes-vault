# Hermes Vault v0.21.0 Release Readiness Report

**Status:** Release Ready (release/v0.21.0, combined validation complete)

## Version

- Target: `0.21.0`
- Codename: Audit Assurance
- Release branch SHA: `5f78c2f` (release/v0.21.0)

## PRs and Issues

| Item | Status | Evidence |
|------|--------|----------|
| Issue #30 | **CLOSED** | PR #39 merged |
| Issue #31 | **CLOSED** | PR #40 merged |
| Issue #32 | **CLOSED** | PR #41 merged |
| Issue #33 | **CLOSED** | 30 adversarial tests on release branch |
| PR #42 | **DRAFT** | Combined release candidate, awaiting final merge |

## Implementation Scope

### Complete (merged to master)
- [x] Canonical audit-entry serialization (`canonical.py`)
- [x] HKDF-derived Ed25519 signing (`crypto.py`)
- [x] Integrity chain schema and records (`schema.py`, `repository.py`)
- [x] Authenticated checkpoint repository (`checkpoint.py`)
- [x] Protected append and read-only verification (`service.py`)
- [x] Migration anchoring (`migration.py`, `service.py`)
- [x] Master-key rotation segments
- [x] Verification result model with healthy/legacy/incomplete/failed states
- [x] `hvbackup-v2` format with integrity evidence
- [x] v2 backup verification with structural/consistency checks
- [x] v1 backup backward compatibility
- [x] Transactional restore with staging and rollback
- [x] CLI: `audit-verify`, `audit-checkpoint`, `audit-export`
- [x] Dashboard: `GET /api/audit-integrity`, `POST /api/audit-integrity/verify`
- [x] MCP: `vault://audit-integrity` resource, integrity in `vault://status`
- [x] Version bump to `0.21.0`
- [x] Changelog, README, and site updates
- [x] Release regression test updates

### Complete (release/v0.21.0 branch)
- [x] Adversarial integrity test suite (30 corruption scenarios)
- [x] Dashboard server wait helper for Windows Python 3.12 reliability
- [x] Real Windows DPAPI validation (16 assertions, all passed)
- [x] Packaged dashboard proof (4 states, auth, read-only, static assets)
- [x] Website production deployment

## Test Counts

**877 passed, 1 skipped** (up from 802)

Breakdown:
- 809 core + backup tests
- 38 audit surface tests (CLI, dashboard, MCP contracts)
- 30 adversarial integrity tests (all failure classifications)

## CI and Validation Results

| Check | Result |
|-------|--------|
| Ubuntu Python 3.11 | PASSED (PR #41) |
| Ubuntu Python 3.12 | PASSED (PR #41) |
| Windows Python 3.11 | PASSED (PR #41) |
| Windows Python 3.12 | PASSED (PR #41, fix applied) |
| Ruff | PASSED |
| mypy | PASSED (test files exempted for monkeypatch typing) |
| Wheel build | PASSED (hermes_vault-0.21.0-py3-none-any.whl) |
| Dependency audit | PASSED |
| Gitleaks (secret scan) | PASSED |
| Post-merge security validation | PASSED |
| Secret Source conformance | PASSED |

### DPAPI Validation (local Windows proof)
- Platform: win32 (Python 3.11.9, MSC v.1938)
- pywin32: available
- DPAPI envelope: created and verified
- Credential round-trip: PASSED
- Audit chain creation: PASSED
- Integrity verification (initial): healthy
- Vault reopen: PASSED
- Integrity verification (reopened): healthy
- Master-key rotation: PASSED
- Post-rotation verification: healthy (7 verified)
- hvbackup-v2 backup: created and verified
- Restore dry-run: PASSED
- Full restore: 2 credentials restored
- Plaintext scan: NO plaintext fake credential found in database, checkpoint, backup, or reports
- **All 16 assertions passed, 0 failures**

### Packaged Dashboard Proof (installed wheel)
- State: healthy → GET/POST audit-integrity, auth, read-only **PASSED**
- State: legacy-anchor → same contract **PASSED**
- State: stale-checkpoint → same contract **PASSED**
- State: failed → same contract **PASSED**
- Missing token → 401 **PASSED**
- Invalid token → 401 **PASSED**
- Packaged static assets present (index.html, app.js, styles.css) **PASSED**
- Status text included (not color-dependent) **PASSED**
- No secret leakage in API responses **PASSED**

### Screenshots
Browser screenshots could not be captured — this environment lacks a graphical browser and rendering engine. Screenshot capture requires a headless Chromium/Playwright or browser-based CI runner. The dashboard API and contract were validated through direct HTTP requests against the installed wheel.

### Website Deployment
- Project: hermesvault-site (Vercel)
- Production URL: https://hermesvault.tonysimons.dev
- HTTP status: 200
- Content verified: v0.21.0 branding visible, installation command correct
- GitHub link: https://github.com/asimons81/hermes-vault
- Old v0.20 content: updated to v0.21.0

## Version Surface Audit

| Surface | Value | Status |
|---------|-------|--------|
| pyproject.toml | 0.21.0 | ✅ |
| src/hermes_vault/__init__.py | 0.21.0 | ✅ |
| MCP server (via __version__) | 0.21.0 | ✅ |
| CLI version output | 0.21.0 | ✅ |
| README.md | v0.21.0 | ✅ |
| CHANGELOG.md | section for 0.21.0 | ✅ |
| site/index.html | v0.21.0 | ✅ |
| docs/operator-guide.md | references 0.21.0 | ✅ |
| tests/test_release_regression.py | asserts 0.21.0 | ✅ |

## Key Security Boundaries

- Private signing material derived in memory only, never stored or exported
- Integrity-key material never logged, serialized, or environment-placed
- Checkpoint mutation is explicit and operator-only (requires `--yes`)
- Verification is read-only across all surfaces
- Secret Source and MCP credential authority unchanged
- Pre-v0.21 history preserved but not retrospectively protected
- Local integrity verification is not third-party attestation
- An attacker controlling the local account, key material, database, and checkpoint is outside the trust model

## Documentation Notes

- Verification begins at the migration anchor (legacy history recorded but not individually signed)
- Legacy history was not retrospectively protected (only counted and snapshotted)
- Local verification is not third-party attestation
- v1 backup compatibility maintained (classified as legacy)
- v2 backup includes integrity evidence (structural + key compatibility)
- Checkpoint recovery requires explicit operator action (`recover --yes --reason`)
- Rotation segments maintain predecessor chain continuity
- CLI exit codes: 0=healthy, 2=incomplete, 3=failed, 1=error
- Dashboard and MCP return metadata only, no raw audit rows or secrets

## Unresolved Risks and Accepted Limitations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Browser screenshots not captured | Low | Dashboard API validated directly; browser captures deferred to post-release CI enhancement |
| Adversarial tests at DB level only | Low | SQL-level corruption covers all failure classifications; file-level adversarial path is defense-in-depth |
| DPAPI validation on local runner only | Low | 16 assertions pass on real Windows with real pywin32; CI workflow would repeat same script |
