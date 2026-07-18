# Hermes Vault v0.21.0 Release Readiness Report

**Status:** In Progress (pending PR merges and CI validation)

## Version

- Target: `0.21.0`
- Codename: Audit Assurance

## PRs and Issues

- Issue #30: Audit Assurance core — **CLOSED** (PR #39 merged)
- Issue #31: Backup and recovery integration — **PR #40 open**, CI running
- Issue #32: CLI, dashboard, and MCP surfaces — **PR #41 open**, CI running
- Issue #33: Cross-platform validation and release evidence — **In progress**

## Implementation Scope

### Complete
- [x] Canonical audit-entry serialization (`canonical.py`)
- [x] HKDF-derived Ed25519 signing (`crypto.py`)
- [x] Integrity chain schema and records (`schema.py`, `repository.py`)
- [x] Authenticated checkpoint repository (`checkpoint.py`)
- [x] Protected append and read-only verification (`service.py`)
- [x] Migration anchoring (`migration.py`, `service.py`)
- [x] Master-key rotation segments
- [x] Verification result model with healthy/legacy/incomplete/failed states

### Complete (unmerged)
- [x] `hvbackup-v2` format with integrity evidence (PR #40)
- [x] v2 backup verification with structural/consistency checks (PR #40)
- [x] v1 backup backward compatibility (PR #40)
- [x] Transactional restore with staging and rollback (PR #40)
- [x] CLI: `audit-verify`, `audit-checkpoint`, `audit-export` (PR #41)
- [x] Dashboard: `GET /api/audit-integrity`, `POST /api/audit-integrity/verify` (PR #41)
- [x] MCP: `vault://audit-integrity` resource, integrity in `vault://status` (PR #41)
- [x] Version bump to `0.21.0`
- [x] Changelog, README, and site updates
- [x] Release regression test updates

### Not yet started
- [ ] Adversarial integrity fixtures (30+ corruption scenarios)
- [ ] Full automated operator proof path
- [ ] Real Windows DPAPI validation
- [ ] Packaged-wheel dashboard validation
- [ ] Website deployment (Vercel)
- [ ] GitHub release with annotated tag

## Test Counts

Current: **802 passed, 1 skipped** (post-backup: 809 passed, 1 skipped)
Expected final: ~840+ passed, 1 skipped

## CI Status

- PR #40 (backup): CI in progress
- PR #41 (surfaces): CI in progress
- Post-merge security validation: passing on both branches

## Key Security Boundaries

- Private signing material derived in memory only, never stored or exported
- Integrity-key material never logged, serialized, or environment-placed
- Checkpoint mutation is explicit and operator-only (requires `--yes`)
- Verification is read-only across all surfaces
- Secret Source and MCP credential authority unchanged
- Pre-v0.21 history preserved but not retrospectively protected
- Local integrity verification is not third-party attestation

## Known Limitations

- Adversarial fixture coverage not yet automated
- Real Windows DPAPI validation not yet performed
- Dashboard screenshots not yet captured with fake-data vault
- Website not yet deployed to Vercel production
- Release tag and GitHub release not yet created
