# Hermes Vault v0.24.0 — Release-Readiness Audit

**Auditor**: Hermes Agent (default) — on Arch GEEKOM
**Date**: 2026-08-06
**Candidate**: `release/v0.24.0` (762dc55), descends from `origin/master` (bcb40dd)
**Version**: 0.24.0
**Codename**: Vault Intelligence (line) — Desktop Integration release

## Decision: GO ✓

All release gates pass. 1158 core tests + 14 desktop-plugin tests. Zero P0/P1 findings.

---

## Phase 1 — Git Ancestry

- `release/v0.24.0` built on fresh `origin/master` (bcb40dd, v0.23.2) via cherry-pick of the verified integration chain (7 commits: bridge ×4, adapter+runtime ×2, CSS fix ×1) plus 2 release commits.
- Working tree: clean (except `release-readiness/v0.24.0/` and `.worktrees/` untracked by design).
- No `v0.24*` tags exist.
- The desktop-bridge/adapter/UI work was previously reviewed (Aug 3-4): 106/106 adversarial probes, 11 security findings fixed, no blockers.

## Phase 2 — Version Surfaces

| Surface | Value | Status |
|---------|-------|--------|
| `src/hermes_vault/__init__.py` | 0.24.0 | ✓ |
| `pyproject.toml` | 0.24.0 | ✓ |
| `CHANGELOG.md` | 0.24.0 section | ✓ |
| `README.md` hero + What's New + install | v0.24.0 | ✓ |
| `site/index.html` hero + release card + install | v0.24.0 | ✓ |
| `tests/test_release_regression.py` | 0.24.0 | ✓ |

Zero old-version leakage outside historical CHANGELOG sections (`grep 0.23.2 site/` clean).

## Phase 3 — Quality Gates

| Gate | Result |
|------|--------|
| `pytest tests/` (PYTHONPATH cleared) | 1158 passed, 0 failed (50.6s) |
| `pytest plugins/hermes-vault-desktop/tests/` | 14 passed (10 adapter + 4 runtime) |
| `ruff check .` | All checks passed |
| `mypy src/hermes_vault --python-version=3.11` | Success, no issues in 64 source files |
| `python -m build` | sdist + wheel built (hermes_vault-0.24.0) |
| CI workflow | core + secret-source + **desktop plugin** test lanes |

## Phase 4 — Desktop Integration Evidence

- Bridge CLI smoke against the REAL vault (canonical launcher env, repo 0.24.0 code): all 8 methods (`hello`, `overview`, `credentials`, `leases`, `policy`, `requests`, `audit`, `integrity`) returned `ok: true` with metadata; integrity checkpoint `valid`.
- Production desktop plugin e2e (Arch GEEKOM, Hermes Desktop): authenticated `/api/plugins/hermes-vault-desktop/overview` → HTTP 200, `credential_count: 7`, after restart of the dashboard serve child.
- Canonical-launcher requirement enforced: `BRIDGE_BINARY = "hermes-vault-canonical"` (PATH-resolved). Raw binary returns 423 `MISSING_PASSPHRASE` (verified live before the fix).

## Phase 5 — Security

- Bridge: read-only SQLite (`mode=ro`), no schema init, no audit-run recording, no policy/runtime-dir writes during locked requests, env-only passphrase resolution (never prompts), error redaction (paths/JWTs/bearer/hex), bounded framing, recursion-safe JSON, `NaN`/`Infinity` rejection.
- Adapter: no `hermes_vault` import in the gateway, one child per request, allowlisted child env (`PYTHONPATH`/provider keys excluded), stderr discarded, sanitized error envelopes, fixed GET routes only.
- Fixed during this release: `_ReadOnlyAuditIntegrityService._connection` now matches the parent contextmanager contract (connection leak + mypy override).
- No secrets in repo, docs, or test fixtures (Gitleaks allowlist untouched).

## Phase 6 — Post-Release Verification Plan

1. Tag `v0.24.0` on the release branch (NOT the merge commit); tag push triggers PyPI trusted publishing.
2. PR to master; CI must pass; merge.
3. Verify PyPI `hermes-vault==0.24.0`; verify site auto-deploy (hermesvault.tonysimons.dev).
4. Reinstall local tool from PyPI, restart dashboard serve child, re-verify `/overview` 200 and desktop UI.

---

**Outstanding (non-blocking)**: hermes-vault-security-remediation branch (`pr45`, TOCTOU fix) remains unmerged on a separate worktree — tracked by its own board, not part of this release.
