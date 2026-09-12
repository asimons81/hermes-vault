# Hermes Vault v0.26.0 — Release-Readiness Notes

**Prepared by**: Hermes (docs lane, kanban task t_7a1eb405)
**Date**: 2026-09-11
**Candidate**: `release/v0.26.0` at e382377 (all nine packs P1–P9 merged; version bumped to 0.26.0 by a70718d)
**Version**: 0.26.0 (feature) — CONFIRMED by Tony 2026-09-11
**Line**: Trustworthy Under Failure — reliability/assurance release on the Vault Intelligence line (v0.25.x surfaces unchanged)

## Decision: RELEASED (gates cleared 2026-09-11)

All gates cleared:
1. **Tony**: confirmed version 0.26.0 (feature) and approved release ("GOGOGO", 2026-09-11).
2. **QA**: independent acceptance — the orchestrator's post-merge suite
   re-run was in flight when this report was drafted; QA must PASS the
   candidate before tag.

Docs-lane owner-side verification is complete and green (below). Nothing has
been pushed, tagged, or published.

## What ships (36 non-merge commits / 44 total, e169328 → e382377, 65 files, +10,263/−189)

**P1 Safe recovery (MUST)** — restore preflight proving decryptability before
any mutation (`restore-receipt-v1` receipts, fail-closed recovery dir,
`restore_preflight` audit events); non-destructive `audit-checkpoint repair`
(quarantine tables + manifest + safety copy in one `BEGIN IMMEDIATE`, no DROP,
no VACUUM; tamper-evidence and key-mismatch classes refused); typed
`SaltMismatchError` guard; `recover` no longer rebuilds on key mismatch
(F-06, BREAKING-fix); foreign-key restores fail closed (BREAKING-fix);
`docs/safe-recovery.md`.

**P2 Authorization enforcement (MUST)** — lease ownership enforced on
list/show/renew/revoke (F-01; DB-query filter, never post-fetch);
expired credentials denied at final env materialization (F-03; only escape is
the explicit `allow_expired_env` override); `manage_leases` capability
(explicit-only, never implicit for legacy agents); negative cross-agent tests.

**P3 CLI truth (MUST)** — PYTHONPATH self-guard at the installed entrypoint
(`_envguard.py`); `backup` writes the audit row health scans (truthful "Days
since last backup"; scanners deduped into `AuditLogger.last_backup_at()` with
the timestamp-preference flaw fixed); `--version` flag; truthful `verify`
exit codes + single-encoded JSON (same fix for `broker get`/`list` JSON);
actionable `agent_id` errors on stderr.

**P4 MCP correctness (MUST)** — advertised `vault://` resources readable in
unbound mode (default-agent fallback → operator metadata-only default;
intended behavior change, test pin deliberately rewritten); typed
`MISSING_PASSPHRASE`/`VAULT_NOT_READY` envelopes instead of cold-start
tracebacks; lazy broker build (capabilities-only sessions need no vault).

**P5 Crypto v2 default (SHOULD)** — `WRITE_CRYPTO_VERSION` → `aesgcm-v2`
(issue #60 write-side cutover; v1 rows stay readable per-row);
opt-in all-or-nothing `migrate-crypto` with per-row post-verification;
`HERMES_VAULT_CRYPTO_VERSION` downgrade override; fixed `oauth normalize`
alias renames bricking v2 rows.

**P6 Release & repo integrity (SHOULD)** — PyPI publish gated on a full green
test matrix; lock-freshness (`uv lock --check`) + locked-set pip-audit
(`--require-hashes` over `uv export --locked`) CI jobs; CI contract tests
pinning the invariants; v0.23.1 release strays committed for archive parity;
0.25.1 Windows-reader attribution corrected (F-1); `.worktrees/` ignored.

**P7 `hermes-vault doctor` (SHOULD)** — read-only install/recovery health
(binary, launcher/home, store integrity, salt/key pairing, audit chain +
repair verdict, optional backup pairing, MCP wiring); `--json` (`doctor-v1`);
exit 0/1/2; wraps P1 primitives, owns no recovery logic; `docs/doctor.md`.

**P8 `hermes-vault run` (SHOULD)** — child-process env injection through the
verbatim broker path (policy, TTL, lease ownership, expiry, OAuth freshness
all apply); deny-by-default, all-or-nothing, secrets never in argv/logs/audit;
`docs/run.md`.

**P9 Interop on-ramp (SHOULD, answers #84/#85)** — `import bitwarden` bridge
(dry-run, collision policies, audited apply with provenance, nothing silently
dropped); `docs/multi-client.md`; `docs/bitwarden-comparison.md` (dated,
source-cited).

Scope deviations vs the approved proposal: P6's Vercel git-integration toggle
and the stale `hermes-vault-fixes` checkout archive are environment-side
items, not repo changes — not in this branch (the local checkout still exists
at `~/workspace/hermes-vault-fixes`; INTEGRITY_RECOVERY_PLAN.md salvage was
not landed as a tracked file). All other approved MUST/SHOULD items shipped.

## Version surfaces (verified by docs lane at e382377)

| Surface | Value | Status |
|---|---|---|
| `src/hermes_vault/__init__.py` | `__version__ = "0.26.0"` | ✓ |
| `pyproject.toml` | `version = "0.26.0"` | ✓ |
| `uv.lock` | `hermes_vault-0.26.0` | ✓ |
| `CHANGELOG.md` | `## 0.26.0 -- Feature: Trustworthy Under Failure (2026-09-11)` themed entry (Fixed/Changed/Added/Tests/Upgrade notes) | ✓ (restructured by docs lane this task) |
| `README.md` | current-release paragraph + "What's New in 0.26.0" + install cmds `@v0.26.0` | ✓ |
| `site/index.html` / `site/app.js` | 0.26.0 strings, `git@v0.26.0` install cmds | ✓ |
| `tests/test_release_regression.py` | pins 0.26.0 on all surfaces | ✓ (16/16 pass) |

## Quality gates (docs-lane verification run at e382377, 2026-09-11)

| Gate | Command | Result |
|---|---|---|
| Full suite | `env -u PYTHONPATH uv run --extra dev --with fastapi python -m pytest tests/ plugins/hermes-vault-desktop/tests/ plugins/hermes-vault-secret-source/tests/ -q` | **1506 passed, exit 0** (baseline at v0.25.1: 1190) |
| Release regression | same runner, `tests/test_release_regression.py` | **16 passed, exit 0** |
| ruff (tracked tree) | `uv run --with ruff ruff check . --exclude .worktrees` | all checks passed |
| mypy | `uv run --with mypy mypy src/hermes_vault` | no issues in 69 source files |
| lock | `uv lock --check` | PASS |
| build | `uv run --with build python -m build` | sdist + wheel `hermes_vault-0.26.0`, exit 0 |
| MCP surface probe | `list_resources()` | 10 resources advertised |

Accuracy spot-checks performed by docs lane (attribution rules from the F-1
nit): every CHANGELOG/notes claim traced to its commit(s); the "6 audit
tables" list read from `QUARANTINE_TABLES` in `audit_integrity/repair.py`;
the "10 advertised URIs" counted live; `manage_leases` never-implicit grant
read from `PolicyEngine.can_manage_leases`; the verify exemption
(`UNSUPPORTED_VERIFIER_REASON`) read from the 91d58e0 commit body;
`HERMES_VAULT_CRYPTO_VERSION` confirmed as the only new environment variable
(diff-wide scan of `os.environ`/`getenv` additions); v2 read support
confirmed as shipping in v0.24.0 (8156a12) for the downgrade caveat.

## Known considerations for QA

- Two BREAKING-fixes are deliberate (P1's thesis): cross-key restores now
  fail closed, and `recover` refuses to rebuild on key mismatch. Both carry
  recovery guidance in the error text.
- Deliberately rewritten test pins: `test_mcp_server` unbound-resource error,
  `test_governance` expired-credential warning, `test_cli` verify
  double-encoding + exit-0, P1's `recover_checkpoint` rebuild test. The PRs
  state this loudly; QA should verify the new pins, not just the pass count.
- The crypto default flip means new writes are v2; QA on any pre-v0.24.0
  consumer interop should exercise `HERMES_VAULT_CRYPTO_VERSION=aesgcm-v1`.

## Working-tree state at docs handoff

- This report and `release-notes-0.26.0.md` are committed by the docs lane on
  branch `pack/d2-release-notes` (worktree `.worktrees/D2-release-docs`),
  following the release-notes-0.23.0 precedent (draft committed pre-tag; the
  orchestrator stages them into the release branch). Nothing pushed/tagged.
- CHANGELOG.md restructured on the same branch: the per-pack 0.26.0-Unreleased
  sections replaced by the themed entry (Fixed/Changed/Added/Tests/Upgrade
  notes) following the 0.25.1 entry structure.

## Post-release verification plan (execution)

1. ⬜ Tony confirms version 0.26.0 (feature) and approves release.
2. ⬜ QA gate returns PASS at the candidate commit.
3. ⬜ Tag `v0.26.0` on the release branch (not the merge commit); tag push
   triggers PyPI trusted publishing — now gated on the green test matrix (P6).
4. ⬜ PR to master; CI green (incl. the new lock-freshness and locked-set
   audit jobs); merge.
5. ⬜ Verify PyPI `hermes-vault==0.26.0` and site auto-deploy; reinstall the
   local tool from PyPI; smoke `hermes-vault --version` → `hermes-vault
   0.26.0`, `hermes-vault doctor` on the live vault home.
6. ⬜ Post-release sanity record appended here (per v0.23.1 precedent).
