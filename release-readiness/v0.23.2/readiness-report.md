# Hermes Vault v0.23.2 — Release Readiness Report

Date: 2026-08-01
Prepared by: Hermes (kanban task t_e5992bea)
Release: v0.23.2 "Patch: audit chain wedge + export fail-closed"
Base: master @ 73e9ceb (v0.23.1 merge)

## What ships

- **HIGH fix — audit chain wedge.** Six CLI write paths (`set-expiry`, `clear-expiry`,
  `backup-verify`, `restore --dry-run`, `rotate-master-key` pre-rotation logger,
  `recovery drill`) constructed `AuditLogger(settings.db_path)` without
  `master_key`, so their audit rows went in via the legacy unprotected INSERT
  branch. The next integrity-protected append raised
  `AuditIntegrityError: An audit row is not protected by an integrity record`,
  wedging the whole chain (delete/add/lease/request all crash). All six sites
  now pass `master_key=vault.key`, matching `build_services`.
- **MEDIUM fix — export fail-closed.** `export --with-secrets` with a wrong
  passphrase previously exited 0 and emitted `"secret": null` for every
  credential (decrypt exceptions swallowed in import_export.py). It now fails
  with a clear error, no output file content, and exit code 1.

## Quality gates

| Gate | Result |
|---|---|
| Full test suite | **905 passed in ~42s** (898 prior + 7 new regression tests) |
| Plugin tests | 14 passed |
| Ruff | All checks passed (src/ + tests/) |
| Mypy | Success: no issues in 61 source files |
| Build | `hermes_vault-0.23.2.tar.gz` + `hermes_vault-0.23.2-py3-none-any.whl` built clean |
| Clean-venv wheel smoke | Installed wheel in fresh venv; full repro sequence passed (see below) |

## Regression tests (tests/test_audit_chain_regression.py)

Each of the six commands is exercised against the smoke-test sequence:
seed the chain with a protected `hermes-vault add`, run the command, assert
`audit-verify --format json` returns `status: healthy`, then assert a
subsequent `delete --yes` mutation succeeds. Verified these tests FAIL on the
pre-fix code (`missing_integrity_record`, exit 3) and PASS with the fix.
Export test asserts wrong-passphrase `--with-secrets` raises ValueError for
both json and env formats and that the correct passphrase still exports the
real secret.

## Clean-venv wheel smoke (installed 0.23.2 wheel)

1. `add openai --secret sk-fake-0232` → chain init OK
2. `set-expiry openai --days 30` → exit 0, row protected
3. `audit-verify --format json` → **status: healthy**
4. `clear-expiry openai`, `backup-verify --input backup.json`,
   `restore --input backup.json --dry-run`, `recovery drill --backup backup.json`
   → all exit 0
5. `rotate-master-key` (old→new passphrase) → success, audit-verify healthy
6. `delete openai --yes` → succeeds (mutation after all six, no wedge)
7. `export --with-secrets` with wrong passphrase → exit 1,
   `Failed to decrypt secret for github/default (InvalidTag). Export --with-secrets requires the correct vault passphrase; no secret was exported.`
8. `export --with-secrets` with correct passphrase → real secret present

## Version surfaces

pyproject.toml 0.23.2, `__init__.py` 0.23.2, README header/What's New/install pins,
site/index.html eyebrow/release card/install code, tests/test_release_regression.py
assertions, CHANGELOG 0.23.2 section. No stray 0.23.1 refs outside historical
CHANGELOG/README context.

## Rollback

Tag on feature-branch head per repo workflow; master advances by squash merge
(PR). v0.23.1 tag and PyPI release remain untouched; 0.23.2 is a pure
bug-fix patch with no schema/API changes, so downgrade is safe (no migration
steps).
