# Hermes Vault v0.20.0 Readiness Report

- Release: `0.20.0`
- Codename: Hermes Secret Source Plugin
- Release commit: `32ecf03b3a1c946a990bda1d0ae699a2c1bd287a`
- Hardening PR: #22 (squash-merge `034457b` onto master)
- Report status: All blocking CI checks pass — awaiting security manual checks

## Scope

v0.20.0 adds a standalone mapped-only Hermes Secret Source plugin and a non-interactive `hermes-vault secret-source fetch` path for startup environment materialization. MCP remains the in-loop agent control plane.

## Release validation recorded at publication

The v0.20.0 changelog records the following maintainer validation:

- focused Secret Source, CLI, broker, config, and redaction suites
- full pytest validation
- upstream Hermes Secret Source conformance
- isolated manual startup smoke cases for missing passphrase, valid mapping, aliases, empty values, policy denial, malformed refs, and closed-stdin behavior

This report does not convert those notes into independent proof. Exact counts and fresh results must be added from a clean checkout.

## Repository-hardening validation

The `chore/repo-hardening` branch adds independent GitHub checks for:

- full tests on Ubuntu and Windows
- Python 3.11 and 3.12
- Secret Source plugin tests
- Ruff static checks
- advisory mypy baseline
- source and wheel builds
- built-wheel CLI smoke test
- dependency vulnerability audit
- full-history secret scanning

### Results

#### Windows test fixes

Two pre-existing Windows-only failures were fixed in this PR:

1. **`test_import_from_env_redact_source_only_imported_lines`** — Rich's
   Console wraps output at 80 columns on non-TTY output. The long Windows
   `tmp_path` pushed the tail of the output line across a word-wrap
   boundary, so the substring `"1 skipped line"` spanned a newline.
   Changed assertion to `"1 skipped"` which is immune to line-wrapping.

2. **`test_v2_policy_normalizes_service_names`** — Used hardcoded
   `Path("/tmp/_test_v2_norm.yaml")` which resolves to a relative path on
   Windows. Changed to use `tmp_path` (pytest fixture) for a platform-
   appropriate temp directory.

Reference: commit `70a9d44` of `chore/repo-hardening` branch.

Typer 0.27.0+ vendored its own `Exit` exception class
(`typer._click.exceptions.Exit` with attribute `.exit_code`) that is NOT a
subclass of `click.exceptions.Exit` (which uses `.exit_code` in click 8.4.2 but
`.code` in older click). Click's `main()` catches `click.exceptions.Exit` but
cannot catch the vendored sibling class, so the exception propagates uncaught
through Click's handler chain. The CliRunner then intercepts it as a generic
`Exception` and sets `exit_code=1` regardless of the intended exit code.

**Fix:** Added a `typer.Exit` normalization handler in `HermesGroup.invoke()`
(`src/hermes_vault/cli.py:171-183`) that catches the exception, reads the exit
code from whichever attribute the installed version provides (`.exit_code` or
`.code`), and re-raises as `click.exceptions.Exit` so Click's standard handler
chain processes it correctly. This works with all typer versions (>=0.12.0) and
click 8.x.

Reference: commit `HEAD` of `chore/repo-hardening` branch.

- [x] Linux tests pass on Python 3.11  
  CI run: `29471789038`  
  Core: 797 passed, 0 failed in 48.25s  
  Secret Source plugin: 14 passed  
  ✅
- [x] Linux tests pass on Python 3.12  
  Core: 797 passed, 0 failed in 50.83s  
  Secret Source plugin: 14 passed  
  ✅
- [x] Windows tests pass on Python 3.11  
  Core: 796 passed, 1 skipped (DPAPI symlink), 0 failed in 7m 58s  
  Secret Source plugin: 14 passed  
  ✅
- [x] Windows tests pass on Python 3.12  
  Core: 796 passed, 1 skipped (DPAPI symlink), 0 failed in 3m 42s  
  Secret Source plugin: 14 passed  
  ✅
- [x] Ruff passes  
  `ruff check . --output-format=concise` → "All checks passed!"
- [x] mypy findings reviewed and triaged  
  60 errors across 14 files — pre-existing baseline unchanged. No new errors
  introduced by this fix. Advisory only (non-blocking).
- [x] sdist and wheel build successfully  
  `python -m build` → `hermes_vault-0.20.0.tar.gz` and `hermes_vault-0.20.0-py3-none-any.whl`
- [x] built wheel installs and `hermes-vault --help` succeeds  
  Validated via CI `Build and install package` job (artifacts pass smoke test)
- [x] dependency audit passes or findings are documented  
  All identified CVEs are in transitive dev/optional dependencies (pillow, nltk,
  starlette, python-multipart, httplib2, msgpack, pynacl, pip, setuptools) --
  nothing in hermes-vault's declared runtime deps. Project deps:
  cryptography, mcp, pydantic, PyYAML, rich, typer, pathspec, requests.
- [x] Gitleaks passes or findings are documented as verified test fixtures  
  CI: full-history scan passed on run `29471789038` (Secret scan job: success)

## Security-boundary review

- [ ] Secret Source remains startup-only and mapped-only
- [ ] `HERMES_VAULT_PASSPHRASE` cannot be overwritten
- [ ] fetch remains non-interactive and never uses `shell=True`
- [ ] empty values are omitted
- [ ] partial success returns warnings without hiding skipped mappings
- [ ] zero usable secrets returns a structured failure
- [ ] policy denial fails closed
- [ ] MCP and Secret Source remain separate authority paths
- [ ] logs, errors, tests, docs, and workflow artifacts contain no real secret material

## Manual checks still required

- [ ] Run a clean Windows checkout with DPAPI extras installed
- [ ] Exercise a disposable vault through add, broker env, Secret Source fetch, backup, verify, restore dry-run, and recovery drill
- [ ] Confirm dashboard localhost binding and token rejection behavior
- [ ] Confirm packaged dashboard static assets load from the built wheel
- [ ] Run upstream Hermes conformance against the current Hermes Agent package rather than only the local compatibility fixture
- [ ] Capture current v0.20.0 dashboard screenshots using fake credentials

## Release decision

Do not mark this report `Ready` until blocking GitHub checks pass and the manual security-sensitive checks above have been recorded with exact commands and outcomes.
