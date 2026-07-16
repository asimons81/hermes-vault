# Hermes Vault v0.20.0 Readiness Report

- Release: `0.20.0`
- Codename: Hermes Secret Source Plugin
- Release commit: `32ecf03b3a1c946a990bda1d0ae699a2c1bd287a`
- Report status: Pending independent CI validation

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

- [ ] Linux tests pass on Python 3.11
- [ ] Linux tests pass on Python 3.12
- [ ] Windows tests pass on Python 3.11
- [ ] Windows tests pass on Python 3.12
- [ ] Ruff passes
- [ ] mypy findings reviewed and triaged
- [ ] sdist and wheel build successfully
- [ ] built wheel installs and `hermes-vault --help` succeeds
- [ ] dependency audit passes or findings are documented
- [ ] Gitleaks passes or findings are documented as verified test fixtures

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
