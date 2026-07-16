# Hermes Vault v0.20.0 Readiness Report

- Release: `0.20.0`
- Codename: Hermes Secret Source Plugin
- Release commit: `32ecf03b3a1c946a990bda1d0ae699a2c1bd287a`
- Hardening PR: #22 (squash-merge `034457b` onto master)
- Post-merge validation PR: #27
- Report status: **Ready**

## Scope

v0.20.0 adds a standalone mapped-only Hermes Secret Source plugin and a non-interactive `hermes-vault secret-source fetch` path for startup environment materialization. MCP remains the in-loop agent control plane.

## Release validation recorded at publication

The v0.20.0 changelog records the following maintainer validation:

- focused Secret Source, CLI, broker, config, and redaction suites
- full pytest validation
- upstream Hermes Secret Source conformance
- isolated manual startup smoke cases for missing passphrase, valid mapping, aliases, empty values, policy denial, malformed refs, and closed-stdin behavior

The post-merge validation below adds independent clean-runner evidence rather than treating those publication notes as proof.

## Repository-hardening validation

PR #22 established independent GitHub checks for:

- full tests on Ubuntu and Windows
- Python 3.11 and 3.12
- Secret Source plugin tests
- Ruff static checks
- advisory mypy baseline
- source and wheel builds
- built-wheel CLI smoke test
- dependency vulnerability audit
- full-history secret scanning

### Hardening defects found and resolved

#### Typer 0.27.0 / Click 8.4.2 compatibility

Typer 0.27.0+ vendors an `Exit` class that is not a subclass of `click.exceptions.Exit`. The custom CLI invocation layer now normalizes `typer.Exit` into Click's expected exception while preserving the intended exit code across old and new attribute names.

#### Windows-only test assumptions

- Rich output assertions no longer depend on an 80-column line-wrap boundary.
- Policy normalization uses pytest's platform-neutral `tmp_path` rather than a hardcoded `/tmp` path.

#### Real pywin32 DPAPI contract

Post-merge validation found that the fake DPAPI shim had hidden a production incompatibility. Real pywin32 accepts five positional arguments for `CryptUnprotectData` and returns `(description, plaintext)`. Hermes Vault previously passed six arguments and expected raw bytes.

`src/hermes_vault/dpapi.py` now uses the real pywin32 signature, normalizes the tuple result to bytes, and retains compatibility with raw-byte test doubles. `tests/test_dpapi_pywin32_contract.py` locks the real return shape into the normal suite.

## Final cross-platform CI evidence

Validation commit: `4013dbc09b2b844d7bf59d15e55bb1093ad43ecb`

CI run: `29475535741`

- [x] Ubuntu, Python 3.11
  - Core: 798 passed, 0 failed, 0 skipped
  - Secret Source plugin: 14 passed
- [x] Ubuntu, Python 3.12
  - Core: 798 passed, 0 failed, 0 skipped
  - Secret Source plugin: 14 passed
- [x] Windows, Python 3.11
  - Core: 797 passed, 1 skipped, 0 failed
  - Secret Source plugin: 14 passed
- [x] Windows, Python 3.12
  - Core: 797 passed, 1 skipped, 0 failed
  - Secret Source plugin: 14 passed
- [x] Blocking Ruff checks pass
- [x] Advisory Ruff and mypy reports were captured
- [x] Source distribution and wheel build successfully
- [x] Built wheel installs and `hermes-vault --help` succeeds
- [x] Dependency audit passes
- [x] Full-history Gitleaks scan passes

Advisory engineering debt is tracked separately:

- Ruff/Pyflakes cleanup: #24
- Mypy cleanup: #25

## Post-merge security validation

Security validation run: `29475535772`

### Disposable vault and recovery boundaries

- [x] Fake credentials only
- [x] Disposable vault home
- [x] Lease-required broker access denies before checkout
- [x] Lease checkout returns the expected ephemeral environment
- [x] Mapped Secret Source fetch succeeds
- [x] Malformed references fail closed
- [x] Unknown agents fail closed
- [x] Backup verification succeeds
- [x] Restore dry-run succeeds
- [x] Recovery drill reports healthy
- [x] Validation summary contains no raw fake secret
- [x] Focused security suite: 100 passed, 0 failed, 0 skipped

Evidence artifact: `operator-security-evidence`

### Real Windows DPAPI

Windows Server 2025, Python 3.11, project installed with the `windows` extra:

- [x] pywin32 is available
- [x] DPAPI envelope is created
- [x] Credential decrypts after reopening with a different passphrase
- [x] Plaintext secret is absent from the SQLite database bytes
- [x] Master-key rotation completes
- [x] Credential decrypts after the rotated reopen

Evidence artifact: `real-windows-dpapi-evidence`

### Installed-wheel dashboard boundaries

The built wheel was installed into a clean virtual environment before validation.

- [x] Dashboard binds to `127.0.0.1`
- [x] Non-local binding is rejected
- [x] Missing bearer token receives `401`
- [x] Invalid bearer token receives `401`
- [x] Authorized credential metadata is sanitized
- [x] Raw fake secrets do not appear in the response
- [x] Packaged `index.html`, JavaScript, CSS, and brand image load successfully

Evidence artifact: `packaged-dashboard-evidence`

### Current dashboard screenshots

Playwright launched the real local dashboard with a disposable fake-data vault and captured:

- `hermes-vault-v0.20-overview.png`
- `hermes-vault-v0.20-credentials.png`

The browser asserted that neither fake secret value appeared in rendered page text before capture.

Evidence artifact: `dashboard-screenshot-evidence`

### Upstream Hermes Agent conformance

Hermes Agent source was checked out at:

`2ea39daeb1f675d72e5c21c9400f2d58d7e6d71a`

The official `tests/secret_sources/conformance.py` kit ran against the Hermes Vault plugin using real upstream `agent.secret_sources` modules:

- [x] 10 passed
- [x] 0 failed
- [x] 0 skipped

Evidence artifact: `upstream-hermes-conformance-evidence`

## Security-boundary review

- [x] Secret Source remains startup-only and mapped-only
- [x] `HERMES_VAULT_PASSPHRASE` is protected from overwrite
- [x] Fetch remains non-interactive and uses Hermes `run_secret_cli()` with argv lists, never `shell=True`
- [x] Empty values are omitted
- [x] Partial success returns warnings without hiding usable mappings
- [x] Zero usable secrets returns a structured failure
- [x] Policy denial fails closed
- [x] MCP and Secret Source remain separate authority paths
- [x] Plugin discovery timing and the subsequent-process requirement are documented
- [x] Tests, validation summaries, screenshots, and workflow artifacts use fake material and expose no raw secret values

## Plugin discovery timing

Hermes plugin discovery occurs after the first dotenv load in the process that discovers the plugin. The source is available to subsequently spawned Hermes processes, including later sessions and child processes. The install guide documents this behavior so operators restart or start a subsequent session after first discovery.

## Release decision

**Ready.**

All blocking cross-platform CI checks pass. Real Windows DPAPI, disposable-vault recovery, installed-wheel dashboard boundaries, fake-data screenshot capture, and the current upstream Hermes Secret Source conformance kit have independent evidence. The remaining Ruff and mypy work is explicitly advisory and tracked outside the v0.20.0 release gate.
