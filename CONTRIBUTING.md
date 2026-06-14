# Contributing to Hermes Vault

Thanks for helping improve Hermes Vault. This project handles credential material, so contributor workflows need to be boring, local, and explicit.

## Ground rules

- Never commit real tokens, passphrases, vault databases, provider responses, or screenshots that expose credential material.
- Keep tests hermetic. Use temporary `HERMES_VAULT_HOME` directories and fake credentials.
- Route all vault writes through the existing mutation, policy, broker, or CLI layers. Don't add side paths that bypass audit or policy checks.
- Keep the dashboard localhost-only and token-guarded. It is not a remote admin surface.
- Prefer small PRs with focused tests and docs.

## Local development setup

Hermes Vault targets Python 3.11+.

### Option A: uv

```bash
git clone https://github.com/asimons81/hermes-vault.git
cd hermes-vault
uv sync --extra dev
uv run hermes-vault --help
uv run python -m pytest tests/ -q
```

### Option B: venv and editable pip

```bash
git clone https://github.com/asimons81/hermes-vault.git
cd hermes-vault
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
hermes-vault --help
python -m pytest tests/ -q
```

If your shell expands extras differently, use double quotes instead:

```bash
python -m pip install -e ".[dev]"
```

## Safe runtime environment for manual testing

Use a temporary vault home when testing commands that create or mutate vault state:

```bash
export HERMES_VAULT_HOME="$(mktemp -d)"
export HERMES_VAULT_PASSPHRASE="dev-only-passphrase"
hermes-vault list
hermes-vault add openai --alias primary --secret fake-dev-secret
hermes-vault broker env openai --agent hermes --ttl 60
```
The `openai` service and `hermes` agent are both defined in the default generated policy, so the broker command resolves without extra setup. If you add a custom service or use a different agent ID, update the policy first.

Do not point tests or reproductions at a real operator vault such as `~/.hermes/hermes-vault-data` unless the maintainer explicitly asks for an operator-only recovery workflow.

## Test commands

Run the full suite before opening a PR:

```bash
python -m pytest tests/ -q
```

Useful targeted commands:

```bash
python -m pytest tests/test_vault.py tests/test_broker.py -q
python -m pytest tests/test_policy.py tests/test_policy_doctor.py -q
python -m pytest tests/test_mcp_server.py -q
python -m pytest tests/test_dashboard.py -q
python -m pytest tests/test_oauth.py tests/test_oauth_refresh.py -q
```

Packaging smoke check:

```bash
python -m pip install build
python -m build
```
If you use `uv`: `uv run --with build python -m build`.

If you change dashboard assets, confirm the wheel and sdist include `hermes_vault/dashboard_static/`.

## Common contribution paths

| Change type | Start here | Usually update |
|---|---|---|
| Secret detector | `src/hermes_vault/detectors.py` | detector tests, scanner docs |
| Verifier | `src/hermes_vault/verifier.py` | verifier tests, issue labels/docs |
| Policy behavior | `src/hermes_vault/policy.py`, `src/hermes_vault/models.py` | policy tests, operator guide |
| Brokered access | `src/hermes_vault/broker.py`, `src/hermes_vault/mutations.py` | broker/mutation tests, audit tests |
| MCP tool | `src/hermes_vault/mcp_server.py` | MCP tests, `docs/mcp-server.md` |
| CLI command | `src/hermes_vault/cli.py` | CLI tests, README/operator docs |
| Dashboard action | `src/hermes_vault/dashboard.py`, `src/hermes_vault/dashboard_static/` | dashboard tests, screenshots if UI changes |
| OAuth provider/flow | `src/hermes_vault/oauth/` | OAuth tests, threat model notes |

See `docs/contributor-architecture.md` for the contributor-oriented module map and data flows.

## Security-sensitive areas

Ask for maintainer review early when a change touches:

- encryption, key derivation, salts, or backup decryptability
- vault storage schema or migration behavior
- policy enforcement or canonical service resolution
- broker env materialization or raw secret handling
- MCP binding, caller identity, or tool schemas
- OAuth token storage, refresh, provider exchange, or callback handling
- dashboard API serialization or localhost binding
- filesystem path traversal, scanning, import, or restore logic

## PR process

1. Open an issue first for behavioral, security, UX, or architecture changes. Small docs fixes can go straight to a PR.
2. Keep the PR narrow and explain the motivation.
3. Add or update tests for behavior changes.
4. Update docs when commands, policies, public workflows, MCP schemas, dashboard actions, or security boundaries change.
5. Run the full test suite and paste the exact command/output summary in the PR template.
6. Confirm no real secrets are present in tests, docs, logs, screenshots, or fixtures.

Maintainers handle releases, tags, publishing, and deployment. Contributors should not push release tags or publish packages from a PR branch.
