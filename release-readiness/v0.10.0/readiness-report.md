# Hermes Vault v0.10.0 Release Readiness Report

Scope: documentation and version-surface updates only, with release proof gathered from the current `v010/ready` worktree.

## What changed

- `pyproject.toml`, `src/hermes_vault/__init__.py`, and `src/hermes_vault/mcp_server.py` now report `0.10.0`.
- `README.md` now calls out unattended OAuth refresh and generic custom verifiers in a new v0.10.0 section.
- `CHANGELOG.md` now has a `0.10.0` release entry and a future-facing `Unreleased` note.
- `docs/operator-guide.md` now explains unattended OAuth refresh, `rotate` permission, and the browser-based initial login boundary.
- `docs/threat-model.md` now reflects the current unattended renewal path while keeping the browserless initial-login gap explicit.
- `docs/mcp-server.md` now documents `oauth_refresh` as `rotate`-gated.

## Validation

- `git diff --check` - PASS
- `python -m pytest tests/ -x -q` - PASS, 585 passed, 2 warnings
- `python -m build --outdir /tmp/hermes-vault-build` - PASS, wheel and sdist built
- Wheel smoke in a clean venv - PASS, installed `/tmp/hermes-vault-build/hermes_vault-0.10.0-py3-none-any.whl` and `hermes-vault --help` worked
- Sdist smoke in a clean venv - PASS, installed `/tmp/hermes-vault-build/hermes_vault-0.10.0.tar.gz` and `hermes-vault --help` worked
- Secret scan on code surfaces (`src/hermes_vault`, `tests`, `data`, `pyproject.toml`) - PASS for secret-related findings, with only `insecure_permissions` noise and zero `plaintext_secret` or `duplicate_secret` findings

## Build artifacts

- Wheel: `/tmp/hermes-vault-build/hermes_vault-0.10.0-py3-none-any.whl`
- Sdist: `/tmp/hermes-vault-build/hermes_vault-0.10.0.tar.gz`

## Notes

The repository still emits permission-noise findings when scanned broadly because the scanner treats world-readable source and doc files as insecure by default. That noise did not include any plaintext secrets or duplicate secrets in the touched surfaces.
