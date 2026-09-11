# v0.23.1 — Patch: mcp SDK cap

Patch release fixing the PyPI artifact for the mcp SDK constraint. 0.23.0 shipped with an unbounded `mcp>=1.0.0`; mcp 2.0.0 removed `Server.list_tools`, which broke `import hermes_vault.mcp_server` on fresh pip installs. This release pins `mcp>=1.0.0,<2.0.0` so pip resolves a working SDK.

## Fixed

- **Cap mcp SDK below 2.0**: pin `mcp>=1.0.0,<2.0.0` in runtime and dev dependencies. mcp 2.0.0 removed `Server.list_tools`, which broke `import hermes_vault.mcp_server` (line 853, `@server.list_tools()`) on fresh pip installs of 0.23.0.

## Upgrade notes

- No upgrade or migration steps required. Users on 0.23.0 should reinstall as 0.23.1 (`uv tool install hermes-vault==0.23.1` or reinstall the git URL) so pip resolves mcp < 2.0.0.

## Validation

- 898 tests passed
- ruff clean
- mypy clean (61 files)
- wheel + sdist build OK
- fresh venv install resolves mcp 1.29.0; `import hermes_vault.mcp_server` OK
