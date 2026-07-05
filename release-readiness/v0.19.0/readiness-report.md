# Hermes Vault v0.19.0 Readiness Report

- Release: `0.19.0`
- Codename: Agent Control Plane
- Date: 2026-07-05
- Status: Ready after local validation

## Scope

v0.19.0 turns Hermes Vault into a local-first agent access control plane:

- Explainable policy through CLI, dashboard, and MCP.
- Lease-enforced env materialization with optional purpose requirements.
- Durable access requests with approve/deny lifecycle and optional lease issuance.
- Redacted agent-context manifests.
- Recovery drills and incident bundles.
- Dashboard Command Center for agent context, policy explain, access requests, approvals, and recovery drills.
- MCP control-plane tools and resources.
- Version, README, changelog, docs, site, policy example, and release regression alignment.

## Validation

- Focused suite: `uv run python -m pytest tests/test_policy.py tests/test_broker.py tests/test_cli.py tests/test_mcp_server.py tests/test_dashboard.py tests/test_release_regression.py -q --tb=short`
  - Result: `302 passed`
- Full suite: `uv run python -m pytest tests/ -q --tb=short`
  - Result: `789 passed, 1 skipped`
- Build: `uv run --with build python -m build`
  - Result: built `hermes_vault-0.19.0.tar.gz` and `hermes_vault-0.19.0-py3-none-any.whl`
- CLI Windows help regression:
  - Command: `uv run hermes-vault add --help`
  - Result: exits cleanly and renders ASCII service-normalization help.
- Dashboard browser QA:
  - Runtime: disposable fake vault under `work/qa-dashboard`
  - URL: `http://127.0.0.1:9876/?token=<redacted>&no_intro=1`
  - Interactions: Command Center navigation, agent context load, policy explain, access request creation, recovery drill.
  - Screenshots: `release-readiness/v0.19.0/screenshots/dashboard-command-desktop.png`, `release-readiness/v0.19.0/screenshots/dashboard-command-mobile.png`
  - Result: no console errors or page errors; mobile panel width issue fixed with `min-width: 0` on panels.

## Security Boundary

- No raw secrets, OAuth tokens, provider responses, encrypted payloads, vault databases, or salt files are included in dashboard resources, MCP passive resources, agent context, recovery drill summaries, or incident bundles.
- `lease_checkout` remains an access-materialization tool and routes through the broker.
- Dashboard remains localhost-only and token-guarded.
- Access requests are metadata records; request creation does not grant access.

## Release Notes

- `pyproject.toml`, `src/hermes_vault/__init__.py`, MCP server metadata, and `uv.lock` report `0.19.0`.
- Public README and site install snippets target `git@v0.19.0`.
- `policy.example.yaml` is ASCII and includes v0.19 lease fields.
- `maintain --print-schedule` is available; `--print-systemd` remains a compatibility alias.
