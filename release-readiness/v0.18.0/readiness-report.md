# Hermes Vault v0.18.0 Readiness Report

## Release

- Version: `0.18.0`
- Codename: Operator Workflow Convergence
- Site target: `hermesvault.tonysimons.dev`

## Implemented Scope

- Dashboard Onboarding Preview for dry-run, redacted env import planning.
- Dashboard Recovery Hub backup diff alongside verify and restore dry-run.
- Searchable and sortable credential, lease, and audit dashboard views.
- MCP `vault://status` read-only resource.
- Bug fixes for dashboard lease metrics, exhaustive key validation, stale dashboard copy, and OAuth login state collisions.

## Verification Checklist

- [x] Focused dashboard/MCP tests pass.
- [x] Full test suite passes.
- [x] Browser QA passes on desktop and mobile dashboard viewports.
- [x] Public site copy reflects v0.18.0.
- [x] `hermesvault.tonysimons.dev` returns HTTP 200 with v0.18.0 release copy.

## Publish Notes

Deploy the static site after the release is ready:

```bash
scripts/deploy-hermesvault-site.sh
```

The deploy script checks the Vercel project link and aliases the immutable deployment to `hermesvault.tonysimons.dev`.
