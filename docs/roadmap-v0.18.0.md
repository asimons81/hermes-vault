# Hermes Vault v0.18.0 Roadmap

- **Release**: v0.18.0 -- Operator Workflow Convergence
- **Status**: Implemented release scope
- **Date**: 2026-07-03

## Summary

v0.18.0 turns existing Hermes Vault capabilities into clearer operator workflows. The release keeps the dashboard local and bounded while adding dry-run onboarding preview, recovery diff drills, searchable inventory views, and a consolidated MCP status resource.

## Key Changes

- Dashboard fixes: lease metric rendering, all-record key validation, current operational copy, and safer MCP OAuth browser login state.
- Dashboard Onboarding Preview: redacted `bootstrap --dry-run` style import preview, policy doctor summary, skill next step, and MCP config snippet.
- Dashboard Recovery Hub: backup verification, restore dry-run, and metadata-only diff from one local panel.
- Dashboard usability: client-side search, status filters, and sorting for credentials, leases, and audit entries.
- MCP `vault://status`: policy-scoped health, lease, backup, policy, profile, and safe next-step metadata.

## Test Plan

- Targeted dashboard/MCP regression suite.
- Full test suite with UTF-8 output and banner suppression on Windows.
- Dashboard browser QA at desktop and mobile widths for overview, onboarding, operations/recovery, and dense table filters.

## Assumptions

- Dashboard remains local-only and token-guarded.
- Browser actions remain metadata-only, dry-run, or bounded checks; live credential import, policy editing, destructive restore, and raw secret display stay CLI-only or out of scope.
- No database schema migration is required.
