# Hermes Vault v0.22.0 Roadmap

**Codename: Vault Intelligence**
**Status:** Draft — pending approval
**Date:** 2026-07-24

## Release Thesis

Hermes Vault already stores secrets safely. v0.21.0 proved they haven't been tampered with. v0.22.0 makes the vault *active* — it knows credential health, flags problems before they cause outages, and gives operators the tools to clean up fast.

This is the release where `hermes-vault verify --all` actually works across all 45+ services, bulk operations become first-class, and the dashboard stops being a status screen and becomes a command center.

---

## Baseline

- **Version:** v0.21.0 on `master` (893 tests, all CI green)
- **PR #47 merged:** 4 critical/high fixes (recover_checkpoint, MCP secret masking, 21 service IDs, policy capabilities)
- **Open PRs:** #45 (TOCTOU race fix — external contributor), #44 (docs verification record)
- **Credentials in Tony's vault:** 162, 142 never verified, 20 stale (>30d)
- **Verification coverage:** 6 of 45 services have built-in verifiers (openai, anthropic, evolink, minimax, github, supabase)
- **Tags:** Schema exists (`tags TEXT NOT NULL DEFAULT '[]'`), zero usage in CLI/dashboard
- **Dashboard:** Functional but basic — tables, no search, no bulk actions, no filtering beyond CLI verbatim
- **Installed binary:** Stale (v0.21.0 under jefferson user's uv tools, passphrase mismatch with tony's vault)

---

## Phase 1 — Universal Credential Verification (4-6 hours)

### 1.1 Generic HTTP verifier via YAML config

Add a file-based verifier config system so adding a new provider takes 4 lines of YAML instead of 30 lines of Python.

```yaml
# ~/.hermes/hermes-vault-data/verifiers/deepseek.yaml
service: deepseek
url: https://api.deepseek.com/v1/models
headers:
  Authorization: "Bearer {secret}"
method: GET
success_statuses: [200]
invalid_statuses: [401, 403]
```

Changes:
- New `VerifierRegistry` that loads YAML configs from `verifiers/` directory
- New `_HttpVerifierPlugin` that drives the generic path
- `hermes-vault verify` CLI picks up file verifiers alongside built-in plugins

### 1.2 Ship verifier configs for all 45+ service IDs

One YAML file per service. Generated, not hand-written — pull from known API docs. Ship with the package.

### 1.3 Verification telemetry

Record verification timestamp + result in the vault DB. Expose:
- `hermes-vault health` shows verification coverage %
- `hermes-vault list --unverified` filters to never-verified creds
- Dashboard "Credential Health" card with red/yellow/green

---

## Phase 2 — Bulk Operations (3-4 hours)

### 2.1 Import from CSV/JSON/.env

```
hermes-vault import --input creds.csv --service-column provider --secret-column key
hermes-vault import --input .env --auto-detect
hermes-vault import --input export.json
```

Dry-run mode shows what would be added without committing. Handles duplicates, aliases, tag assignment.

### 2.2 Export filtered credentials

```
hermes-vault export --service openai --format json > openai-backup.json
hermes-vault export --tag production --format env > prod.env
hermes-vault export --unverified --format csv > stale.csv
```

### 2.3 Bulk tag management

```
hermes-vault tag --service openai --add production,primary
hermes-vault tag --unverified --add needs-review
hermes-vault tag --all --remove deprecated
```

### 2.4 Tag-based search and filter

```
hermes-vault list --tag production --format table
hermes-vault list --tag needs-review --unverified
```

Dashboard gets a tag filter bar and tag cloud.

---

## Phase 3 — Credential Health Automation (2-3 hours)

### 3.1 Auto-verification scheduling

```
hermes-vault schedule-verify --every 24h
hermes-vault schedule-verify --services openai,anthropic --every 6h
```

Backed by a systemd timer or cron. Verification failures surface in `hermes-vault health`.

### 3.2 Expiry tracking and alerts

Parse expiry from credential metadata (JWT `exp`, OAuth `expires_in`). Flag upcoming expirations in:
- `hermes-vault health`
- Dashboard warning banner
- MCP `vault://status`

### 3.3 Health dashboard v2

Redesigned dashboard landing page:
- Overall health score (A-F)
- Verification coverage %
- Stale credentials count
- Upcoming expirations
- Recent verification failures
- Tag distribution

---

## Phase 4 — Polish & Ecosystem (2-3 hours)

### 4.1 Shell tab completion

```
hermes-vault --install-completion bash
hermes-vault --install-completion zsh
hermes-vault --install-completion fish
```

Typer supports this natively. Just needs packaging.

### 4.2 Service catalog

`hermes-vault catalog` — lists all 45 canonical services with:
- Description (one-liner)
- Env var name
- Verification status (supported/unsupported)
- Usage count in local vault

### 4.3 Dashboard UX refresh

- Real-time search across all tables
- Sortable columns (name, service, age, status)
- Bulk select + action (tag, verify, export)
- Dark/light theme persistence
- Responsive: looks good at 900px and 1920px

### 4.4 Land external PR #45

Review, test, and merge the TOCTOU race fix from @doronkatz:
- Close race in `ensure_initialized`
- Roll back credential on audit chain failure

### 4.5 Remaining Phase 3 items from v0.21 review

- Fix `audit checkpoint recover` doc (--reason mismatch)
- Resolve ambiguous `hermes-vault` skill names
- Set up weekly backup cron

---

## Phase 5 — Operator Experience (1-2 hours)

### 5.1 Quick-start wizard

```
hermes-vault setup
```
Walks a new operator through:
1. Create vault + passphrase
2. Import from .env
3. Bootstrap policy
4. Schedule verification
5. Enable Secret Source / MCP

### 5.2 Release readiness

- Version bump to 0.22.0
- CHANGELOG
- Release-readiness report
- Dashboard screenshots (fake data)
- Updated README + operator guide
- Tag + publish to PyPI

---

## Non-Goals (explicit)

- Multi-vault sync (too big, needs design review)
- Remote access / cloud vault
- Third-party SIEM/webhook integrations (Phase 3 covers local only)
- Raw secret viewing in dashboard (policy boundary — never)
- New MCP credential authority paths

---

## Dependency Order

1. **Phase 1** — Generic verifier blocks Phase 3 health, unblocks Phase 5 setup wizard
2. **Phase 4.4** — Land TOCTOU PR first (external, don't bitrot)
3. **Phase 2** — Bulk ops independent of verifier, can parallelize
4. **Phase 3** — Depends on Phase 1 verification coverage
5. **Phase 4** — Independent polish, parallelizable
6. **Phase 5** — Last, depends on all above

---

## Test Plan

- Verifier YAML loading + HTTP mocks for all 45 services
- Import/export round-trip (CSV, JSON, .env)
- Bulk tag idempotency and edge cases
- Dashboard search + sort + bulk actions (Playwright)
- Shell completion file generation + smoke
- Full CI matrix (ubuntu + windows, 3.11 + 3.12)

---

## Effort Estimate

| Phase | Items | Est. Hours |
|-------|-------|-----------|
| 1 — Universal Verification | Generic verifier + 45 configs + telemetry | 4-6 |
| 2 — Bulk Operations | Import/export/tags/search | 3-4 |
| 3 — Health Automation | Scheduling + expiry + dashboard v2 | 2-3 |
| 4 — Polish & Ecosystem | Completion + catalog + dashboard + PR #45 | 2-3 |
| 5 — Operator Experience | Setup wizard + release | 1-2 |
| **Total** | | **12-18** |

---

## Acceptance Criteria

- `hermes-vault verify --all` succeeds for 40+ of 45 services with valid test keys
- `hermes-vault import creds.csv --dry-run` previews without committing
- `hermes-vault export --tag production --format env` produces valid env file
- `hermes-vault tag --service openai --add production` idempotent
- `hermes-vault list --tag needs-review` filters correctly
- `hermes-vault health` shows verification coverage %, stale count, upcoming expirations
- Dashboard loads at <1s, search filters all tables, bulk tag works
- `hermes-vault --install-completion bash` generates valid completion script
- `hermes-vault catalog` lists all 45 services with one-liner descriptions
- PR #45 merged, all tests pass
- Full CI green on ubuntu + windows, Python 3.11 + 3.12
- 1000+ tests
