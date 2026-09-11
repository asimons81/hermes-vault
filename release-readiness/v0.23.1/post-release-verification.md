# Hermes Vault v0.23.1 — Post-Release Verification Record

Date: 2026-08-01
Verifier: Hermes (kanban task t_94332d90)
Release under test: v0.23.1 "Patch: mcp SDK cap" (tag `v0.23.1` @ cf14a5e, master squash-merge 73e9ceb, PR #50)
Also checked: v0.23.0 (tag @ 58926c7) as the prior release in the same train.

## Verdict

**PASS** — all artifact checks pass, no missing files or version mismatches, rollback proven ready.
One deployment discrepancy found (P1, live site stale) — see Findings.

## Artifact checklist (mapped to task body)

| Expected artifact | Status | Evidence |
|---|---|---|
| Compiled binaries / packages | PASS | PyPI wheel + sdist for 0.23.1; sha256 verified against PyPI API (wheel `fbde09da…`, sdist `08a34466…`). GitHub release carries same-named assets (wheel `da9c97f1…`, sdist `ca2b907d…`) — separate builds, both carry the mcp fix. |
| Container images | N/A | No Dockerfile, no ghcr/docker.io/quay refs anywhere in repo. Pure Python package, PyPI-only distribution. |
| Database migration files | N/A | No `.sql`/migrations dir in repo. CHANGELOG declares "No upgrade or migration steps required" for 0.23.x (no storage schema / encryption / KDF changes since v0.22.0). Historical migration docs only (docs/migration-*.md). |
| Helm charts / manifests | N/A | No Helm/manifest files in repo. Deployment = `uv tool`/pipx install. |
| Sidecar tools / bundled assets | PASS | Wheel (PyPI, 111 files) contains 40 `verifier_configs/*.yaml` + 5 `dashboard_static` files; zero junk (no .db/.pyc/.env/.sqlite/__pycache__). METADATA version 0.23.1; `Requires-Dist: mcp<2.0.0,>=1.0.0` present in wheel + sdist (both PyPI and GitHub builds). |
| Checksums / signatures | PASS (partial) | sha256 verified against PyPI JSON API and GitHub releases API digests. No GPG/sigstore signatures published — documented N/A (none exist for any prior release). |
| Image digests vs deployment manifests | N/A | No container images. |

## Quality gates (independently re-run)

- Test suite from master: **898 passed in 40.86s** — exactly matches the release notes claim (898).
- CI on release commit cf14a5e: **10/10 checks success** — Tests ×4 (ubuntu/windows × py3.11/3.12), Secret scan, Dependency audit, Static analysis, Build and install package, Disposable vault and recovery boundaries, Upstream Hermes Secret Source conformance.
- Version surfaces sync: pyproject.toml 0.23.1, `__init__.py` 0.23.1, README install pins `@v0.23.1`, site/index.html pins `v0.23.1`, tests/test_release_regression.py 0.23.1, CHANGELOG 0.23.1 section. Remaining 0.23.0 mentions are legitimate historical context.
- Git state: master tree == v0.23.1 tag tree (diff empty). Tag points to pre-merge branch head (documented "never tag the merge commit" workflow). Prior tags v0.23.0 / v0.22.0 unchanged.

## Deployed configuration vs release notes

- Local deployment: `hermes-vault` 0.22.0 via uv tool (NOT yet on 0.23.1). mcp 1.29.0 in tool env; `import hermes_vault.mcp_server` OK; MCP server log active (ListTools/Ping at 2026-08-01 12:17 local). The 0.23.x dependency-only patch does not affect this install; it is functional and consistent with release notes.
- Policy: `raw_secret_access: false`, `ephemeral_env_only: true`, `require_verification_before_reauth: true` — matches security expectations.
- Launcher `/home/tony/.local/bin/hermes-vault-canonical`: 0700, wires HERMES_VAULT_HOME/POLICY/PASSPHRASE, clears PYTHONPATH (the 0.23.0 PYTHONPATH guard). Contains Google OAuth client secret by design (file-protected).
- TLS/logging/feature flags: site serves HTTPS with HSTS (max-age=63072000); vault mcp.log active; verifier configs loaded. No release-specific TLS/flag/logger mismatch for 0.23.1.

## Rollback readiness

Documented: CHANGELOG upgrade notes ("reinstall as 0.23.1", no migration); docs/operator-guide.md (recovery drill, backup-verify, restore --dry-run, diff); docs/windows.md (Backup and Restore); docs/threat-model.md (recovery drills); docs/update-workflow.md (guarded `hermes-vault update`).

Proven:
- New full backup created: `/home/tony/vault-backups/hermes-vault-current-20260801.json` (0600, 2 credentials).
- `backup-verify`: decryptable: true, findings: [], would_restore_count: 2.
- `recovery drill`: verify + restore dry-run + diff all pass; diff entry_count 0 (backup == current); policy_hash `f13dabc51bd622c2653ae87e490bcdd105bbb95d590beb25619fb3e75863e212`; recommended_next_step: "Recovery drill passed".
- Rollback targets: v0.23.0 and v0.22.0 still published on PyPI (artifacts + digests verified) with tags intact.

Pre-existing backup status (context): `hermes-vault-pre-wipe-20260731.json` (162 creds) is NOT decryptable with the current key — expected, since the master key was rotated at the 2026-07-31 fresh start; treat as legacy archive, not a rollback source. `hermes-vault-fresh-20260801.json` is decryptable but empty (0 creds at time of capture).

## Findings

- **P1 — Live site stale.** `hermesvault.tonysimons.dev` last deployed 2026-08-01 06:10 UTC (after the v0.23.0 merge, before the v0.23.1 merge at 06:32 UTC). Live install command still pins `git+…@v0.23.0` — the release whose fresh installs break under mcp 2.0. Repo `site/index.html` is correct (v0.23.1). Fix: redeploy site from master (`npx vercel --cwd site --prod`, or verify the GitHub→Vercel integration fired for commit 73e9ceb). Requires operator action; not performed (public deploy).
- **P2 — PyPI vs GitHub wheel hash divergence.** Same version/size (4310961 B) but different sha256 (fbde09da vs da9c97f1). Non-reproducible zip builds; both wheels carry the mcp fix and pass METADATA inspection. PyPI is authoritative; anyone diffing GitHub asset hashes against PyPI digests will see a mismatch — documented here to avoid false tampering flags.
- **P2 — Missing readiness reports for 0.23.x.** `release-readiness/` stops at v0.22.0; no v0.23.0/v0.23.1 report. Process gap only.
- **P3 — release-notes-0.23.1.md untracked** in the repo (attached to GitHub release; not committed).
- **Info — Local install still on 0.22.0.** Not affected by the mcp breakage; upgrade to 0.23.1 when convenient (`uv tool install hermes-vault==0.23.1` or `hermes-vault update`).
- **Info — Secret hygiene.** The canonical launcher contains a Google OAuth client secret (protected 0700, by design). It was surfaced in a session transcript during this read-only verification; no at-rest exposure. Avoid `cat`-ing the launcher in future sessions.

## Recommended next actions

1. Redeploy the site (P1) — then re-check `@v0.23.1` appears in the live install block.
2. Commit this record + release-notes file under `release-readiness/v0.23.1/` via the normal PR workflow.
3. Optionally upgrade the local uv tool install to 0.23.1.
