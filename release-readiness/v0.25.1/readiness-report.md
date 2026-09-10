# Hermes Vault v0.25.1 — Release-Readiness Notes

**Prepared by**: Hermes (docs lane, kanban task t_23d63138)
**Date**: 2026-09-10
**Candidate**: `bump/v0.25.1` (local, 4 commits ahead of `origin/master` 9b05b77)
**Version**: 0.25.1 — **PROVISIONAL** (Tony confirms 0.25.1 vs 0.26.0 before tag)
**Line**: Vault Intelligence — patch on the Desktop Mutation Surface (v0.25.0)

## Decision: PENDING

Not a GO/NO-GO from this lane. Remaining gates before release:

1. **Tony**: version-number confirmation (0.25.1 patch vs 0.26.0 minor — the mcp
   constraint widening in #81 is the argument for minor) and release approval.
2. **QA** (task t_51ecfad3): independent acceptance — version consistency,
   suite re-run, notes-vs-commits spot check, clean tree, nothing
   pushed/tagged.
3. Tag `v0.25.1` on the release branch, PR to master, PyPI trusted publish.

Pre-bump audit (t_4c34ec46) verdict NOT READY with blockers B1–B3 — all three
cleared on this branch (see below).

## What ships (commits fbf39fe, 74f24c0, 7d41298, 08c1dfd + docs commit)

- **Integrity stat fix (via #80)**: Desktop plugin header derives its Integrity
  stat from the `/integrity` endpoint instead of `overview.health.integrity_status`
  (never emitted by the bridge) — v0.25.0 rendered a false red ✗ Check.
- **Windows plugin adapter (#77, fixes #76)**: `communicate()` fallback for
  Windows children (no `os.set_blocking` / pipe-fd `selectors`), `ComSpec` +
  user-profile env keys for `.cmd` launchers, CRLF normalization before strict
  line framing.
- **MCP 2.x support (#81)**: constraint `mcp>=1.0.0,<3.0.0`; handler
  registration via the 2.x `add_request_handler` API. Lock regenerated with
  mcp 2.2.0 — fixes master's silently-broken lock-based installs (see caveat).
- **Test hardening (#82, #83)**: OAuth concurrent-refresh barrier flake;
  audit-integrity TOCTOU Windows lock-race flake.
- **README hero (#86)** + **site branding pass**: Studio black/white/red theme,
  AIowa LLC footer, hero webp tracked in git, deploy script uses local `vercel`
  CLI instead of `npx --yes vercel`.

### Known caveat (documented, decision routed to owner)

The widened mcp constraint still admits mcp 1.x, which lacks
`add_request_handler` — an environment that resolves mcp 1.x fails to import
`hermes_vault.mcp_server` (verified against the mcp 1.27.0 package: the symbol
does not exist anywhere in it; `mcp_server.py:1401` calls it unconditionally at
import). Fresh pip installs resolve mcp 2.x and are unaffected. Whether to raise
the floor to `>=2.0.0` (or add a 1.x shim) is a developer/Tony decision, not a
docs one.

## Pre-bump blockers — cleared

| Blocker (t_4c34ec46) | Resolution |
|---|---|
| B1/P0 stale master (local master at e589fc9, missing #77 #81 #82 #83 #86) | `git fetch origin`; branch cut from `origin/master` 9b05b77 |
| B2/P1 untracked hero webp (deploys from fresh clone serve broken hero) | committed 74f24c0; unreferenced `site/assets/hermes-vault-logo.jpg` left untracked per orchestrator decision |
| B3/P1 installed tool stale (0.23.1) | `uv tool install --force .` → dist-info `hermes_vault-0.25.1`, `--help` exit 0; `hermes-vault-canonical` launcher intact |

## Version surfaces (verified by docs lane on this branch)

| Surface | Value | Status |
|---|---|---|
| `src/hermes_vault/__init__.py` | `__version__ = "0.25.1"` | ✓ |
| `pyproject.toml` | `version = "0.25.1"` | ✓ |
| `uv.lock` | `hermes_vault-0.25.1`, mcp 2.2.0 | ✓ |
| `CHANGELOG.md` | `## 0.25.1 -- Patch: ...` entry | ✓ (accuracy-corrected by docs lane, see commit) |
| `README.md` | current-release paragraph + "What's New in 0.25.1" + install cmds | ✓ |
| `site/index.html` | eyebrow, hero cmd, metric card, timeline v0.25.1 | ✓ |
| `site/app.js` | uv/pipx install cmds @v0.25.1 | ✓ |
| `tests/test_release_regression.py` | 4 pinned assertions | ✓ (16/16 pass) |

## Quality gates (recorded from the implementation run, t_81946f45; subset re-verified by docs lane)

| Gate | Command | Result |
|---|---|---|
| Full suite | `env -u PYTHONPATH uv run --extra dev --with fastapi python -m pytest tests/ plugins/hermes-vault-desktop/tests/ plugins/hermes-vault-secret-source/tests/ -q` | 1303 passed, exit 0 (impl run) |
| Release regression (docs re-run) | same runner, `tests/test_release_regression.py` | 16 passed, exit 0 |
| ruff (tracked tree) | `ruff check . --exclude .worktrees` | all checks passed |
| mypy | `mypy src/hermes_vault` | no issues in 64 files |
| build | `uv run --with build python -m build` | sdist + wheel `hermes_vault-0.25.1`, exit 0 |
| lock | `uv lock --check` | PASS on branch (FAILS at master tip — the lock fix this release carries) |
| installed tool | `hermes-vault --help` | exit 0; dist-info 0.25.1 |

## Working-tree state at docs handoff

- Branch `bump/v0.25.1`, 4 impl commits + this docs commit, nothing pushed/tagged.
- Untracked by design: `.worktrees/` (audit W3, Tony's cleanup call),
  `release-notes-0.23.1.md` + `release-readiness/v0.23.1/` (stale 0.23.1
  artifacts), `site/assets/hermes-vault-logo.jpg` (unreferenced).
- `release-notes-0.25.1.md` (this release's notes) and this directory are
  committed by the docs lane, per the release-notes-0.23.0 precedent (draft
  committed pre-tag, removed after the CHANGELOG becomes the record).

## Post-release verification plan (for after approval)

1. Tony confirms version (0.25.1 vs 0.26.0 — if 0.26.0, only the version
   strings in 7d41298 + this directory/filename change).
2. Tag `v0.25.1` on the release branch (not the merge commit); tag push
   triggers PyPI trusted publishing.
3. PR to master; CI green; merge.
4. Verify PyPI `hermes-vault==0.25.1` and site auto-deploy
   (hermesvault.tonysimons.dev) — deploy script now requires the local `vercel`
   CLI on PATH.
5. Reinstall local tool from PyPI; restart dashboard serve child; re-verify
   `/overview` 200 and the Desktop plugin Integrity stat shows ✓ on a healthy
   vault.
