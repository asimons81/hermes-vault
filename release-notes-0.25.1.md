# v0.25.1 — Patch: Desktop plugin fixes + mcp 2.x support

> **PRE-TAG DRAFT — version number PROVISIONAL.** 0.25.1 is the working
> target; Tony confirms 0.25.1 vs 0.26.0 before tag (the mcp constraint
> widening in #81 is the argument for a minor bump). If 0.26.0 is chosen, the
> version strings in the bump commit plus this filename are the only changes.
> Nothing is tagged, pushed, or published yet — approval gate intact.

Patch release on the **Vault Intelligence** line's Desktop Mutation Surface
(v0.25.0). It fixes the false ✗ Integrity stat in the Desktop plugin, makes the
plugin adapter Windows-safe (#77, fixing #76), fixes master's stale `uv.lock`
(silently broken for lock-based installs since #81), widens the MCP SDK
constraint to mcp 2.x (#81), hardens two flaky tests (#82, #83), refreshes the
README hero (#86), and lands the site's black/white/red Studio branding with
the hero asset now tracked in git. No vault schema, backup-format, encryption,
or policy changes; the read-only surface from v0.24.0 and the opt-in mutation
surface from v0.25.0 are unchanged.

## Fixed

- **False ✗ Integrity stat (Desktop plugin)**: the plugin header derived its Integrity stat from `overview.health.integrity_status`, which the bridge never emits — v0.25.0 rendered a false red ✗ Check on healthy vaults. The header now derives it from the `/integrity` endpoint, with fixtures mirroring the real bridge payload and an explicit regression assertion. Found during post-approval live verification of v0.25.0; content landed on master via #80 (squash of the fix-branch work) with the UTF-8 node-harness decode for Windows.
- **Windows plugin adapter crashes (#77, fixes #76)**: `os.set_blocking` is absent on Windows and `selectors.select()` rejects anonymous pipe fds (WinError 10093) — the bounded child reader now routes Windows children to the timeout-bounded `communicate()` fallback; `_SAFE_ENV_KEYS` adds `ComSpec`, `USERPROFILE`, `HOMEDRIVE`, `HOMEPATH` so `.cmd` canonical launchers spawn and expand user-profile paths; `_parse_response` normalizes CRLF before the strict single-line framing check (cmd.exe converts LF to CRLF on pipes) while embedded newlines and bare CR stay rejected. Regression tests cover all four Windows crashes.
- **Broken `uv.lock` inherited from master**: #81 widened pyproject's mcp constraint to `>=1.0.0,<3.0.0` but never regenerated `uv.lock`, whose `requires-dist` mirror still said `<2.0.0` while resolving mcp 1.27.0 — but post-#81 `mcp_server.py` registers handlers via the 2.x-only `add_request_handler` API, so **any lock-based install of master tip crashed at import** (`AttributeError`). CI stayed green only because ci.yml installs without the lock. This release regenerates the lock: mcp 2.2.0 (adds httpx2/httpcore2/mcp-types/truststore/opentelemetry-api; drops mcp-1.x-only httpx-sse/pydantic-settings/python-dotenv, none imported by hermes_vault). If you installed from master's lock since #81 (2026-09-04), reinstall from this release.

## Changed

- **MCP SDK constraint widened (#81)**: `mcp>=1.0.0,<3.0.0` in runtime + dev deps (was `<2.0.0`). `mcp_server.py` registers handlers explicitly via the mcp 2.x low-level API (`server.add_request_handler("tools/list", ...)`) — mcp 2.0.0 removed the decorator API and renamed wire kwargs to snake_case — so fresh installs resolve mcp 2.x (the lock pins 2.2.0). **Caveat**: the widened constraint still admits mcp 1.x, which lacks `add_request_handler`; an environment that resolves mcp 1.x will fail to import `hermes_vault.mcp_server` (verified against the mcp 1.27.0 package: no `add_request_handler` exists anywhere in it).
- **README hero (#86)**: architecture diagram (`assets/hermes-vault-architecture.webp`) replaces the promo image.
- **Site branding + hero asset**: black/white/red Studio color scheme with modern Studio header and AIowa LLC footer; the hero `site/assets/hermes-vault-architecture.webp` referenced by the deployed `site/index.html` (hero `<img>` + `og:image`) is now tracked in git — deploys from a fresh clone no longer serve a broken hero.
- **Site deploy script**: `scripts/deploy-hermesvault-site.sh` calls the local `vercel` CLI directly (`vercel link` / `vercel deploy --prod` / `vercel alias set`) instead of `npx --yes vercel`.

## Tests

- **Concurrent OAuth refresh hardening (#82)**: the concurrent-refresh test no longer trips barrier timeouts (flaky on loaded CI runners).
- **Audit-integrity TOCTOU hardening (#83)**: the concurrent-writer test no longer races Windows file locks.

## Upgrade notes

- No upgrade or migration steps required. No vault schema or backup-format changes. Users on 0.25.0 should reinstall as 0.25.1 (`uv tool install --force git+https://github.com/asimons81/hermes-vault.git@v0.25.1` or the pipx equivalent). Windows Desktop plugin users get the adapter fix on next plugin adapter restart.
- Users who installed from master's `uv.lock` after #81 merged (2026-09-04) have a broken MCP server and should reinstall from this release.
- Version number note (pre-tag): 0.25.1 is the provisional target; the mcp constraint widening (#81) may argue for 0.26.0 — Tony decides before tag.

## Validation

Recorded from the implementation run (branch `bump/v0.25.1`, docs task t_23d63138 independently re-verified the subset marked ✓):

- Full suite — core + desktop plugin + secret-source plugin: **1303 passed, exit 0** (`env -u PYTHONPATH uv run --extra dev --with fastapi python -m pytest tests/ plugins/hermes-vault-desktop/tests/ plugins/hermes-vault-secret-source/tests/ -q`)
- ✓ Release-regression tests re-run by docs lane: **16 passed** (version surfaces, README "What's New", site strings)
- ruff (tracked tree): **all checks passed**
- mypy `src/hermes_vault`: **no issues in 64 files**
- build: **sdist + wheel `hermes_vault-0.25.1` built, exit 0**
- lock check: **`uv lock --check` PASS after regen** (fails at master tip — the broken-lock fix above)
- installed tool smoke: `hermes-vault --help` exit 0; dist-info `hermes_vault-0.25.1`
