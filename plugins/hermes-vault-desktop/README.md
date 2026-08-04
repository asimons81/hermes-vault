# Hermes Vault Desktop Plugin (backend adapter)

A thin Hermes dashboard plugin backend that exposes a read-only view of
Hermes Vault — credentials, leases, policy, access requests, audit log, and
integrity status — as validated REST routes under the
`hermes-vault-desktop` namespace.

This plugin is the **backend adapter only**. It does not contain a desktop
renderer; it exists to be mounted by the Hermes desktop dashboard and called
via `ctx.rest('/api/plugins/hermes-vault-desktop/...')` by a frontend plugin
pane.

## How it works

Every HTTP request spawns a fresh Vault-owned child process:

```text
hermes-vault --no-banner desktop-bridge
```

The child is a read-only NDJSON bridge that speaks one request/response per
line over stdin/stdout. The adapter sends one bounded request line, closes
stdin (EOF terminates the bridge), reads exactly one bounded response line,
and tears the child down. Nothing about the Vault is imported into the
gateway process — all Vault code runs inside the short-lived child.

## Security model

- **Read-only.** Fixed GET routes only, mirroring the bridge's read-only
  method surface. There are no mutation, action, or path-taking routes.
- **Fixed argv.** `[hermes-vault, --no-banner, desktop-bridge]` with
  `shell=False` — no shell interpolation, no dynamic arguments.
- **Scrubbed environment.** The child receives only safe basics (PATH, HOME,
  locale, temp dirs) plus `HERMES_VAULT_HOME`, `HERMES_VAULT_POLICY`, and the
  `HERMES_VAULT_PASSPHRASE*` family. Ambient `PYTHONPATH` and provider keys
  never reach the child.
- **Passphrase handling.** The passphrase may reach the child through the
  environment (env-only resolution, never prompted), but it never returns to
  the parent, is never logged, and never appears in a response.
- **No secret transport.** Request bodies are never logged, child stderr is
  discarded, and bridge error text is sanitized before it reaches a response.
- **Bounded.** One request line (64 KiB) and one response line (512 KiB),
  a per-request timeout, and terminate/kill cleanup on timeout.

## Routes

All routes are `GET` and return the bridge result envelope.

| Route | Bridge method | Query params |
|-------|---------------|--------------|
| `/hello` | `hello` | none |
| `/health` | `hello` (liveness alias) | none |
| `/overview` | `overview` | `profile` |
| `/credentials` | `credentials` | `profile` |
| `/leases` | `leases` | `profile` |
| `/policy` | `policy` | `profile` |
| `/requests` | `requests` | `profile`, `agent_id` |
| `/audit` | `audit` | `profile`, `limit` (1–250) |
| `/integrity` | `integrity` | `profile` |

Query parameters are strictly validated: unknown keys are rejected with 400,
`limit` must be an integer in 1–250, and `profile` / `agent_id` have length
bounds. Unknown paths and non-GET verbs are rejected by the router.

Error mapping:

| Condition | Status |
|-----------|--------|
| Missing bridge binary | 503 |
| Bridge timeout | 504 |
| Bridge closed without a response (EOF) | 502 |
| Malformed response / protocol mismatch | 502 |
| Locked Vault (missing passphrase / not ready) | 423 |
| Bridge-reported invalid request | 400 |
| Other bridge errors | 502 |

## Requirements

- Hermes Vault installed with the `desktop-bridge` command available:
  `hermes-vault --no-banner desktop-bridge` must run.
- Hermes desktop dashboard (the plugin backend is mounted by the dashboard
  plugin system).
- `fastapi` available to the dashboard backend (a normal Hermes desktop
  dependency). Tests additionally require `httpx` for `TestClient`.

## Install

1. Copy the plugin directory to your Hermes plugins folder **as a separate
   directory**:

   ```text
   cp -r plugins/hermes-vault-desktop ~/.hermes/plugins/hermes-vault-desktop
   ```

   > **Important:** do NOT copy this plugin over
   > `~/.hermes/plugins/hermes-vault/`. That directory holds the existing
   > **hermes-vault Secret Source** plugin. This desktop plugin is a separate
   > component and must live in its own directory. Installing it must never
   > overwrite or replace the Secret Source plugin.

2. Enable the plugin backend in `~/.hermes/config.yaml` under `plugins` as a
   proper YAML list:

   ```yaml
   plugins:
     enabled:
       - hermes-vault-desktop
   ```

   (Edit the YAML block directly; `hermes config set plugins.enabled '[...]'`
   writes a string and breaks the list.)

3. Restart the Hermes desktop (or the `hermes serve` child that mounts plugin
   API routes) so the backend mounts under `/api/plugins/hermes-vault-desktop/`.

4. Verify the mount by checking the desktop log for the plugin API mount line,
   or `curl` the route with the session token (401 from the auth gate also
   proves the route exists; 404 means it is not mounted).

## Rollback

1. Remove the plugin from the `plugins.enabled` list in
   `~/.hermes/config.yaml`.
2. Remove the plugin directory:

   ```text
   rm -rf ~/.hermes/plugins/hermes-vault-desktop
   ```

3. Restart the desktop / `hermes serve` child.

Rolling back this plugin has **no effect** on the hermes-vault Secret Source
plugin at `~/.hermes/plugins/hermes-vault/` — the two are independent.

## Test

```text
env -u PYTHONPATH .venv/bin/pytest plugins/hermes-vault-desktop/tests -q
```

The test suite covers success mapping through a fake bridge, missing binary,
timeout, EOF, protocol mismatch, locked Vault, malformed responses, route
allowlisting, argv/env construction, and poison-string hygiene. `fastapi` and
`httpx` are required in the test environment (installed locally only — they
are not declared in the project manifest).
