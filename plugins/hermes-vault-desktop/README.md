# Hermes Vault Desktop integration

The Hermes Vault **read-only** desktop integration ships as the
`hermes-vault-desktop` plugin with two halves:

1. **Backend adapter** (`dashboard/`) — exposes the verified Vault desktop bridge
   to the Hermes dashboard backend as fixed GET routes.
2. **Desktop runtime** (`desktop/plugin.js`) — the native Hermes Desktop plugin
   page that renders the metadata (overview cards, credential/lease/request
   metadata, audit, integrity) and refreshes on an interval.

The adapter is intentionally thin:

- it does **not** import `hermes_vault` into the Hermes gateway;
- it does **not** start the legacy Vault dashboard;
- every request starts one `hermes-vault-canonical --no-banner desktop-bridge` child;
- the child receives one bounded NDJSON request and exits after stdin EOF;
- only fixed GET routes are exposed: `hello`, `health`, `overview`, `credentials`,
  `leases`, `policy`, `requests`, `audit`, and `integrity`;
- query parameters are limited to `profile`, `agent_id`, and `limit`, with strict
  bounds and no dynamic paths or mutation actions;
- the child environment is allowlisted. `PYTHONPATH`, provider credentials, and
  unrelated ambient variables are not forwarded;
- the bridge passphrase variables may reach the child so Vault can unlock, but they
  are never logged or returned by this adapter;
- child stderr and request bodies are never logged or returned;
- timeouts, EOF, malformed JSON, protocol mismatch, and output overflow fail closed.

Successful HTTP responses contain the bridge result object directly. Failure
responses have the form:

```json
{
  "ok": false,
  "error": {
    "code": "VAULT_NOT_READY",
    "message": "Vault key material is unavailable",
    "locked": true
  }
}
```

The UI/runtime half of the integration is separate from this backend adapter. The
manifest hides the dashboard tab so an unfinished or unavailable static bundle cannot
create a second UI surface; the API remains mountable for the native Desktop plugin.

## Install

The plugin package ships in the Hermes Vault release under
`plugins/hermes-vault-desktop/`. Install both halves:

1. **Backend adapter**: copy `dashboard/manifest.json` and `dashboard/plugin_api.py`
   to the Hermes installation's plugin root (e.g. `~/.hermes/plugins/hermes-vault-desktop/`).
2. **Desktop runtime**: copy `desktop/plugin.js` to the desktop plugin root
   (e.g. `~/.hermes/desktop-plugins/hermes-vault-desktop/plugin.js`).

Keep the existing `hermes-vault` Secret Source plugin installed; this adapter is a
separate technical id and does not replace or overwrite that plugin.

Before enabling it, verify:

1. `hermes-vault-canonical --no-banner desktop-bridge` is available on the Hermes
   service PATH. The launcher must be the canonical one: it self-sources the vault
   passphrase from the 0600 file inside the vault dir and clears `PYTHONPATH`.
   Spawning the raw `hermes-vault` binary returns HTTP 423 `MISSING_PASSPHRASE`
   because the scrubbed child environment deliberately contains no passphrase.
2. Hermes Vault is initialized, or the expected locked/read-only state is understood.
3. The Hermes dashboard can import FastAPI plugin routers.
4. The plugin manifest reports `name: hermes-vault-desktop` and `api: plugin_api.py`.

Enable the plugin through the normal Hermes plugin allow-list for the target release,
then reload desktop plugins (or restart the dashboard service). Do not copy
credentials into the manifest, README, environment examples, or logs.

## Tests

```bash
uv run python -m pytest plugins/hermes-vault-desktop/tests/ -q --tb=short
```

Covers the backend adapter (route surface, query bounds, env allowlist, bridge
error mapping) and the runtime plugin (structure, route registration, id
consistency) with no live Vault or Hermes processes required.

## Rollback

Disable `hermes-vault-desktop` through the normal Hermes plugin disable mechanism and
restart the dashboard service if the target release requires a restart. If the plugin
was installed as a bundled release artifact, restore the previous release artifact.
Do not remove or modify the existing `hermes-vault` Secret Source plugin as part of
this rollback. The adapter is read-only and has no Vault database migration or
persistent state to roll back.
