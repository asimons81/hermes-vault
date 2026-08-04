# Hermes Vault Desktop dashboard adapter

This plugin exposes the verified Hermes Vault **read-only** desktop bridge to the
Hermes dashboard backend. Its technical plugin id is `hermes-vault-desktop`.

The adapter is intentionally thin:

- it does **not** import `hermes_vault` into the Hermes gateway;
- it does **not** start the legacy Vault dashboard;
- every request starts one `hermes-vault --no-banner desktop-bridge` child;
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

Install the **bundled** plugin files under the Hermes installation's bundled plugin
root, or install the complete Hermes Vault Desktop release using the release procedure
for the target Hermes version. Keep the existing `hermes-vault` Secret Source plugin
installed; this adapter is a separate technical id and does not replace or overwrite
that plugin.

Before enabling it, verify:

1. `hermes-vault --no-banner desktop-bridge` is available on the Hermes service PATH.
2. Hermes Vault is initialized, or the expected locked/read-only state is understood.
3. The Hermes dashboard can import FastAPI plugin routers.
4. The plugin manifest reports `name: hermes-vault-desktop` and `api: plugin_api.py`.

Enable the plugin through the normal Hermes plugin allow-list for the target release.
Do not copy credentials into the manifest, README, environment examples, or logs.

## Rollback

Disable `hermes-vault-desktop` through the normal Hermes plugin disable mechanism and
restart the dashboard service if the target release requires a restart. If the plugin
was installed as a bundled release artifact, restore the previous release artifact.
Do not remove or modify the existing `hermes-vault` Secret Source plugin as part of
this rollback. The adapter is read-only and has no Vault database migration or
persistent state to roll back.
