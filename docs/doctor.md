# Doctor — guided install & recovery health check

`hermes-vault doctor` is one command for install and recovery health. It replaces the six-step expert recipe (reinstall the binary, recreate the launcher, verify the store, re-establish the audit chain, fix the MCP wiring) with a single read-only sweep that names the exact failure and the exact command that fixes it.

Doctor **wraps the P1 safe-recovery primitives** — the store decryptability proof, the audit-chain repairability classification, the backup decryptability proof, the salt fingerprints. It owns no recovery logic: every repair it names is an existing P1 command.

## Usage

```bash
hermes-vault doctor                       # full sweep, human-readable
hermes-vault doctor --json                # machine-readable findings for agents
hermes-vault doctor --backup ~/vault-backups/hermes-vault-20260910.json
hermes-vault doctor --no-mcp-smoke        # skip spawning the MCP server
hermes-vault doctor --hermes-config /path/to/config.yaml
```

Doctor never prompts (it is cron/agent-safe). Without a passphrase the key-dependent checks report `skip` with a pointer to the launcher guidance rather than failing.

## What it checks

| Check | What it proves | Fix it names |
|---|---|---|
| `binary` | the installed package imports, its version is readable, and PYTHONPATH does not show the documented hermes-agent poisoning pattern | clean environment / canonical launcher |
| `launcher` | vault-home layout, db/salt pairing (the #1 brick), salt shape, key-material file permissions, passphrase source | restore the ORIGINAL salt / chmod |
| `store` | `PRAGMA quick_integrity_check` on vault.db (keyless) | restore vault.db from backup/safety copy — never write to it |
| `salt-match` | P1 `store_decryptability`: every live credential decrypts under the current master key | the canonical P1 salt-migration guidance (restore paired salt / re-export from paired home) |
| `audit-chain` | P1 `verify()` + `classify_repairability` | `audit-checkpoint establish` (legacy/incomplete) or `audit-checkpoint repair --yes --reason` (repairable); tamper/key-mismatch are named as REFUSED with the reason |
| `backup-pairing` (only with `--backup`) | P1 `prove_backup_decryptable`: the backup decrypts under this vault's key | the restore preflight would block it — fix key material first |
| `mcp-wiring` | the Hermes config has a well-formed `mcp_servers.hermes-vault` entry (real list `args`, resolvable command) and the configured server answers a JSON-RPC `initialize` handshake | exact config YAML to write; the documented `args:` string trap |

## Exit codes

```
0  healthy    — every executed check passed
1  degraded   — warnings only (fresh install, missing MCP config, loose permissions, no passphrase…)
2  broken     — at least one check failed (missing/corrupt salt, corrupt db, key-material mismatch, wedged/tampered audit chain)
```

The `--json` payload repeats the verdict and exit code (`version: doctor-v1`):

```json
{
  "version": "doctor-v1",
  "verdict": "broken",
  "exit_code": 2,
  "checks": [
    {
      "name": "salt-match",
      "status": "fail",
      "summary": "Store decryptability: 0/2 — KEY-MATERIAL MISMATCH, salt fingerprint f98a84b30119f020",
      "detail": "…canonical P1 salt-migration guidance…",
      "remediation": ["…"],
      "data": {"salt_fingerprint": "…", "credential_count": 2, "decryptable_count": 0}
    }
  ]
}
```

## Read-only guarantees

- Doctor never mutates the store, never writes audit rows (a wedged chain must not crash it), and never creates a vault where none exists.
- The vault is opened only when the store already exists and passed the integrity check; otherwise key-dependent checks skip.
- The MCP smoke test performs only the `initialize` handshake — the lazy broker means no unlock, no credentials.

## The two bricking traps, caught before damage

- **Trap #1 — audit wedge** (raw audit rows past an initialized chain): `audit-chain` fails with the reason code and `repair_class: repairable`, naming `hermes-vault audit-checkpoint repair --yes --reason "…"`.
- **Trap #2 — rotated salt** (rebuilt store under new key material): `salt-match` fails with the P1 KEY-MATERIAL MISMATCH block; `audit-chain` reports `refuse_key_material` — doctor never suggests a repair that would cover it up.

## Suggested cron

```bash
# daily recovery posture sweep (read-only)
hermes-vault doctor --json
```

Treat exit 2 as a paging condition: the vault is in a state where the next write path may fail or has already failed.
