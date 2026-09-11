# Safe Recovery — Restore Preflight, Receipts, and Audit-Chain Repair

v0.26.0 (P1). This guide is the operator-facing companion to the safe-recovery
machinery: the mandatory restore preflight, recovery receipts, the
non-destructive `audit-checkpoint repair`, and the salt-migration guard.

Design reference: `p1-design.md` (board `hermes-vault-v0260-impl`, card D1).
The ops skill's older manual recipes (`references/audit-integrity-repair.md`)
are superseded by the commands below — prefer the product behavior.

## The two failure modes this prevents

1. **Silent restore brick.** Restoring a backup encrypted under different key
   material used to import "cleanly" and then fail on every later access with
   `secret could not be decrypted`. The master key is derived from the vault
   passphrase **and** `master_key_salt.bin`; a backup from a different vault
   home (or from before a rebuild rotated the salt) cannot decrypt under the
   current key. hermes-vault now proves decryptability *before* any mutation
   and blocks the restore with recovery instructions.
2. **Audit-chain wedge.** Unprotected audit rows past an initialized
   integrity chain make every protected write path (`maintain`, `verify`,
   `broker env`, `backup`) raise `AuditIntegrityError`. The recovery is now
   one command that quarantines the old evidence instead of destroying it.

**hermes-vault never rotates or replaces `master_key_salt.bin` automatically.**
The only legitimate salt writers are fresh-vault creation (no database
exists) and the explicit `rotate-master-key` command (full re-encryption).

## Restore preflight and receipts

Every `restore` attempt — dry-run or real — goes through a preflight that:

- attempts to decrypt **every** credential payload in the backup under the
  live master key (`decryptable N/M` must equal the credential count);
- computes identity fingerprints: the destination salt file's
  `sha256[:16]` and, for v2 backups, the evidence segment's entry public key;
- for v2 backups, detached-verifies the audit integrity evidence;
- writes a receipt.

```
hermes-vault restore --input backup.json --dry-run   # read-only drill + receipt
hermes-vault restore --input backup.json --yes       # preflight -> receipt -> guarded import
```

There is **no `--skip-preflight`**. If the preflight fails, the restore is
blocked (exit 1), nothing is written, and the receipt records
`decision: blocked` with a reason:

| `blocked_reason` | meaning |
|---|---|
| `salt_mismatch` | 0/N payloads decrypt — the backup is keyed to different key material |
| `partial_decrypt_failure` | some payloads decrypt, some do not (corruption or mixed keys) |
| `integrity_evidence_invalid` | v2 audit evidence does not verify under this key |

### Receipts

Each attempt writes `$VAULT_HOME/recovery/restore-receipt-<UTC-ts>.json`
(0600, atomic). A real restore rewrites the same file twice: first with
`outcome: "preflight-passed"`, then with the final outcome
(`"restored"` or `"failed:<class>"`).

```json
{
  "version": "restore-receipt-v1",
  "mode": "preflight",
  "backup_path": "/home/ops/backup.json",
  "backup_sha256": "…",
  "backup_version": "hvbackup-v2",
  "credential_count": 3,
  "decryptable_credential_count": 3,
  "destination_salt_fingerprint": "9f86d081884c7d65",
  "backup_key_fingerprint": "2c26b46b68ffc68f",
  "decision": "proceed",
  "outcome": "restored"
}
```

**Fail-closed rule:** if the receipt cannot be written (unwritable or
read-only `$VAULT_HOME/recovery`), the restore is *not performed*. For
drills against a read-only vault home, run `--dry-run` against a copied home.

### If a restore is blocked (salt mismatch)

Do **not** delete `vault.db` or `master_key_salt.bin`. Either:

1. Restore the ORIGINAL `master_key_salt.bin` that pairs with the backup
   (check safety copies in the vault home: `master_key_salt.bin.bak-*`,
   `vault.db.pre-auditreset-*`, `vault.db.pre-repair-*`), then re-run the
   restore; or
2. Open the backup in a vault home that still has the paired salt, re-export
   a fresh backup there, and restore that file here.

Run `hermes-vault backup-verify --input <path>` for the full per-entry report.

## Audit-chain repair

```
hermes-vault audit-checkpoint repair                 # READ-ONLY self-check (default)
hermes-vault audit-checkpoint repair --dry-run       # same, explicit
hermes-vault audit-checkpoint repair --yes --reason "incident <date> wedge"
hermes-vault audit-checkpoint repair --yes --reason "…" --no-safety-copy
```

**Self-check (no flags)** mutates nothing (byte-identical database and
checkpoint) and prints: the verify result with the exact `reason_code`, a
store-decryptability line (`N/N credentials decrypt under the current master
key` or `KEY-MATERIAL MISMATCH`), and the verdict:

- `REPAIRABLE by 'audit-checkpoint repair --yes --reason …'` — drift/anchor
  loss (e.g. `missing_integrity_record`, `checkpoint_stale`); includes the
  row counts that would be quarantined. Exit 2.
- `REFUSED (evidence of tampering)` — digest/signature/sequence failures.
  Repairing would destroy the record of alteration: export the evidence
  (`audit-export --with-integrity`), preserve it, and restore from a
  verified backup instead. Exit 2.
- `REFUSED (key-material mismatch)` — `active_key_mismatch` is the
  salt-migration signature; fix the key material (see above), not the audit
  tables. Exit 2.
- `healthy — nothing to do`. Exit 0.

**Executed repair (`--yes --reason`)** — both flags required; `--reason` is
forced provenance and lands in the audit event. Steps:

1. Safety copy `vault.db` → `vault.db.pre-repair-<ts>` (0600; skip with
   `--no-safety-copy`).
2. One `BEGIN IMMEDIATE` transaction: per-table row counts into
   `audit_quarantine_manifest`, `CREATE TABLE quarantine_<table>_<ts> AS
   SELECT *` for the 6 audit tables, then ordered deletes (FK-correct:
   records before access_logs). Any failure rolls back — the database is
   left byte-identical. No `VACUUM` is run; quarantined pages are retained
   on purpose (evidence outlives the incident; purge old quarantine sets
   manually with `DROP TABLE` after your evidence window closes).
3. `ensure_initialized` + `establish_checkpoint` re-anchor a fresh chain;
   `audit.checkpoint.json` from before the repair is renamed to
   `audit.checkpoint.json.quarantine-<ts>`.
4. Post-verify must be healthy, and a protected `audit_repair` event lands
   as part of the new chain with the quarantine id, per-table counts,
   safety-copy path, prior failure reason, operator reason, and any
   deferred recovery events that were recorded in receipts while the old
   chain was broken.

`credentials` and `leases` are never touched by repair.

## Guard rails always on

- `import_backup` (the library under every restore surface — CLI, broker,
  future tooling) independently re-proves decryptability and raises the
  typed `SaltMismatchError`; the CLI preflight and the library guard are two
  layers over one helper.
- Creating a salt file is refused when a `vault.db` exists beside it (the
  temp-home rebuild trap's entry point) — the error names the original-salt
  recovery instead of silently re-keying.
- `recover_checkpoint` no longer rebuilds integrity tables on
  `active_key_mismatch` (the destructive path was removed; the mismatch is
  surfaced, not paved over).
- `restore_preflight` (every real restore) and `audit_repair` (every
  executed repair) land in the audit log; while a broken chain cannot accept
  appends, those facts persist in the receipt/manifest and are folded into
  the post-repair `audit_repair` metadata.

## Boundaries (what code cannot prevent)

A raw file copy of `vault.db`/`master_key_salt.bin` into a live vault home
(the "swap" step of older rebuild playbooks) happens outside any
hermes-vault process — no code can intercept a `cp`. After P1, the first
`restore`, `repair`, or `doctor` invocation names the exact state
(`active_key_mismatch` / `KEY-MATERIAL MISMATCH`) and points at the fix, and
nothing in-product performs the rotation for you. Recovery from a swapped
home = restore the original `vault.db` **and** `master_key_salt.bin` pair
from safety copies.
