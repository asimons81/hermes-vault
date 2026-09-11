# v0.26.0 — Feature: Trustworthy Under Failure

The **Trustworthy Under Failure** release. Recovery that cannot brick the vault,
authorization that is actually enforced, and existing surfaces (CLI, health,
MCP) that stop lying — depth, not new surfaces. Nine packs: safe recovery (P1),
authorization enforcement (P2), CLI truth (P3), MCP correctness (P4), crypto
v2 default (P5), release & CI integrity (P6), `doctor` (P7), `run` (P8), and
the Bitwarden interop on-ramp (P9, answering #84/#85). There are no vault
storage-schema or backup-format changes; existing v1 credential rows stay
readable, and the Vault Intelligence / Desktop surfaces from v0.25.x are
unchanged.

The headline honesty changes: a restore performed per the documented playbook
can no longer produce "secret could not be decrypted" or
`AuditIntegrityError` wedges; an agent can no longer receive another agent's
lease or an expired key; and the surfaces operators actually touch daily
(`--version`, `verify` exit codes, backup health, MCP resource reads) report
the truth.

## Fixed

- **Lease ownership enforced on list/show/renew/revoke (F-01)**: non-operator
  callers may now only access leases issued to themselves — `list_leases`
  applies the `agent_id` filter in the DB query itself (never post-fetch), and
  `show_lease`/`renew_lease`/`revoke_lease` require `lease.agent_id == caller`
  before the service-policy check and before any write. Previously an agent
  allowed on a service could inspect or alter any other agent's lease on that
  service. Operators/auditors holding the explicit new `manage_leases`
  capability keep cross-agent administration; it is never implicitly granted
  to legacy agents — ownership is the security default. Negative cross-agent
  tests in `tests/test_authorization_enforcement.py`.
- **Expired credentials denied at final env materialization (F-03)**:
  `get_ephemeral_env()` re-checks `record.expiry <= now` at the point of final
  materialization — after any OAuth refresh and re-resolution — and denies.
  Expiry is no longer advisory for ordinary credentials: a stale API key with
  an expiry timestamp can no longer be handed to an agent. A successful OAuth
  refresh (which moves expiry forward) still hands off; the only escape is the
  explicit `allow_expired_env` policy override (service entry overrides the
  agent-level default). This is a deliberate behavior change — the
  expired-credential test changed pin from "served with a warning" to "denied
  with `expired_at` metadata and empty env".
- **`recover` no longer rebuilds on key mismatch (F-06) — BREAKING-fix**: the
  `active_key_mismatch` route that DROPped all integrity tables and rebuilt
  from current `access_logs` is deleted — it erased forensic evidence and
  covered up the exact state that means wrong key material. The mismatch now
  returns the failed verification with the salt-migration guidance.
- **Foreign-key restores fail closed — BREAKING-fix**: a backup whose payloads
  do not decrypt under the destination vault's key (previously imported
  cleanly, silently bricking the vault with "secret could not be decrypted")
  is blocked at two layers — the CLI preflight and the `import_backup` library
  guard — as `SaltMismatchError`/exit 1. Automation that relied on cross-key
  imports must share the salt file or re-export from a paired home.
- **"Days since last backup" was permanently "never"**: `backup` wrote the
  archive and returned without recording any audit row, while health and the
  broker backup reminder scanned for exactly such rows — every cron/scheduled
  CLI backup was invisible to health. `backup` now records an `export_backup`
  audit row (audit failure degrades to a warning so the recovery tool is never
  blocked by an integrity wedge). The two duplicated scanners are deduplicated
  into `AuditLogger.last_backup_at()`, which also fixes a latent flaw both
  shared: it now returns the genuinely most recent row across
  `export_backup`/`backup` actions instead of preferring `export_backup`
  regardless of timestamp.
- **PYTHONPATH leakage crashed the installed CLI**: the shipped console script
  died with `ModuleNotFoundError` in Hermes worker/cron shells whose global
  `PYTHONPATH` points into the agent venv (incompatible pydantic wheels shadow
  the tool's deps) — the #1 documented fleet friction, worked around
  everywhere with `env -u` prefixes. The v0.23.0 conftest pattern now runs at
  the installed entrypoint: `hermes_vault/_envguard.py` strips marker paths
  from `sys.path` and filters them from `PYTHONPATH` for child processes;
  dev/editable installs whose checkout path merely contains the marker are
  preserved (entry-file ancestor check).
- **`verify` exit codes lied and its JSON was double-encoded**: `verify
  <unknown-service>` printed `allowed: false` and exited 0 — pipelines
  branching on the exit code read real failures as success. `verify` now exits
  1 when any target failed (not-found/denied, or invalid/network/rate-limit);
  mixed batches fail if any target failed. One exemption: a missing
  provider-specific verifier is a configured no-op, not a failed check.
  `verify --format json` previously printed a JSON string containing JSON
  (rich `print_json` re-encodes str data); the object is now passed once.
  `broker get` and `broker list` had the same double-encoding defect on both
  allow and deny paths — fixed the same way (`broker env` was already correct).
- **Bare `--agent` failures gave no path forward**: `--agent <undefined>`
  printed only the bare denial JSON with no way to discover valid ids. A
  stderr hint (stdout JSON stays parseable) now lists the agents defined in
  the active policy, names the policy file, and surfaces the default-binding
  mechanism (`?agent_id=` / `HERMES_VAULT_MCP_DEFAULT_AGENT`); wired into
  `broker get/env/list`, the lease verbs, and `request access`.
- **Advertised `vault://` resources were unreadable in unbound mode —
  intended behavior change**: generic MCP hosts do `resources/list` then
  `resources/read` on the advertised URI verbatim, and all 10 advertised URIs
  returned `Missing required parameter: agent_id`. Bare resource reads now
  resolve to `HERMES_VAULT_MCP_DEFAULT_AGENT` when set (normal policy-gated
  path, `binding_mode: "default_fallback"`), otherwise to the embedded
  operator default (`binding_mode: "operator_default"`) — the operator's
  metadata-only view, audit-logged, never secrets or encrypted payloads.
  Parameterized resources (`vault://policy-explain`, `vault://recovery`) keep
  their documented missing-parameter errors; tool calls remain agent-scoped.
  The test that pinned the old error envelope was deliberately rewritten —
  the old error WAS the bug.
- **MCP cold start died with a 53-line traceback on locked vaults**: tool
  calls and resource reads now return a typed `MISSING_PASSPHRASE` envelope
  (`locked: true`, mirroring the desktop bridge's 423 MISSING_PASSPHRASE) or
  `VAULT_NOT_READY` for missing/corrupt key material; the CLI entrypoint
  prints a one-line typed error on stderr if startup ever raises. The server
  also no longer builds the vault broker at startup — capabilities-only
  sessions (`initialize`, `tools/list`, `resources/list`,
  `resources/templates/list`) never require a decryptable vault; the broker is
  built on the first vault-touching request.
- **`oauth normalize` alias rename bricked v2 rows**: the legacy refresh-alias
  rename was a raw SQL `alias` UPDATE; on AAD-bound v2 rows (the alias is part
  of the canonical AAD) that left the row undecryptable. v2 rows are now
  decrypted with their pre-rename metadata and re-encrypted with the new alias
  bound in one atomic UPDATE; v1 rows keep the plain metadata rename. Exposed
  by the v2-default flip; regression tests cover both paths.
- **Windows-reader attribution corrected in the 0.25.1 notes (F-1)**: verified
  against git history — the Windows-safe reader mechanism (timeout-bounded
  `communicate()` runner, `ComSpec`/`USERPROFILE` safe-env entries,
  CRLF-tolerant framing) shipped with v0.25.0 (4d95bf3); #77's delta is
  `HOMEDRIVE`/`HOMEPATH` in the child-env allowlist plus the four regression
  tests.

## Changed

- **New writes produce AAD-bound `aesgcm-v2` envelopes by default**:
  `WRITE_CRYPTO_VERSION` flipped from `aesgcm-v1` (issue #60 write-side
  cutover). Existing v1 rows stay readable — decryption dispatches per-row on
  the stored `crypto_version`. Set `HERMES_VAULT_CRYPTO_VERSION=aesgcm-v1` to
  downgrade new writes (e.g. a fleet interoperating with an older consumer;
  unknown values are rejected).
- **`import` is now a Typer group**: the legacy `--from-env`/`--from-file`/
  `--from-csv` flat flags work unchanged; `bitwarden` is the first interop
  subcommand.

## Added

- **Mandatory restore preflight + recovery receipts (P1)**: every `restore
  --yes` proves — before any mutation — that every credential payload in the
  backup decrypts under the live master key, computes salt/key identity
  fingerprints, and writes a `restore-receipt-v1` JSON artifact under
  `$VAULT_HOME/recovery/` (atomic write, 0600, fail-closed). `restore
  --dry-run` writes the same receipt with `mode: dry-run`. There is no
  `--skip-preflight`; the receipt records `proceed`/`blocked` + reason
  (`salt_mismatch`, `partial_decrypt_failure`, `integrity_evidence_invalid`),
  counts, fingerprints, and the two-phase outcome. Every real restore writes a
  protected `restore_preflight` audit event.
- **`audit-checkpoint repair` — non-destructive audit recovery (P1)**:
  read-only self-check by default (verify + store-decryptability proof +
  repair verdict, byte-identical db); `--yes --reason` executes the quarantine
  repair — the 6 audit tables (`access_logs`, `access_requests`,
  `audit_integrity_records`, `audit_integrity_segments`,
  `audit_integrity_state`, `audit_verification_runs`) are copied to
  `quarantine_<table>_<ts>` with an `audit_quarantine_manifest` row per table
  and a `vault.db.pre-repair-<ts>` safety copy, all inside one
  `BEGIN IMMEDIATE` transaction (no `DROP`, no `VACUUM`), then re-anchored via
  `ensure_initialized` + `establish_checkpoint`; a protected `audit_repair`
  event lands on the new chain with quarantine metadata plus any deferred
  recovery events recorded while the old chain was broken. Tamper-evidence
  reasons and the salt-migration signature (`active_key_mismatch`) are refused
  with guidance — repair never destroys evidence or covers up a key-material
  brick. This ships the previously documented purge-and-re-establish recipe
  as a first-class subcommand.
- **Typed `SaltMismatchError` salt-migration guard (P1)**: a single canonical,
  actionable error block — why the mismatch happened, that hermes-vault never
  rotates `master_key_salt.bin` automatically, and the two recovery options
  (restore the paired salt or re-export from a paired home; never delete
  `vault.db`/salt). `load_or_create_master_key` refuses salt creation when a
  `vault.db` exists next to the missing default salt file.
- **`hermes-vault doctor` (P7)**: one read-only command for install and
  recovery health — binary integrity (version, import, PYTHONPATH-poisoning
  signal), launcher/home layout (db/salt pairing, salt shape, key-material
  file permissions, passphrase source), store integrity (keyless
  `PRAGMA quick_integrity_check`), salt/key pairing, audit-chain state (verify
  + repair verdict with the named command), optional `--backup` pairing, and
  MCP wiring (config entry shape incl. the documented `args:`-string trap,
  resolvable command, JSON-RPC `initialize` smoke). Human-readable findings
  plus `--json` (`doctor-v1`) for agents; exit 0 healthy / 1 degraded / 2
  broken. Wraps P1's primitives as-is and owns no recovery logic: never
  mutates the store, never writes audit rows (a wedged chain cannot crash it),
  never prompts, never creates a vault. The two documented ops bricking traps
  surface as named failures: audit wedge → `repairable` + the exact
  `audit-checkpoint repair` command; rotated salt → `KEY-MATERIAL MISMATCH`,
  never a cover-up repair. New `docs/doctor.md`.
- **`hermes-vault run` (P8)**: `run [--agent ID] [--service S ...] [--alias A]
  [--ttl N] -- <cmd>` injects vault-backed env variables ONLY into the child
  process environment for its lifetime — the exact contract
  CrewAI/LangChain/MCP `env:` blocks speak. Resolution calls
  `Broker.get_ephemeral_env` verbatim (the `broker env` path), so policy
  deny-by-default, TTL clamping, lease ownership + expiry enforcement, OAuth
  freshness, and expiry-at-handoff all apply unchanged; operator authority
  bypass is a non-goal. All-or-nothing across multiple `--service` flags (the
  first denial aborts before the child spawns; env-var collisions fail
  closed); with no `--service`, injects every policy-`get_env`-allowed service
  with a stored credential. Secrets never appear in argv, logs, or the audit
  record — a `run_env_inject` audit row carries service and variable NAMES
  plus the command name and TTL — and passphrase env vars are always stripped
  from the child. Shell exit conventions preserved. New `docs/run.md`.
- **`import bitwarden` + interop docs (P9, answers #84/#85)**: import bridge
  for unencrypted `bw export --format json` files — logins → credentials
  (username→alias with intra-import dedup, password→secret, TOTP seed
  preserved as a `totp:` line inside the secret, custom fields → encrypted
  secret metadata, item notes → plaintext notes, folders → service-name
  prefixes); secure notes → note credentials; card/identity/no-password items
  counted and skipped with explicit reasons — nothing silently dropped.
  `--dry-run` previews the full plan without a passphrase or vault and never
  prints a secret; apply goes through the audited `VaultMutations.add_credential`
  path with `imported_from=bitwarden` provenance and a summary
  `import_bitwarden` audit event. Collision policy `--on-collision
  skip|rename|fail` resolves against the live vault before any write; encrypted
  exports are rejected with guidance. New `docs/multi-client.md` (single-host
  multi-client topology, per-agent policy identities, the five "what NOT to
  do" patterns, explicit non-goals) and `docs/bitwarden-comparison.md` (dated,
  source-cited comparison — every Bitwarden claim linked to their public help
  center, verified 2026-09-11).
- **`migrate-crypto` (P5, opt-in v1→v2 re-encryption)**: re-encrypts legacy
  `aesgcm-v1` rows as AAD-bound `aesgcm-v2` inside one `BEGIN EXCLUSIVE`
  transaction and verifies EVERY row decrypts under its post-migration version
  + authorization metadata before committing — any failure rolls back
  completely; partial migrations are never committed and the vault stays fully
  readable in its pre-migration state. Undecryptable rows and unknown
  `crypto_version` labels are refused up front with actionable errors. The CLI
  is explicit and opt-in (`--dry-run` reports eligibility, `--yes` skips the
  prompt); success, refusal, and dry-run outcomes are audited; refusal exits
  non-zero.
- **Policy controls for authorization enforcement (P2 groundwork)**:
  `manage_leases` agent capability (explicit-only escape hatch for cross-agent
  lease administration/audit) and the `allow_expired_env` override (service
  entry overrides agent-level default, default false), both surfaced in
  `docs/operator-guide.md`.
- **`--version` flag**: eager root option prints `hermes-vault <version>` and
  exits 0 before any dispatch; a single parseable line for scripts. Live probe
  at v0.25.1 died with click exit 2.
- **Release & CI integrity (P6)**: `publish-to-pypi.yml` now runs the full
  test matrix (ubuntu/windows × py3.11/3.12, core + both plugin suites) and
  gates `pypi-publish` on it — tags previously published with zero test
  execution. New CI jobs: lock-freshness (`uv lock --check` — the #81
  stale-lock class, killed permanently) and locked-set dependency advisory
  (pip-audit `--require-hashes` over `uv export --locked` output — audits the
  exact hash-pinned set a lock-based install gets). `tests/test_ci_contract.py`
  pins the workflow invariants structurally so a future edit cannot silently
  drop a guard. The v0.23.1 release strays are committed for archive parity.
- **Docs**: `docs/safe-recovery.md` — operator guide for the restore
  preflight, receipt schema, blocked-restore recovery options, and repair
  semantics; operator-guide sections for recovery, doctor, run, crypto
  versions, and Bitwarden import; README common-commands and quickstart
  updates.

## Tests

- Suite: **1190 → 1506 passed** (exit 0). New test files (192 tests):
  `test_p1_safe_recovery.py` (16 — both documented bricking traps as
  end-to-end regressions, transactionality, refusal classes, receipt
  lifecycle), `test_authorization_enforcement.py` (21 — negative cross-agent
  lease access + expiry-at-handoff), `test_p7_doctor.py` (31 — every check
  path, exit-code contract, read-only guarantees), `test_p8_run.py` (31 —
  broker-path composition, deny-by-default, env+audit hygiene, exit codes),
  `test_bitwarden_import.py` (36), `test_crypto_migration.py` (12),
  `test_envguard.py` (7), `test_version_flag.py` (5),
  `test_verify_exit_codes.py` (9), `test_agent_id_errors.py` (7),
  `test_backup_audit_row.py` (9), `test_ci_contract.py` (8).
- Deliberately rewritten pins (the old behavior WAS the bug): `test_mcp_server`
  unbound-resource error pin; `test_governance` expired-credential warning
  pin; `test_cli` double-encoded verify JSON + failed-verify exit-0 pins;
  `test_recover_checkpoint_handles_active_key_mismatch` →
  `test_recover_checkpoint_refuses_key_mismatch_without_rebuild`.

## Upgrade notes

- Users on 0.25.x should reinstall as 0.26.0 (`uv tool install --force
  git+https://github.com/asimons81/hermes-vault.git@v0.26.0` or the pipx
  equivalent). No vault storage-schema or backup-format changes;
  `hvbackup-v2` backups are unchanged.
- **Crypto**: new writes are `aesgcm-v2` (AAD-bound) as of this release;
  existing v1 rows stay readable, and `migrate-crypto` is strictly opt-in —
  nothing re-encrypts automatically. Pre-v0.24.0 hermes-vault releases cannot
  read v2 rows (v2 read support shipped in v0.24.0): a fleet interoperating
  with older consumers can set `HERMES_VAULT_CRYPTO_VERSION=aesgcm-v1` to keep
  new writes on v1. This is the only new environment variable.
- **Behavior changes to review before upgrading**: expired credentials are now
  denied at env handoff (set `allow_expired_env` in policy to keep serving
  them deliberately); cross-agent lease administration now requires the
  `manage_leases` capability; restores of backups encrypted under a different
  key are blocked (share the salt file or re-export from a paired home);
  `recover` refuses to rebuild on key mismatch; `verify` exits 1 on failed
  checks (fix any script that branched on the old exit-0); bare MCP resource
  reads now succeed in unbound mode; the MCP server returns typed lock
  envelopes instead of dying on locked vaults.
- The `env -u PYTHONPATH` prefix workaround for Hermes worker/cron shells is
  no longer needed — the installed CLI scrubs the leakage itself.

## Validation

Recorded from the docs-lane verification run on `release/v0.26.0` at e382377
(2026-09-11), plus pack-run evidence:

- Full suite — core + desktop plugin + secret-source plugin: **1506 passed,
  exit 0** (`env -u PYTHONPATH uv run --extra dev --with fastapi python -m
  pytest tests/ plugins/hermes-vault-desktop/tests/
  plugins/hermes-vault-secret-source/tests/ -q`, re-run by docs lane at
  e382377; baseline at v0.25.1 was 1190 passed)
- Release regression: **16 passed, exit 0** (docs lane)
- ruff (tracked tree): **all checks passed** (docs lane, `uv run --with ruff
  ruff check . --exclude .worktrees`)
- mypy `src/hermes_vault`: **no issues in 69 source files** (docs lane)
- lock: **`uv lock --check` PASS** (docs lane)
- build: **sdist + wheel `hermes_vault-0.26.0` built, exit 0** (docs lane,
  `uv run --with build python -m build`)
- MCP surface probe (docs lane): 10 resources advertised; all listed by
  `resources/list`
- Version confirmed by Tony: **PENDING** — see
  `release-readiness/v0.26.0/readiness-report.md` for gate status.
