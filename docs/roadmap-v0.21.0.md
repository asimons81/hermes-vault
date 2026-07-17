# Hermes Vault v0.21.0 Roadmap

## Release thesis

**Codename: Audit Assurance**

Hermes Vault v0.21.0 will let operators verify the integrity and continuity of local audit history. The release adds versioned integrity records, durable checkpoints, verification commands, and recovery evidence without changing credential-access authority.

This is an operator-assurance release. MCP remains the in-loop authority path. Secret Source remains startup-only, mapped-only, non-interactive, read-only, and separate from MCP.

## Operator outcomes

An operator can:

- verify audit continuity with one command;
- distinguish healthy chained history, legacy history, incomplete evidence, and an integrity failure;
- export sanitized audit evidence with integrity metadata;
- view safe integrity status in the local dashboard and MCP metadata surfaces;
- confirm backup and restore operations preserve audit evidence;
- establish a new trusted checkpoint only through an explicit, audited operator action.

Agents receive status and safe next steps only. They do not gain authority to rewrite or reset audit history.

## In scope

### Versioned audit integrity

Audit records gain a deterministic, versioned integrity envelope with sequence, predecessor, digest, and authentication metadata. The design must detect altered, missing, duplicated, or reordered history and must verify consistently across supported Python versions and operating systems.

Integrity-key material must be derived with explicit domain separation from vault-controlled key material. It must never be logged, serialized, exported, or placed in environment material.

### Durable checkpoints

A secure checkpoint outside the audit table records the latest trusted sequence and digest. It uses the existing durable-write and file-permission abstractions.

The checkpoint protects the verification boundary when the database changes but retained vault key material remains trusted. Documentation must state clearly that local verification is not third-party attestation and cannot protect against an actor who controls both the local account and the key material.

### Verification surfaces

Add:

- `hermes-vault audit verify`
- `hermes-vault audit checkpoint`
- `hermes-vault audit export --with-integrity`

Human-readable and JSON results should include overall status, chain version, verified count, legacy count, sequence range, checkpoint status, sanitized failure location, and recommended next step.

The dashboard shows integrity status and recent verification evidence. MCP exposes metadata only through existing policy boundaries.

### Backup and recovery integration

Backups preserve audit-integrity and checkpoint state. Backup verification and restore dry-runs validate that state before reporting success. Incident bundles may include sanitized verification summaries and evidence-file hashes, but never raw credentials or key material.

### Legacy migration

Existing audit rows remain readable. First v0.21 initialization creates an explicit migration anchor over the current legacy snapshot and starts a new protected segment.

The product must not imply that pre-v0.21 history was protected before the migration anchor existed. Migration must be non-destructive, idempotent, and recoverable after interruption.

## Explicit non-goals

v0.21.0 will not add:

- blockchain, public ledgers, or cryptocurrency components;
- cloud-hosted audit storage or mandatory network access;
- remote attestation or hardware requirements;
- enterprise SIEM integrations;
- automatic or silent repair of failed integrity evidence;
- bulk secret export or background Secret Source refresh;
- write access through Secret Source;
- new MCP credential authority;
- unrelated provider features;
- broad quality cleanup unrelated to touched code.

## Trust boundaries

The release is designed to detect local audit-history corruption when retained vault key material and the authenticated checkpoint remain trusted. It also covers accidental corruption, incomplete copies, interrupted writes, stale checkpoints, and recovery flows that omit chain state.

It does not claim protection when an actor controls the vault key material, the authenticated local user, and every copy of the database and checkpoint.

Checkpoint reset and recovery are operator-only, explicit, and audited. Audit verification is read-only.

## Architecture

Introduce small, independently tested components:

- canonical audit-entry serializer;
- versioned integrity-chain model;
- domain-separated integrity-key derivation;
- durable checkpoint repository;
- verification result model;
- legacy migration coordinator;
- adapters for CLI, dashboard, MCP metadata, backup, restore, and incident evidence.

Serialization and algorithm versions must be stored with the evidence so future releases can verify older records.

## Compatibility

- Existing v0.20 vaults open without destructive migration.
- Existing audit rows remain readable and are labeled as legacy history.
- Interrupted migration is safe to retry.
- Pre-v0.21 backups remain restorable but report that authenticated audit checkpoints were unavailable.
- v0.21 backups include integrity and checkpoint state.
- Windows and POSIX behavior uses the existing platform abstraction.
- DPAPI-backed and passphrase-backed vaults provide the same audit-integrity behavior.

The operator guide must require a verified backup before upgrade. No automatic downgrade is promised after new protected audit entries are written.

## Acceptance criteria

The release candidate must pass on Ubuntu and Windows with Python 3.11 and 3.12.

Required validation covers:

- fresh audit-chain creation and extension;
- deterministic verification across restarts;
- passphrase-backed and real Windows DPAPI flows;
- integrity-failure classification;
- checkpoint validation and stale-checkpoint handling;
- migration and interrupted-migration recovery;
- backup verification and restore dry-run;
- packaged-wheel dashboard assets and integrity status;
- sanitized CLI, dashboard, MCP, workflow-artifact, and incident output.

## Test and CI plan

### Unit coverage

- canonical serialization;
- chain calculation and version dispatch;
- checkpoint parsing and authentication;
- migration state transitions;
- result classification and redaction.

### Integration coverage

- real SQLite audit lifecycle;
- vault reopen and key derivation;
- backup and restore;
- dashboard and MCP metadata;
- real Windows DPAPI;
- disposable operator workflow with fake credentials.

### Blocking gates

- full Ubuntu and Windows Python matrix;
- full Ruff/Pyflakes gate;
- mypy gate at the repository baseline established before feature work;
- package build and clean-wheel smoke;
- dependency audit;
- full-history Gitleaks;
- post-merge security validation;
- release-specific audit-integrity suite;
- no raw fake-secret values in logs or uploaded evidence.

## Documentation and screenshots

Update the README, operator guide, threat model, architecture document, backup and recovery guidance, MCP documentation, Windows guide, changelog, and release-readiness ledger.

Capture browser-generated screenshots from a real local fake-data vault for:

- healthy integrity status;
- failed-integrity diagnostic;
- checkpoint and recovery guidance.

Screenshots must be checked for fake-secret values before upload.

## Release-readiness checklist

- [ ] Version surfaces agree on `0.21.0`.
- [ ] Migration from a clean v0.20 vault is tested.
- [ ] Legacy history is labeled honestly.
- [ ] Linux and Windows matrices pass.
- [ ] Real Windows DPAPI verification passes.
- [ ] Integrity failures are precise and fail closed.
- [ ] Backup and restore preserve evidence.
- [ ] Dashboard and MCP expose metadata only.
- [ ] Incident evidence contains no secret material.
- [ ] Package and clean-wheel smoke pass.
- [ ] Dependency audit and Gitleaks pass.
- [ ] Screenshots use fake credentials.
- [ ] Release-readiness evidence records exact commands, counts, run URLs, and artifact names.
- [ ] No release tag is created before every blocking item is complete.

## Dependency order

1. **Core chain and migration**
   - canonicalization, key derivation, storage, checkpoint repository, migration, verification model.

2. **Backup and recovery integration**
   - preserve and verify integrity state across backup, restore, and incident evidence.

3. **Operator and agent-safe surfaces**
   - CLI, dashboard, and metadata-only MCP status.

4. **Cross-platform validation and release evidence**
   - DPAPI, package checks, screenshots, documentation, and readiness report.

## Release gate

v0.21.0 is releasable only when an operator can create a disposable vault, generate audited activity, verify continuity, detect deliberate evidence corruption, verify a backup, run a restore dry-run, and inspect the same sanitized status through the packaged dashboard on Linux and Windows.

A successful digest calculation alone is not the release. The release is the complete operator proof path.