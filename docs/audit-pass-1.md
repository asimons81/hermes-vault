# Hermes Vault Audit Pass 1

## Scope

[FACT] Audited the current Hermes Vault implementation with emphasis on key management, verifier correctness, source-of-truth policy, live Hermes skill contracts, and end-to-end non-auth failure handling.

## Confirmed Strengths

- [FACT] The vault uses passphrase-derived encryption with AES-GCM and a separate local salt file.
- [FACT] The CLI, vault, policy, scanner, verifier, broker, audit, and skill generation pieces are present and wired together.
- [FACT] The scanner detects plaintext secrets, duplicate fingerprints, and insecure permissions.
- [FACT] The broker now prefers ephemeral environment materialization and records policy decisions in audit logs.
- [FACT] The verifier classifies invalid or expired credentials separately from network failure, endpoint misconfiguration, permission or scope problems, and rate limits.
- [FACT] Generated skills now explicitly forbid filesystem-based credential discovery and require verification before re-auth claims.

## Confirmed Weaknesses Found

- [FACT] The original key handling could silently regenerate a missing salt for an existing vault, which would have made restored encrypted data unreadable.
- [FACT] The original broker path exposed raw secret material in decision metadata.
- [FACT] The original runtime commands did not consistently prompt for a vault passphrase when vault-backed actions were run interactively.
- [FACT] The original plaintext policy was advisory rather than explicit about managed Hermes paths, migration windows, and exemptions.
- [FACT] MiniMax verification was not opinionated; it needed a practical configured endpoint or it could only report unknown.

## Fixes Made

- [FACT] Hardened vault key handling so an existing database with a missing salt now fails closed instead of silently re-keying.
- [FACT] Added corrupt salt detection and file permission hardening for runtime vault state.
- [FACT] Removed raw secret material from broker decision metadata and kept broker output centered on env materialization and metadata only.
- [FACT] Added policy-aware plaintext classification for managed Hermes paths, explicit migration allowances, and explicit exemptions.
- [FACT] Tightened the generated skill contract and the checked-in templates to say the generated copies are review artifacts unless explicitly installed by an operator.
- [FACT] Expanded verifier classification and added a MiniMax verification path that requires an explicit configured endpoint instead of pretending to know one.
- [FACT] Added regression tests for the end-to-end non-auth failure path, missing and corrupt key material, duplicate credential conflicts, redaction under exception conditions, broker env issuance, and policy-aware plaintext handling.

## What Is Now Verified

- [FACT] `pytest` passes with 23 tests.
- [FACT] CLI smoke tests passed for `list`, `import`, `add`, and `generate-skill` using a throwaway runtime home.
- [FACT] Runtime files created by the CLI smoke test were permissioned as expected: runtime directory `700`, generated skills directory `700`, vault database `600`, and salt file `600`.
- [FACT] The end-to-end regression proves that brokered access can succeed while verifier output still preserves a non-auth failure category instead of collapsing into “re-auth required.”

## Remaining V1 Limitations

- [GUESS] MiniMax live verification is still configuration-dependent because the project does not ship a provider-specific endpoint contract that can be assumed safely.
- [FACT] Full master-key rotation tooling is still not implemented.
- [FACT] Automatic plaintext cleanup is still not implemented.
- [FACT] The project still relies on the operator account being trusted on the local machine.
- [FACT] Generated skills are review artifacts by default; the repo does not yet provide a controlled live-install workflow.

## Residual Risks

- [FACT] Loss of the salt file makes existing encrypted vault data unrecoverable.
- [FACT] Provider-side network outages and endpoint changes can still prevent verification from reaching a hard classification.
- [FACT] If the operator allows duplicate semantic credentials under different aliases, source-of-truth drift can still happen at a higher policy layer than the current hard duplicate check.

## Conclusion

[JUDGMENT] Hermes Vault is materially better at solving the persistent-sub-agent false re-auth problem than the original V1 because it now has safer key handling, stricter source-of-truth policy, stronger skill contracts, and a regression test that proves non-auth failures are preserved through verification.

