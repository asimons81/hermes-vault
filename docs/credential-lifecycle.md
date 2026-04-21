# Credential Lifecycle

## 1. Discovery

- Hermes Vault scans approved Hermes-relevant paths
- Plaintext secrets, duplicates, and insecure permissions are identified

## 2. Import or Add

- Operator imports from `.env` or JSON, or manually adds a credential
- All additions flow through ``VaultMutations`` (centralized audit-backed mutation path)
- Operator path skips policy checks but produces audit entries
- Agent path requires ``add_credential`` capability and service action permission
- Raw secret is encrypted before being written to the vault
- Metadata records service, alias, type, provenance, timestamps, and crypto version
- Plaintext copies are allowed only during migration windows or explicit exemptions
- Long-lived plaintext under managed Hermes paths is a policy violation, not a normal state

## 3. Brokered Use

- Hermes or a sub-agent requests access through the broker
- Policy v2 determines whether access is allowed based on per-service action permissions
- Agent-level capabilities gate non-service-scoped actions (list, scan, export, import)
- Broker prefers ephemeral environment materialization for downstream task execution
- All broker decisions are recorded in the audit log

## 4. Verification

- When a task fails or an operator requests verification, the verifier checks the credential against a provider endpoint
- Result is classified precisely
- Vault status and last verified timestamp are updated
- Non-auth failures such as network, scope, endpoint, and rate limit should remain distinct from invalid/expired credential results

## 5. Rotation

- Operator replaces the secret for an existing record
- Rotation flows through ``VaultMutations`` with policy check and audit
- Agent path requires ``rotate`` service action permission
- Old ciphertext is overwritten in the record
- Status returns to unknown until verification runs again

## 6. Deletion

- Operator explicitly confirms deletion
- Deletion flows through ``VaultMutations`` with policy check and audit
- Agent path requires ``delete`` service action permission
- Metadata and encrypted payload are removed from SQLite

## 7. Skill Contract

- Generated SKILL.md files tell agents to stop credential freelancing
- Verification-before-reauth is part of the required workflow
- Generated skills are review artifacts unless explicitly installed by the operator
