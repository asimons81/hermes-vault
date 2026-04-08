# Credential Lifecycle

## 1. Discovery

- Hermes Vault scans approved Hermes-relevant paths
- Plaintext secrets, duplicates, and insecure permissions are identified

## 2. Import or Add

- Operator imports from `.env` or JSON, or manually adds a credential
- Raw secret is encrypted before being written to the vault
- Metadata records service, alias, type, provenance, timestamps, and crypto version
- Plaintext copies are allowed only during migration windows or explicit exemptions
- Long-lived plaintext under managed Hermes paths is a policy violation, not a normal state

## 3. Brokered Use

- Hermes or a sub-agent requests access through the broker
- Policy determines whether access is allowed
- Broker prefers ephemeral environment materialization for downstream task execution

## 4. Verification

- When a task fails or an operator requests verification, the verifier checks the credential against a provider endpoint
- Result is classified precisely
- Vault status and last verified timestamp are updated
- Non-auth failures such as network, scope, endpoint, and rate limit should remain distinct from invalid/expired credential results

## 5. Rotation

- Operator replaces the secret for an existing record
- Old ciphertext is overwritten in the record
- Status returns to unknown until verification runs again

## 6. Deletion

- Operator explicitly confirms deletion
- Metadata and encrypted payload are removed from SQLite

## 7. Skill Contract

- Generated SKILL.md files tell agents to stop credential freelancing
- Verification-before-reauth is part of the required workflow
- Generated skills are review artifacts unless explicitly installed by the operator
