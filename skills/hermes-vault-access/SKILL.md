---
name: hermes-vault-access
description: Use Hermes Vault as the canonical credential broker for Hermes and persistent sub-agents.
version: 1.0
author: Tony Simons
license: private
metadata:
  hermes:
    tags: [security, credentials, vault, hermes]
---

# Hermes Vault Access

## Purpose

Use Hermes Vault as the single canonical credential authority for Hermes-only credential access and verification.

## When to Load

- A task needs an API key, token, or OAuth credential
- A service request fails and auth state needs verification
- A sub-agent is about to inspect files, env vars, notes, or memory for credentials
- The agent is tempted to freestyle a credential lookup outside Hermes Vault

## Core Rules

1. Never scan arbitrary files or the filesystem for credentials.
2. Never assume a service needs re-auth without Hermes Vault verification first.
3. Always resolve credentials through Hermes Vault.
4. Prefer ephemeral environment materialization over raw secret access.
5. Never print, summarize, log, or store raw credentials in notes, reports, chat responses, or memory.
6. If a service fails, report the exact verified failure category instead of vague auth claims.
7. Hermes Vault is the canonical source of truth for credentials and auth state.
8. Generated skills are review artifacts unless an operator explicitly installs them into a live Hermes skill directory.

## Workflow

1. Identify the required service.
2. Request credential access through Hermes Vault.
3. Attempt the task using brokered access.
4. If access fails, run Hermes Vault verification.
5. Only report re-auth required if verification explicitly shows invalid or expired credentials.
6. Otherwise report the real issue such as network, endpoint, scope, or configuration.
7. Do not invent alternate credential sources if Hermes Vault denies access or reports a missing secret.

## Error Handling

| Failure mode | Required response |
|---|---|
| Broker denies access | Report the denial reason exactly and stop |
| Credential missing | Report that the vault does not contain the service credential |
| Verification returns invalid or expired | Report re-auth required with the explicit verification result |
| Verification returns network failure | Report network failure, not re-auth |
| Verification returns permission or scope issue | Report permission or scope issue, not re-auth |
| Verification returns endpoint misconfiguration | Report endpoint or configuration issue, not re-auth |

## Validation Checklist
- [ ] This skill says never scan disk for credentials
- [ ] This skill says never report re-auth before verification
- [ ] This skill says prefer brokered ephemeral env access
- [ ] This skill says never print or store raw secrets
- [ ] This skill says generated copies are review artifacts unless explicitly installed
