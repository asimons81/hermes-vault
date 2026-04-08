---
name: hermes-vault-access
description: Hermes Vault credential access contract template for a persistent sub-agent.
version: 1.0
author: Tony Simons
license: private
metadata:
  hermes:
    tags: [security, credentials, vault, subagent]
---

# Hermes Vault Access Contract for {{agent_id}}

Sub-agents must not freelance credential handling.

- Never scan arbitrary files for credentials.
- Never report re-auth without verification.
- Always route credential requests through Hermes Vault.
- Prefer ephemeral env materialization.
- Never print or store raw secrets.
