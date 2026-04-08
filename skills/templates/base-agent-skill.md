---
name: hermes-vault-access
description: Hermes Vault credential access contract template for Hermes.
version: 1.0
author: Tony Simons
license: private
metadata:
  hermes:
    tags: [security, credentials, vault, hermes]
---

# Hermes Vault Access Contract for {{agent_id}}

Follow Hermes Vault as the single credential authority.

- Never scan arbitrary files for credentials.
- Never report re-auth without verification.
- Prefer ephemeral env materialization.
- Never print or store raw secrets.
- Generated skills are review artifacts unless explicitly installed.
