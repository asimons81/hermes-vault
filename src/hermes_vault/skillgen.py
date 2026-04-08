from __future__ import annotations

from pathlib import Path

from hermes_vault.models import AgentPolicy
from hermes_vault.policy import PolicyEngine


BASE_FRONTMATTER = """---
name: hermes-vault-access
description: Hermes Vault credential access contract for Hermes and persistent sub-agents.
version: 1.0
author: Tony Simons
license: private
metadata:
  hermes:
    tags: [security, credentials, vault, hermes]
---
"""


BASE_BODY = """
# Hermes Vault Access Contract for {agent_id}

## Purpose

Use Hermes Vault as the single canonical credential authority for {agent_id}. This skill exists to stop ad hoc credential discovery, prevent false re-auth claims, and keep raw secrets out of logs, notes, chat output, memory, and agent scratch files.

## When to Load

- Any task requires an API key, bearer token, OAuth token, or service credential
- A service call fails and auth state must be verified
- You are tempted to inspect `.env`, shell config, notes, memory, JSON, YAML, or arbitrary files for credentials
- You need to decide whether a failure is re-auth, scope, endpoint, network, or rate limit

## Core Rules

1. Never scan arbitrary files or the filesystem for credentials.
2. Never assume a service needs re-auth without Hermes Vault verification first.
3. Always resolve credentials through Hermes Vault.
4. Prefer ephemeral environment materialization over raw secret access.
5. Never print, summarize, log, or store raw credentials in notes, reports, chat responses, or memory.
6. If a service fails, report the exact verified failure category instead of vague auth claims.
7. Stay within policy. Approved services for this agent: {services}.
8. Raw secret access is {raw_access}. Ephemeral env only is {ephemeral_only}. Max TTL is {max_ttl} seconds.
9. Generated skills are review artifacts unless an operator explicitly installs them into a live Hermes skill directory.
10. Do not freestyle new credential paths, token caches, or secret mirrors.

## Workflow

1. Identify the required service.
2. Request credential access through Hermes Vault.
3. Attempt the task using brokered access.
4. If access fails, run Hermes Vault verification.
5. Only report re-auth required if verification explicitly shows invalid or expired credentials.
6. Otherwise report the verified issue category: network, endpoint, scope, rate limit, or unknown.
7. If Hermes Vault denies access, report the broker denial exactly and stop.
8. If a credential is missing from the vault, do not infer that it needs re-auth; report that the canonical source is missing.

## Error Handling

| Failure mode | Required response |
|---|---|
| Broker denies access | Report the denial reason exactly and stop |
| Credential missing from vault | Report that the vault has no credential for the service |
| Verification says invalid or expired | Report re-auth required with the explicit verification result |
| Verification says network failure | Report a network issue, not re-auth |
| Verification says permission or scope issue | Report a permission or scope problem, not re-auth |
| Verification says endpoint misconfiguration | Report endpoint/config error, not re-auth |
| Verification says unknown | Report unknown verification result and include the verifier reason |

## Validation Checklist
- [ ] This skill tells the agent not to scan arbitrary files for credentials
- [ ] This skill tells the agent to verify before reporting re-auth
- [ ] This skill tells the agent to prefer ephemeral env materialization
- [ ] This skill tells the agent never to print or store raw secrets
- [ ] This skill states generated skills are review artifacts unless installed explicitly
"""


class SkillGenerator:
    def __init__(self, policy: PolicyEngine, output_dir: Path) -> None:
        self.policy = policy
        self.output_dir = output_dir

    def generate_for_agent(self, agent_id: str) -> Path:
        agent_policy = self.policy.get_agent_policy(agent_id) or AgentPolicy()
        directory = self.output_dir / agent_id
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / "SKILL.md"
        content = BASE_FRONTMATTER + BASE_BODY.format(
            agent_id=agent_id,
            services=", ".join(agent_policy.services) if agent_policy.services else "none",
            raw_access="allowed" if agent_policy.raw_secret_access else "disabled",
            ephemeral_only="true" if agent_policy.ephemeral_env_only else "false",
            max_ttl=agent_policy.max_ttl_seconds,
        ).strip() + "\n"
        target.write_text(content, encoding="utf-8")
        return target

    def generate_all(self) -> list[Path]:
        return [self.generate_for_agent(agent_id) for agent_id in self.policy.config.agents]
