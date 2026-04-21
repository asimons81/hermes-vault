from __future__ import annotations

from pathlib import Path

import yaml

from hermes_vault.models import AgentPolicy, FindingSeverity, PolicyConfig
from hermes_vault.service_ids import normalize


def _normalize_policy(config: PolicyConfig) -> PolicyConfig:
    """Normalize all service references in a PolicyConfig to canonical IDs.

    Returns a new PolicyConfig with service names normalized.  The original
    is not mutated (Pydantic models are immutable by default).
    """
    normalized_agents: dict[str, AgentPolicy] = {}
    for agent_id, policy in config.agents.items():
        normalized_agents[agent_id] = policy.model_copy(
            update={
                "services": [normalize(s) for s in policy.services],
                "approval_required_services": [normalize(s) for s in policy.approval_required_services],
            }
        )
    return config.model_copy(update={"agents": normalized_agents})


DEFAULT_POLICY = _normalize_policy(
    PolicyConfig(
        agents={
            "hermes": AgentPolicy(
                services=["openai", "anthropic", "minimax", "github"],
                raw_secret_access=False,
                ephemeral_env_only=True,
                require_verification_before_reauth=True,
                max_ttl_seconds=1800,
            )
        },
        managed_paths=["~/.hermes", "~/.config/hermes"],
        plaintext_migration_paths=[],
        plaintext_exempt_paths=[],
        deny_plaintext_under_managed_paths=True,
    )
)


class PolicyEngine:
    def __init__(self, config: PolicyConfig | None = None) -> None:
        raw = config or DEFAULT_POLICY
        self.config = _normalize_policy(raw)

    @classmethod
    def from_yaml(cls, path: Path) -> "PolicyEngine":
        if not path.exists():
            return cls(DEFAULT_POLICY)
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls(PolicyConfig.model_validate(raw))

    def write_default(self, path: Path) -> None:
        if path.exists():
            return
        path.write_text(
            yaml.safe_dump(self.config.model_dump(mode="json"), sort_keys=False),
            encoding="utf-8",
        )

    def get_agent_policy(self, agent_id: str) -> AgentPolicy | None:
        return self.config.agents.get(agent_id)

    def can_access_service(self, agent_id: str, service: str) -> tuple[bool, str]:
        service = normalize(service)
        agent = self.get_agent_policy(agent_id)
        if not agent:
            return False, f"agent '{agent_id}' is not defined in policy"
        if service not in agent.services:
            return False, f"service '{service}' is not allowed for agent '{agent_id}'"
        return True, "allowed by policy"

    def classify_plaintext_storage(self, path: Path) -> tuple[FindingSeverity, str]:
        normalized = path.expanduser()
        if self._matches_any(normalized, self.config.plaintext_exempt_paths):
            return (
                FindingSeverity.medium,
                "plaintext secret is explicitly exempted and should be reviewed for removal during the next policy cycle",
            )
        if self._matches_any(normalized, self.config.plaintext_migration_paths):
            return (
                FindingSeverity.medium,
                "temporary migration allowance: import this credential and remove the plaintext copy after cutover",
            )
        if self._matches_any(normalized, self.config.managed_paths):
            if self.config.deny_plaintext_under_managed_paths:
                return (
                    FindingSeverity.critical,
                    "policy violation: plaintext secrets under managed Hermes paths must be imported into Hermes Vault",
                )
            return (
                FindingSeverity.high,
                "plaintext secret is under a managed Hermes path and should be imported into Hermes Vault",
            )
        return (
            FindingSeverity.high,
            "plaintext secret is outside managed paths but should still be imported into Hermes Vault",
        )

    def allow_raw_secret_access(self, agent_id: str, service: str) -> tuple[bool, str]:
        service = normalize(service)
        allowed, reason = self.can_access_service(agent_id, service)
        if not allowed:
            return False, reason
        agent = self.config.agents[agent_id]
        if agent.ephemeral_env_only or not agent.raw_secret_access:
            return False, "policy requires ephemeral environment materialization only"
        return True, "raw secret access allowed"

    def enforce_ttl(self, agent_id: str, requested_ttl: int) -> tuple[bool, str, int]:
        agent = self.get_agent_policy(agent_id)
        if not agent:
            return False, f"agent '{agent_id}' is not defined in policy", 0
        if requested_ttl <= 0:
            return False, "ttl must be greater than zero", 0
        effective = min(requested_ttl, agent.max_ttl_seconds)
        return True, "ttl accepted", effective

    def _matches_any(self, path: Path, patterns: list[str]) -> bool:
        text = str(path)
        candidates = {text, text.replace("\\", "/")}
        for pattern in patterns:
            expanded = str(Path(pattern).expanduser())
            expanded_candidates = {expanded, expanded.replace("\\", "/")}
            if any(candidate.startswith(item.rstrip("/")) for candidate in candidates for item in expanded_candidates):
                return True
        return False
