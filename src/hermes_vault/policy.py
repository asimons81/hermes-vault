from __future__ import annotations

from pathlib import Path

import yaml

from hermes_vault.models import (
    AgentCapability,
    AgentPolicy,
    ALL_SERVICE_ACTIONS,
    FindingSeverity,
    PolicyConfig,
    ServiceAction,
    ServicePolicyEntry,
)
from hermes_vault.service_ids import normalize


def _normalize_agent_services(agent: AgentPolicy) -> AgentPolicy:
    """Ensure *service_actions* is populated from the raw input.

    Handles three input shapes:
    - legacy list  → ``services=[\"openai\"]``  (all actions, agent max_ttl)
    - v2 dict      → ``services={\"openai\": {\"actions\": [...]}}``
    - already-normalized → ``service_actions`` already populated
    """
    if agent.service_actions:
        return agent  # already v2

    if not agent.services:
        return agent.model_copy(update={"service_actions": {}})

    # If services is a flat list (legacy), build service_actions.
    # If it was a dict (v2 raw input), services was already converted
    # to a list by _preprocess_policy and service_actions was set there.
    entry = ServicePolicyEntry(
        actions=list(ALL_SERVICE_ACTIONS),
        max_ttl_seconds=None,  # inherit agent-level
    )
    sa = {s: entry for s in agent.services}
    return agent.model_copy(update={"service_actions": sa})


def _preprocess_policy(raw: dict) -> dict:
    """Convert v2 ``services: {name: {actions: …}}`` to normalised intermediate form.

    Also converts ``capabilities: [list_credentials, …]`` string list to
    ``AgentCapability`` enums before Pydantic validation.

    Legacy ``services: [name, …]`` dicts pass through unchanged.
    """
    agents = raw.get("agents", {})
    for _agent_id, agent_data in agents.items():
        svc = agent_data.get("services")
        if isinstance(svc, dict):
            # v2 format — convert to service_actions
            sa: dict = {}
            for svc_name, entry_data in svc.items():
                actions_raw = entry_data.get("actions", [])
                actions = [ServiceAction(a) for a in actions_raw]
                sa[svc_name] = ServicePolicyEntry(
                    actions=actions,
                    max_ttl_seconds=entry_data.get("max_ttl_seconds"),
                )
            agent_data["service_actions"] = sa
            agent_data["services"] = list(svc.keys())
        # legacy list passes through as-is
        # capabilities: convert string list to AgentCapability enums
        caps_raw = agent_data.get("capabilities", [])
        if caps_raw and isinstance(caps_raw[0], str):
            agent_data["capabilities"] = [AgentCapability(c) for c in caps_raw]
    return raw


def _normalize_policy(config: PolicyConfig) -> PolicyConfig:
    """Normalize all service references in a PolicyConfig to canonical IDs.

    Returns a new PolicyConfig with service names normalized.  The original
    is not mutated (Pydantic models are immutable by default).
    """
    normalized_agents: dict[str, AgentPolicy] = {}
    for agent_id, policy in config.agents.items():
        policy = _normalize_agent_services(policy)
        normalized_agents[agent_id] = policy.model_copy(
            update={
                "services": [normalize(s) for s in policy.services],
                "approval_required_services": [
                    normalize(s) for s in policy.approval_required_services
                ],
                "service_actions": {
                    normalize(k): v for k, v in policy.service_actions.items()
                },
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
        raw = _preprocess_policy(raw)
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

    def can(self, agent_id: str, service: str, action: str | ServiceAction) -> tuple[bool, str]:
        """Action-aware permission check (policy v2).

        Falls back to legacy service-list check when no per-service
        actions are defined.
        """
        service = normalize(service)
        agent = self.get_agent_policy(agent_id)
        if not agent:
            return False, f"agent '{agent_id}' is not defined in policy"
        if service not in agent.services:
            return False, f"service '{service}' is not allowed for agent '{agent_id}'"
        if agent.service_actions:
            entry = agent.service_actions.get(service)
            if not entry:
                return False, f"service '{service}' is not allowed for agent '{agent_id}'"
            act = ServiceAction(action) if isinstance(action, str) else action
            if act not in entry.actions:
                return (
                    False,
                    f"action '{act.value}' not permitted on service '{service}' for agent '{agent_id}'",
                )
        # Legacy: no per-service action restrictions — any action allowed.
        return True, "allowed by policy"

    def can_capability(self, agent_id: str, capability: str | AgentCapability) -> tuple[bool, str]:
        """Check whether an agent has a non-service-scoped capability.

        Capabilities cover actions that aren't naturally scoped to a single
        service — e.g. ``list_credentials``, ``scan_secrets``,
        ``export_backup``, ``import_credentials``.

        Backward compatibility: if the agent's ``capabilities`` list is empty
        (i.e. the policy predates capability support), all capabilities are
        implicitly allowed.
        """
        agent = self.get_agent_policy(agent_id)
        if not agent:
            return False, f"agent '{agent_id}' is not defined in policy"
        cap = AgentCapability(capability) if isinstance(capability, str) else capability
        # Empty capabilities list = legacy policy → allow all (backward compat).
        if not agent.capabilities:
            return True, "allowed by policy (implicit — legacy agent)"
        if cap in agent.capabilities:
            return True, "allowed by policy"
        return False, f"capability '{cap.value}' not granted to agent '{agent_id}'"

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

    def enforce_ttl(self, agent_id: str, requested_ttl: int, service: str | None = None) -> tuple[bool, str, int]:
        agent = self.get_agent_policy(agent_id)
        if not agent:
            return False, f"agent '{agent_id}' is not defined in policy", 0
        if requested_ttl <= 0:
            return False, "ttl must be greater than zero", 0
        ceiling = agent.max_ttl_seconds
        if service and agent.service_actions:
            entry = agent.service_actions.get(normalize(service))
            if entry and entry.max_ttl_seconds is not None:
                ceiling = min(ceiling, entry.max_ttl_seconds)
        effective = min(requested_ttl, ceiling)
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

    def suggest_v2_migration(self, agent_id: str) -> dict | None:
        """Return a v2 ``services`` dict snippet for the given agent, or *None*
        if the agent is not found or already uses v2 format."""
        agent = self.get_agent_policy(agent_id)
        if not agent:
            return None
        # If service_actions has entries with restricted actions (not all), it's already v2.
        if agent.service_actions and any(
            len(e.actions) < len(ALL_SERVICE_ACTIONS) for e in agent.service_actions.values()
        ):
            return None
        # Build a v2 snippet with all actions and no per-service TTL.
        return {
            svc: {"actions": [a.value for a in ALL_SERVICE_ACTIONS]}
            for svc in agent.services
        }
