from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from hermes_vault.models import AgentCapability, AgentPolicy, PolicyConfig, ServiceAction, ServicePolicyEntry

PACK_NAMES = ("coder", "auditor", "operator")


def _pack(service_actions: dict[str, list[ServiceAction]], *, max_ttl_seconds: int, capabilities: list[AgentCapability] | None = None) -> dict[str, Any]:
    agent = AgentPolicy(
        services=sorted(service_actions),
        capabilities=capabilities or [AgentCapability.list_credentials],
        raw_secret_access=False,
        ephemeral_env_only=True,
        require_verification_before_reauth=True,
        max_ttl_seconds=max_ttl_seconds,
        service_actions={
            service: ServicePolicyEntry(actions=actions, max_ttl_seconds=max_ttl_seconds)
            for service, actions in service_actions.items()
        },
    )
    config = PolicyConfig(
        agents={"hermes": agent},
        managed_paths=["~/.hermes", "~/.config/hermes"],
        plaintext_migration_paths=[],
        plaintext_exempt_paths=[],
        deny_plaintext_under_managed_paths=True,
    )
    return config.model_dump(mode="json")


PACKS: dict[str, dict[str, Any]] = {
    "coder": _pack(
        {
            "openai": [ServiceAction.get_env, ServiceAction.get_credential, ServiceAction.metadata, ServiceAction.verify, ServiceAction.issue_lease, ServiceAction.list_leases, ServiceAction.show_lease, ServiceAction.renew_lease],
            "anthropic": [ServiceAction.get_env, ServiceAction.get_credential, ServiceAction.metadata, ServiceAction.verify, ServiceAction.issue_lease, ServiceAction.list_leases, ServiceAction.show_lease, ServiceAction.renew_lease],
            "github": [ServiceAction.get_env, ServiceAction.get_credential, ServiceAction.metadata, ServiceAction.verify, ServiceAction.issue_lease, ServiceAction.list_leases, ServiceAction.show_lease, ServiceAction.renew_lease],
        },
        max_ttl_seconds=1800,
    ),
    "auditor": _pack(
        {
            "openai": [ServiceAction.metadata, ServiceAction.verify, ServiceAction.list_leases, ServiceAction.show_lease],
            "anthropic": [ServiceAction.metadata, ServiceAction.verify, ServiceAction.list_leases, ServiceAction.show_lease],
            "github": [ServiceAction.metadata, ServiceAction.verify, ServiceAction.list_leases, ServiceAction.show_lease],
        },
        max_ttl_seconds=900,
    ),
    "operator": _pack(
        {
            "openai": [ServiceAction.get_env, ServiceAction.get_credential, ServiceAction.metadata, ServiceAction.verify, ServiceAction.issue_lease, ServiceAction.list_leases, ServiceAction.show_lease, ServiceAction.renew_lease, ServiceAction.revoke_lease],
            "anthropic": [ServiceAction.get_env, ServiceAction.get_credential, ServiceAction.metadata, ServiceAction.verify, ServiceAction.issue_lease, ServiceAction.list_leases, ServiceAction.show_lease, ServiceAction.renew_lease, ServiceAction.revoke_lease],
            "github": [ServiceAction.get_env, ServiceAction.get_credential, ServiceAction.metadata, ServiceAction.verify, ServiceAction.issue_lease, ServiceAction.list_leases, ServiceAction.show_lease, ServiceAction.renew_lease, ServiceAction.revoke_lease],
        },
        max_ttl_seconds=3600,
    ),
}


def list_policy_packs() -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "description": {
                "coder": "General-purpose builder with lease issuance and env access.",
                "auditor": "Read-mostly reviewer with metadata and lease visibility.",
                "operator": "Broad operational access with explicit lease revocation.",
            }[name],
        }
        for name in PACK_NAMES
    ]


def get_policy_pack(name: str) -> dict[str, Any]:
    try:
        return deepcopy(PACKS[name])
    except KeyError as exc:
        raise ValueError(f"unknown policy pack: {name}") from exc


def render_policy_pack_yaml(name: str) -> str:
    return yaml.safe_dump(get_policy_pack(name), sort_keys=False)


def write_policy_pack(name: str, output_path: Path, *, force: bool = False) -> Path:
    if output_path.exists() and not force:
        raise FileExistsError(f"refusing to overwrite existing policy file: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_policy_pack_yaml(name), encoding="utf-8")
    return output_path
