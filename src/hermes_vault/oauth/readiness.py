"""Read-only OAuth provider readiness reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hermes_vault.oauth.providers import OAuthProviderRegistry


@dataclass(frozen=True)
class OAuthProviderReadiness:
    provider: str
    configured: bool
    supports_pkce: bool = False
    supports_device_code: bool = False
    missing_env: list[str] = field(default_factory=list)
    default_scopes: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    recommended_commands: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "configured": self.configured,
            "supports_pkce": self.supports_pkce,
            "supports_device_code": self.supports_device_code,
            "missing_env": list(self.missing_env),
            "default_scopes": list(self.default_scopes),
            "findings": list(self.findings),
            "recommended_commands": list(self.recommended_commands),
        }


def provider_readiness(registry: OAuthProviderRegistry, provider_id: str) -> OAuthProviderReadiness:
    provider_key = provider_id.strip().lower()
    provider = registry.get(provider_key)
    if provider is None:
        known = registry.list_providers()
        return OAuthProviderReadiness(
            provider=provider_key,
            configured=False,
            findings=[f"unknown_provider: known providers are {', '.join(known) or 'none'}"],
            recommended_commands=["hermes-vault oauth providers"],
        )

    missing_env: list[str] = []
    client_id, client_secret = registry.get_client_credentials(provider)
    env_prefix = f"HERMES_VAULT_OAUTH_{provider.service_id.upper()}_"
    if provider.requires_client_id and not client_id:
        missing_env.append(f"{env_prefix}CLIENT_ID")
    if provider.requires_client_secret and not client_secret:
        missing_env.append(f"{env_prefix}CLIENT_SECRET")

    findings: list[str] = []
    if missing_env:
        findings.append("missing_required_env")
    if provider.device_authorization_endpoint is None:
        findings.append("device_code_unsupported")

    commands = [
        f"hermes-vault oauth login {provider.service_id} --alias work",
        f"hermes-vault oauth refresh {provider.service_id} --alias work",
    ]
    if provider.device_authorization_endpoint is not None:
        commands.insert(0, f"hermes-vault oauth login {provider.service_id} --alias work --headless")
        commands.insert(1, f"hermes-vault oauth device-login {provider.service_id} --alias work")
    else:
        commands.insert(0, f"hermes-vault oauth login {provider.service_id} --alias work --no-browser")

    return OAuthProviderReadiness(
        provider=provider.service_id,
        configured=len(missing_env) == 0,
        supports_pkce=provider.use_pkce,
        supports_device_code=provider.device_authorization_endpoint is not None,
        missing_env=missing_env,
        default_scopes=list(provider.default_scopes),
        findings=findings,
        recommended_commands=commands,
    )


def all_provider_readiness(registry: OAuthProviderRegistry) -> list[OAuthProviderReadiness]:
    return [provider_readiness(registry, provider_id) for provider_id in registry.list_providers()]
