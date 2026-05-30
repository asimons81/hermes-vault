"""Device-code OAuth login flow for Hermes Vault."""

from __future__ import annotations

import time
from typing import Callable

from rich.console import Console

from hermes_vault.oauth.errors import (
    OAuthDeniedError,
    OAuthMissingClientIdError,
    OAuthProviderError,
    OAuthTimeoutError,
)
from hermes_vault.oauth.exchange import TokenExchanger
from hermes_vault.oauth.flow import _store_oauth_tokens
from hermes_vault.oauth.providers import OAuthProviderRegistry
from hermes_vault.vault import Vault


class DeviceLoginFlow:
    """Executes a device-code OAuth login flow.

    The flow is explicit and browser-free, so it is safe to use on devices
    that cannot open a browser or when operators prefer a manual approval step.
    """

    def __init__(
        self,
        provider_id: str,
        alias: str = "default",
        timeout: int = 300,
        scopes: list[str] | None = None,
        console: Console | None = None,
        vault: Vault | None = None,
        mutations=None,
        registry: OAuthProviderRegistry | None = None,
        sleep_fn: Callable[[float], None] | None = None,
        clock_fn: Callable[[], float] | None = None,
    ) -> None:
        self.provider_id = provider_id
        self.alias = alias
        self.timeout = timeout
        self.scopes = scopes or []
        self.console = console or Console()
        self.vault = vault
        self.mutations = mutations
        self._registry = registry
        self.sleep_fn = sleep_fn or time.sleep
        self.clock_fn = clock_fn or time.monotonic

    @property
    def registry(self) -> OAuthProviderRegistry:
        if self._registry is None:
            from hermes_vault.config import get_settings

            settings = get_settings()
            self._registry = OAuthProviderRegistry(
                settings.runtime_home / "oauth-providers.yaml",
            )
        return self._registry

    def run(self) -> None:
        """Execute the full device-code login flow."""
        provider = self.registry.get(self.provider_id)
        if provider is None:
            known = self.registry.list_providers()
            raise OAuthProviderError(
                f"Unknown OAuth provider '{self.provider_id}'. "
                f"Known providers: {', '.join(known) or 'none'}"
            )

        if provider.device_authorization_endpoint is None:
            supported = self.registry.list_device_code_providers()
            raise OAuthProviderError(
                f"Provider '{provider.service_id}' does not support device-code login. "
                f"Supported providers: {', '.join(supported) or 'none'}. "
                f"Use `hermes-vault oauth login {provider.service_id} --alias {self.alias} --no-browser` "
                "for browser callback fallback."
            )

        client_id, client_secret = self.registry.get_client_credentials(provider)
        if provider.requires_client_id and not client_id:
            raise OAuthMissingClientIdError(
                f"Provider '{provider.service_id}' requires a client_id. "
                f"Set HERMES_VAULT_OAUTH_{provider.service_id.upper()}_CLIENT_ID, "
                f"then run `hermes-vault oauth doctor {provider.service_id}`."
            )

        requested_scopes = self.scopes if self.scopes else provider.default_scopes
        scope_str = provider.scope_separator.join(requested_scopes)
        exchanger = TokenExchanger(provider)

        with self.console.status("[bold green]Requesting device-code login...", spinner="dots"):
            device_response = exchanger.request_device_code(
                client_id=client_id or "",
                scope=scope_str,
                client_secret=client_secret,
                extra_params=getattr(provider, "device_extra_params", None) or None,
            )

        if device_response.message:
            self.console.print(device_response.message)
        else:
            self.console.print(
                f"Visit [bold cyan]{device_response.verification_uri}[/bold cyan] and enter code "
                f"[bold]{device_response.user_code}[/bold]."
            )
        if device_response.verification_uri_complete:
            self.console.print(
                f"Direct link: {device_response.verification_uri_complete}"
            )
        self.console.print(
            f"Polling every {max(1, device_response.interval)}s for up to {self.timeout}s."
        )

        poll_interval = max(1, device_response.interval or 5)
        deadline = self.clock_fn() + self.timeout
        token_response = None

        while True:
            if self.clock_fn() >= deadline:
                raise OAuthTimeoutError(
                    f"Timed out after {self.timeout}s. Device authorization was not completed."
                )

            poll_result = exchanger.poll_device_code(
                device_code=device_response.device_code,
                client_id=client_id or "",
                client_secret=client_secret,
            )

            if poll_result.status == "success":
                token_response = poll_result.token_response
                assert token_response is not None
                break

            if poll_result.status == "authorization_pending":
                self.console.print("[yellow]Waiting for device authorization...[/yellow]")
            elif poll_result.status == "slow_down":
                poll_interval += poll_result.retry_after or 5
                self.console.print(
                    f"[yellow]Provider asked us to slow down. Polling every {poll_interval}s.[/yellow]"
                )
            elif poll_result.status == "access_denied":
                raise OAuthDeniedError("Authorization denied by user or provider.")
            elif poll_result.status == "expired_token":
                raise OAuthTimeoutError(
                    "Device code expired before authorization completed."
                )
            else:
                raise OAuthProviderError(
                    f"Device token polling failed: {poll_result.status} — {poll_result.error_description or ''}"
                )

            remaining = deadline - self.clock_fn()
            if remaining <= 0:
                raise OAuthTimeoutError(
                    f"Timed out after {self.timeout}s. Device authorization was not completed."
                )
            self.sleep_fn(min(poll_interval, remaining))

        if not self.mutations or not self.vault:
            vault, _policy, _broker, mutations = self._build_services()
            self.vault = vault
            self.mutations = mutations

        record = _store_oauth_tokens(
            provider=provider,
            alias=self.alias,
            requested_scopes=requested_scopes,
            token_response=token_response,
            vault=self.vault,
            mutations=self.mutations,
            console=self.console,
        )

        msg = (
            f"Stored OAuth credential [cyan]{record.id}[/cyan] "
            f"for [bold]{provider.service_id}[/bold] alias '{self.alias}'."
        )
        self.console.print(f"[green]{msg}[/green]")
        if token_response.expires_in:
            self.console.print(
                f"[yellow]Access token expires in {token_response.expires_in}s. "
                f"Run `hermes-vault oauth refresh {provider.service_id} --alias {self.alias}` before expiry.[/yellow]"
            )

    def _build_services(self) -> tuple:
        from hermes_vault.cli import build_services

        return build_services(prompt=True)
