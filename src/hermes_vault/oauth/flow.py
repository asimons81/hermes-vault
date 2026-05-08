"""High-level PKCE OAuth login flow orchestrator.

Ties together PKCE generation, callback server, browser open, state
validation, token exchange, and vault storage.
"""

from __future__ import annotations

import urllib.parse
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rich.console import Console

from hermes_vault.models import CredentialSecret, CredentialStatus
from hermes_vault.mutations import OPERATOR_AGENT_ID, VaultMutations
from hermes_vault.oauth.callback import CallbackServer
from hermes_vault.oauth.errors import (
    OAuthDeniedError,
    OAuthMissingClientIdError,
    OAuthProviderError,
    OAuthStateMismatchError,
    OAuthTimeoutError,
)
from hermes_vault.oauth.exchange import TokenExchanger
from hermes_vault.oauth.pkce import PKCEGenerator
from hermes_vault.oauth.providers import OAuthProviderRegistry
from hermes_vault.oauth.oauth_refresh import refresh_alias_for
from hermes_vault.oauth.state import StateManager
from hermes_vault.vault import Vault


class LoginFlow:
    """Executes a full browser-interactive PKCE OAuth login."""

    def __init__(
        self,
        provider_id: str,
        alias: str = "default",
        port: int = 0,
        timeout: int = 120,
        no_browser: bool = False,
        scopes: list[str] | None = None,
        console: Console | None = None,
        vault: Vault | None = None,
        mutations: VaultMutations | None = None,
        registry: OAuthProviderRegistry | None = None,
    ) -> None:
        self.provider_id = provider_id
        self.alias = alias
        self.port = port
        self.timeout = timeout
        self.no_browser = no_browser
        self.scopes = scopes or []
        self.console = console or Console()
        self.vault = vault
        self.mutations = mutations
        self._registry = registry

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
        """Execute the full login flow.

        Raises:
            OAuthTimeoutError: callback not received in time.
            OAuthDeniedError: user denied consent.
            OAuthStateMismatchError: CSRF state mismatch.
            OAuthProviderError: token endpoint returned an error.
            OAuthMissingClientIdError: provider requires a client_id.
        """
        # ── 1. Look up provider ──────────────────────────────────────────────
        provider = self.registry.get(self.provider_id)
        if provider is None:
            known = self.registry.list_providers()
            raise OAuthProviderError(
                f"Unknown OAuth provider '{self.provider_id}'. "
                f"Known providers: {', '.join(known) or 'none'}"
            )

        # ── 2. Client credentials ───────────────────────────────────────────
        client_id, client_secret = self.registry.get_client_credentials(provider)
        if provider.requires_client_id and not client_id:
            raise OAuthMissingClientIdError(
                f"Provider '{provider.service_id}' requires a client_id. "
                f"Set HERMES_VAULT_OAUTH_{provider.service_id.upper()}_CLIENT_ID."
            )

        # ── 3. Generate PKCE + state ───────────────────────────────────────
        pkce = PKCEGenerator()
        code_verifier = pkce.generate_verifier()
        code_challenge = pkce.generate_challenge(code_verifier)
        state_manager = StateManager()
        state = state_manager.generate()

        # ── 4. Start callback server ───────────────────────────────────────
        server = CallbackServer(port=self.port, timeout=self.timeout)
        with self.console.status("[bold green]Starting local callback server...", spinner="dots"):
            actual_port = server.start()
        redirect_uri = f"http://127.0.0.1:{actual_port}/callback"

        # ── 5. Build authorization URL ─────────────────────────────────────
        requested_scopes = self.scopes if self.scopes else provider.default_scopes
        scope_str = provider.scope_separator.join(requested_scopes)
        auth_params: dict[str, str] = {
            "response_type": "code",
            "client_id": client_id or "",
            "redirect_uri": redirect_uri,
            "scope": scope_str,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        for k, v in provider.extra_params.items():
            auth_params.setdefault(k, v)

        # Remove empty client_id if not required
        if not client_id and not provider.requires_client_id:
            auth_params.pop("client_id", None)

        auth_url = (
            str(provider.authorization_endpoint)
            + "?"
            + urllib.parse.urlencode(auth_params)
        )

        # ── 6. Open browser ────────────────────────────────────────────────
        if not self.no_browser:
            with self.console.status("[bold green]Opening browser...", spinner="dots"):
                opened = webbrowser.open(auth_url, new=2)
            if not opened:
                self.console.print(
                    f"[yellow]Could not open browser automatically. Open this URL:[/yellow]\n{auth_url}"
                )
        else:
            self.console.print(f"Open this URL in your browser:\n{auth_url}")

        # ── 7. Wait for callback ───────────────────────────────────────────
        with self.console.status("[bold green]Waiting for browser authorization...", spinner="dots"):
            result = server.wait()

        if result.error == "timeout":
            raise OAuthTimeoutError(
                f"Timed out after {self.timeout}s. No authorization callback received."
            )
        if result.error == "access_denied":
            raise OAuthDeniedError("Authorization denied by user or provider.")
        if result.error:
            raise OAuthProviderError(
                f"Authorization failed: {result.error} — {result.error_description or ''}"
            )

        # ── 8. Validate state ─────────────────────────────────────────────
        if not state_manager.validate(result.state):
            raise OAuthStateMismatchError(
                "Security error: state parameter mismatch (possible CSRF). Aborting."
            )

        if not result.code:
            raise OAuthProviderError("No authorization code returned from provider.")

        # ── 9. Exchange code for tokens ────────────────────────────────────
        with self.console.status("[bold green]Exchanging code for tokens...", spinner="dots"):
            exchanger = TokenExchanger(provider)
            token_response = exchanger.exchange(
                code=result.code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
                client_id=client_id,
                client_secret=client_secret,
            )

        if not self.mutations or not self.vault:
            # CLI mode: build services now
            vault, policy, _broker, mutations = self._build_services()
            self.vault = vault
            self.mutations = mutations

        # ── 10. Store in vault ───────────────────────────────────────────
        credential_secret = token_response.to_credential_secret(provider)
        with self.console.status("[bold green]Storing credential...", spinner="dots"):
            result_mutation = self.mutations.add_credential(
                agent_id=OPERATOR_AGENT_ID,
                service=provider.service_id,
                secret=credential_secret.secret,
                credential_type="oauth_access_token",
                alias=self.alias,
                scopes=requested_scopes,
                metadata=credential_secret.metadata,
                replace_existing=True,
            )

        if not result_mutation.allowed:
            raise OAuthProviderError(
                f"Vault refused credential storage: {result_mutation.reason}"
            )

        record = result_mutation.record
        assert record is not None

        # Set expiry if provider returned one
        if token_response.expires_in is not None:
            expiry = datetime.now(timezone.utc) + timedelta(seconds=token_response.expires_in)
            self.vault.set_expiry(record.id, expiry)

        # Store refresh token separately at an alias-scoped refresh record
        if token_response.refresh_token:
            refresh_secret = CredentialSecret(
                secret=token_response.refresh_token,
                metadata={
                    "associated_access_token_alias": self.alias,
                    "provider": provider.service_id,
                },
            )
            self.mutations.add_credential(
                agent_id=OPERATOR_AGENT_ID,
                service=provider.service_id,
                secret=refresh_secret.secret,
                credential_type="oauth_refresh_token",
                alias=refresh_alias_for(self.alias),
                scopes=requested_scopes,
                metadata=refresh_secret.metadata,
                replace_existing=True,
            )

        # ── 11. Success ────────────────────────────────────────────────────
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
