"""OAuth provider registry and model.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, HttpUrl, ValidationError


class OAuthProvider(BaseModel):
    """Configuration for a single OAuth identity provider."""

    service_id: str
    name: str
    authorization_endpoint: HttpUrl
    token_endpoint: HttpUrl
    default_scopes: list[str] = Field(default_factory=list)
    scope_separator: str = " "
    use_pkce: bool = True
    extra_params: dict[str, str] = Field(default_factory=dict)
    requires_client_id: bool = False
    requires_client_secret: bool = False


class OAuthProviderRegistry:
    """Lightweight YAML-backed registry of OAuth providers.

    Loads from a user-writable config file, seeding from baked-in defaults
    on first use. Allows operators to add custom providers without code changes.
    """

    def __init__(
        self,
        path: Path,
        defaults_path: Path | None = None,
    ) -> None:
        self._path = path
        self._defaults_path = defaults_path
        self._providers: dict[str, OAuthProvider] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            self._seed_defaults()
        data: dict[str, Any] = {}
        if self._path.exists():
            try:
                raw = yaml.safe_load(self._path.read_text(encoding="utf-8")) or {}
                data = raw.get("providers", {})
            except Exception:
                data = {}
        for sid, item in data.items():
            if not isinstance(item, dict):
                continue
            try:
                cloned = copy.deepcopy(item)
                cloned["service_id"] = sid
                provider = OAuthProvider.model_validate(cloned)
                self._providers[sid] = provider
            except ValidationError:
                continue

    def _seed_defaults(self) -> None:
        """Copy baked-in defaults to the user config path."""
        if self._defaults_path and self._defaults_path.exists():
            defaults_text = self._defaults_path.read_text(encoding="utf-8")
        else:
            defaults_text = DEFAULT_PROVIDERS_YAML
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(defaults_text, encoding="utf-8")
        self._path.chmod(0o600)

    def get(self, service: str) -> OAuthProvider | None:
        """Look up a provider by canonical service ID."""
        return self._providers.get(service.lower())

    def list_providers(self) -> list[str]:
        """Return sorted list of registered provider IDs."""
        return sorted(self._providers.keys())

    def get_client_credentials(self, provider: OAuthProvider) -> tuple[str | None, str | None]:
        """Read client_id and client_secret from environment variables.

        Naming convention:
            HERMES_VAULT_OAUTH_\u003cPROVIDER\u003e_CLIENT_ID
            HERMES_VAULT_OAUTH_\u003cPROVIDER\u003e_CLIENT_SECRET

        Example: HERMES_VAULT_OAUTH_GOOGLE_CLIENT_ID
        """
        prefix = f"HERMES_VAULT_OAUTH_{provider.service_id.upper()}_"
        client_id = os.environ.get(f"{prefix}CLIENT_ID")
        client_secret = os.environ.get(f"{prefix}CLIENT_SECRET")
        return client_id, client_secret


DEFAULT_PROVIDERS_YAML = '''\
providers:
  google:
    name: "Google"
    authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint: "https://oauth2.googleapis.com/token"
    default_scopes:
      - "openid"
      - "email"
    scope_separator: " "
    use_pkce: true
    extra_params:
      access_type: "offline"
      prompt: "consent"
    requires_client_id: true

  github:
    name: "GitHub"
    authorization_endpoint: "https://github.com/login/oauth/authorize"
    token_endpoint: "https://github.com/login/oauth/access_token"
    default_scopes:
      - "repo"
      - "read:org"
    scope_separator: " "
    use_pkce: true
    extra_params: {}
    requires_client_id: true
    requires_client_secret: true

  openai:
    name: "OpenAI"
    authorization_endpoint: "https://auth.openai.com/oauth/authorize"
    token_endpoint: "https://auth.openai.com/oauth/token"
    default_scopes:
      - "api_access"
    scope_separator: " "
    use_pkce: true
    extra_params: {}
    requires_client_id: false
'''
