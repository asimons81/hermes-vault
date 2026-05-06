"""Token exchange with the provider's token endpoint."""

from __future__ import annotations

from typing import Any

import requests

from hermes_vault.models import CredentialSecret
from hermes_vault.oauth.errors import OAuthNetworkError, OAuthProviderError
from hermes_vault.oauth.providers import OAuthProvider


class TokenResponse:
    """Response from a successful token exchange."""

    def __init__(
        self,
        access_token: str,
        token_type: str,
        expires_in: int | None,
        refresh_token: str | None,
        scope: str | None,
        raw: dict[str, Any],
    ) -> None:
        self.access_token = access_token
        self.token_type = token_type
        self.expires_in = expires_in
        self.refresh_token = refresh_token
        self.scope = scope
        self.raw = raw

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "TokenResponse":
        return cls(
            access_token=data.get("access_token", ""),
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in"),
            refresh_token=data.get("refresh_token"),
            scope=data.get("scope"),
            raw=data,
        )

    def to_credential_secret(self, provider: OAuthProvider) -> CredentialSecret:
        """Build a CredentialSecret from this token response."""
        metadata: dict[str, Any] = {
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "raw_response": self.raw,
            "provider": provider.service_id,
        }
        if self.scope is not None:
            metadata["scope"] = self.scope
        return CredentialSecret(secret=self.access_token, metadata=metadata)


class TokenExchanger:
    """POST authorization codes to a provider's token endpoint."""

    def __init__(self, provider: OAuthProvider) -> None:
        self.provider = provider

    def exchange(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> TokenResponse:
        """Exchange an authorization code for tokens.

        Args:
            code: The authorization code from the callback.
            redirect_uri: The redirect URI used in the auth request.
            code_verifier: The PKCE code_verifier.
            client_id: Optional OAuth client ID.
            client_secret: Optional OAuth client secret.

        Raises:
            OAuthNetworkError: On connection or timeout errors.
            OAuthProviderError: When the token endpoint returns an error.
        """
        payload: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }
        if client_id is not None:
            payload["client_id"] = client_id
        if client_secret is not None:
            payload["client_secret"] = client_secret

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        try:
            resp = requests.post(
                str(self.provider.token_endpoint),
                data=payload,
                headers=headers,
                timeout=30,
            )
        except requests.RequestException as exc:
            raise OAuthNetworkError(f"Token exchange failed: {exc}") from exc

        try:
            data = resp.json()
        except Exception:
            # Some legacy endpoints send URL-encoded text
            data = _parse_url_encoded_body(resp.text)

        if "error" in data:
            raise OAuthProviderError(
                f"Token endpoint error: {data.get('error')} — {data.get('error_description', '')}"
            )

        if not resp.ok:
            raise OAuthProviderError(
                f"Token endpoint error: HTTP {resp.status_code} — {resp.text}"
            )

        access_token = data.get("access_token")
        if not access_token:
            raise OAuthProviderError("Token endpoint response missing access_token")

        return TokenResponse.from_json(data)


def _parse_url_encoded_body(text: str) -> dict[str, str]:
    """Best-effort parse for URL-encoded responses (e.g., GitHub legacy)."""
    from urllib.parse import parse_qs
    result = parse_qs(text.strip())
    return {k: v[0] if len(v) == 1 else " ".join(v) for k, v in result.items()}
