"""Token exchange with the provider's token endpoint."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import requests

from hermes_vault.models import CredentialSecret, utc_now
from hermes_vault.oauth.errors import OAuthNetworkError, OAuthProviderError, format_oauth_provider_error
from hermes_vault.oauth.providers import OAuthProvider


@dataclass(slots=True)
class TokenResponse:
    """Response from a successful token exchange."""

    access_token: str
    token_type: str
    expires_in: int | None
    refresh_token: str | None
    scope: str | None
    raw: dict[str, Any]

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
        """Build a CredentialSecret from this token response.

        The stored metadata is intentionally sanitized: it never includes the
        refresh token or the raw provider response payload.
        """
        issued_at = utc_now()
        metadata: dict[str, Any] = {
            "token_type": self.token_type,
            "provider": provider.service_id,
            "issued_at": issued_at.isoformat(),
        }
        if self.expires_in is not None:
            metadata["expires_at"] = (issued_at + timedelta(seconds=self.expires_in)).isoformat()
        scopes = _parse_scope_list(self.scope)
        if scopes:
            metadata["scopes"] = scopes
        return CredentialSecret(secret=self.access_token, metadata=metadata)


@dataclass(slots=True)
class DeviceAuthorizationResponse:
    """Response returned by a device-code authorization endpoint."""

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str | None
    expires_in: int
    interval: int
    message: str | None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DevicePollResult:
    """Response returned by a device-code token polling request."""

    status: str
    token_response: TokenResponse | None = None
    error_description: str | None = None
    retry_after: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)


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

        data = _parse_response_payload(resp)

        if "error" in data:
            raise OAuthProviderError(
                format_oauth_provider_error(
                    f"Token endpoint error: {data.get('error')}",
                    data.get("error_description", ""),
                )
            )

        if not resp.ok:
            raise OAuthProviderError(
                format_oauth_provider_error(
                    f"Token endpoint error: HTTP {resp.status_code}",
                    resp.text,
                )
            )

        access_token = data.get("access_token")
        if not access_token:
            raise OAuthProviderError("Token endpoint response missing access_token")

        return TokenResponse.from_json(data)

    def request_device_code(
        self,
        *,
        client_id: str,
        scope: str,
        client_secret: str | None = None,
        extra_params: dict[str, str] | None = None,
    ) -> DeviceAuthorizationResponse:
        """Request a device/user code from the provider."""
        if getattr(self.provider, "device_authorization_endpoint", None) is None:
            raise OAuthProviderError(
                f"Provider '{self.provider.service_id}' does not support device-code login."
            )

        payload: dict[str, str] = {
            "client_id": client_id,
            "scope": scope,
        }
        if client_secret is not None:
            payload["client_secret"] = client_secret
        for key, value in (extra_params or {}).items():
            payload[key] = value

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        try:
            resp = requests.post(
                str(self.provider.device_authorization_endpoint),
                data=payload,
                headers=headers,
                timeout=30,
            )
        except requests.RequestException as exc:
            raise OAuthNetworkError(f"Device authorization failed: {exc}") from exc

        data = _parse_response_payload(resp)
        if "error" in data:
            raise OAuthProviderError(
                format_oauth_provider_error(
                    f"Device authorization error: {data.get('error')}",
                    data.get("error_description", ""),
                )
            )

        if not resp.ok:
            raise OAuthProviderError(
                format_oauth_provider_error(
                    f"Device authorization error: HTTP {resp.status_code}",
                    resp.text,
                )
            )

        device_code = data.get("device_code")
        user_code = data.get("user_code")
        verification_uri = data.get("verification_uri") or data.get("verification_url")
        if not device_code or not user_code or not verification_uri:
            raise OAuthProviderError(
                "Device authorization response missing required fields"
            )

        return DeviceAuthorizationResponse(
            device_code=str(device_code),
            user_code=str(user_code),
            verification_uri=str(verification_uri),
            verification_uri_complete=(
                str(data.get("verification_uri_complete"))
                if data.get("verification_uri_complete")
                else None
            ),
            expires_in=_coerce_int(data.get("expires_in"), default=0),
            interval=_coerce_int(data.get("interval"), default=5),
            message=str(data.get("message")) if data.get("message") else None,
            raw=data,
        )

    def poll_device_code(
        self,
        *,
        device_code: str,
        client_id: str,
        client_secret: str | None = None,
    ) -> DevicePollResult:
        """Poll the token endpoint using the device-code grant."""
        payload: dict[str, str] = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": client_id,
        }
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
            raise OAuthNetworkError(f"Device token polling failed: {exc}") from exc

        data = _parse_response_payload(resp)
        error = data.get("error")
        if error == "authorization_pending":
            return DevicePollResult(
                status="authorization_pending",
                error_description=data.get("error_description"),
                raw=data,
            )
        if error == "slow_down":
            return DevicePollResult(
                status="slow_down",
                error_description=data.get("error_description"),
                retry_after=5,
                raw=data,
            )
        if error == "access_denied":
            return DevicePollResult(
                status="access_denied",
                error_description=data.get("error_description"),
                raw=data,
            )
        if error == "expired_token":
            return DevicePollResult(
                status="expired_token",
                error_description=data.get("error_description"),
                raw=data,
            )
        if error:
            raise OAuthProviderError(
                format_oauth_provider_error(
                    f"Token endpoint error: {error}",
                    data.get("error_description", ""),
                )
            )

        if not resp.ok:
            raise OAuthProviderError(
                format_oauth_provider_error(
                    f"Token endpoint error: HTTP {resp.status_code}",
                    resp.text,
                )
            )

        access_token = data.get("access_token")
        if not access_token:
            raise OAuthProviderError("Token endpoint response missing access_token")

        return DevicePollResult(
            status="success",
            token_response=TokenResponse.from_json(data),
            raw=data,
        )


def _parse_url_encoded_body(text: str) -> dict[str, str]:
    """Best-effort parse for URL-encoded responses (e.g., GitHub legacy)."""
    from urllib.parse import parse_qs

    result = parse_qs(text.strip())
    return {k: v[0] if len(v) == 1 else " ".join(v) for k, v in result.items()}


def _parse_response_payload(resp: requests.Response) -> dict[str, Any]:
    try:
        data = resp.json()
    except Exception:
        data = _parse_url_encoded_body(resp.text)
    return data if isinstance(data, dict) else {}


def _coerce_int(value: Any, default: int) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_scope_list(scope: str | None) -> list[str]:
    if not scope:
        return []
    return [item for item in (part.strip() for part in scope.split(" ")) if item]
