"""Tests for the explicit OAuth device-code login flow."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hermes_vault.models import CredentialRecord, MutationResult
from hermes_vault.oauth.device import DeviceLoginFlow
from hermes_vault.oauth.errors import OAuthDeniedError, OAuthProviderError, OAuthTimeoutError
from hermes_vault.oauth.exchange import DeviceAuthorizationResponse, DevicePollResult, TokenExchanger, TokenResponse
from hermes_vault.oauth.oauth_refresh import refresh_alias_for
from hermes_vault.oauth.providers import OAuthProvider, OAuthProviderRegistry


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class _FakeRegistry:
    def __init__(self, provider: OAuthProvider, client_id: str = "test-client-id", client_secret: str | None = None) -> None:
        self._provider = provider
        self.get = MagicMock(return_value=provider)
        self.list_providers = MagicMock(return_value=[provider.service_id])
        self.list_device_code_providers = MagicMock(
            return_value=[provider.service_id] if provider.device_authorization_endpoint else []
        )
        self.get_client_credentials = MagicMock(return_value=(client_id, client_secret))


class _FakeMutations:
    def __init__(self, record_id: str = "cred-123") -> None:
        self.record_id = record_id
        self.calls: list[dict] = []

    def add_credential(self, **kwargs):
        self.calls.append(kwargs)
        record = CredentialRecord(
            id=self.record_id,
            service=kwargs["service"],
            alias=kwargs["alias"],
            credential_type=kwargs["credential_type"],
            encrypted_payload="encrypted",
            scopes=kwargs.get("scopes") or [],
        )
        return MutationResult(
            allowed=True,
            service=kwargs["service"],
            agent_id=kwargs["agent_id"],
            action="add_credential",
            reason="ok",
            record=record,
        )


class _FakeVault:
    def __init__(self) -> None:
        self.set_expiry = MagicMock(return_value=None)


@pytest.fixture
def device_provider() -> OAuthProvider:
    return OAuthProvider(
        service_id="google",
        name="Google",
        authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
        device_authorization_endpoint="https://oauth2.googleapis.com/device/code",
        token_endpoint="https://oauth2.googleapis.com/token",
        default_scopes=["openid", "email"],
        requires_client_id=True,
    )


class TestOAuthProviderRegistryDeviceSupport:
    def test_default_registry_lists_device_code_providers(self, tmp_path: Path) -> None:
        registry = OAuthProviderRegistry(tmp_path / "providers.yaml")

        providers = registry.list_device_code_providers()

        assert "google" in providers
        assert "github" in providers
        assert "openai" not in providers

    def test_packaged_default_yaml_lists_device_code_providers(self, tmp_path: Path) -> None:
        defaults_path = Path(__file__).resolve().parents[1] / "data" / "oauth-default-providers.yaml"
        registry = OAuthProviderRegistry(tmp_path / "providers.yaml", defaults_path=defaults_path)

        providers = registry.list_device_code_providers()

        assert "google" in providers
        assert "github" in providers
        assert "openai" not in providers


class TestDeviceCodeExchange:
    def test_request_device_code_builds_payload(self, device_provider: OAuthProvider) -> None:
        exchanger = TokenExchanger(device_provider)
        fake_resp = MagicMock()
        fake_resp.ok = True
        fake_resp.json.return_value = {
            "device_code": "dev-123",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://example.com/device",
            "verification_uri_complete": "https://example.com/device?user_code=ABCD-EFGH",
            "expires_in": 900,
            "interval": 5,
            "message": "Visit the URL and enter the code.",
        }
        fake_resp.status_code = 200
        fake_resp.text = ""

        with patch("hermes_vault.oauth.exchange.requests.post", return_value=fake_resp) as mock_post:
            response = exchanger.request_device_code(client_id="client-123", scope="openid email")

        assert isinstance(response, DeviceAuthorizationResponse)
        assert response.device_code == "dev-123"
        assert response.user_code == "ABCD-EFGH"
        assert response.verification_uri == "https://example.com/device"
        assert response.verification_uri_complete == "https://example.com/device?user_code=ABCD-EFGH"
        assert response.expires_in == 900
        assert response.interval == 5
        assert response.message == "Visit the URL and enter the code."

        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["data"]["client_id"] == "client-123"
        assert call_kwargs["data"]["scope"] == "openid email"
        assert "grant_type" not in call_kwargs["data"]

    def test_poll_device_code_parses_pending_slow_down_and_success(self, device_provider: OAuthProvider) -> None:
        exchanger = TokenExchanger(device_provider)
        pending_resp = MagicMock()
        pending_resp.ok = False
        pending_resp.json.return_value = {"error": "authorization_pending"}
        pending_resp.status_code = 400
        pending_resp.text = ""

        slow_resp = MagicMock()
        slow_resp.ok = False
        slow_resp.json.return_value = {"error": "slow_down", "error_description": "poll slower"}
        slow_resp.status_code = 400
        slow_resp.text = ""

        success_resp = MagicMock()
        success_resp.ok = True
        success_resp.json.return_value = {
            "access_token": "tok",
            "token_type": "Bearer",
            "refresh_token": "ref",
            "scope": "openid email",
        }
        success_resp.status_code = 200
        success_resp.text = ""

        with patch(
            "hermes_vault.oauth.exchange.requests.post",
            side_effect=[pending_resp, slow_resp, success_resp],
        ):
            pending = exchanger.poll_device_code(device_code="dev-123", client_id="client-123")
            slow = exchanger.poll_device_code(device_code="dev-123", client_id="client-123")
            success = exchanger.poll_device_code(device_code="dev-123", client_id="client-123")

        assert pending.status == "authorization_pending"
        assert slow.status == "slow_down"
        assert slow.retry_after == 5
        assert success.status == "success"
        assert success.token_response is not None
        assert success.token_response.access_token == "tok"


class TestDeviceLoginFlow:
    def test_device_login_flow_stores_access_and_refresh_tokens(self, device_provider: OAuthProvider) -> None:
        registry = _FakeRegistry(device_provider)
        vault = _FakeVault()
        mutations = _FakeMutations()
        console = MagicMock()
        clock = _FakeClock()

        device_auth = DeviceAuthorizationResponse(
            device_code="dev-123",
            user_code="ABCD-EFGH",
            verification_uri="https://example.com/device",
            verification_uri_complete="https://example.com/device?user_code=ABCD-EFGH",
            expires_in=900,
            interval=2,
            message="Visit the URL and enter the code.",
            raw={"device_code": "dev-123"},
        )
        poll_results = [
            DevicePollResult(status="authorization_pending", raw={"error": "authorization_pending"}),
            DevicePollResult(status="slow_down", retry_after=5, raw={"error": "slow_down"}),
            DevicePollResult(
                status="success",
                token_response=TokenResponse(
                    access_token="atok-123",
                    token_type="Bearer",
                    expires_in=3600,
                    refresh_token="rtok-456",
                    scope="openid email",
                    raw={"access_token": "atok-123"},
                ),
                raw={"access_token": "atok-123"},
            ),
        ]

        with patch("hermes_vault.oauth.device.TokenExchanger.request_device_code", return_value=device_auth) as request_mock, patch(
            "hermes_vault.oauth.device.TokenExchanger.poll_device_code",
            side_effect=poll_results,
        ) as poll_mock:
            flow = DeviceLoginFlow(
                provider_id="google",
                alias="work",
                timeout=30,
                vault=vault,
                mutations=mutations,
                registry=registry,
                console=console,
                sleep_fn=clock.sleep,
                clock_fn=clock.monotonic,
            )
            flow.run()

        request_mock.assert_called_once()
        assert poll_mock.call_count == 3
        assert clock.now == pytest.approx(9.0)
        assert vault.set_expiry.call_count == 1
        assert len(mutations.calls) == 2

        access_call = mutations.calls[0]
        assert access_call["credential_type"] == "oauth_access_token"
        assert access_call["alias"] == "work"
        assert access_call["scopes"] == ["openid", "email"]
        assert access_call["metadata"]["provider"] == "google"
        assert access_call["metadata"]["token_type"] == "Bearer"
        assert access_call["metadata"]["scopes"] == ["openid", "email"]
        assert "refresh_token" not in access_call["metadata"]
        assert "raw_response" not in access_call["metadata"]

        refresh_call = mutations.calls[1]
        assert refresh_call["credential_type"] == "oauth_refresh_token"
        assert refresh_call["alias"] == refresh_alias_for("work")
        assert refresh_call["secret"] == "rtok-456"
        assert refresh_call["metadata"]["provider"] == "google"
        assert refresh_call["metadata"]["associated_access_token_alias"] == "work"

    def test_device_login_flow_rejects_unsupported_provider(self) -> None:
        provider = OAuthProvider(
            service_id="openai",
            name="OpenAI",
            authorization_endpoint="https://auth.openai.com/oauth/authorize",
            token_endpoint="https://auth.openai.com/oauth/token",
            default_scopes=["api_access"],
        )
        registry = _FakeRegistry(provider)
        console = MagicMock()

        with pytest.raises(OAuthProviderError) as exc_info:
            DeviceLoginFlow(
                provider_id="openai",
                alias="default",
                timeout=10,
                vault=_FakeVault(),
                mutations=_FakeMutations(),
                registry=registry,
                console=console,
            ).run()

        assert "does not support device-code login" in str(exc_info.value)
        assert "google" not in str(exc_info.value)

    def test_device_login_flow_access_denied_raises(self, device_provider: OAuthProvider) -> None:
        registry = _FakeRegistry(device_provider)
        console = MagicMock()

        device_auth = DeviceAuthorizationResponse(
            device_code="dev-123",
            user_code="ABCD-EFGH",
            verification_uri="https://example.com/device",
            verification_uri_complete=None,
            expires_in=900,
            interval=1,
            message=None,
            raw={"device_code": "dev-123"},
        )
        poll_results = [
            DevicePollResult(status="authorization_pending", raw={"error": "authorization_pending"}),
            DevicePollResult(status="access_denied", error_description="user refused", raw={"error": "access_denied"}),
        ]

        with patch("hermes_vault.oauth.device.TokenExchanger.request_device_code", return_value=device_auth), patch(
            "hermes_vault.oauth.device.TokenExchanger.poll_device_code",
            side_effect=poll_results,
        ):
            flow = DeviceLoginFlow(
                provider_id="google",
                alias="default",
                timeout=10,
                vault=_FakeVault(),
                mutations=_FakeMutations(),
                registry=registry,
                console=console,
                sleep_fn=lambda _: None,
                clock_fn=lambda: 0.0,
            )
            with pytest.raises(OAuthDeniedError):
                flow.run()

    def test_device_login_flow_expired_token_raises_timeout(self, device_provider: OAuthProvider) -> None:
        registry = _FakeRegistry(device_provider)
        console = MagicMock()

        device_auth = DeviceAuthorizationResponse(
            device_code="dev-123",
            user_code="ABCD-EFGH",
            verification_uri="https://example.com/device",
            verification_uri_complete=None,
            expires_in=900,
            interval=1,
            message=None,
            raw={"device_code": "dev-123"},
        )
        poll_results = [
            DevicePollResult(status="expired_token", error_description="expired", raw={"error": "expired_token"}),
        ]

        with patch("hermes_vault.oauth.device.TokenExchanger.request_device_code", return_value=device_auth), patch(
            "hermes_vault.oauth.device.TokenExchanger.poll_device_code",
            side_effect=poll_results,
        ):
            flow = DeviceLoginFlow(
                provider_id="google",
                alias="default",
                timeout=10,
                vault=_FakeVault(),
                mutations=_FakeMutations(),
                registry=registry,
                console=console,
                sleep_fn=lambda _: None,
                clock_fn=lambda: 0.0,
            )
            with pytest.raises(OAuthTimeoutError):
                flow.run()
