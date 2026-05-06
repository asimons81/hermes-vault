"""Integration tests for OAuth token exchange.

Mocks ``requests.post`` so TokenExchanger.exchange() can be tested without
hitting real OAuth token endpoints.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from hermes_vault.oauth.errors import OAuthNetworkError, OAuthProviderError
from hermes_vault.oauth.exchange import TokenExchanger, TokenResponse, _parse_url_encoded_body
from hermes_vault.oauth.providers import OAuthProvider


@pytest.fixture
def test_provider():
    return OAuthProvider(
        service_id="testprovider",
        name="Test Provider",
        authorization_endpoint="https://example.com/auth",
        token_endpoint="https://example.com/token",
        default_scopes=["openid", "email"],
        requires_client_id=True,
    )


# ── Successful exchange ──────────────────────────────────────────────────────────


class TestTokenExchangerSuccess:
    def test_exchanges_code_for_tokens(self, test_provider):
        exchanger = TokenExchanger(test_provider)
        fake_resp = MagicMock()
        fake_resp.ok = True
        fake_resp.json.return_value = {
            "access_token": "the-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "the-refresh-token",
            "scope": "openid email",
        }
        fake_resp.status_code = 200
        fake_resp.text = ""

        with patch("hermes_vault.oauth.exchange.requests.post", return_value=fake_resp) as mock_post:
            result = exchanger.exchange(
                code="auth-code-123",
                redirect_uri="http://127.0.0.1:65432/callback",
                code_verifier="my-verifier",
                client_id="my-client-id",
                client_secret="my-secret",
            )

        assert isinstance(result, TokenResponse)
        assert result.access_token == "the-access-token"
        assert result.token_type == "Bearer"
        assert result.expires_in == 3600
        assert result.refresh_token == "the-refresh-token"
        assert result.scope == "openid email"

        # Verify POST payload
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["data"]["grant_type"] == "authorization_code"
        assert call_kwargs["data"]["code"] == "auth-code-123"
        assert call_kwargs["data"]["redirect_uri"] == "http://127.0.0.1:65432/callback"
        assert call_kwargs["data"]["code_verifier"] == "my-verifier"
        assert call_kwargs["data"]["client_id"] == "my-client-id"
        assert call_kwargs["data"]["client_secret"] == "my-secret"

    def test_exchange_without_client_secret(self, test_provider):
        exchanger = TokenExchanger(test_provider)
        fake_resp = MagicMock()
        fake_resp.ok = True
        fake_resp.json.return_value = {
            "access_token": "tok",
            "token_type": "Bearer",
        }
        fake_resp.status_code = 200
        fake_resp.text = ""

        with patch("hermes_vault.oauth.exchange.requests.post", return_value=fake_resp) as mock_post:
            result = exchanger.exchange(
                code="c",
                redirect_uri="http://127.0.0.1:1/callback",
                code_verifier="v",
                client_id="id",
                client_secret=None,
            )

        assert result.access_token == "tok"
        data = mock_post.call_args[1]["data"]
        assert "client_secret" not in data

    def test_exchange_without_client_id(self, test_provider):
        exchanger = TokenExchanger(test_provider)
        fake_resp = MagicMock()
        fake_resp.ok = True
        fake_resp.json.return_value = {
            "access_token": "tok",
            "token_type": "Bearer",
        }
        fake_resp.status_code = 200
        fake_resp.text = ""

        with patch("hermes_vault.oauth.exchange.requests.post", return_value=fake_resp) as mock_post:
            result = exchanger.exchange(
                code="c",
                redirect_uri="http://127.0.0.1:1/callback",
                code_verifier="v",
                client_id=None,
                client_secret=None,
            )

        assert result.access_token == "tok"
        data = mock_post.call_args[1]["data"]
        assert "client_id" not in data
        assert "client_secret" not in data


# ── Error paths ──────────────────────────────────────────────────────────────────


class TestTokenExchangerErrors:
    def test_network_failure_raises_oauth_network_error(self, test_provider):
        exchanger = TokenExchanger(test_provider)

        with patch(
            "hermes_vault.oauth.exchange.requests.post",
            side_effect=OAuthNetworkError("Connection refused"),
        ):
            with pytest.raises(OAuthNetworkError):
                exchanger.exchange(
                    code="c",
                    redirect_uri="http://127.0.0.1:1/callback",
                    code_verifier="v",
                )

    def test_token_endpoint_error_json_raises(self, test_provider):
        exchanger = TokenExchanger(test_provider)
        fake_resp = MagicMock()
        fake_resp.ok = False
        fake_resp.json.return_value = {"error": "invalid_grant", "error_description": "Code expired"}
        fake_resp.status_code = 400
        fake_resp.text = ""

        with patch("hermes_vault.oauth.exchange.requests.post", return_value=fake_resp):
            with pytest.raises(OAuthProviderError) as exc_info:
                exchanger.exchange(
                    code="c",
                    redirect_uri="http://127.0.0.1:1/callback",
                    code_verifier="v",
                )
        assert "invalid_grant" in str(exc_info.value)

    def test_token_endpoint_http_error_without_error_key(self, test_provider):
        exchanger = TokenExchanger(test_provider)
        fake_resp = MagicMock()
        fake_resp.ok = False
        fake_resp.json.return_value = {}  # no "error" key
        fake_resp.status_code = 500
        fake_resp.text = "Internal Server Error"

        with patch("hermes_vault.oauth.exchange.requests.post", return_value=fake_resp):
            with pytest.raises(OAuthProviderError) as exc_info:
                exchanger.exchange(
                    code="c",
                    redirect_uri="http://127.0.0.1:1/callback",
                    code_verifier="v",
                )
        assert "HTTP 500" in str(exc_info.value)

    def test_missing_access_token_raises(self, test_provider):
        exchanger = TokenExchanger(test_provider)
        fake_resp = MagicMock()
        fake_resp.ok = True
        fake_resp.json.return_value = {"token_type": "Bearer"}
        fake_resp.status_code = 200
        fake_resp.text = ""

        with patch("hermes_vault.oauth.exchange.requests.post", return_value=fake_resp):
            with pytest.raises(OAuthProviderError) as exc_info:
                exchanger.exchange(
                    code="c",
                    redirect_uri="http://127.0.0.1:1/callback",
                    code_verifier="v",
                )
        assert "missing access_token" in str(exc_info.value)

    def test_url_encoded_legacy_response(self, test_provider):
        exchanger = TokenExchanger(test_provider)
        fake_resp = MagicMock()
        fake_resp.ok = True
        fake_resp.json.side_effect = Exception("not JSON")
        fake_resp.text = "access_token=legacy-tok&token_type=Bearer&scope=read"
        fake_resp.status_code = 200

        with patch("hermes_vault.oauth.exchange.requests.post", return_value=fake_resp):
            result = exchanger.exchange(
                code="c",
                redirect_uri="http://127.0.0.1:1/callback",
                code_verifier="v",
            )
        assert result.access_token == "legacy-tok"
        assert result.token_type == "Bearer"
        assert result.scope == "read"


# ── URL-encoded body parser ──────────────────────────────────────────────────────


class TestParseUrlEncodedBody:
    def test_basic(self):
        result = _parse_url_encoded_body("access_token=tok&token_type=Bearer")
        assert result["access_token"] == "tok"
        assert result["token_type"] == "Bearer"

    def test_empty(self):
        assert _parse_url_encoded_body("") == {}

    def test_multi_value(self):
        result = _parse_url_encoded_body("scope=read&scope=write")
        assert result["scope"] == "read write"
