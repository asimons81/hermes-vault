"""Integration tests for the OAuth PKCE login flow.

Patches out the callback server, browser, and token endpoint to test
LoginFlow.run() without real network or browser I/O.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from hermes_vault.oauth.callback import CallbackResult
from hermes_vault.oauth.errors import (
    OAuthDeniedError,
    OAuthMissingClientIdError,
    OAuthNetworkError,
    OAuthProviderError,
    OAuthStateMismatchError,
    OAuthTimeoutError,
)
from hermes_vault.oauth.exchange import TokenResponse
from hermes_vault.oauth.flow import LoginFlow
from hermes_vault.oauth.providers import OAuthProvider


# ── Helpers ──────────────────────────────────────────────────────────────────────


def _make_fake_registry(provider: OAuthProvider, client_id: str = "test-client-id", client_secret: str | None = None):
    """Create a minimal registry mock that returns a known provider."""
    registry = MagicMock()
    registry.get.return_value = provider
    registry.get_client_credentials.return_value = (client_id, client_secret)
    registry.list_providers.return_value = ["testprovider"]
    return registry


def _make_mock_vault():
    """Minimal vault stub that tracks set_expiry calls."""
    vault = MagicMock()
    vault.set_expiry = MagicMock(return_value=None)
    return vault


def _make_mock_mutations(record_id: str = "cred-123"):
    """Minimal mutations stub that returns an allowed add_credential result."""
    from hermes_vault.models import CredentialRecord, MutationResult

    class _Mutations:
        def __init__(self):
            self.calls: list[dict] = []

        def add_credential(self, **kwargs):
            self.calls.append(kwargs)
            rec = CredentialRecord(
                id=record_id,
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
                record=rec,
            )

    return _Mutations()


# ── Fake callback server (drop in for CallbackServer) ──────────────────────────


class _FakeStateManager:
    """Deterministic StateManager replacement for tests."""

    def __init__(self, state: str = "test-state-abc"):
        self._state = state

    def generate(self):
        return self._state

    def validate(self, incoming):
        return incoming == self._state

    def clear(self):
        pass

    @property
    def current(self):
        return self._state


class _FakeCallbackServer:
    def __init__(self, result: CallbackResult, port: int = 65432):
        self._result = result
        self._port = port

    def start(self) -> int:
        return self._port

    def wait(self) -> CallbackResult:
        return self._result

    def shutdown(self) -> None:
        pass


# ── Fixtures ─────────────────────────────────────────────────────────────────────


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


@pytest.fixture
def flow_deps(test_provider):
    registry = _make_fake_registry(test_provider)
    vault = _make_mock_vault()
    mutations = _make_mock_mutations()
    return registry, vault, mutations


# ── PKCE correctness in auth URL ────────────────────────────────────────────────


class TestPKCEInFlow:
    def test_code_challenge_is_s256_of_verifier(self, test_provider, flow_deps, monkeypatch):
        """The authorization URL must contain a code_challenge that is the S256 hash
        of the generated code_verifier. We can't extract the verifier, but we
        verify the code_challenge has the correct S256 shape (43 chars, base64url)."""
        registry, vault, mutations = flow_deps
        captured_url = None

        def capture_browser(url, new=2):
            nonlocal captured_url
            captured_url = url
            return True

        monkeypatch.setattr(
            "hermes_vault.oauth.flow.CallbackServer",
            lambda port, timeout: _FakeCallbackServer(
                CallbackResult(code="auth-code-123", state="fixed-state-xyz")
            ),
        )
        monkeypatch.setattr("hermes_vault.oauth.flow.webbrowser.open", capture_browser)
        monkeypatch.setattr(
            "hermes_vault.oauth.flow.TokenExchanger.exchange",
            lambda self, code, redirect_uri, code_verifier, client_id, client_secret: TokenResponse(
                access_token="atok",
                token_type="Bearer",
                expires_in=3600,
                refresh_token="rtok",
                scope="openid email",
                raw={"access_token": "atok"},
            ),
        )

        flow = LoginFlow(
            provider_id="testprovider",
            alias="default",
            port=0,
            timeout=1,
            vault=vault,
            mutations=mutations,
            registry=registry,
        )
        monkeypatch.setattr("hermes_vault.oauth.flow.StateManager", _FakeStateManager)
        flow.run()

        assert captured_url is not None
        from urllib.parse import parse_qs, urlparse

        qs = parse_qs(urlparse(captured_url).query)
        code_challenge = qs["code_challenge"][0]
        code_challenge_method = qs["code_challenge_method"][0]
        assert code_challenge_method == "S256"
        assert len(code_challenge) == 43
        assert "=" not in code_challenge


# ── Callback flow integration ─────────────────────────────────────────────────


class TestCallbackFlow:
    def test_callback_receives_code_and_exchanges(self, test_provider, flow_deps, monkeypatch):
        registry, vault, mutations = flow_deps
        exchanged = {}

        def fake_exchange(self, code, redirect_uri, code_verifier, client_id, client_secret):
            exchanged["code"] = code
            exchanged["redirect_uri"] = redirect_uri
            exchanged["client_id"] = client_id
            return TokenResponse(
                access_token="atok",
                token_type="Bearer",
                expires_in=3600,
                refresh_token="rtok",
                scope="openid email",
                raw={"access_token": "atok"},
            )

        monkeypatch.setattr(
            "hermes_vault.oauth.flow.CallbackServer",
            lambda port, timeout: _FakeCallbackServer(
                CallbackResult(code="auth-code-123", state="test-state-abc")
            ),
        )
        monkeypatch.setattr("hermes_vault.oauth.flow.webbrowser.open", lambda url, new=2: True)
        monkeypatch.setattr("hermes_vault.oauth.flow.TokenExchanger.exchange", fake_exchange)

        flow = LoginFlow(
            provider_id="testprovider",
            alias="default",
            port=0,
            timeout=1,
            vault=vault,
            mutations=mutations,
            registry=registry,
        )
        monkeypatch.setattr("hermes_vault.oauth.flow.StateManager", _FakeStateManager)
        flow.run()

        assert exchanged["code"] == "auth-code-123"
        assert exchanged["redirect_uri"] == "http://127.0.0.1:65432/callback"
        assert exchanged["client_id"] == "test-client-id"

    def test_state_mismatch_raises_csrf(self, test_provider, flow_deps, monkeypatch):
        registry, vault, mutations = flow_deps
        callback_result = CallbackResult(code="auth-code-123", state="attacker-state")

        monkeypatch.setattr(
            "hermes_vault.oauth.flow.CallbackServer",
            lambda port, timeout: _FakeCallbackServer(callback_result),
        )
        monkeypatch.setattr("hermes_vault.oauth.flow.webbrowser.open", lambda url, new=2: True)

        flow = LoginFlow(
            provider_id="testprovider",
            alias="default",
            port=0,
            timeout=1,
            vault=vault,
            mutations=mutations,
            registry=registry,
        )
        monkeypatch.setattr("hermes_vault.oauth.flow.StateManager", _FakeStateManager)
        with pytest.raises(OAuthStateMismatchError):
            flow.run()

    def test_timeout_raises(self, test_provider, flow_deps, monkeypatch):
        registry, vault, mutations = flow_deps
        callback_result = CallbackResult(error="timeout")

        monkeypatch.setattr(
            "hermes_vault.oauth.flow.CallbackServer",
            lambda port, timeout: _FakeCallbackServer(callback_result),
        )
        monkeypatch.setattr("hermes_vault.oauth.flow.webbrowser.open", lambda url, new=2: True)

        flow = LoginFlow(
            provider_id="testprovider",
            alias="default",
            port=0,
            timeout=1,
            vault=vault,
            mutations=mutations,
            registry=registry,
        )
        with pytest.raises(OAuthTimeoutError):
            flow.run()

    def test_denied_raises(self, test_provider, flow_deps, monkeypatch):
        registry, vault, mutations = flow_deps
        callback_result = CallbackResult(error="access_denied", error_description="user refused")

        monkeypatch.setattr(
            "hermes_vault.oauth.flow.CallbackServer",
            lambda port, timeout: _FakeCallbackServer(callback_result),
        )
        monkeypatch.setattr("hermes_vault.oauth.flow.webbrowser.open", lambda url, new=2: True)

        flow = LoginFlow(
            provider_id="testprovider",
            alias="default",
            port=0,
            timeout=1,
            vault=vault,
            mutations=mutations,
            registry=registry,
        )
        with pytest.raises(OAuthDeniedError):
            flow.run()

    def test_provider_error_on_callback(self, test_provider, flow_deps, monkeypatch):
        registry, vault, mutations = flow_deps
        callback_result = CallbackResult(error="invalid_scope", error_description="bad scope")

        monkeypatch.setattr(
            "hermes_vault.oauth.flow.CallbackServer",
            lambda port, timeout: _FakeCallbackServer(callback_result),
        )
        monkeypatch.setattr("hermes_vault.oauth.flow.webbrowser.open", lambda url, new=2: True)

        flow = LoginFlow(
            provider_id="testprovider",
            alias="default",
            port=0,
            timeout=1,
            vault=vault,
            mutations=mutations,
            registry=registry,
        )
        with pytest.raises(OAuthProviderError) as exc_info:
            flow.run()
        assert "invalid_scope" in str(exc_info.value)

    def test_network_failure_during_exchange(self, test_provider, flow_deps, monkeypatch):
        registry, vault, mutations = flow_deps
        callback_result = CallbackResult(code="auth-code-123", state="test-state-abc")

        def failing_exchange(*args, **kwargs):
            raise OAuthNetworkError("Connection refused")

        monkeypatch.setattr(
            "hermes_vault.oauth.flow.CallbackServer",
            lambda port, timeout: _FakeCallbackServer(callback_result),
        )
        monkeypatch.setattr("hermes_vault.oauth.flow.webbrowser.open", lambda url, new=2: True)
        monkeypatch.setattr("hermes_vault.oauth.flow.TokenExchanger.exchange", failing_exchange)

        flow = LoginFlow(
            provider_id="testprovider",
            alias="default",
            port=0,
            timeout=1,
            vault=vault,
            mutations=mutations,
            registry=registry,
        )
        monkeypatch.setattr("hermes_vault.oauth.flow.StateManager", _FakeStateManager)
        with pytest.raises(OAuthNetworkError):
            flow.run()


# ── Token storage in vault ───────────────────────────────────────────────────────


class TestVaultStorage:
    def test_stores_access_token_with_scopes_and_expiry(self, test_provider, flow_deps, monkeypatch):
        registry, vault, mutations = flow_deps
        callback_result = CallbackResult(code="auth-code-123", state="test-state-abc")

        monkeypatch.setattr(
            "hermes_vault.oauth.flow.CallbackServer",
            lambda port, timeout: _FakeCallbackServer(callback_result),
        )
        monkeypatch.setattr("hermes_vault.oauth.flow.webbrowser.open", lambda url, new=2: True)
        monkeypatch.setattr(
            "hermes_vault.oauth.flow.TokenExchanger.exchange",
            lambda self, code, redirect_uri, code_verifier, client_id, client_secret: TokenResponse(
                access_token="atok-123",
                token_type="Bearer",
                expires_in=3600,
                refresh_token="rtok-456",
                scope="openid email",
                raw={"access_token": "atok-123"},
            ),
        )

        flow = LoginFlow(
            provider_id="testprovider",
            alias="custom-alias",
            port=0,
            timeout=1,
            scopes=["openid", "email"],
            vault=vault,
            mutations=mutations,
            registry=registry,
        )
        with patch("hermes_vault.oauth.flow.StateManager.generate", return_value="test-state-abc"):
            flow.run()

        access_call = mutations.calls[0]
        assert access_call["service"] == "testprovider"
        assert access_call["credential_type"] == "oauth_access_token"
        assert access_call["alias"] == "custom-alias"
        assert access_call["scopes"] == ["openid", "email"]
        assert access_call["secret"] == "atok-123"

        assert vault.set_expiry.call_count == 1
        call_args = vault.set_expiry.call_args
        assert call_args[0][0] == "cred-123"
        expiry: datetime = call_args[0][1]
        assert expiry.tzinfo is not None
        now = datetime.now(timezone.utc)
        assert now < expiry < now.replace(year=now.year + 1)

    def test_stores_refresh_token_separately(self, test_provider, flow_deps, monkeypatch):
        registry, vault, mutations = flow_deps
        callback_result = CallbackResult(code="auth-code-123", state="test-state-abc")

        monkeypatch.setattr(
            "hermes_vault.oauth.flow.CallbackServer",
            lambda port, timeout: _FakeCallbackServer(callback_result),
        )
        monkeypatch.setattr("hermes_vault.oauth.flow.webbrowser.open", lambda url, new=2: True)
        monkeypatch.setattr(
            "hermes_vault.oauth.flow.TokenExchanger.exchange",
            lambda self, code, redirect_uri, code_verifier, client_id, client_secret: TokenResponse(
                access_token="atok",
                token_type="Bearer",
                expires_in=3600,
                refresh_token="rtok-789",
                scope="openid",
                raw={"access_token": "atok"},
            ),
        )

        flow = LoginFlow(
            provider_id="testprovider",
            alias="default",
            port=0,
            timeout=1,
            vault=vault,
            mutations=mutations,
            registry=registry,
        )
        with patch("hermes_vault.oauth.flow.StateManager.generate", return_value="test-state-abc"):
            flow.run()

        assert len(mutations.calls) == 2

        refresh_call = mutations.calls[1]
        assert refresh_call["credential_type"] == "oauth_refresh_token"
        assert refresh_call["alias"] == "refresh"
        assert refresh_call["secret"] == "rtok-789"
        assert refresh_call["scopes"] == ["openid"]

    def test_no_refresh_token_skips_refresh_storage(self, test_provider, flow_deps, monkeypatch):
        registry, vault, mutations = flow_deps
        callback_result = CallbackResult(code="auth-code-123", state="test-state-abc")

        monkeypatch.setattr(
            "hermes_vault.oauth.flow.CallbackServer",
            lambda port, timeout: _FakeCallbackServer(callback_result),
        )
        monkeypatch.setattr("hermes_vault.oauth.flow.webbrowser.open", lambda url, new=2: True)
        monkeypatch.setattr(
            "hermes_vault.oauth.flow.TokenExchanger.exchange",
            lambda self, code, redirect_uri, code_verifier, client_id, client_secret: TokenResponse(
                access_token="atok",
                token_type="Bearer",
                expires_in=1800,
                refresh_token=None,
                scope=None,
                raw={"access_token": "atok"},
            ),
        )

        flow = LoginFlow(
            provider_id="testprovider",
            alias="default",
            port=0,
            timeout=1,
            vault=vault,
            mutations=mutations,
            registry=registry,
        )
        with patch("hermes_vault.oauth.flow.StateManager.generate", return_value="test-state-abc"):
            flow.run()

        assert len(mutations.calls) == 1  # only access token

    def test_vault_denial_raises(self, test_provider, flow_deps, monkeypatch):
        from hermes_vault.models import MutationResult

        registry, vault, mutations = flow_deps
        callback_result = CallbackResult(code="auth-code-123", state="test-state-abc")

        def deny_add(**kwargs):
            return MutationResult(
                allowed=False,
                service=kwargs["service"],
                agent_id=kwargs["agent_id"],
                action="add_credential",
                reason="policy denied",
            )

        mutations.add_credential = deny_add

        monkeypatch.setattr(
            "hermes_vault.oauth.flow.CallbackServer",
            lambda port, timeout: _FakeCallbackServer(callback_result),
        )
        monkeypatch.setattr("hermes_vault.oauth.flow.webbrowser.open", lambda url, new=2: True)
        monkeypatch.setattr(
            "hermes_vault.oauth.flow.TokenExchanger.exchange",
            lambda self, code, redirect_uri, code_verifier, client_id, client_secret: TokenResponse(
                access_token="atok",
                token_type="Bearer",
                expires_in=None,
                refresh_token=None,
                scope=None,
                raw={"access_token": "atok"},
            ),
        )

        flow = LoginFlow(
            provider_id="testprovider",
            alias="default",
            port=0,
            timeout=1,
            vault=vault,
            mutations=mutations,
            registry=registry,
        )
        with patch("hermes_vault.oauth.flow.StateManager.generate", return_value="test-state-abc"):
            with pytest.raises(OAuthProviderError) as exc_info:
                flow.run()
        assert "Vault refused" in str(exc_info.value)

    def test_missing_client_id_raises(self, test_provider, flow_deps):
        registry, vault, mutations = flow_deps
        registry.get_client_credentials.return_value = (None, None)

        flow = LoginFlow(
            provider_id="testprovider",
            alias="default",
            port=0,
            timeout=1,
            vault=vault,
            mutations=mutations,
            registry=registry,
        )
        with pytest.raises(OAuthMissingClientIdError):
            flow.run()

    def test_unknown_provider_raises(self, flow_deps):
        registry, vault, mutations = flow_deps
        registry.get.return_value = None
        registry.list_providers.return_value = ["google", "github"]

        flow = LoginFlow(
            provider_id="unknownprovider",
            alias="default",
            port=0,
            timeout=1,
            vault=vault,
            mutations=mutations,
            registry=registry,
        )
        with pytest.raises(OAuthProviderError) as exc_info:
            flow.run()
        assert "Unknown OAuth provider" in str(exc_info.value)
