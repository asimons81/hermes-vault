"""Tests for the OAuth PKCE login flow."""

from __future__ import annotations

import threading
from pathlib import Path


from hermes_vault.oauth.callback import CallbackServer
from hermes_vault.oauth.errors import (
    OAuthDeniedError,
    OAuthFlowError,
    OAuthMissingClientIdError,
    OAuthNetworkError,
    OAuthProviderError,
    OAuthStateMismatchError,
    OAuthTimeoutError,
)
from hermes_vault.oauth.exchange import TokenResponse, _parse_url_encoded_body
from hermes_vault.oauth.pkce import PKCEGenerator
from hermes_vault.oauth.providers import OAuthProvider, OAuthProviderRegistry
from hermes_vault.oauth.state import StateManager


# ── PKCE ─────────────────────────────────────────────────────────────────────────

class TestPKCEGenerator:
    def test_verifier_length(self):
        verifier = PKCEGenerator.generate_verifier()
        assert isinstance(verifier, str)
        assert len(verifier) > 128

    def test_challenge_from_verifier(self):
        verifier = PKCEGenerator.generate_verifier()
        challenge = PKCEGenerator.generate_challenge(verifier)
        assert challenge != verifier
        assert len(challenge) == 43

    def test_challenges_are_deterministic(self):
        v = PKCEGenerator.generate_verifier()
        assert PKCEGenerator.generate_challenge(v) == PKCEGenerator.generate_challenge(v)

    def test_different_verifiers_different_challenges(self):
        v1 = PKCEGenerator.generate_verifier()
        v2 = PKCEGenerator.generate_verifier()
        assert PKCEGenerator.generate_challenge(v1) != PKCEGenerator.generate_challenge(v2)

    def test_verifier_is_safe_base64(self):
        v = PKCEGenerator.generate_verifier()
        assert "=" not in v
        assert "+" not in v
        assert "/" not in v
        assert all(c.isascii() for c in v)


# ── State ────────────────────────────────────────────────────────────────────────

class TestStateManager:
    def test_generate_returns_string(self):
        sm = StateManager()
        state = sm.generate()
        assert isinstance(state, str)
        assert len(state) > 20

    def test_validate_correct_state(self):
        sm = StateManager()
        state = sm.generate()
        assert sm.validate(state) is True

    def test_validate_wrong_state(self):
        sm = StateManager()
        sm.generate()
        assert sm.validate("wrong-state") is False

    def test_validate_after_mismatch_clears_state(self):
        sm = StateManager()
        sm.generate()
        assert sm.validate("nope") is False
        assert sm.current is None

    def test_validate_once(self):
        sm = StateManager()
        state = sm.generate()
        assert sm.validate(state) is True
        assert sm.validate(state) is False  # already cleared

    def test_clear(self):
        sm = StateManager()
        sm.generate()
        sm.clear()
        assert sm.current is None

    def test_validate_none(self):
        sm = StateManager()
        assert sm.validate(None) is False


# ── Callback ─────────────────────────────────────────────────────────────────────

class TestCallbackServer:
    def test_server_starts_with_ephemeral_port(self):
        server = CallbackServer()
        port = server.start()
        assert port > 0
        assert port < 65536
        server.shutdown()

    def test_callback_result_timeout(self):
        server = CallbackServer(timeout=1)
        server.start()
        result = server.wait()
        assert result.error == "timeout"
        assert "No callback received" in result.error_description
        server.shutdown()

    def test_callback_result_populated(self):
        server = CallbackServer(timeout=5)
        server.start()
        port = server._server.server_address[1]
        from urllib.request import urlopen
        url = f"http://127.0.0.1:{port}/callback?code=abc123&state=xyz"
        t = threading.Thread(target=lambda: urlopen(url, timeout=5))
        t.start()
        result = server.wait()
        t.join()
        assert result.code == "abc123"
        assert result.state == "xyz"
        assert result.error is None
        server.shutdown()

    def test_error_callback(self):
        server = CallbackServer(timeout=5)
        server.start()
        port = server._server.server_address[1]
        from urllib.request import urlopen
        url = f"http://127.0.0.1:{port}/callback?error=access_denied&error_description=user+denied"
        t = threading.Thread(target=lambda: urlopen(url, timeout=5))
        t.start()
        result = server.wait()
        t.join()
        assert result.error == "access_denied"
        assert "user denied" in result.error_description
        server.shutdown()

    @staticmethod
    def _fetch_status(url: str) -> int:
        """Fetch a callback URL and return the HTTP status (non-2xx included)."""
        from urllib.error import HTTPError
        from urllib.request import urlopen
        try:
            with urlopen(url, timeout=5) as resp:
                resp.read()
                return resp.status
        except HTTPError as e:
            return e.code

    def test_first_callback_wins(self):
        """Issue #65: a later callback to the same server must not overwrite the first.

        The second request arrives before the waiter shuts the listener down, so the
        narrow window described in the issue is exercised deterministically.
        """
        server = CallbackServer(timeout=5)
        server.start()
        port = server._server.server_address[1]
        base = f"http://127.0.0.1:{port}/callback"
        status_first = self._fetch_status(f"{base}?code=first&state=expected")
        status_later = self._fetch_status(f"{base}?code=second&state=other")
        result = server.wait()
        server.shutdown()
        assert status_first == 200
        assert status_later >= 400, "later callback must receive a non-success response"
        assert result.code == "first"
        assert result.state == "expected"

    def test_concurrent_servers_are_isolated(self):
        """Issue #61/#64: two simultaneous logins must not share callback state.

        Each waiter must receive only its own code/state even though both servers
        are accepting callbacks at the same time.
        """
        server_a = CallbackServer(timeout=2)
        server_b = CallbackServer(timeout=2)
        port_a = server_a.start()
        port_b = server_b.start()
        assert port_a != port_b
        status_a = self._fetch_status(f"http://127.0.0.1:{port_a}/callback?code=aaa&state=stateA")
        status_b = self._fetch_status(f"http://127.0.0.1:{port_b}/callback?code=bbb&state=stateB")
        result_a = server_a.wait()
        result_b = server_b.wait()
        server_a.shutdown()
        server_b.shutdown()
        assert status_a == 200
        assert status_b == 200
        assert result_a.code == "aaa"
        assert result_a.state == "stateA"
        assert result_b.code == "bbb"
        assert result_b.state == "stateB"

    def test_server_terminates_internal_thread_after_wait(self):
        """The serving thread must exit after wait()/shutdown cleanup."""
        server = CallbackServer(timeout=5)
        server.start()
        thread = server._thread
        port = server._server.server_address[1]
        self._fetch_status(f"http://127.0.0.1:{port}/callback?code=one")
        server.wait()
        server.shutdown()
        assert thread is not None
        thread.join(timeout=5)
        assert not thread.is_alive()


# ── Provider registry ────────────────────────────────────────────────────────────

class TestOAuthProviderRegistry:
    def test_load_defaults(self, tmp_path: Path):
        registry_path = tmp_path / "providers.yaml"
        registry = OAuthProviderRegistry(registry_path)
        assert registry.get("google") is not None
        assert registry.get("github") is not None
        assert registry.get("openai") is not None

    def test_unknown_provider(self, tmp_path: Path):
        registry = OAuthProviderRegistry(tmp_path / "providers.yaml")
        assert registry.get("nope") is None

    def test_list_providers(self, tmp_path: Path):
        registry = OAuthProviderRegistry(tmp_path / "providers.yaml")
        providers = registry.list_providers()
        assert "google" in providers
        assert "github" in providers
        assert "openai" in providers

    def test_client_credentials_env(self, tmp_path: Path, monkeypatch):
        registry = OAuthProviderRegistry(tmp_path / "providers.yaml")
        google = registry.get("google")
        assert google is not None
        monkeypatch.setenv("HERMES_VAULT_OAUTH_GOOGLE_CLIENT_ID", "my-client-id")
        monkeypatch.setenv("HERMES_VAULT_OAUTH_GOOGLE_CLIENT_SECRET", "my-secret")
        cid, csec = registry.get_client_credentials(google)
        assert cid == "my-client-id"
        assert csec == "my-secret"

    def test_provider_model(self):
        p = OAuthProvider(
            service_id="test",
            name="Test Provider",
            authorization_endpoint="https://example.com/auth",
            token_endpoint="https://example.com/token",
            default_scopes=["scope1"],
            requires_client_id=True,
        )
        assert p.service_id == "test"
        assert p.use_pkce is True
        assert p.scope_separator == " "


# ── Token exchange ───────────────────────────────────────────────────────────────

class TestTokenResponse:
    def test_from_json(self):
        tr = TokenResponse.from_json({
            "access_token": "tok",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "ref",
            "scope": "openid email",
        })
        assert tr.access_token == "tok"
        assert tr.token_type == "Bearer"
        assert tr.expires_in == 3600
        assert tr.refresh_token == "ref"
        assert tr.scope == "openid email"

    def test_to_credential_secret(self):
        provider = OAuthProvider(
            service_id="test",
            name="Test",
            authorization_endpoint="https://example.com/auth",
            token_endpoint="https://example.com/token",
        )
        tr = TokenResponse.from_json({
            "access_token": "tok",
            "token_type": "Bearer",
            "refresh_token": "ref",
            "scope": "openid",
        })
        secret = tr.to_credential_secret(provider)
        assert secret.secret == "tok"
        assert secret.metadata["provider"] == "test"
        assert secret.metadata["token_type"] == "Bearer"
        assert secret.metadata["scopes"] == ["openid"]
        assert "refresh_token" not in secret.metadata
        assert "raw_response" not in secret.metadata


class TestParseUrlEncodedBody:
    def test_ok(self):
        result = _parse_url_encoded_body("access_token=tok&token_type=Bearer")
        assert result["access_token"] == "tok"
        assert result["token_type"] == "Bearer"

    def test_empty(self):
        assert _parse_url_encoded_body("") == {}


# ── Errors ───────────────────────────────────────────────────────────────────────

class TestOAuthErrors:
    def test_error_hierarchy(self):
        assert issubclass(OAuthTimeoutError, OAuthFlowError)
        assert issubclass(OAuthDeniedError, OAuthFlowError)
        assert issubclass(OAuthStateMismatchError, OAuthFlowError)
        assert issubclass(OAuthNetworkError, OAuthFlowError)
        assert issubclass(OAuthProviderError, OAuthFlowError)
        assert issubclass(OAuthMissingClientIdError, OAuthFlowError)
