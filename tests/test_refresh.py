"""Tests for the OAuth token refresh engine."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hermes_vault.models import (
    CredentialRecord,
    CredentialSecret,
    CredentialStatus,
    utc_now,
)
from hermes_vault.oauth.errors import OAuthNetworkError
from hermes_vault.oauth.oauth_refresh import (
    RefreshAttempt,
    RefreshEngine,
    RefreshTokenExpiredError,
    RefreshTokenMissingError,
)
from hermes_vault.oauth.providers import OAuthProvider, OAuthProviderRegistry
from hermes_vault.vault import Vault


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_vault(tmp_path: Path) -> Vault:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    return Vault(db_path=db, salt_path=salt, passphrase="testpassphrase")


@pytest.fixture
def provider(tmp_path: Path) -> OAuthProvider:
    return OAuthProvider(
        service_id="test",
        name="Test Provider",
        authorization_endpoint="https://example.com/auth",
        token_endpoint="https://example.com/token",
    )


@pytest.fixture
def registry(tmp_path: Path, provider: OAuthProvider) -> OAuthProviderRegistry:
    path = tmp_path / "providers.yaml"
    path.write_text("providers:\n  test:\n    name: Test Provider\n    authorization_endpoint: https://example.com/auth\n    token_endpoint: https://example.com/token\n")
    registry = OAuthProviderRegistry(path)
    return registry


# ── Detection ────────────────────────────────────────────────────────────────────

class TestDetection:
    def test_is_expired_true_when_past_expiry(self, tmp_vault: Vault):
        engine = RefreshEngine(vault=tmp_vault)
        past = utc_now() - timedelta(seconds=10)
        record = CredentialRecord(
            service="test",
            alias="default",
            credential_type="oauth_access_token",
            encrypted_payload="dummy",
            expiry=past,
        )
        assert engine.is_expired(record) is True

    def test_is_expired_false_when_well_in_future(self, tmp_vault: Vault):
        engine = RefreshEngine(vault=tmp_vault)
        future = utc_now() + timedelta(seconds=3600)
        record = CredentialRecord(
            service="test",
            alias="default",
            credential_type="oauth_access_token",
            encrypted_payload="dummy",
            expiry=future,
        )
        assert engine.is_expired(record) is False

    def test_is_expired_true_within_margin(self, tmp_vault: Vault):
        engine = RefreshEngine(vault=tmp_vault, proactive_margin_seconds=300)
        near = utc_now() + timedelta(seconds=100)
        record = CredentialRecord(
            service="test",
            alias="default",
            credential_type="oauth_access_token",
            encrypted_payload="dummy",
            expiry=near,
        )
        assert engine.is_expired(record) is True

    def test_list_expired_filters_by_type(self, tmp_vault: Vault):
        engine = RefreshEngine(vault=tmp_vault)
        past = utc_now() - timedelta(seconds=10)
        _add_credential(tmp_vault, "svc1", "tok1", "oauth_access_token", alias="default", expiry=past)
        _add_credential(tmp_vault, "svc2", "tok2", "api_key", alias="default", expiry=past)
        expired = engine.list_expired()
        assert len(expired) == 1
        assert expired[0].service == "svc1"

    def test_list_expired_filters_by_service(self, tmp_vault: Vault):
        engine = RefreshEngine(vault=tmp_vault)
        past = utc_now() - timedelta(seconds=10)
        _add_credential(tmp_vault, "alpha", "tok1", "oauth_access_token", alias="default", expiry=past)
        _add_credential(tmp_vault, "beta", "tok2", "oauth_access_token", alias="default", expiry=past)
        expired = engine.list_expired(service="alpha")
        assert len(expired) == 1
        assert expired[0].service == "alpha"


# ── Refresh core ───────────────────────────────────────────────────────────────

class TestRefreshCore:
    def test_refresh_success(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        _seed_tokens(tmp_vault, "test")

        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "new_access",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new_refresh",
            "scope": "openid email",
        }

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", return_value=mock_resp):
            result = engine.refresh("test")

        assert result.success is True
        assert result.new_access_token == "new_access"
        assert result.new_refresh_token == "new_refresh"
        assert result.expires_in == 3600
        assert result.scopes == ["openid", "email"]

        # Verify vault was updated
        access_rec = tmp_vault.resolve_credential("test", alias="default")
        secret = tmp_vault.get_secret(access_rec.id)
        assert secret is not None
        assert secret.secret == "new_access"
        assert access_rec.status == CredentialStatus.active

    def test_refresh_dry_run_no_vault_update(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        _seed_tokens(tmp_vault, "test")

        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "new_access",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", return_value=mock_resp):
            result = engine.refresh("test", dry_run=True)

        assert result.success is True
        assert result.reason == "Token refresh simulated (dry-run)"

        # Vault should still have old token
        access_rec = tmp_vault.resolve_credential("test", alias="default")
        secret = tmp_vault.get_secret(access_rec.id)
        assert secret is not None
        assert secret.secret == "old_access"

    def test_refresh_missing_refresh_token(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        _add_credential(
            tmp_vault, "test", "old_access", "oauth_access_token",
            alias="default", expiry=utc_now() - timedelta(seconds=10)
        )
        with pytest.raises(RefreshTokenMissingError, match="No refresh token found"):
            engine.refresh("test")

    def test_refresh_provider_error(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        _seed_tokens(tmp_vault, "test")

        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 400
        mock_resp.json.return_value = {"error": "invalid_grant", "error_description": "Token revoked"}
        mock_resp.text = '{"error": "invalid_grant"}'

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", return_value=mock_resp):
            with pytest.raises(RefreshTokenExpiredError, match="Token revoked"):
                engine.refresh("test")

    def test_refresh_retry_on_network_error(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(vault=tmp_vault, registry=registry, max_retries=2, base_backoff_seconds=0.001)
        _seed_tokens(tmp_vault, "test")

        from requests import RequestException
        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=RequestException("boom")):
            with pytest.raises(OAuthNetworkError, match="Network failure after"):
                engine.refresh("test")

    def test_refresh_success_after_retry(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(vault=tmp_vault, registry=registry, max_retries=3, base_backoff_seconds=0.001)
        _seed_tokens(tmp_vault, "test")

        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"access_token": "recovered", "token_type": "Bearer"}

        from requests import RequestException
        side_effects = [RequestException("boom"), mock_resp]
        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=side_effects):
            result = engine.refresh("test")

        assert result.success is True
        assert result.new_access_token == "recovered"
        assert result.retry_count == 2


# ── RefreshAll ─────────────────────────────────────────────────────────────────

class TestRefreshAll:
    def test_refresh_all_multiple_services(self, tmp_vault: Vault):
        registry_path = Path(tmp_vault.db_path).parent / "providers.yaml"
        registry_path.write_text(
            "providers:\n"
            "  alpha:\n    name: Alpha\n"
            "    authorization_endpoint: https://alpha.example.com/auth\n"
            "    token_endpoint: https://alpha.example.com/token\n"
            "  beta:\n    name: Beta\n"
            "    authorization_endpoint: https://beta.example.com/auth\n"
            "    token_endpoint: https://beta.example.com/token\n"
        )
        registry = OAuthProviderRegistry(registry_path)
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        past = utc_now() - timedelta(seconds=10)
        _seed_tokens(tmp_vault, "alpha", expiry=past)
        _seed_tokens(tmp_vault, "beta", expiry=past)

        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"access_token": "new_tok", "token_type": "Bearer"}

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", return_value=mock_resp):
            results = engine.refresh_all()

        assert len(results) == 2
        assert all(r.success for r in results)

    def test_refresh_all_no_candidates(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        results = engine.refresh_all()
        assert results == []


# ── Parse scopes ───────────────────────────────────────────────────────────────

class TestParseScopes:
    def test_single_scope(self):
        assert RefreshEngine._parse_scopes("openid") == ["openid"]

    def test_multiple_scopes(self):
        assert RefreshEngine._parse_scopes("openid email profile") == ["openid", "email", "profile"]

    def test_empty(self):
        assert RefreshEngine._parse_scopes("") == []

    def test_none(self):
        assert RefreshEngine._parse_scopes(None) == []


# ── Helpers ────────────────────────────────────────────────────────────────────

def _add_credential(
    vault: Vault,
    service: str,
    secret: str,
    credential_type: str,
    alias: str = "default",
    expiry: datetime | None = None,
) -> CredentialRecord:
    rec = vault.add_credential(
        service=service,
        secret=secret,
        credential_type=credential_type,
        alias=alias,
        replace_existing=True,
    )
    if expiry is not None:
        vault.set_expiry(rec.id, expiry)
    return rec


def _seed_tokens(
    vault: Vault,
    service: str,
    expiry: datetime | None = None,
) -> None:
    """Store a paired access + refresh token for *service*."""
    if expiry is None:
        expiry = utc_now() - timedelta(seconds=10)
    _add_credential(
        vault, service, "old_access", "oauth_access_token",
        alias="default", expiry=expiry,
    )
    vault.add_credential(
        service=service,
        secret="old_refresh",
        credential_type="oauth_refresh_token",
        alias="refresh",
        replace_existing=True,
    )
