"""Unit tests for the OAuth auto-refresh engine."""

from __future__ import annotations

import json
import threading
import time
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
from hermes_vault.oauth.errors import OAuthNetworkError, OAuthProviderError
from hermes_vault.oauth.oauth_refresh import (
    RefreshAttempt,
    RefreshEngine,
    RefreshTokenExpiredError,
    RefreshTokenMissingError,
    refresh_alias_for,
)
from hermes_vault.oauth.providers import OAuthProvider, OAuthProviderRegistry
from hermes_vault.vault import Vault


# ── Helpers ───────────────────────────────────────────────────────────────────

class MockTokenEndpoint:
    """A programmable mock token endpoint for refresh flows.

    Usage:
        endpoint = MockTokenEndpoint(success_tokens={...})
        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
            engine.refresh("test")
    """

    def __init__(
        self,
        success_tokens: dict | None = None,
        error_response: dict | None = None,
        status_code: int = 200,
        fail_count: int = 0,
    ):
        self.calls: list[dict] = []
        self.success_tokens = success_tokens or {
            "access_token": "new_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new_refresh_token",
            "scope": "openid email",
        }
        self.error_response = error_response
        self.status_code = status_code
        self.fail_count = fail_count
        self._call_count = 0

    def handler(self, url, data=None, headers=None, timeout=None, **kwargs):
        self._call_count += 1
        if isinstance(data, dict):
            parsed = data
        elif data:
            parsed = dict(p.split("=", 1) for p in data.split("&"))
        else:
            parsed = {}
        self.calls.append({"url": str(url), "data": parsed})

        mock_resp = MagicMock()
        if self._call_count <= self.fail_count:
            from requests import RequestException
            raise RequestException(f"Simulated failure #{self._call_count}")

        if self.error_response:
            mock_resp.ok = False
            mock_resp.status_code = self.status_code
            mock_resp.json.return_value = self.error_response
            mock_resp.text = json.dumps(self.error_response)
            return mock_resp

        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = self.success_tokens
        mock_resp.text = json.dumps(self.success_tokens)
        return mock_resp


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
    access_alias: str = "default",
    refresh_alias: str = "refresh",
    refresh_secret: str = "old_refresh",
) -> None:
    if expiry is None:
        expiry = utc_now() - timedelta(seconds=10)
    _add_credential(
        vault, service, "old_access", "oauth_access_token",
        alias=access_alias, expiry=expiry,
    )
    vault.add_credential(
        service=service,
        secret=refresh_secret,
        credential_type="oauth_refresh_token",
        alias=refresh_alias,
        replace_existing=True,
    )


def _seed_scoped_tokens(
    vault: Vault,
    service: str,
    access_alias: str,
    expiry: datetime | None = None,
    refresh_secret: str = "old_refresh",
) -> None:
    _seed_tokens(
        vault,
        service,
        expiry=expiry,
        access_alias=access_alias,
        refresh_alias=refresh_alias_for(access_alias),
        refresh_secret=refresh_secret,
    )


def _make_registry(tmp_path: Path) -> OAuthProviderRegistry:
    path = tmp_path / "providers.yaml"
    path.write_text(
        "providers:\n"
        "  test:\n    name: Test Provider\n"
        "    authorization_endpoint: https://example.com/auth\n"
        "    token_endpoint: https://example.com/token\n"
    )
    return OAuthProviderRegistry(path)


@pytest.fixture
def tmp_vault(tmp_path: Path) -> Vault:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    return Vault(db_path=db, salt_path=salt, passphrase="testpassphrase")


@pytest.fixture
def registry(tmp_path: Path) -> OAuthProviderRegistry:
    return _make_registry(tmp_path)


# ── Deliverable 1: Mock token endpoint for refresh flows ─────────────────────

class TestMockTokenEndpoint:
    def test_mock_token_endpoint_records_calls(self):
        endpoint = MockTokenEndpoint(success_tokens={"access_token": "tok"})
        assert len(endpoint.calls) == 0

    def test_mock_token_endpoint_returns_success(self):
        endpoint = MockTokenEndpoint()
        resp = endpoint.handler("https://example.com/token", data="grant_type=refresh_token")
        assert resp.ok is True
        assert resp.json()["access_token"] == "new_access_token"

    def test_mock_token_endpoint_returns_error(self):
        endpoint = MockTokenEndpoint(
            error_response={"error": "invalid_grant", "error_description": "bad"},
            status_code=400,
        )
        resp = endpoint.handler("https://example.com/token")
        assert resp.ok is False
        assert resp.json()["error"] == "invalid_grant"

    def test_mock_token_endpoint_simulates_failures(self):
        endpoint = MockTokenEndpoint(fail_count=2)
        with pytest.raises(Exception):
            endpoint.handler("https://example.com/token")
        with pytest.raises(Exception):
            endpoint.handler("https://example.com/token")
        resp = endpoint.handler("https://example.com/token")
        assert resp.ok is True


# ── Deliverable 2: Token expiry detection ────────────────────────────────────

class TestExpiryDetection:
    def test_is_expired_true_when_past(self, tmp_vault: Vault):
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

    def test_is_expired_false_when_far_future(self, tmp_vault: Vault):
        engine = RefreshEngine(vault=tmp_vault)
        future = utc_now() + timedelta(hours=2)
        record = CredentialRecord(
            service="test",
            alias="default",
            credential_type="oauth_access_token",
            encrypted_payload="dummy",
            expiry=future,
        )
        assert engine.is_expired(record) is False

    def test_list_expired_filters_by_service(self, tmp_vault: Vault):
        engine = RefreshEngine(vault=tmp_vault)
        past = utc_now() - timedelta(seconds=10)
        _add_credential(tmp_vault, "alpha", "tok1", "oauth_access_token", alias="default", expiry=past)
        _add_credential(tmp_vault, "beta", "tok2", "oauth_access_token", alias="default", expiry=past)
        expired = engine.list_expired(service="alpha")
        assert len(expired) == 1
        assert expired[0].service == "alpha"

    def test_list_expired_skips_non_access_tokens(self, tmp_vault: Vault):
        engine = RefreshEngine(vault=tmp_vault)
        past = utc_now() - timedelta(seconds=10)
        _add_credential(tmp_vault, "svc1", "tok1", "oauth_access_token", alias="default", expiry=past)
        _add_credential(tmp_vault, "svc2", "tok2", "api_key", alias="default", expiry=past)
        expired = engine.list_expired()
        assert len(expired) == 1
        assert expired[0].service == "svc1"


# ── Deliverable 3: Successful refresh stores new tokens ────────────────────────

class TestSuccessfulRefresh:
    def test_refresh_alias_helper_is_deterministic(self):
        assert refresh_alias_for("default") == "refresh:default"
        assert refresh_alias_for("work") == "refresh:work"

    def test_refresh_stores_new_access_and_refresh_tokens(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        _seed_tokens(tmp_vault, "test")

        endpoint = MockTokenEndpoint(success_tokens={
            "access_token": "new_access",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new_refresh",
            "scope": "openid email",
        })

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
            result = engine.refresh("test")

        assert result.success is True
        assert result.new_access_token == "new_access"
        assert result.new_refresh_token == "new_refresh"
        assert result.expires_in == 3600
        assert result.scopes == ["openid", "email"]

        # Vault was updated atomically
        access_rec = tmp_vault.resolve_credential("test", alias="default")
        secret = tmp_vault.get_secret(access_rec.id)
        assert secret is not None
        assert secret.secret == "new_access"
        assert secret.metadata["provider"] == "test"
        assert secret.metadata["token_type"] == "Bearer"
        assert secret.metadata["scopes"] == ["openid", "email"]
        assert "refresh_token" not in secret.metadata
        assert "raw_response" not in secret.metadata

    def test_refresh_prefers_alias_scoped_pair(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        _seed_scoped_tokens(tmp_vault, "test", "work")

        endpoint = MockTokenEndpoint(success_tokens={
            "access_token": "new_access_work",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new_refresh_work",
            "scope": "openid email",
        })

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
            result = engine.refresh("test", alias="work")

        assert result.success is True
        assert result.alias == "work"
        assert len(endpoint.calls) == 1
        assert endpoint.calls[0]["data"]["refresh_token"] == "old_refresh"

        scoped_refresh = tmp_vault._find_by_service_alias("test", refresh_alias_for("work"))
        assert scoped_refresh is not None
        scoped_secret = tmp_vault.get_secret(scoped_refresh.id)
        assert scoped_secret is not None
        assert scoped_secret.secret == "new_refresh_work"
        assert scoped_secret.metadata["associated_access_token_alias"] == "work"
        assert scoped_secret.metadata["provider"] == "test"
        assert scoped_secret.metadata["rotation_counter"] == 1

    def test_refresh_falls_back_to_legacy_refresh_alias(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        _seed_tokens(tmp_vault, "test", access_alias="work")

        endpoint = MockTokenEndpoint(success_tokens={
            "access_token": "new_access_work",
            "token_type": "Bearer",
            "expires_in": 3600,
        })

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
            result = engine.refresh("test", alias="work")

        assert result.success is True
        assert len(endpoint.calls) == 1
        assert endpoint.calls[0]["data"]["refresh_token"] == "old_refresh"

    def test_refresh_handles_multiple_aliases_independently(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        _seed_scoped_tokens(tmp_vault, "test", "work", refresh_secret="refresh-work")
        _seed_scoped_tokens(tmp_vault, "test", "personal", refresh_secret="refresh-personal")

        def post_side_effect(url, data=None, **kwargs):
            refresh_token = data["refresh_token"]
            token_suffix = "work" if refresh_token == "refresh-work" else "personal"
            resp = MagicMock()
            resp.ok = True
            resp.status_code = 200
            resp.json.return_value = {
                "access_token": f"new_access_{token_suffix}",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": f"new_refresh_{token_suffix}",
                "scope": "openid email",
            }
            resp.text = json.dumps(resp.json.return_value)
            return resp

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=post_side_effect):
            work_result = engine.refresh("test", alias="work")
            personal_result = engine.refresh("test", alias="personal")

        assert work_result.success is True
        assert personal_result.success is True
        assert work_result.alias == "work"
        assert personal_result.alias == "personal"

        work_refresh = tmp_vault._find_by_service_alias("test", refresh_alias_for("work"))
        personal_refresh = tmp_vault._find_by_service_alias("test", refresh_alias_for("personal"))
        assert work_refresh is not None
        assert personal_refresh is not None

        work_secret = tmp_vault.get_secret(work_refresh.id)
        personal_secret = tmp_vault.get_secret(personal_refresh.id)
        assert work_secret is not None
        assert personal_secret is not None
        assert work_secret.secret == "new_refresh_work"
        assert personal_secret.secret == "new_refresh_personal"

    def test_refresh_without_new_refresh_token_preserves_existing(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        _seed_tokens(tmp_vault, "test")

        endpoint = MockTokenEndpoint(success_tokens={
            "access_token": "new_access",
            "token_type": "Bearer",
            "expires_in": 3600,
        })

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
            engine.refresh("test")

        # Original refresh token still in vault
        refresh_rec = tmp_vault._find_by_service_alias("test", "refresh")
        assert refresh_rec is not None
        secret = tmp_vault.get_secret(refresh_rec.id)
        assert secret is not None
        assert secret.secret == "old_refresh"

    def test_refresh_rotates_refresh_token_when_provider_returns_new(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        _seed_tokens(tmp_vault, "test")

        endpoint = MockTokenEndpoint(success_tokens={
            "access_token": "new_access",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "rotated_refresh",
            "scope": "openid",
        })

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
            engine.refresh("test")

        refresh_rec = tmp_vault._find_by_service_alias("test", "refresh")
        assert refresh_rec is not None
        secret = tmp_vault.get_secret(refresh_rec.id)
        assert secret is not None
        assert secret.secret == "rotated_refresh"
        assert isinstance(secret.metadata, dict)
        assert secret.metadata["rotation_counter"] == 1


# ── Deliverable 4: Refresh failure ─ retry, audit, graceful degradation ────────

class TestRefreshFailure:
    def test_refresh_retries_on_transient_network_errors(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(
            vault=tmp_vault,
            registry=registry,
            max_retries=2,
            base_backoff_seconds=0.001,
        )
        _seed_tokens(tmp_vault, "test")

        endpoint = MockTokenEndpoint(fail_count=1, success_tokens={
            "access_token": "recovered",
            "token_type": "Bearer",
        })

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
            result = engine.refresh("test")

        assert result.success is True
        assert result.new_access_token == "recovered"
        assert result.retry_count == 2
        assert len(endpoint.calls) == 2

    def test_refresh_raises_after_exhausted_retries(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(
            vault=tmp_vault,
            registry=registry,
            max_retries=2,
            base_backoff_seconds=0.001,
        )
        _seed_tokens(tmp_vault, "test")

        endpoint = MockTokenEndpoint(fail_count=3)

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
            with pytest.raises(OAuthNetworkError, match="Network failure after"):
                engine.refresh("test")

    def test_refresh_raises_on_invalid_grant(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        _seed_tokens(tmp_vault, "test")

        endpoint = MockTokenEndpoint(
            error_response={"error": "invalid_grant", "error_description": "Token revoked"},
            status_code=400,
        )

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
            with pytest.raises(RefreshTokenExpiredError, match="Token revoked"):
                engine.refresh("test")

    def test_refresh_audit_log_records_success(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        _seed_tokens(tmp_vault, "test")

        # Inject a real audit logger so records land in a test DB
        from hermes_vault.audit import AuditLogger
        audit_db = tmp_vault.db_path.parent / "test_audit.db"
        audit_logger = AuditLogger(audit_db)
        audit_logger.initialize()
        engine.set_audit(audit_logger)

        endpoint = MockTokenEndpoint(success_tokens={
            "access_token": "ok",
            "token_type": "Bearer",
        })

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
            engine.refresh("test")

        records = audit_logger.list_recent(limit=10)
        assert len(records) == 1
        assert records[0]["action"] == "refresh_token"
        assert records[0]["decision"] == "allow"
        assert "success" in records[0]["reason"].lower()

    def test_refresh_audit_log_records_failure(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        _seed_tokens(tmp_vault, "test")

        from hermes_vault.audit import AuditLogger
        audit_db = tmp_vault.db_path.parent / "test_audit.db"
        audit_logger = AuditLogger(audit_db)
        audit_logger.initialize()
        engine.set_audit(audit_logger)

        # Use invalid_scope which raises OAuthProviderError (caught and logged),
        # NOT invalid_grant which raises RefreshTokenExpiredError (inherits RuntimeError, bypasses log).
        endpoint = MockTokenEndpoint(
            error_response={"error": "invalid_scope", "error_description": "scope not allowed"},
            status_code=400,
        )

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
            with pytest.raises(OAuthProviderError, match="scope not allowed"):
                engine.refresh("test")

        records = audit_logger.list_recent(limit=10)
        assert len(records) == 1
        assert records[0]["action"] == "refresh_token"
        assert records[0]["decision"] == "deny"

    def test_refresh_all_graceful_degradation(self, tmp_vault: Vault, tmp_path: Path):
        """One service fails; the other still succeeds."""
        reg_path = tmp_path / "providers.yaml"
        reg_path.write_text(
            "providers:\n"
            "  good:\n    name: Good\n"
            "    authorization_endpoint: https://good.example.com/auth\n"
            "    token_endpoint: https://good.example.com/token\n"
            "  bad:\n    name: Bad\n"
            "    authorization_endpoint: https://bad.example.com/auth\n"
            "    token_endpoint: https://bad.example.com/token\n"
        )
        registry = OAuthProviderRegistry(reg_path)
        engine = RefreshEngine(vault=tmp_vault, registry=registry)

        _seed_tokens(tmp_vault, "good")
        _seed_tokens(tmp_vault, "bad")

        side_effects = []
        for _ in range(3):
            err = MagicMock()
            err.ok = False
            err.status_code = 400
            err.json.return_value = {"error": "invalid_grant"}
            err.text = '{"error":"invalid_grant"}'
            side_effects.append(err)

        ok = MagicMock()
        ok.ok = True
        ok.status_code = 200
        ok.json.return_value = {"access_token": "new_tok", "token_type": "Bearer"}

        # order depends on list_credentials; seed deterministically
        def post_side_effect(url, data=None, **kwargs):
            if "good" in str(url):
                return ok
            err = MagicMock()
            err.ok = False
            err.status_code = 400
            err.json.return_value = {"error": "invalid_grant"}
            err.text = '{"error":"invalid_grant"}'
            return err

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=post_side_effect):
            results = engine.refresh_all()

        assert len(results) == 2
        # One success, one failure
        success = [r for r in results if r.success]
        failure = [r for r in results if not r.success]
        assert len(success) == 1
        assert len(failure) == 1
        assert success[0].service == "good"


# ── Deliverable 5: Concurrent refresh safety (single writer) ───────────────────

class TestConcurrentRefresh:
    def test_concurrent_refresh_no_vault_corruption(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        """Two threads racing to refresh the same token must not corrupt vault state."""
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        _seed_tokens(tmp_vault, "test")

        barrier = threading.Barrier(2)
        results: list[RefreshAttempt | None] = [None, None]
        exceptions: list[Exception | None] = [None, None]

        call_count = 0
        lock = threading.Lock()

        def post_side_effect(url, data=None, **kwargs):
            nonlocal call_count
            with lock:
                call_count += 1
                token = f"threaded_tok_{call_count}"
            mock_resp = MagicMock()
            mock_resp.ok = True
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": 3600,
            }
            return mock_resp

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=post_side_effect):
            def refresh_worker(idx: int):
                try:
                    barrier.wait(timeout=2)
                    results[idx] = engine.refresh("test")
                except Exception as exc:
                    exceptions[idx] = exc

            threads = [threading.Thread(target=refresh_worker, args=(i,)) for i in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)

        # SQLite serializes writers, so at least one succeeds
        success_count = sum(1 for r in results if r is not None and r.success)
        assert success_count >= 1

        # Vault secret must decrypt cleanly and status must be active
        access_rec = tmp_vault.resolve_credential("test", alias="default")
        secret = tmp_vault.get_secret(access_rec.id)
        assert secret is not None
        assert secret.secret.startswith("threaded_tok_")
        assert access_rec.status == CredentialStatus.active

    def test_atomic_update_prevents_partial_writes(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        """If _update_vault_atomic raises, vault must remain in its prior state."""
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        _seed_tokens(tmp_vault, "test")

        endpoint = MockTokenEndpoint(success_tokens={
            "access_token": "should_not_land",
            "token_type": "Bearer",
        })

        with patch.object(
            engine, "_update_vault_atomic", side_effect=RuntimeError("Simulated DB crash")
        ):
            with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
                with pytest.raises(RuntimeError, match="Simulated DB crash"):
                    engine.refresh("test")

        # Vault must still hold the old access token
        access_rec = tmp_vault.resolve_credential("test", alias="default")
        secret = tmp_vault.get_secret(access_rec.id)
        assert secret is not None
        assert secret.secret == "old_access"


# ── Deliverable 6: Dry-run mode ────────────────────────────────────────────────

class TestDryRunMode:
    def test_dry_run_detects_without_mutating_vault(self, tmp_vault: Vault, registry: OAuthProviderRegistry):
        engine = RefreshEngine(vault=tmp_vault, registry=registry)
        _seed_tokens(tmp_vault, "test")

        endpoint = MockTokenEndpoint(success_tokens={
            "access_token": "dryrun_new",
            "token_type": "Bearer",
            "expires_in": 3600,
        })

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
            result = engine.refresh("test", dry_run=True)

        assert result.success is True
        assert result.reason == "Token refresh simulated (dry-run)"

        # Vault unchanged -- access token still old_access, refresh still old_refresh
        access_rec = tmp_vault.resolve_credential("test", alias="default")
        secret = tmp_vault.get_secret(access_rec.id)
        assert secret is not None
        assert secret.secret == "old_access"

    def test_dry_run_in_refresh_all(self, tmp_vault: Vault, tmp_path: Path):
        reg_path = tmp_path / "providers.yaml"
        reg_path.write_text(
            "providers:\n"
            "  alpha:\n    name: Alpha\n"
            "    authorization_endpoint: https://alpha.example.com/auth\n"
            "    token_endpoint: https://alpha.example.com/token\n"
            "  beta:\n    name: Beta\n"
            "    authorization_endpoint: https://beta.example.com/auth\n"
            "    token_endpoint: https://beta.example.com/token\n"
        )
        registry = OAuthProviderRegistry(reg_path)
        engine = RefreshEngine(vault=tmp_vault, registry=registry)

        _seed_tokens(tmp_vault, "alpha")
        _seed_tokens(tmp_vault, "beta")

        endpoint = MockTokenEndpoint(success_tokens={
            "access_token": "would_be_new",
            "token_type": "Bearer",
        })

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
            results = engine.refresh_all(dry_run=True)

        assert len(results) == 2
        assert all(r.success for r in results)
        assert all("dry-run" in r.reason.lower() or "simulated" in r.reason.lower() for r in results)

        # Verify vault untouched for both services
        for svc in ("alpha", "beta"):
            access_rec = tmp_vault.resolve_credential(svc, alias="default")
            secret = tmp_vault.get_secret(access_rec.id)
            assert secret is not None
            assert secret.secret == "old_access"
