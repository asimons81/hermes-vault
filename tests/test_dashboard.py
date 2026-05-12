from __future__ import annotations

import json
import time
import urllib.error
from types import SimpleNamespace
import urllib.request
from pathlib import Path

import pytest

from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.dashboard import (
    DashboardAPI,
    DashboardContext,
    _safe_refresh_attempt_dict,
    _sanitize_maintenance_for_dashboard,
    dashboard_static_dir,
    create_dashboard_server,
    run_dashboard,
    sanitize_credential,
    validate_vault_key,
)
from hermes_vault.models import AccessLogRecord, BrokerDecision, Decision, VerificationCategory, VerificationResult
from hermes_vault.policy import PolicyEngine
from hermes_vault.verifier import Verifier
from hermes_vault.vault import Vault


def _context(tmp_path: Path) -> DashboardContext:
    from hermes_vault.config import AppSettings

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
agents:
  hermes:
    services:
      openai:
        actions: [get_env, verify, metadata]
    capabilities: [list_credentials]
    raw_secret_access: false
    ephemeral_env_only: true
""".lstrip(),
        encoding="utf-8",
    )
    settings = AppSettings(runtime_home=tmp_path, policy_path=policy_path)
    settings.ensure_runtime_layout()
    policy = PolicyEngine.from_yaml(policy_path)
    vault = Vault(settings.db_path, settings.salt_path, "test-passphrase")
    vault.add_credential("openai", "sk-test-secret", "api_key", alias="default")
    audit = AuditLogger(settings.db_path)
    audit.record(
        AccessLogRecord(
            agent_id="operator",
            service="openai",
            action="test",
            decision=Decision.allow,
            reason="seed audit",
        )
    )
    broker = Broker(vault=vault, policy=policy, verifier=Verifier(), audit=audit)
    return DashboardContext(
        settings=settings,
        vault=vault,
        policy=policy,
        broker=broker,
        audit=audit,
    )


def _empty_context(tmp_path: Path) -> DashboardContext:
    from hermes_vault.config import AppSettings

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
agents:
  hermes:
    services:
      openai:
        actions: [get_env, verify, metadata]
    capabilities: [list_credentials]
    raw_secret_access: false
    ephemeral_env_only: true
""".lstrip(),
        encoding="utf-8",
    )
    settings = AppSettings(runtime_home=tmp_path, policy_path=policy_path)
    settings.ensure_runtime_layout()
    policy = PolicyEngine.from_yaml(policy_path)
    vault = Vault(settings.db_path, settings.salt_path, "test-passphrase")
    audit = AuditLogger(settings.db_path)
    broker = Broker(vault=vault, policy=policy, verifier=Verifier(), audit=audit)
    return DashboardContext(
        settings=settings,
        vault=vault,
        policy=policy,
        broker=broker,
        audit=audit,
    )


def test_sanitize_credential_excludes_encrypted_payload(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    record = ctx.vault.list_credentials()[0]

    payload = sanitize_credential(record)

    assert "encrypted_payload" not in payload
    assert payload["service"] == "openai"
    assert payload["alias"] == "default"


def test_dashboard_api_credentials_are_sanitized(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    api = DashboardAPI(context_factory=lambda: ctx)

    payload = api.credentials()

    assert payload["credentials"]
    assert payload["runtime"]["credential_count"] == 1
    assert payload["runtime"]["db_path"].endswith("vault.db")
    assert payload["runtime"]["home_source"] in {"default", "env"}
    assert "encrypted_payload" not in payload["credentials"][0]
    assert "sk-test-secret" not in json.dumps(payload)


def test_dashboard_rejects_non_local_binding() -> None:
    with pytest.raises(ValueError):
        create_dashboard_server(host="0.0.0.0")


def test_dashboard_server_requires_token(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    api = DashboardAPI(context_factory=lambda: ctx)
    server = create_dashboard_server(token="secret-token", api=api)
    try:
        port = server.server_address[1]
        import threading

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/credentials", timeout=5)
        assert exc.value.code == 401

        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/credentials",
            headers={"Authorization": "Bearer secret-token"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
            assert response.headers["X-Content-Type-Options"] == "nosniff"
            assert response.headers["X-Frame-Options"] == "DENY"
        assert payload["credentials"][0]["service"] == "openai"
        assert "encrypted_payload" not in payload["credentials"][0]
    finally:
        server.shutdown()
        server.server_close()


def test_dashboard_serves_static_assets_and_404s_missing_assets(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    api = DashboardAPI(context_factory=lambda: ctx)
    server = create_dashboard_server(token="secret-token", api=api)
    try:
        port = server.server_address[1]
        import threading

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/app.js", timeout=5) as response:
            assert response.headers["Content-Type"].startswith("text/javascript")
            assert response.status == 200

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/styles.css", timeout=5) as response:
            assert response.headers["Content-Type"].startswith("text/css")
            assert response.status == 200

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/assets/hermes-vault-console-brand.png", timeout=5) as response:
            assert response.headers["Content-Type"].startswith("image/png")
            assert response.status == 200

        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/assets/missing.png", timeout=5)
        assert exc.value.code == 404
    finally:
        server.shutdown()
        server.server_close()


def test_dashboard_static_asset_exists_in_package() -> None:
    assert (dashboard_static_dir() / "assets" / "hermes-vault-console-brand.png").exists()


def test_dashboard_server_expires_session_token(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    api = DashboardAPI(context_factory=lambda: ctx)
    server = create_dashboard_server(token="secret-token", api=api, ttl_seconds=1)
    try:
        port = server.server_address[1]
        import threading

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(1.1)

        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/credentials",
            headers={"Authorization": "Bearer secret-token"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(request, timeout=5)
        assert exc.value.code == 401
    finally:
        server.shutdown()
        server.server_close()


def test_dashboard_safe_health_action(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    api = DashboardAPI(context_factory=lambda: ctx)

    status, payload = api.action("health", {})

    assert status == 200
    assert payload["version"] == "health-v1"
    assert "findings" in payload


def test_dashboard_validates_correct_vault_key(tmp_path: Path) -> None:
    ctx = _context(tmp_path)

    validation = validate_vault_key(ctx)

    assert validation["status"] == "valid"
    assert validation["ok"] is True
    assert validation["checked_count"] == 1
    assert validation["decrypted_count"] == 1


def test_dashboard_reports_degraded_key_validation_when_only_some_credentials_fail(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    broken = ctx.vault.add_credential("aaa-broken", "broken-secret", "api_key", alias="default")
    import sqlite3

    with sqlite3.connect(ctx.settings.db_path) as conn:
        conn.execute("UPDATE credentials SET encrypted_payload = ? WHERE id = ?", ("not-valid-ciphertext", broken.id))
        conn.commit()
    api = DashboardAPI(context_factory=lambda: ctx)

    validation = validate_vault_key(ctx)
    overview = api.overview()
    status, payload = api.action("health", {})

    assert validation["status"] == "degraded"
    assert validation["ok"] is True
    assert validation["decrypted_count"] == 1
    assert validation["failed_count"] == 1
    assert validation["failures"] == [{"service": "aaa-broken", "alias": "default"}]
    assert overview["runtime"]["key_validation"]["status"] == "degraded"
    assert status == 200
    assert payload["version"] == "health-v1"


def test_dashboard_reports_empty_vault_key_validation(tmp_path: Path) -> None:
    ctx = _empty_context(tmp_path)
    api = DashboardAPI(context_factory=lambda: ctx)

    validation = validate_vault_key(ctx)
    payload = api.overview()

    assert validation["status"] == "empty_vault"
    assert validation["ok"] is True
    assert payload["runtime"]["key_validation"]["status"] == "empty_vault"


def test_dashboard_blocks_secret_actions_when_vault_key_invalid(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    wrong_vault = Vault(ctx.settings.db_path, ctx.settings.salt_path, "wrong-passphrase")
    wrong_ctx = DashboardContext(
        settings=ctx.settings,
        vault=wrong_vault,
        policy=ctx.policy,
        broker=Broker(vault=wrong_vault, policy=ctx.policy, verifier=Verifier(), audit=ctx.audit),
        audit=ctx.audit,
    )
    api = DashboardAPI(context_factory=lambda: wrong_ctx)

    overview = api.overview()
    status, payload = api.action("verify", {"all": True})
    health_status, health_payload = api.action("health", {})

    assert overview["runtime"]["key_validation"]["status"] == "invalid"
    assert status == 423
    assert payload["key_validation"]["status"] == "invalid"
    assert payload["key_validation"]["decrypted_count"] == 0
    assert "key material" in payload["error"]
    assert health_status == 200
    assert health_payload["version"] == "health-v1"
    assert "sk-test-secret" not in json.dumps(payload)


def test_dashboard_verify_all_reports_decrypt_failure_without_500(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    wrong_vault = Vault(ctx.settings.db_path, ctx.settings.salt_path, "wrong-passphrase")
    wrong_ctx = DashboardContext(
        settings=ctx.settings,
        vault=wrong_vault,
        policy=ctx.policy,
        broker=Broker(vault=wrong_vault, policy=ctx.policy, verifier=Verifier(), audit=ctx.audit),
        audit=ctx.audit,
    )
    api = DashboardAPI(context_factory=lambda: wrong_ctx)

    status, payload = api.action("verify", {"all": True})

    assert status == 423
    assert payload["key_validation"]["status"] == "invalid"
    assert "sk-test-secret" not in json.dumps(payload)


def test_dashboard_verify_all_collects_per_credential_exceptions(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    ctx.vault.add_credential("github", "ghp-test-secret", "personal_access_token", alias="work")

    class PartiallyFailingBroker:
        def verify_credential(self, service: str, alias: str | None = None):
            if service == "github":
                raise RuntimeError("provider exploded with sensitive details")
            return BrokerDecision(
                allowed=True,
                service=service,
                agent_id="hermes-vault",
                reason="ok",
                metadata={"alias": alias or "default"},
            )

    batch_ctx = DashboardContext(
        settings=ctx.settings,
        vault=ctx.vault,
        policy=ctx.policy,
        broker=PartiallyFailingBroker(),  # type: ignore[arg-type]
        audit=ctx.audit,
    )
    api = DashboardAPI(context_factory=lambda: batch_ctx)

    status, payload = api.action("verify", {"all": True})

    assert status == 200
    assert len(payload["results"]) == 2
    github_result = next(result for result in payload["results"] if result["service"] == "github")
    assert github_result["allowed"] is False
    assert github_result["metadata"]["error_kind"] == "dashboard_verify_exception"
    assert "sensitive details" not in json.dumps(payload)


def test_dashboard_verify_all_keeps_unsupported_provider_as_result(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    ctx.vault.add_credential("internal-tool", "internal-secret", "api_key", alias="default")
    api = DashboardAPI(context_factory=lambda: ctx)

    status, payload = api.action("verify", {"all": True})

    assert status == 200
    internal_result = next(result for result in payload["results"] if result["service"] == "internal-tool")
    assert internal_result["allowed"] is False
    assert "No provider-specific verifier" in internal_result["reason"]
    internal_record = ctx.vault.resolve_credential("internal-tool", alias="default")
    assert internal_record.last_verified_at is None
    assert "internal-secret" not in json.dumps(payload)


def test_dashboard_verify_all_handles_legacy_stored_service_alias(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    ctx.vault.add_credential("google", "gmail-secret", "app_password", alias="primary")
    import sqlite3

    with sqlite3.connect(ctx.settings.db_path) as conn:
        conn.execute("UPDATE credentials SET service = ? WHERE alias = ?", ("gmail", "primary"))
        conn.commit()

    class RecordingVerifier:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def verify(self, service: str, secret: str) -> VerificationResult:
            self.calls.append((service, secret))
            return VerificationResult(
                service=service,
                category=VerificationCategory.valid,
                success=True,
                reason="ok",
            )

    verifier = RecordingVerifier()
    broker = Broker(vault=ctx.vault, policy=ctx.policy, verifier=verifier, audit=ctx.audit)
    api = DashboardAPI(context_factory=lambda: DashboardContext(
        settings=ctx.settings,
        vault=ctx.vault,
        policy=ctx.policy,
        broker=broker,
        audit=ctx.audit,
    ))

    status, payload = api.action("verify", {"service": "gmail", "alias": "primary"})

    assert status == 200
    result = payload["results"][0]
    assert result["allowed"] is True
    assert verifier.calls == [("google", "gmail-secret")]
    assert "gmail-secret" not in json.dumps(payload)


def test_dashboard_session_endpoint_reports_safe_actions(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    api = DashboardAPI(context_factory=lambda: ctx)
    server = create_dashboard_server(token="secret-token", api=api, ttl_seconds=120)
    try:
        payload = api.session(server)
    finally:
        server.server_close()

    assert payload["local_only"] is True
    assert "verify" in payload["safe_actions"]
    assert "delete_credential" not in payload["safe_actions"]
    assert payload["dry_run_only_actions"] == ["maintenance", "oauth_refresh"]
    assert payload["seconds_remaining"] > 0


def test_dashboard_forces_oauth_refresh_to_dry_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    api = DashboardAPI(context_factory=lambda: ctx)
    calls: list[tuple[str, str | None, str | None, bool]] = []

    class FakeRefreshEngine:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def set_audit(self, audit) -> None:
            pass

        def refresh(self, service: str, alias: str = "default", dry_run: bool = False):
            calls.append(("refresh", service, alias, dry_run))
            return SimpleNamespace(
                service=service,
                alias=alias,
                success=True,
                reason="simulated",
                new_access_token=None,
                new_refresh_token=None,
                expires_in=None,
                scopes=[],
                retry_count=0,
            )

        def refresh_all(self, dry_run: bool = False):
            calls.append(("refresh_all", None, None, dry_run))
            return []

    monkeypatch.setattr("hermes_vault.dashboard.RefreshEngine", FakeRefreshEngine)

    status, payload = api.action("oauth_refresh", {"service": "openai", "alias": "default", "dry_run": False})

    assert status == 200
    assert calls == [("refresh", "openai", "default", True)]
    assert payload["dry_run"] is True
    assert payload["dashboard_boundary"] == "dry_run_only"


def test_dashboard_forces_maintenance_to_dry_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    api = DashboardAPI(context_factory=lambda: ctx)
    calls: list[dict[str, object]] = []

    class FakeMaintenanceReport:
        def as_dict(self, *, exclude_none: bool = True) -> dict[str, object]:
            return {"version": "maintain-v1", "dry_run": True}

    def fake_run_maintenance(*args, **kwargs):
        calls.append(dict(kwargs))
        return FakeMaintenanceReport()

    monkeypatch.setattr("hermes_vault.dashboard.run_maintenance", fake_run_maintenance)

    status, payload = api.action("maintenance", {"dry_run": False})

    assert status == 200
    assert calls[0]["dry_run"] is True
    assert payload["dry_run"] is True


def test_dashboard_overview_reports_runtime_diagnostics(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    api = DashboardAPI(context_factory=lambda: ctx)

    payload = api.overview()

    assert payload["runtime"]["runtime_home"] == str(tmp_path)
    assert payload["runtime"]["db_exists"] is True
    assert payload["runtime"]["policy_exists"] is True
    assert payload["runtime"]["salt_exists"] is True
    assert payload["runtime"]["credential_count"] == 1
    assert payload["runtime"]["is_temp_runtime"] is str(tmp_path).startswith("/tmp/")


def test_dashboard_unknown_action_denied(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    api = DashboardAPI(context_factory=lambda: ctx)

    status, payload = api.action("delete_credential", {})

    assert status == 404
    assert "unknown" in payload["error"]


def test_dashboard_bad_limit_returns_json_400(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    api = DashboardAPI(context_factory=lambda: ctx)
    server = create_dashboard_server(token="secret-token", api=api)
    try:
        port = server.server_address[1]
        import threading

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/audit?limit=nope",
            headers={"Authorization": "Bearer secret-token"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(request, timeout=5)
        assert exc.value.code == 400
        payload = json.loads(exc.value.read().decode("utf-8"))
        assert payload["error"] == "limit must be an integer"
    finally:
        server.shutdown()
        server.server_close()


def test_dashboard_bad_json_returns_json_400(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    api = DashboardAPI(context_factory=lambda: ctx)
    server = create_dashboard_server(token="secret-token", api=api)
    try:
        port = server.server_address[1]
        import threading

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/actions/health",
            data=b"{",
            headers={"Authorization": "Bearer secret-token", "Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(request, timeout=5)
        assert exc.value.code == 400
        payload = json.loads(exc.value.read().decode("utf-8"))
        assert payload["error"] == "request body must be valid JSON"
    finally:
        server.shutdown()
        server.server_close()


def test_run_dashboard_builds_context_before_server_start(monkeypatch) -> None:
    def fail_context(*, prompt: bool = True):
        raise RuntimeError("missing passphrase")

    monkeypatch.setattr("hermes_vault.dashboard.build_dashboard_context", fail_context)

    with pytest.raises(RuntimeError, match="missing passphrase"):
        run_dashboard(open_browser=False)


def test_safe_refresh_attempt_dict_never_exposes_tokens() -> None:
    attempt = SimpleNamespace(
        service="google",
        alias="default",
        success=True,
        reason="simulated",
        new_access_token="live-access-token-abc123",
        new_refresh_token="live-refresh-token-xyz789",
        expires_in=3600,
        scopes=["read", "write"],
        retry_count=0,
    )
    safe = _safe_refresh_attempt_dict(attempt)
    assert safe["service"] == "google"
    assert safe["success"] is True
    assert "new_access_token" not in safe
    assert "new_refresh_token" not in safe
    assert "live-access-token" not in str(safe)
    assert "live-refresh-token" not in str(safe)


def test_sanitize_maintenance_for_dashboard_strips_tokens() -> None:
    raw = {
        "version": "maintain-v1",
        "dry_run": True,
        "refresh_results": [
            {
                "service": "google",
                "success": True,
                "new_access_token": "live-access-token-abc123",
                "new_refresh_token": "live-refresh-token-xyz789",
                "reason": "refreshed",
            }
        ],
    }
    clean = _sanitize_maintenance_for_dashboard(raw)
    assert clean["version"] == "maintain-v1"
    result = clean["refresh_results"][0]
    assert "new_access_token" not in result
    assert "new_refresh_token" not in result
    assert "live-access-token" not in str(clean)
    assert "live-refresh-token" not in str(clean)


def test_dashboard_oauth_refresh_response_excludes_tokens(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    api = DashboardAPI(context_factory=lambda: ctx)

    class FakeRefreshEngine:
        def __init__(self, *args, **kwargs) -> None:
            pass
        def set_audit(self, audit) -> None:
            pass
        def refresh(self, service: str, alias: str = "default", dry_run: bool = False):
            return SimpleNamespace(
                service=service,
                alias=alias,
                success=True,
                reason="simulated",
                new_access_token="live-access-token-abc123",
                new_refresh_token="live-refresh-token-xyz789",
                expires_in=3600,
                scopes=["read"],
                retry_count=0,
            )

    monkeypatch.setattr("hermes_vault.dashboard.RefreshEngine", FakeRefreshEngine)
    status, payload = api.action("oauth_refresh", {"service": "google", "alias": "default", "dry_run": False})
    assert status == 200
    result = payload["results"][0]
    assert "new_access_token" not in result
    assert "new_refresh_token" not in result
    assert "live-access-token" not in json.dumps(payload)
    assert "live-refresh-token" not in json.dumps(payload)


def test_dashboard_maintenance_response_excludes_tokens(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    api = DashboardAPI(context_factory=lambda: ctx)

    class FakeMaintenanceReport:
        def as_dict(self, *, exclude_none: bool = True) -> dict[str, object]:
            return {
                "version": "maintain-v1",
                "dry_run": True,
                "refresh_results": [
                    {
                        "service": "google",
                        "success": True,
                        "new_access_token": "live-access-token-abc123",
                        "new_refresh_token": "live-refresh-token-xyz789",
                        "reason": "refreshed",
                    }
                ],
            }

    def fake_run_maintenance(*args, **kwargs):
        return FakeMaintenanceReport()

    monkeypatch.setattr("hermes_vault.dashboard.run_maintenance", fake_run_maintenance)
    status, payload = api.action("maintenance", {"dry_run": False})
    assert status == 200
    result = payload["refresh_results"][0]
    assert "new_access_token" not in result
    assert "new_refresh_token" not in result
    assert "live-access-token" not in json.dumps(payload)
    assert "live-refresh-token" not in json.dumps(payload)
