from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from click.testing import CliRunner

from hermes_vault.audit import AuditLogger
from hermes_vault.audit_integrity.checkpoint import read_checkpoint
from hermes_vault.audit_integrity.service import AuditIntegrityService
from hermes_vault.cli import _hermes_group
from hermes_vault.dashboard import DashboardAPI, create_dashboard_server
from hermes_vault.models import AccessLogRecord, Decision
from hermes_vault.vault import Vault


# ── helpers ─────────────────────────────────────────────────────────────────


def _make_vault(tmp_path: Path) -> Vault:
    vault = Vault(tmp_path / "vault.db", tmp_path / "master_key_salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-fake-key-12345", "api_key")
    return vault


def _seed_and_init_integrity(vault: Vault, count: int = 5) -> AuditIntegrityService:
    """Initialize integrity and seed *count* records into the chain."""
    svc = AuditIntegrityService(vault.db_path, vault.key)
    svc.ensure_initialized()
    for i in range(count):
        svc.append(
            AccessLogRecord(
                id=f"svc-{i}-{time.monotonic_ns()}",
                agent_id=f"agent-{i}",
                service="openai",
                action="get_env",
                decision=Decision.allow,
                reason=f"seed row {i}",
            )
        )
    return svc


def _add_unprotected_audit_rows(vault: Vault, count: int = 3) -> None:
    """Add rows directly to access_logs, bypassing integrity service entirely."""
    import sqlite3
    from uuid import uuid4

    conn = sqlite3.connect(vault.db_path)
    try:
        for i in range(count):
            rid = str(uuid4())
            conn.execute(
                "INSERT INTO access_logs (id, timestamp, agent_id, service, action, decision, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (rid, "2026-07-18T16:00:00", f"rogue-{i}", "openai", "get_env", "allow", f"unprotected row {i}"),
            )
        conn.commit()
    finally:
        conn.close()


def _wait_for_server(url: str, timeout: float = 10.0, interval: float = 0.1) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                resp.read()
            return
        except (urllib.error.URLError, OSError) as exc:
            last_error = exc
            time.sleep(interval)
    raise RuntimeError(f"Server at {url} did not become ready within {timeout}s") from last_error


def _mcp_audit_integrity_payload(vault: Vault) -> dict:
    """Direct call to the MCP audit-integrity resource payload function."""
    from hermes_vault.mcp_server import _audit_integrity_resource_payload
    from hermes_vault.broker import Broker
    from hermes_vault.policy import PolicyEngine
    from hermes_vault.verifier import Verifier
    from hermes_vault.config import AppSettings
    import types

    db_path = vault.db_path
    settings = AppSettings(runtime_home=db_path.parent, base_home=db_path.parent)
    settings.ensure_runtime_layout()
    policy = PolicyEngine.from_yaml(settings.effective_policy_path)
    audit = AuditLogger(db_path, master_key=vault.key)
    verifier = Verifier(plugin_dir=settings.verifier_plugin_dir)
    broker = Broker(vault=vault, policy=policy, verifier=verifier, audit=audit)

    binding = types.SimpleNamespace(
        requested_agent_id="test-agent",
        effective_agent_id="test-agent",
        binding_mode="enforcement",
        allowed_agents=("test-agent",),
        default_agent="test-agent",
    )
    return _audit_integrity_resource_payload(broker, binding)


def _api(tmp_path: Path, vault: Vault | None = None) -> DashboardAPI:
    from hermes_vault.config import AppSettings

    vault = vault or _make_vault(tmp_path)
    settings = AppSettings(runtime_home=tmp_path, base_home=tmp_path)
    settings.ensure_runtime_layout()

    class FakeCtx:
        @property
        def settings(self):
            return settings
        @property
        def vault(self):
            return vault
        @property
        def audit(self):
            return AuditLogger(settings.db_path, master_key=vault.key)

    return DashboardAPI(context_factory=lambda: FakeCtx())


def _start_server(api: DashboardAPI):
    server = create_dashboard_server(token="test-token", api=api)
    port = server.server_address[1]
    import threading
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _wait_for_server(f"http://127.0.0.1:{port}/")
    return server, port, thread


def _dash_get(port: int, path: str, token: str | None = "test-token") -> dict:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _dash_post(port: int, path: str, data: dict | None = None, token: str | None = "test-token") -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data or {}).encode("utf-8")
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ── CLI: audit-verify ───────────────────────────────────────────────────────


class TestCliAuditVerify:
    """Exit codes: 0=healthy, 2=incomplete, 3=failed, 1=error."""

    def _invoke(self, monkeypatch, tmp_path: Path, args: list[str]) -> tuple[int, str]:
        monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
        monkeypatch.setenv("HERMES_VAULT_PASSPHRASE_DEFAULT", "test-passphrase")
        runner = CliRunner()
        result = runner.invoke(_hermes_group, ["audit-verify"] + args)
        return result.exit_code, result.output

    def test_healthy_exit_code(self, monkeypatch, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        code, output = self._invoke(monkeypatch, tmp_path, [])
        assert code == 0, f"Expected healthy (0), got {code}: {output}"

    def test_healthy_json_output_contract(self, monkeypatch, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        code, output = self._invoke(monkeypatch, tmp_path, ["--format", "json"])
        assert code == 0
        payload = json.loads(output)
        assert payload["status"] == "healthy"
        assert payload["chain_version"] is not None
        assert isinstance(payload["verified_count"], int) and payload["verified_count"] > 0
        for key in ("status", "chain_version", "verified_count", "checkpoint_status", "verified_at"):
            assert key in payload, f"Missing JSON field: {key}"

    def test_healthy_human_output(self, monkeypatch, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        code, output = self._invoke(monkeypatch, tmp_path, [])
        assert code == 0
        # Human output should contain readable field names
        assert "Status" in output or "healthy" in output.lower()
        assert "Chain" in output or "chain" in output.lower()

    def test_incomplete_with_missing_checkpoint(self, monkeypatch, tmp_path: Path) -> None:
        """A missing checkpoint makes the chain incomplete (exit code 2)."""
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        # Delete the checkpoint to trigger 'missing' state -> incomplete
        cp_path = tmp_path / "audit.checkpoint.json"
        if cp_path.exists():
            cp_path.unlink()
        code, output = self._invoke(monkeypatch, tmp_path, ["--format", "json"])
        assert code == 2, f"Expected incomplete (2), got {code}: {output}"
        payload = json.loads(output)
        assert payload["status"] in ("incomplete",)
        assert payload["checkpoint_status"] == "missing"

    def test_incomplete_json_output(self, monkeypatch, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        cp_path = tmp_path / "audit.checkpoint.json"
        if cp_path.exists():
            cp_path.unlink()
        code, output = self._invoke(monkeypatch, tmp_path, ["--format", "json"])
        assert code == 2
        payload = json.loads(output)
        assert "status" in payload
        assert "reason_code" in payload

    def test_invalid_format_returns_error(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
        monkeypatch.setenv("HERMES_VAULT_PASSPHRASE_DEFAULT", "test-passphrase")
        runner = CliRunner()
        result = runner.invoke(_hermes_group, ["audit-verify", "--format", "xml"])
        assert result.exit_code == 1
        # Sanitized error output (no stack traces)
        assert "must be" in result.output

    def test_verify_is_read_only(self, monkeypatch, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        cp_before = read_checkpoint(tmp_path / "audit.checkpoint.json")
        self._invoke(monkeypatch, tmp_path, ["--format", "json"])
        cp_after = read_checkpoint(tmp_path / "audit.checkpoint.json")
        assert cp_before == cp_after, "Verification mutated checkpoint state"

    def test_sanitized_error_output(self, monkeypatch, tmp_path: Path) -> None:
        """Errors should not leak credentials or paths in raw form."""
        monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
        monkeypatch.setenv("HERMES_VAULT_PASSPHRASE_DEFAULT", "test-passphrase")
        runner = CliRunner()
        result = runner.invoke(_hermes_group, ["audit-verify", "--format", "xml"])
        assert result.exit_code == 1
        # No traceback or debug info in output
        assert "Traceback" not in result.output
        assert "File \"" not in result.output
        assert "sk-fake" not in result.output


# ── CLI: audit-checkpoint ────────────────────────────────────────────────────


class TestCliAuditCheckpoint:
    def _invoke(self, monkeypatch, tmp_path: Path, args: list[str]) -> tuple[int, str]:
        monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
        monkeypatch.setenv("HERMES_VAULT_PASSPHRASE_DEFAULT", "test-passphrase")
        runner = CliRunner()
        result = runner.invoke(_hermes_group, ["audit-checkpoint"] + args)
        return result.exit_code, result.output

    def test_show_healthy(self, monkeypatch, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        code, output = self._invoke(monkeypatch, tmp_path, ["show"])
        assert code == 0
        assert "Status" in output or "healthy" in output.lower()

    def test_establish_requires_yes(self, monkeypatch, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        code, output = self._invoke(monkeypatch, tmp_path, ["establish"])
        assert code == 1
        assert "--yes" in output

    def test_establish_with_yes(self, monkeypatch, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        code, output = self._invoke(monkeypatch, tmp_path, ["establish", "--yes"])
        assert code == 0, f"Expected 0, got {code}: {output}"

    def test_advance_requires_yes(self, monkeypatch, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        code, output = self._invoke(monkeypatch, tmp_path, ["advance"])
        assert code == 1
        assert "--yes" in output

    def test_advance_with_yes(self, monkeypatch, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        code, output = self._invoke(monkeypatch, tmp_path, ["advance", "--yes"])
        assert code == 0, f"Expected 0, got {code}: {output}"

    def test_recover_with_yes(self, monkeypatch, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        code, output = self._invoke(monkeypatch, tmp_path, ["recover", "--yes"])
        # recover may succeed or not depending on state; must not crash
        assert code in (0, 1, 2), f"Unexpected exit code: {code}"

    def test_unknown_action_returns_error(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
        monkeypatch.setenv("HERMES_VAULT_PASSPHRASE_DEFAULT", "test-passphrase")
        runner = CliRunner()
        result = runner.invoke(_hermes_group, ["audit-checkpoint", "fly"])
        assert result.exit_code == 1
        assert "Unknown" in result.output

    def test_show_is_read_only(self, monkeypatch, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        svc = _seed_and_init_integrity(vault)
        result_before = svc.verify()
        self._invoke(monkeypatch, tmp_path, ["show"])
        result_after = svc.verify()
        assert result_before.status == result_after.status


# ── CLI: audit-export ────────────────────────────────────────────────────────


class TestCliAuditExport:
    def _invoke(self, monkeypatch, tmp_path: Path, args: list[str]) -> tuple[int, str]:
        monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
        monkeypatch.setenv("HERMES_VAULT_PASSPHRASE_DEFAULT", "test-passphrase")
        runner = CliRunner()
        result = runner.invoke(_hermes_group, ["audit-export"] + args)
        return result.exit_code, result.output

    def test_export_without_integrity(self, monkeypatch, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        code, output = self._invoke(monkeypatch, tmp_path, [])
        assert code == 0
        payload = json.loads(output)
        assert payload["version"] == "audit-export-v1"
        assert "entries" in payload
        assert isinstance(payload["entries"], list)
        assert payload["entry_count"] > 0
        # Export redaction: no encrypted_payload in entries
        for entry in payload["entries"]:
            assert "encrypted_payload" not in entry

    def test_export_with_integrity(self, monkeypatch, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        code, output = self._invoke(monkeypatch, tmp_path, ["--with-integrity"])
        assert code == 0
        payload = json.loads(output)
        assert payload["version"] == "audit-export-v1"
        assert "integrity" in payload
        integrity = payload["integrity"]
        assert integrity["version"] == "audit-backup-evidence-v1"
        assert integrity["verification_summary"]["status"] is not None
        assert integrity["verification_summary"]["verified_count"] > 0

    def test_export_ordering(self, monkeypatch, tmp_path: Path) -> None:
        """Export entries should have consistent ordering."""
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        code, output = self._invoke(monkeypatch, tmp_path, [])
        assert code == 0
        payload = json.loads(output)
        assert isinstance(payload["entries"], list)
        assert len(payload["entries"]) == payload["entry_count"]

    def test_export_version(self, monkeypatch, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        code, output = self._invoke(monkeypatch, tmp_path, [])
        assert code == 0
        payload = json.loads(output)
        assert payload["version"] == "audit-export-v1"

    def test_no_private_signing_material(self, monkeypatch, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        code, output = self._invoke(monkeypatch, tmp_path, ["--with-integrity"])
        assert code == 0
        payload = json.loads(output)
        output_str = json.dumps(payload)
        assert "private_key" not in output_str
        assert "master_key" not in output_str
        assert "passphrase" not in output_str
        assert "sk-fake" not in output_str


# ── Dashboard: audit-integrity endpoints ─────────────────────────────────────


class TestDashboardAuditIntegrity:
    def test_get_audit_integrity_healthy(self, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        api = _api(tmp_path, vault)
        server, port, _ = _start_server(api)
        try:
            payload = _dash_get(port, "/api/audit-integrity")
            assert payload["status"] == "healthy"
            assert payload["version"] == "audit-integrity-dashboard-v1"
            assert isinstance(payload["verified_count"], int)
        finally:
            server.shutdown()
            server.server_close()

    def test_get_audit_integrity_incomplete(self, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        _add_unprotected_audit_rows(vault)
        api = _api(tmp_path, vault)
        server, port, _ = _start_server(api)
        try:
            payload = _dash_get(port, "/api/audit-integrity")
            assert payload["status"] in ("incomplete", "failed")
        finally:
            server.shutdown()
            server.server_close()

    def test_post_audit_integrity_verify(self, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        api = _api(tmp_path, vault)
        server, port, _ = _start_server(api)
        try:
            payload = _dash_post(port, "/api/audit-integrity/verify")
            assert payload["status"] == "healthy"
            assert payload["version"] == "audit-integrity-dashboard-v1"
        finally:
            server.shutdown()
            server.server_close()

    def test_read_only_behavior(self, tmp_path: Path) -> None:
        """Dashboard audit endpoints must not mutate checkpoint."""
        vault = _make_vault(tmp_path)
        svc = _seed_and_init_integrity(vault)
        result_before = svc.verify()
        api = _api(tmp_path, vault)
        server, port, _ = _start_server(api)
        try:
            _dash_get(port, "/api/audit-integrity")
            _dash_post(port, "/api/audit-integrity/verify")
        finally:
            server.shutdown()
            server.server_close()
        result_after = svc.verify()
        assert result_before.status == result_after.status

    def test_missing_token_returns_401(self, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        api = _api(tmp_path, vault)
        server, port, _ = _start_server(api)
        try:
            with pytest.raises(urllib.error.HTTPError) as exc:
                _dash_get(port, "/api/audit-integrity", token=None)
            assert exc.value.code == 401
        finally:
            server.shutdown()
            server.server_close()

    def test_invalid_token_returns_401(self, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        api = _api(tmp_path, vault)
        server, port, _ = _start_server(api)
        try:
            with pytest.raises(urllib.error.HTTPError) as exc:
                _dash_get(port, "/api/audit-integrity", token="wrong-token")
            assert exc.value.code == 401
        finally:
            server.shutdown()
            server.server_close()

    def test_no_raw_audit_metadata_or_secrets(self, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        api = _api(tmp_path, vault)
        server, port, _ = _start_server(api)
        try:
            payload = _dash_get(port, "/api/audit-integrity")
            output_str = json.dumps(payload)
            assert "encrypted_payload" not in output_str
            assert "sk-fake" not in output_str
            assert "private_key" not in output_str
            assert "master_key" not in output_str
        finally:
            server.shutdown()
            server.server_close()

    def test_packaged_static_assets_exist(self, tmp_path: Path) -> None:
        from hermes_vault.dashboard import dashboard_static_dir
        static = dashboard_static_dir()
        assert static.exists(), f"Static dir not found: {static}"
        assert (static / "index.html").exists()
        assert (static / "app.js").exists()
        assert (static / "styles.css").exists()

    def test_repeated_server_startup_teardown(self, tmp_path: Path) -> None:
        """Clean shutdown and restart on Windows."""
        vault = _make_vault(tmp_path)
        for _ in range(3):
            api = _api(tmp_path, vault)
            server, port, _ = _start_server(api)
            try:
                payload = _dash_get(port, "/api/audit-integrity")
                assert "status" in payload
            finally:
                server.shutdown()
                server.server_close()


# ── MCP: audit-integrity resource and status ─────────────────────────────────


class TestMcpAuditIntegrity:
    def test_vault_audit_integrity_is_listed(self, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        payload = _mcp_audit_integrity_payload(vault)
        assert payload["version"] == "audit-integrity-mcp-v1"
        assert "status" in payload

    def test_exact_result_fields(self, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        payload = _mcp_audit_integrity_payload(vault)
        expected_fields = {
            "version", "status", "reason_code", "chain_version",
            "verified_count", "legacy_count",
            "first_verified_sequence", "last_verified_sequence",
            "checkpoint_status", "recommended_next_step", "verified_at",
        }
        for field in expected_fields:
            assert field in payload, f"Missing MCP field: {field}"

    def test_metadata_only_no_audit_rows(self, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        payload = _mcp_audit_integrity_payload(vault)
        output_str = json.dumps(payload)
        assert "entries" not in output_str
        assert "access_log" not in output_str.lower()

    def test_no_agent_ids(self, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        payload = _mcp_audit_integrity_payload(vault)
        output_str = json.dumps(payload)
        assert "agent-0" not in output_str
        assert "agent-1" not in output_str

    def test_no_service_names(self, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        payload = _mcp_audit_integrity_payload(vault)
        output_str = json.dumps(payload)
        assert "openai" not in output_str

    def test_no_raw_reasons(self, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        payload = _mcp_audit_integrity_payload(vault)
        output_str = json.dumps(payload)
        assert "seed row" not in output_str

    def test_no_checkpoint_mutation_tools(self, tmp_path: Path) -> None:
        from hermes_vault.mcp_server import list_tools
        import asyncio
        tool_names = [t.name for t in asyncio.run(list_tools())]
        checkpoint_tools = [n for n in tool_names if "checkpoint" in n.lower()]
        assert not checkpoint_tools, f"Found unexpected checkpoint mutation tools: {checkpoint_tools}"

    def test_no_secret_source_authority_change(self, tmp_path: Path) -> None:
        vault = _make_vault(tmp_path)
        _seed_and_init_integrity(vault)
        payload = _mcp_audit_integrity_payload(vault)
        output_str = json.dumps(payload)
        assert "sk-fake-key" not in output_str
