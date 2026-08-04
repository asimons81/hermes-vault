from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.config import AppSettings
from hermes_vault.crypto import MissingPassphraseError
from hermes_vault.dashboard import DashboardContext
from hermes_vault.desktop_bridge import (
    PROTOCOL_VERSION,
    DesktopBridge,
    MAX_AUDIT_LIMIT,
    MAX_REQUEST_BYTES,
    run_desktop_bridge,
)
from hermes_vault.models import AccessLogRecord, Decision
from hermes_vault.policy import PolicyEngine
from hermes_vault.verifier import Verifier
from hermes_vault.vault import Vault


def _context(tmp_path: Path) -> DashboardContext:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
agents:
  hermes:
    services:
      openai:
        actions: [get_env, verify, metadata, issue_lease, list_leases, show_lease]
        require_lease_for_env: true
    capabilities: [list_credentials]
    raw_secret_access: false
    ephemeral_env_only: true
""".lstrip(),
        encoding="utf-8",
    )
    settings = AppSettings(runtime_home=tmp_path, base_home=tmp_path, policy_path=policy_path)
    settings.ensure_runtime_layout()
    policy = PolicyEngine.from_yaml(policy_path)
    vault = Vault(settings.db_path, settings.salt_path, "test-passphrase")
    vault.add_credential("openai", "«redacted:sk-…»", "api_key", alias="default", tags=["prod", "ai"], notes="bridge note")
    vault.issue_lease(
        agent_id="hermes",
        service_or_id="openai",
        ttl_seconds=900,
        alias="default",
        purpose="bridge test",
    )
    audit = AuditLogger(settings.db_path, master_key=vault.key)
    audit.record(
        AccessLogRecord(
            agent_id="operator",
            service="openai",
            action="test",
            decision=Decision.allow,
            reason="seed audit",
            metadata={"request_id": "req-1"},
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


def _bridge(tmp_path: Path) -> DesktopBridge:
    ctx = _context(tmp_path)
    return DesktopBridge(context_factory=lambda prompt=True, profile=None: ctx)


def _dispatch(bridge: DesktopBridge, method: str, params: dict | None = None, request_id: int = 1) -> dict:
    request: dict = {"id": request_id, "method": method, "params": params or {}}
    return bridge.handle_request(request)


def _serialized_lines(payload: str) -> list[dict]:
    return [json.loads(line) for line in payload.splitlines() if line.strip()]


# ── hello / protocol version ────────────────────────────────────────────────


def test_hello_reports_protocol_version_and_capabilities(tmp_path: Path) -> None:
    bridge = _bridge(tmp_path)

    response = _dispatch(bridge, "hello")

    assert response["ok"] is True
    result = response["result"]
    assert result["protocol_version"] == PROTOCOL_VERSION
    assert result["name"] == "hermes-vault-desktop-bridge"
    assert result["read_only"] is True
    assert result["raw_values_returned"] is False
    assert {"overview", "credentials", "leases", "policy", "requests", "audit", "integrity"} <= set(result["capabilities"])
    assert response["protocol_version"] == PROTOCOL_VERSION
    # hello must not require a vault context / passphrase
    assert "MISSING_PASSPHRASE" not in json.dumps(response)


def test_request_with_wrong_protocol_version_is_rejected(tmp_path: Path) -> None:
    bridge = _bridge(tmp_path)

    response = bridge.handle_request({"id": 9, "method": "hello", "protocol_version": 999})

    assert response["ok"] is False
    assert response["error"]["code"] == "UNSUPPORTED_PROTOCOL"


def test_request_with_non_integer_protocol_version_is_rejected(tmp_path: Path) -> None:
    bridge = _bridge(tmp_path)

    response = bridge.handle_request({"id": 9, "method": "hello", "protocol_version": "one"})

    assert response["ok"] is False
    assert response["error"]["code"] == "UNSUPPORTED_PROTOCOL"


@pytest.mark.parametrize("protocol_version", [1.5, True])
def test_request_with_non_integer_protocol_types_is_rejected(tmp_path: Path, protocol_version: object) -> None:
    bridge = _bridge(tmp_path)

    response = bridge.handle_request({"id": 9, "method": "hello", "protocol_version": protocol_version})

    assert response["ok"] is False
    assert response["error"]["code"] == "UNSUPPORTED_PROTOCOL"


# ── dispatch coverage ───────────────────────────────────────────────────────


def test_overview_dispatch(tmp_path: Path) -> None:
    bridge = _bridge(tmp_path)

    response = _dispatch(bridge, "overview")

    assert response["ok"] is True
    result = response["result"]
    assert result["profile"] == "default"
    assert result["credential_count"] == 1
    assert result["lease_count"] == 1
    assert result["active_lease_count"] == 1
    assert "health" in result
    assert "policy_doctor" in result
    assert "«redacted:sk-…»" not in json.dumps(response)
    assert "encrypted_payload" not in json.dumps(response)


def test_credentials_dispatch_is_metadata_only(tmp_path: Path) -> None:
    bridge = _bridge(tmp_path)

    response = _dispatch(bridge, "credentials")

    assert response["ok"] is True
    credentials = response["result"]["credentials"]
    assert len(credentials) == 1
    assert credentials[0]["service"] == "openai"
    assert credentials[0]["has_notes"] is True
    assert "bridge note" not in json.dumps(response)
    assert "encrypted_payload" not in credentials[0]
    assert "«redacted:sk-…»" not in json.dumps(response)


def test_leases_dispatch_is_metadata_only(tmp_path: Path) -> None:
    bridge = _bridge(tmp_path)

    response = _dispatch(bridge, "leases")

    assert response["ok"] is True
    leases = response["result"]["leases"]
    assert len(leases) == 1
    assert leases[0]["service"] == "openai"
    assert leases[0]["has_purpose"] is True
    assert "bridge test" not in json.dumps(response)
    assert "metadata_keys" in leases[0]
    assert "«redacted:sk-…»" not in json.dumps(response)


def test_policy_dispatch(tmp_path: Path) -> None:
    bridge = _bridge(tmp_path)

    response = _dispatch(bridge, "policy")

    assert response["ok"] is True
    result = response["result"]
    assert result["policy_exists"] is True
    assert result["doctor"]["version"] == "policy-doctor-v1"
    agents = {agent["agent_id"]: agent for agent in result["agents"]}
    assert "hermes" in agents
    assert "policy_path" not in json.dumps(result["doctor"])


def test_requests_dispatch(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    bridge = DesktopBridge(context_factory=lambda prompt=True, profile=None: ctx)
    ctx.broker.request_access(
        agent_id="hermes",
        service="openai",
        alias="default",
        action="get_env",
        purpose="bridge request",
        requested_ttl_seconds=60,
    )

    response = _dispatch(bridge, "requests")

    assert response["ok"] is True
    requests = response["result"]["requests"]
    assert len(requests) == 1
    assert requests[0]["has_purpose"] is True
    assert "bridge request" not in json.dumps(response)
    assert requests[0]["status"] == "pending"
    assert "«redacted:sk-…»" not in json.dumps(response)


def test_audit_dispatch_is_bounded_and_metadata_only(tmp_path: Path) -> None:
    bridge = _bridge(tmp_path)

    response = _dispatch(bridge, "audit", {"limit": 5000})

    assert response["ok"] is True
    result = response["result"]
    assert result["limit"] == MAX_AUDIT_LIMIT
    assert len(result["entries"]) <= MAX_AUDIT_LIMIT
    entry = result["entries"][0]
    assert entry["action"] == "test"
    assert "metadata_keys" in entry
    # nested metadata values must never serialize
    assert "req-1" not in json.dumps(response)
    assert "«redacted:sk-…»" not in json.dumps(response)


def test_integrity_dispatch(tmp_path: Path) -> None:
    bridge = _bridge(tmp_path)

    response = _dispatch(bridge, "integrity")

    assert response["ok"] is True
    result = response["result"]
    assert result["status"] in {"healthy", "legacy", "error"}
    assert result["profile"] == "default"


# ── malformed / oversized / unknown ─────────────────────────────────────────


def test_malformed_json_line(tmp_path: Path) -> None:
    bridge = _bridge(tmp_path)

    response = bridge.handle_line("not-json{")

    assert response["ok"] is False
    assert response["error"]["code"] == "MALFORMED_REQUEST"


def test_non_object_json_line(tmp_path: Path) -> None:
    bridge = _bridge(tmp_path)

    response = bridge.handle_line("[1, 2, 3]")

    assert response["ok"] is False
    assert response["error"]["code"] == "MALFORMED_REQUEST"


def test_oversized_request_line(tmp_path: Path) -> None:
    bridge = _bridge(tmp_path)

    response = bridge.handle_line("x" * (MAX_REQUEST_BYTES + 1))

    assert response["ok"] is False
    assert response["error"]["code"] == "OVERSIZED_REQUEST"


def test_unknown_method(tmp_path: Path) -> None:
    bridge = _bridge(tmp_path)

    response = _dispatch(bridge, "rotate_credential")

    assert response["ok"] is False
    assert response["error"]["code"] == "UNKNOWN_METHOD"


def test_missing_method(tmp_path: Path) -> None:
    bridge = _bridge(tmp_path)

    response = bridge.handle_request({"id": 1, "params": {}})

    assert response["ok"] is False
    assert response["error"]["code"] == "INVALID_PARAMS"


# ── passphrase / profile / child exception envelopes ────────────────────────


def test_missing_passphrase_returns_locked_envelope(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def no_passphrase(prompt: bool = True, profile: str | None = None) -> DashboardContext:
        raise MissingPassphraseError("No Hermes Vault passphrase available. Set HERMES_VAULT_PASSPHRASE.")

    bridge = DesktopBridge(context_factory=no_passphrase)

    response = _dispatch(bridge, "overview")

    assert response["ok"] is False
    assert response["error"]["code"] == "MISSING_PASSPHRASE"
    assert response["error"]["locked"] is True
    assert "HERMES_VAULT_PASSPHRASE" in response["error"]["message"]
    assert "Traceback" not in json.dumps(response)


def test_invalid_profile_returns_invalid_params(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    bridge = DesktopBridge(context_factory=lambda prompt=True, profile=None: ctx)

    response = _dispatch(bridge, "credentials", {"profile": "../evil"})

    assert response["ok"] is False
    assert response["error"]["code"] == "INVALID_PARAMS"
    assert response["error"]["message"] == "invalid profile name"
    assert "../evil" not in json.dumps(response)


def test_child_exception_returns_sanitized_envelope(tmp_path: Path) -> None:
    def exploding(prompt: bool = True, profile: str | None = None) -> DashboardContext:
        raise RuntimeError("boom with sk-ABCDEFGHIJKLMNOPQRST child value inside")

    bridge = DesktopBridge(context_factory=exploding)

    response = _dispatch(bridge, "overview")

    assert response["ok"] is False
    assert response["error"]["code"] == "INTERNAL"
    assert "sk-ABCDEFGHIJKLMNOPQRST" not in json.dumps(response)
    assert "Traceback" not in json.dumps(response)
    assert "boom" in response["error"]["message"]


# ── canary values never serialize ───────────────────────────────────────────


def test_canary_values_never_serialize(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    ctx.vault.add_credential(
        "github",
        "CANARY-RAW-CREDENTIAL-VALUE",
        "personal_access_token",
        alias="work",
        notes="CANARY-NOTE",
    )
    ctx.vault.issue_lease(
        agent_id="hermes",
        service_or_id="github",
        ttl_seconds=300,
        alias="work",
        purpose="CANARY-PURPOSE",
        metadata={"access_token": "CANARY-TOKEN", "env": {"GITHUB_TOKEN": "CANARY-ENV-VALUE"}},
    )
    ctx.broker.request_access(
        agent_id="hermes",
        service="github",
        alias="work",
        action="get_env",
        purpose="CANARY-REQUEST-PURPOSE",
        requested_ttl_seconds=60,
    )
    ctx.audit.record(
        AccessLogRecord(
            agent_id="operator",
            service="github",
            action="test",
            decision=Decision.allow,
            reason="CANARY-REASON",
            metadata={"oauth": {"access_token": "CANARY-OAUTH-TOKEN"}},
        )
    )
    bridge = DesktopBridge(context_factory=lambda prompt=True, profile=None: ctx)

    outputs: list[str] = []
    for method in ("overview", "credentials", "leases", "policy", "requests", "audit", "integrity"):
        response = _dispatch(bridge, method, {"limit": 50})
        outputs.append(json.dumps(response))

    serialized = "\n".join(outputs)
    # Raw credential values and token-like nested metadata values must never
    # serialize. Key *names* may appear via metadata_keys, never values.
    for canary in (
        "CANARY-RAW-CREDENTIAL-VALUE",
        "CANARY-NOTE",
        "CANARY-PURPOSE",
        "CANARY-REQUEST-PURPOSE",
        "CANARY-REASON",
        "CANARY-TOKEN",
        "CANARY-ENV-VALUE",
        "CANARY-OAUTH-TOKEN",
    ):
        assert canary not in serialized
    assert "encrypted_payload" not in serialized


def test_raw_credential_value_never_appears_in_credentials_dispatch(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    ctx.vault.add_credential("mail", "CANARY-SMTP-PASSWORD", "app_password", alias="primary")
    bridge = DesktopBridge(context_factory=lambda prompt=True, profile=None: ctx)

    response = _dispatch(bridge, "credentials")

    assert "CANARY-SMTP-PASSWORD" not in json.dumps(response)


def test_default_bridge_is_filesystem_read_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _context(tmp_path)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(tmp_path / "policy.yaml"))

    def snapshot() -> dict[str, tuple[int, bytes]]:
        return {
            str(path): (path.stat().st_mtime_ns, path.read_bytes())
            for path in tmp_path.rglob("*")
            if path.is_file()
        }

    before = snapshot()
    bridge = DesktopBridge()
    for method in ("overview", "credentials", "leases", "policy", "requests", "audit", "integrity"):
        response = _dispatch(bridge, method, {"limit": 50})
        assert response["ok"] is True, response
    assert snapshot() == before


def test_request_size_limit_counts_utf8_bytes(tmp_path: Path) -> None:
    bridge = _bridge(tmp_path)

    response = bridge.handle_line("😀" * (MAX_REQUEST_BYTES // 4 + 1))

    assert response["ok"] is False
    assert response["error"]["code"] == "OVERSIZED_REQUEST"


# ── stream / bounded output behavior ────────────────────────────────────────


def test_run_bridge_echoes_ndjson_lines(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    bridge = DesktopBridge(context_factory=lambda prompt=True, profile=None: ctx)
    stdin = io.StringIO(
        '{"id": 1, "method": "hello", "params": {}}\n'
        '{"id": 2, "method": "nope", "params": {}}\n'
    )
    stdout = io.StringIO()

    code = run_desktop_bridge(stream_in=stdin, stream_out=stdout, bridge=bridge)

    assert code == 0
    lines = _serialized_lines(stdout.getvalue())
    assert len(lines) == 2
    assert lines[0]["id"] == 1
    assert lines[0]["ok"] is True
    assert lines[1]["id"] == 2
    assert lines[1]["ok"] is False
    assert lines[1]["error"]["code"] == "UNKNOWN_METHOD"


def test_run_bridge_handles_oversized_line_without_crashing(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    bridge = DesktopBridge(context_factory=lambda prompt=True, profile=None: ctx)
    stdin = io.StringIO("x" * (MAX_REQUEST_BYTES + 1) + "\n" + '{"id": 7, "method": "hello", "params": {}}\n')
    stdout = io.StringIO()

    code = run_desktop_bridge(stream_in=stdin, stream_out=stdout, bridge=bridge)

    assert code == 0
    lines = _serialized_lines(stdout.getvalue())
    assert lines[0]["ok"] is False
    assert lines[0]["error"]["code"] == "OVERSIZED_REQUEST"
    assert lines[1]["id"] == 7
    assert lines[1]["ok"] is True


def test_run_bridge_never_prompts_on_missing_passphrase(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def no_passphrase(prompt: bool = True, profile: str | None = None) -> DashboardContext:
        captured["prompt"] = prompt
        captured["profile"] = profile
        raise MissingPassphraseError("No Hermes Vault passphrase available.")

    bridge = DesktopBridge(context_factory=no_passphrase)
    stdin = io.StringIO('{"id": 1, "method": "overview", "params": {}}\n')
    stdout = io.StringIO()

    code = run_desktop_bridge(stream_in=stdin, stream_out=stdout, bridge=bridge)

    assert code == 0
    # The bridge must construct the context with prompting disabled.
    assert captured.get("prompt") is False
    lines = _serialized_lines(stdout.getvalue())
    assert lines[0]["ok"] is False
    assert lines[0]["error"]["code"] == "MISSING_PASSPHRASE"
    assert lines[0]["error"]["locked"] is True


def test_run_bridge_handles_empty_input(tmp_path: Path) -> None:
    bridge = _bridge(tmp_path)

    code = run_desktop_bridge(stream_in=io.StringIO(""), stream_out=io.StringIO(), bridge=bridge)

    assert code == 0
