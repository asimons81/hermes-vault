"""Tests for the hermes-vault-desktop dashboard backend adapter.

The adapter spawns the Vault-owned ``desktop-bridge`` child process for each
request. Most tests inject a fake ``subprocess.Popen`` to exercise response
mapping and lifecycle deterministically; the env-scrub test runs a real
fake-bridge subprocess to prove what actually reaches the child.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

_PLUGIN_API = Path(__file__).resolve().parents[1] / "dashboard" / "plugin_api.py"
_spec = importlib.util.spec_from_file_location("hv_plugin_api", _PLUGIN_API)
assert _spec is not None and _spec.loader is not None
plugin_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(plugin_api)

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

POISON_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
POISON_HEX = "a" * 40
POISON_PATH = "/home/tony/.hermes/hermes-vault-data/vault.db"
POISON_TEXT = "SUPER_SECRET_POISON_MARKER_XYZ"


def _env_lookup(env: dict[str, str], key: str) -> str | None:
    """Case-insensitive env lookup (Windows environment names are case-insensitive)."""
    upper = key.upper()
    for k, v in env.items():
        if k.upper() == upper:
            return v
    return None


def _ok_result(result: dict) -> str:
    return json.dumps({"id": 1, "ok": True, "protocol_version": 1, "result": result}, sort_keys=True) + "\n"


def _err_envelope(code: str, message: str, *, locked: bool = False) -> str:
    error: dict = {"code": code, "message": message}
    if locked:
        error["locked"] = True
    return json.dumps({"id": 1, "ok": False, "protocol_version": 1, "error": error}, sort_keys=True) + "\n"


@pytest.fixture
def fake_popen(monkeypatch):
    """Replace subprocess.Popen with a scriptable spy.

    Set ``FakePopen.stdout`` / ``FakePopen.stderr`` for the canned
    communicate result, ``FakePopen.exc`` to raise from communicate, or
    ``FakePopen.init_exc`` to raise at construction (e.g. FileNotFoundError).
    """

    class FakePopen:
        instances: list["FakePopen"] = []
        stdout = ""
        stderr = ""
        exc: BaseException | None = None
        init_exc: BaseException | None = None
        wait_exc: BaseException | None = None

        def __init__(self, args, **kwargs):
            self.args = args
            self.kwargs = kwargs
            self.returncode = 0
            self.terminated = False
            self.killed = False
            self.wait_calls = 0
            if FakePopen.init_exc is not None:
                raise FakePopen.init_exc
            FakePopen.instances.append(self)

        def communicate(self, input=None, timeout=None):
            self.input = input
            self.timeout = timeout
            if FakePopen.exc is not None:
                raise FakePopen.exc
            return FakePopen.stdout, FakePopen.stderr

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.killed = True

        def wait(self, timeout=None):
            self.wait_calls += 1
            if FakePopen.wait_exc is not None:
                raise FakePopen.wait_exc
            return 0

    monkeypatch.setattr(plugin_api.subprocess, "Popen", FakePopen)
    return FakePopen


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(plugin_api.router)
    return TestClient(app)


@pytest.fixture
def clean_env(monkeypatch):
    """Remove adapter-affecting env vars for a clean slate."""
    for key in ("HERMES_VAULT_BINARY", "HERMES_VAULT_BRIDGE_TIMEOUT", "HERMES_VAULT_HOME"):
        monkeypatch.delenv(key, raising=False)
    return monkeypatch


# ---------------------------------------------------------------------------
# Success mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "route,method",
    [
        ("/hello", "hello"),
        ("/overview", "overview"),
        ("/credentials", "credentials"),
        ("/leases", "leases"),
        ("/policy", "policy"),
        ("/requests", "requests"),
        ("/audit", "audit"),
        ("/integrity", "integrity"),
        ("/health", "hello"),
    ],
)
def test_success_response_mapping(client, fake_popen, clean_env, route, method):
    fake_popen.stdout = _ok_result({"profile": "default", "ok_field": True})
    resp = client.get(route)
    assert resp.status_code == 200
    assert resp.json() == {"profile": "default", "ok_field": True}
    assert len(fake_popen.instances) == 1
    proc = fake_popen.instances[0]
    sent = json.loads(proc.input)
    assert sent["method"] == method
    assert sent["protocol_version"] == 1
    assert sent["params"] == {}


def test_success_maps_bounded_query_params(client, fake_popen, clean_env):
    fake_popen.stdout = _ok_result({"profile": "alpha", "count": 3})
    resp = client.get("/requests?profile=alpha&agent_id=agent-7")
    assert resp.status_code == 200
    sent = json.loads(fake_popen.instances[0].input)
    assert sent["params"] == {"profile": "alpha", "agent_id": "agent-7"}

    fake_popen.stdout = _ok_result({"limit": 12})
    resp = client.get("/audit?limit=12")
    assert resp.status_code == 200
    sent = json.loads(fake_popen.instances[-1].input)
    assert sent["params"] == {"limit": 12}


# ---------------------------------------------------------------------------
# Failure mapping
# ---------------------------------------------------------------------------


def test_missing_binary_maps_to_503(client, fake_popen, clean_env):
    fake_popen.init_exc = FileNotFoundError()
    resp = client.get("/overview")
    assert resp.status_code == 503
    assert "vault bridge binary not found" in resp.json()["detail"]


def test_timeout_maps_to_504_and_terminates_child(client, fake_popen, clean_env, monkeypatch):
    monkeypatch.setenv("HERMES_VAULT_BRIDGE_TIMEOUT", "0.1")
    fake_popen.exc = subprocess.TimeoutExpired(cmd=["hermes-vault"], timeout=0.1)
    resp = client.get("/credentials")
    assert resp.status_code == 504
    assert fake_popen.instances[0].terminated is True


def test_timeout_escalates_to_kill_when_terminate_hangs(client, fake_popen, clean_env, monkeypatch):
    monkeypatch.setenv("HERMES_VAULT_BRIDGE_TIMEOUT", "0.1")
    fake_popen.exc = subprocess.TimeoutExpired(cmd=["hermes-vault"], timeout=0.1)
    fake_popen.wait_exc = subprocess.TimeoutExpired(cmd=["hermes-vault"], timeout=2.0)
    resp = client.get("/credentials")
    assert resp.status_code == 504
    proc = fake_popen.instances[0]
    assert proc.terminated is True
    assert proc.killed is True


def test_eof_empty_stdout_maps_to_502(client, fake_popen, clean_env):
    fake_popen.stdout = ""
    resp = client.get("/credentials")
    assert resp.status_code == 502
    assert "closed without a response" in resp.json()["detail"]


@pytest.mark.parametrize(
    "payload",
    [
        json.dumps({"id": 1, "ok": True, "protocol_version": 99, "result": {}}) + "\n",
        json.dumps({"id": 1, "ok": True, "result": {}}) + "\n",
        json.dumps({"id": 2, "ok": True, "protocol_version": 1, "result": {}}) + "\n",
        json.dumps([1, 2, 3]) + "\n",
        json.dumps({}) + "\n",
        "not json at all\n",
        _ok_result({}) + _ok_result({}),
    ],
    ids=["version-99", "missing-version", "id-mismatch", "json-list", "empty-dict", "non-json", "multi-line"],
)
def test_protocol_mismatch_and_malformed_maps_to_502(client, fake_popen, clean_env, payload):
    fake_popen.stdout = payload
    resp = client.get("/hello")
    assert resp.status_code == 502
    detail = resp.json()["detail"]
    assert detail.startswith("vault bridge"), detail


def test_locked_vault_missing_passphrase_maps_to_423(client, fake_popen, clean_env):
    fake_popen.stdout = _err_envelope("MISSING_PASSPHRASE", "No passphrase available for profile default", locked=True)
    resp = client.get("/overview")
    assert resp.status_code == 423
    assert "No passphrase available" in resp.json()["detail"]


def test_locked_vault_not_ready_maps_to_423(client, fake_popen, clean_env):
    fake_popen.stdout = _err_envelope("VAULT_NOT_READY", "Vault key material is unavailable", locked=True)
    resp = client.get("/integrity")
    assert resp.status_code == 423


def test_bridge_internal_error_maps_to_502(client, fake_popen, clean_env):
    fake_popen.stdout = _err_envelope("INTERNAL", "child failure")
    resp = client.get("/policy")
    assert resp.status_code == 502
    assert resp.json()["detail"] == "child failure"


# ---------------------------------------------------------------------------
# Route allowlist / rejection of unknown, live, and path-taking actions
# ---------------------------------------------------------------------------


def test_allowlisted_routes_only(client, fake_popen, clean_env):
    fake_popen.stdout = _ok_result({})
    for route in (
        "/hello",
        "/overview",
        "/credentials",
        "/leases",
        "/policy",
        "/requests",
        "/audit",
        "/integrity",
        "/health",
    ):
        assert client.get(route).status_code == 200, route


@pytest.mark.parametrize(
    "method,path",
    [
        ("post", "/hello"),
        ("put", "/overview"),
        ("delete", "/integrity"),
        ("patch", "/requests"),
        ("get", "/credentials/1"),
        ("get", "/requests/approve"),
        ("get", "/leases/revoke"),
        ("get", "/wat"),
        ("get", "/integrity/rebuild"),
    ],
)
def test_rejects_unknown_live_and_path_taking_actions(client, fake_popen, clean_env, method, path):
    fake_popen.stdout = _ok_result({})
    resp = getattr(client, method)(path)
    assert resp.status_code in (404, 405)


def test_unknown_query_params_rejected(client, fake_popen, clean_env):
    fake_popen.stdout = _ok_result({})
    resp = client.get("/overview?foo=1")
    assert resp.status_code == 400
    assert "unknown query parameter" in resp.json()["detail"]


def test_hello_accepts_bounded_query_rejects_unknown(client, fake_popen, clean_env):
    fake_popen.stdout = _ok_result({})
    # hello/health accept the same bounded query params as other read routes
    # (release/v0.24.0 behavior; the renderer version-gates via hello).
    assert client.get("/hello?profile=x").status_code == 200
    assert client.get("/health?limit=5").status_code == 200
    # Unknown or oversized params are still rejected.
    assert client.get("/hello?foo=1").status_code == 400
    assert client.get(f"/hello?profile={'p' * 129}").status_code == 400


@pytest.mark.parametrize(
    "qs",
    ["limit=abc", "limit=0", "limit=-1", "limit=999"],
    ids=["non-int", "zero", "negative", "too-large"],
)
def test_audit_limit_bounds(client, fake_popen, clean_env, qs):
    fake_popen.stdout = _ok_result({})
    resp = client.get(f"/audit?{qs}")
    assert resp.status_code == 400


def test_oversized_profile_and_agent_id_rejected(client, fake_popen, clean_env):
    fake_popen.stdout = _ok_result({})
    assert client.get(f"/overview?profile={'p' * 129}").status_code == 400
    assert client.get(f"/requests?agent_id={'a' * 257}").status_code == 400


# ---------------------------------------------------------------------------
# Subprocess construction: argv, env scrub, bounded IO
# ---------------------------------------------------------------------------


def test_argv_is_fixed_and_shell_disabled(client, fake_popen, clean_env):
    fake_popen.stdout = _ok_result({})
    client.get("/hello")
    proc = fake_popen.instances[0]
    assert proc.args == ["hermes-vault-canonical", "--no-banner", "desktop-bridge"]
    assert proc.kwargs["shell"] is False
    assert proc.kwargs["stdin"] == subprocess.PIPE
    assert proc.kwargs["stdout"] == subprocess.PIPE
    assert proc.kwargs["stderr"] == subprocess.DEVNULL
    assert proc.kwargs["text"] is True


def test_child_env_scrubs_pythonpath_and_provider_keys(monkeypatch, clean_env):
    monkeypatch.setenv("PYTHONPATH", "/evil/path")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-evil")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-evil")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-evil")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp-evil")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("HOME", "/home/tony")
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "hunter2")
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE_work", "hunter3")
    monkeypatch.setenv("HERMES_VAULT_POLICY", "/tmp/policy.yaml")

    env = plugin_api._child_env()

    assert "PYTHONPATH" not in env
    assert "OPENAI_API_KEY" not in env
    assert "ANTHROPIC_API_KEY" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "GITHUB_TOKEN" not in env
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["HOME"] == "/home/tony"
    assert env["HERMES_VAULT_PASSPHRASE"] == "hunter2"
    # Windows environment names are case-insensitive; the passphrase alias var
    # may be copied under the OS-normalized casing. Look up case-insensitively.
    assert _env_lookup(env, "HERMES_VAULT_PASSPHRASE_work") == "hunter3"
    assert env["HERMES_VAULT_POLICY"] == "/tmp/policy.yaml"


def test_child_env_drops_hermes_vault_binary_seam(monkeypatch, clean_env):
    monkeypatch.setenv("HERMES_VAULT_BINARY", "/fake/bridge")
    env = plugin_api._child_env()
    assert "HERMES_VAULT_BINARY" not in env


def test_request_line_is_bounded_and_single(client, fake_popen, clean_env):
    fake_popen.stdout = _ok_result({})
    client.get("/overview")
    proc = fake_popen.instances[0]
    # communicate receives exactly one line (no trailing extra newline).
    assert proc.input.endswith("\n")
    assert proc.input.count("\n") == 1
    assert len(proc.input.encode("utf-8")) <= plugin_api.MAX_REQUEST_BYTES


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="real-child spawn test relies on a POSIX shebang script; the env-scrub and passphrase-forwarding logic is covered by the fake-process and unit tests on all platforms",
)
def test_real_subprocess_env_scrub_and_passphrase_forwarding(client, clean_env, tmp_path, monkeypatch):
    """End-to-end: a real fake-bridge child must see the scrubbed env."""
    vault_home = tmp_path / "vault-home"
    vault_home.mkdir()
    dump_path = vault_home / "env_dump.json"

    fake_script = tmp_path / "fake_bridge.py"
    fake_script.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "with open(os.path.join(os.environ['HERMES_VAULT_HOME'], 'env_dump.json'), 'w') as fh:\n"
        "    json.dump(dict(os.environ), fh, sort_keys=True)\n"
        "line = sys.stdin.readline()\n"
        "req = json.loads(line)\n"
        "resp = {'id': req['id'], 'ok': True, 'protocol_version': 1, 'result': {'method': req['method']}}\n"
        "sys.stdout.write(json.dumps(resp) + '\\n')\n"
        "sys.stdout.flush()\n",
        encoding="utf-8",
    )
    fake_script.chmod(0o755)

    monkeypatch.setenv("HERMES_VAULT_BINARY", str(fake_script))
    monkeypatch.setenv("HERMES_VAULT_HOME", str(vault_home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "hunter2")
    monkeypatch.setenv("PYTHONPATH", "/evil/path")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-evil")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-evil")

    resp = client.get("/hello")
    assert resp.status_code == 200
    assert resp.json()["method"] == "hello"
    assert dump_path.is_file()

    child_env = json.loads(dump_path.read_text(encoding="utf-8"))
    assert child_env.get("HERMES_VAULT_PASSPHRASE") == "hunter2"
    assert child_env.get("HERMES_VAULT_HOME") == str(vault_home)
    assert "PYTHONPATH" not in child_env
    assert "OPENAI_API_KEY" not in child_env
    assert "AWS_SECRET_ACCESS_KEY" not in child_env
    assert "HERMES_VAULT_BINARY" not in child_env
    assert "PATH" in child_env
    assert "HOME" in child_env


# ---------------------------------------------------------------------------
# Poison-string hygiene
# ---------------------------------------------------------------------------


def test_child_stderr_never_reaches_response_or_log(client, fake_popen, clean_env, caplog):
    fake_popen.stdout = _ok_result({})
    fake_popen.stderr = f"Traceback ... {POISON_TEXT} {POISON_HEX}\n"
    with caplog.at_level("WARNING"):
        resp = client.get("/hello")
    assert resp.status_code == 200
    assert POISON_TEXT not in resp.text
    assert POISON_TEXT not in caplog.text


def test_malformed_stdout_poison_never_echoed(client, fake_popen, clean_env, caplog):
    fake_popen.stdout = f"{POISON_TEXT} {POISON_JWT} {POISON_PATH}\n"
    with caplog.at_level("WARNING"):
        resp = client.get("/hello")
    assert resp.status_code == 502
    assert POISON_TEXT not in resp.text
    assert POISON_JWT not in resp.text
    assert POISON_PATH not in resp.text
    assert POISON_TEXT not in caplog.text
    assert POISON_JWT not in caplog.text


def test_bridge_error_message_is_sanitized(client, fake_popen, clean_env, caplog):
    fake_popen.stdout = _err_envelope(
        "INTERNAL",
        f"failure near {POISON_JWT} at {POISON_PATH} token={POISON_HEX}",
    )
    with caplog.at_level("WARNING"):
        resp = client.get("/overview")
    assert resp.status_code == 502
    detail = resp.json()["detail"]
    assert POISON_JWT not in detail
    assert POISON_PATH not in detail
    assert POISON_HEX not in detail
    assert "[redacted:jwt]" in detail
    assert "[redacted:hex-token]" in detail
    assert POISON_JWT not in caplog.text
    assert POISON_PATH not in caplog.text


def test_logs_never_contain_request_bodies(client, fake_popen, clean_env, caplog):
    fake_popen.stdout = _err_envelope("INTERNAL", "child failure")
    with caplog.at_level("WARNING"):
        client.get("/requests?profile=alpha&agent_id=agent-7")
    assert "profile" not in caplog.text
    assert "agent-7" not in caplog.text
    assert "agent_id" not in caplog.text
    assert "method" not in caplog.text
