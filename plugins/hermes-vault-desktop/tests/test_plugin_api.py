from __future__ import annotations

import importlib.util
import json
import logging
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


PLUGIN_PATH = Path(__file__).parents[1] / "dashboard" / "plugin_api.py"


def load_plugin():
    spec = importlib.util.spec_from_file_location("test_hermes_vault_desktop_plugin_api", PLUGIN_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def plugin():
    return load_plugin()


@pytest.fixture
def client(plugin):
    app = FastAPI()
    app.include_router(plugin.router, prefix="/api/plugins/hermes-vault-desktop")
    return TestClient(app)


def envelope(plugin, *, result: dict[str, Any] | None = None, error: dict[str, Any] | None = None) -> bytes:
    body: dict[str, Any] = {
        "id": plugin.REQUEST_ID,
        "protocol_version": plugin.PROTOCOL_VERSION,
        "ok": error is None,
    }
    if error is None:
        body["result"] = result or {"profile": "default", "read_only": True}
    else:
        body["error"] = error
    return (json.dumps(body) + "\n").encode()


def fake_process(stdout: bytes, *, returncode: int = 0, timeout: bool = False):
    class FakeProcess:
        def __init__(self):
            self.returncode = None
            self.terminated = False
            self.killed = False
            self.input = None

        def communicate(self, input=None, timeout=None):
            self.input = input
            if timeout:
                assert timeout > 0
            if timeout is not None and timeout is False:
                raise AssertionError("timeout was not bounded")
            if timeout is not None and timeout > 0 and timeout_flag:
                raise plugin_subprocess.TimeoutExpired(["fake"], timeout)
            self.returncode = returncode
            return stdout, b""

        def poll(self):
            return self.returncode

        def terminate(self):
            self.terminated = True
            self.returncode = -15

        def kill(self):
            self.killed = True
            self.returncode = -9

        def wait(self, timeout=None):
            return self.returncode

    timeout_flag = timeout
    plugin_subprocess = __import__("subprocess")
    return FakeProcess


def install_fake_process(monkeypatch, plugin, stdout: bytes, *, timeout: bool = False):
    monkeypatch.setattr(plugin.shutil, "which", lambda name: "/usr/bin/hermes-vault")
    fake_cls = fake_process(stdout, timeout=timeout)
    seen: dict[str, Any] = {}

    def popen(*args, **kwargs):
        seen["args"] = args
        seen["kwargs"] = kwargs
        process = fake_cls()
        seen["process"] = process
        return process

    monkeypatch.setattr(plugin.subprocess, "Popen", popen)
    return seen


def test_success_response_mapping(plugin, client, monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("HERMES_VAULT_HOME", "/tmp/vault")
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "[REDACTED]")
    monkeypatch.setenv("PYTHONPATH", "/poison")
    monkeypatch.setenv("OPENAI_API_KEY", "[REDACTED]")
    seen = install_fake_process(
        monkeypatch,
        plugin,
        envelope(plugin, result={"profile": "default", "credential_count": 2}),
    )
    response = client.get("/api/plugins/hermes-vault-desktop/overview")
    assert response.status_code == 200
    assert response.json() == {"profile": "default", "credential_count": 2}
    assert seen["args"] == (["/usr/bin/hermes-vault", "--no-banner", "desktop-bridge"],)
    request = json.loads(seen["process"].input)
    assert request == {
        "id": plugin.REQUEST_ID,
        "method": "overview",
        "params": {},
        "protocol_version": plugin.PROTOCOL_VERSION,
    }
    assert seen["kwargs"]["shell"] is False
    assert seen["kwargs"]["stderr"] is plugin.subprocess.DEVNULL
    assert seen["kwargs"]["stdin"] is plugin.subprocess.PIPE
    assert seen["kwargs"]["stdout"] is plugin.subprocess.PIPE
    assert seen["kwargs"]["env"]["HERMES_VAULT_HOME"] == "/tmp/vault"
    assert seen["kwargs"]["env"]["HERMES_VAULT_PASSPHRASE"] == "[REDACTED]"
    assert "PYTHONPATH" not in seen["kwargs"]["env"]
    assert "OPENAI_API_KEY" not in seen["kwargs"]["env"]


def test_routes_are_fixed_get_only(plugin, client, monkeypatch):
    install_fake_process(monkeypatch, plugin, envelope(plugin))
    for method in ("hello", "health", "overview", "credentials", "leases", "policy", "requests", "audit", "integrity"):
        response = client.get(f"/api/plugins/hermes-vault-desktop/{method}")
        assert response.status_code == 200, method
    assert client.post("/api/plugins/hermes-vault-desktop/overview").status_code == 405
    assert client.get("/api/plugins/hermes-vault-desktop/write").status_code == 404
    assert client.get("/api/plugins/hermes-vault-desktop/credentials/delete").status_code == 404


def test_query_allowlist_and_bounds(plugin, client, monkeypatch):
    install_fake_process(monkeypatch, plugin, envelope(plugin))
    assert client.get("/api/plugins/hermes-vault-desktop/overview?action=delete").status_code == 400
    assert client.get("/api/plugins/hermes-vault-desktop/overview?profile=../../etc").status_code == 400
    assert client.get("/api/plugins/hermes-vault-desktop/audit?limit=999").status_code == 400
    assert client.get("/api/plugins/hermes-vault-desktop/audit?limit=nope").status_code == 400
    assert client.get("/api/plugins/hermes-vault-desktop/overview?profile=default&profile=other").status_code == 400
    assert client.get("/api/plugins/hermes-vault-desktop/overview?agent_id=worker").status_code == 400


def test_missing_binary(plugin, client, monkeypatch):
    monkeypatch.setattr(plugin.shutil, "which", lambda name: None)
    response = client.get("/api/plugins/hermes-vault-desktop/overview")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "BINARY_MISSING"


def test_timeout_is_mapped_and_child_is_cleaned(plugin, client, monkeypatch):
    install_fake_process(monkeypatch, plugin, b"", timeout=True)
    response = client.get("/api/plugins/hermes-vault-desktop/overview")
    assert response.status_code == 504
    assert response.json()["error"]["code"] == "TIMEOUT"


def test_eof_protocol_and_malformed_responses(plugin, client, monkeypatch):
    install_fake_process(monkeypatch, plugin, b"")
    assert client.get("/api/plugins/hermes-vault-desktop/overview").json()["error"]["code"] == "BRIDGE_EOF"

    install_fake_process(
        monkeypatch,
        plugin,
        envelope(plugin, result={"ok": True}).replace(b'"protocol_version": 1', b'"protocol_version": 99'),
    )
    response = client.get("/api/plugins/hermes-vault-desktop/overview")
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "PROTOCOL_MISMATCH"

    install_fake_process(monkeypatch, plugin, b"not-json\n")
    response = client.get("/api/plugins/hermes-vault-desktop/overview")
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "MALFORMED_RESPONSE"


def test_locked_bridge_error(plugin, client, monkeypatch):
    install_fake_process(
        monkeypatch,
        plugin,
        envelope(
            plugin,
            error={
                "code": "MISSING_PASSPHRASE",
                "message": "Vault is locked",
                "locked": True,
            },
        ),
    )
    response = client.get("/api/plugins/hermes-vault-desktop/overview")
    assert response.status_code == 423
    assert response.json()["error"] == {
        "code": "MISSING_PASSPHRASE",
        "message": "Vault is locked",
        "locked": True,
    }


def test_child_environment_is_allowlisted(plugin, monkeypatch):
    source = {
        "PATH": "/usr/bin",
        "HOME": "/home/tony",
        "HERMES_VAULT_HOME": "/tmp/vault",
        "HERMES_VAULT_POLICY": "/tmp/policy.yaml",
        "HERMES_VAULT_HOME_EVIL": "[REDACTED]",
        "HERMES_VAULT_PASSPHRASE": "[REDACTED]",
        "HERMES_VAULT_PASSPHRASE_WORK": "[REDACTED]",
        "PYTHONPATH": "/poison",
        "OPENAI_API_KEY": "[REDACTED]",
        "GITHUB_TOKEN": "[REDACTED]",
        "UNRELATED": "nope",
    }
    env = plugin._child_env(source)
    assert env == {
        "PATH": "/usr/bin",
        "HOME": "/home/tony",
        "HERMES_VAULT_HOME": "/tmp/vault",
        "HERMES_VAULT_POLICY": "/tmp/policy.yaml",
        "HERMES_VAULT_PASSPHRASE": "[REDACTED]",
        "HERMES_VAULT_PASSPHRASE_WORK": "[REDACTED]",
    }


def test_poison_strings_are_not_returned_or_logged(plugin, client, monkeypatch, caplog):
    poison = "sk-live-ABC123 /home/tony/private 0123456789abcdef0123456789abcdef"
    install_fake_process(
        monkeypatch,
        plugin,
        envelope(plugin, error={"code": "INTERNAL", "message": poison}),
    )
    with caplog.at_level(logging.DEBUG):
        response = client.get("/api/plugins/hermes-vault-desktop/overview")
    body = response.text
    assert "sk-live" not in body
    assert "/home/tony" not in body
    assert "0123456789abcdef0123456789abcdef" not in body
    assert poison not in caplog.text


def test_real_child_output_is_bounded(plugin, client, monkeypatch, tmp_path):
    script = tmp_path / "oversized-bridge"
    script.write_text("#!/usr/bin/python3\nimport sys\nsys.stdout.write('x' * 600000)\n", encoding="utf-8")
    script.chmod(0o755)
    monkeypatch.setattr(plugin.shutil, "which", lambda name: str(script))
    response = client.get("/api/plugins/hermes-vault-desktop/overview")
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "OUTPUT_LIMIT"
