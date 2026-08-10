"""Mutation surface tests for the desktop adapter (P2).

Covers the security-architecture test matrix rows 10-20 (§7) for the adapter
POST mutation routes (``add`` / ``rotate`` / ``delete``) plus the R1
Host-header hardening:

10. adapter POST /mutations/add valid -> 200 metadata-only
11. adapter POST /mutations/rotate valid -> 200
12. adapter POST /mutations/delete missing confirmation -> 403 before child spawn
13. adapter rejects query params on mutation routes
14. adapter rejects non-Bearer / missing token on mutation routes
15. adapter body bound (oversized secret) -> 400, no child spawn
16. adapter logs no request bodies / no secret on error path
17. adapter --allow-mutations only on mutation routes; GET routes unchanged
18. adapter error mapping: AUDIT_INTEGRITY->409, CONFIRMATION_MISMATCH->403,
    DUPLICATE->409, locked->423
19. hello advertises mutation capabilities only when adapter supports them
20. full lifecycle through adapter: add -> rotate -> delete with confirmation,
    audit trail has 3 entries
21. (R1) Host-header rejection on all adapter routes

Mutation routes are opt-in via ``HERMES_VAULT_DESKTOP_MUTATIONS=1``; the
fixtures enable it so the read-only GET surface (test_plugin_api.py) remains
unchanged. All fake-bridge tests use the same ``fake_popen`` seam; the full
lifecycle test drives a real disposable-vault bridge via ``HERMES_VAULT_BINARY``.
"""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

_PLUGIN_API = Path(__file__).resolve().parents[1] / "dashboard" / "plugin_api.py"
_spec = importlib.util.spec_from_file_location("hv_plugin_api_mutations", _PLUGIN_API)
assert _spec is not None and _spec.loader is not None
plugin_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(plugin_api)

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

POISON_SECRET = "SUPER_SECRET_MUTATION_POISON_XYZ_9f2c"
MUTATIONS_ENV = "HERMES_VAULT_DESKTOP_MUTATIONS"

AUTH = {"Authorization": "Bearer test-token"}


def _ok_result(result: dict) -> str:
    return json.dumps({"id": 1, "ok": True, "protocol_version": 1, "result": result}, sort_keys=True) + "\n"


def _err_envelope(code: str, message: str, *, locked: bool = False) -> str:
    error: dict = {"code": code, "message": message}
    if locked:
        error["locked"] = True
    return json.dumps({"id": 1, "ok": False, "protocol_version": 1, "error": error}, sort_keys=True) + "\n"


@pytest.fixture
def fake_popen(monkeypatch):
    """Replace subprocess.Popen with a scriptable spy (mirror test_plugin_api.py)."""

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
    for key in ("HERMES_VAULT_BINARY", "HERMES_VAULT_BRIDGE_TIMEOUT", "HERMES_VAULT_HOME", MUTATIONS_ENV):
        monkeypatch.delenv(key, raising=False)
    return monkeypatch


@pytest.fixture
def mutations_on(monkeypatch):
    """Enable the opt-in mutation routes."""
    monkeypatch.setenv(MUTATIONS_ENV, "1")
    return monkeypatch


# ---------------------------------------------------------------------------
# row 10: add route -> 200 metadata-only
# ---------------------------------------------------------------------------


def test_add_route(client, fake_popen, clean_env, mutations_on):
    fake_popen.stdout = _ok_result(
        {
            "allowed": True,
            "action": "add_credential",
            "service": "openai",
            "record": {"service": "openai", "alias": "primary", "has_notes": False},
        }
    )
    resp = client.post(
        "/mutations/add",
        json={"service": "openai", "alias": "primary", "credential_type": "api_key", "secret": POISON_SECRET},
        headers=AUTH,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["allowed"] is True
    assert body["record"]["service"] == "openai"
    assert "secret" not in body

    assert len(fake_popen.instances) == 1
    proc = fake_popen.instances[0]
    assert proc.args == ["hermes-vault-canonical", "--no-banner", "desktop-bridge", "--allow-mutations"]
    sent = json.loads(proc.input)
    assert sent["method"] == "add"
    assert sent["params"]["service"] == "openai"
    assert sent["params"]["alias"] == "primary"
    assert sent["params"]["credential_type"] == "api_key"
    assert sent["params"]["secret"] == POISON_SECRET


# ---------------------------------------------------------------------------
# row 11: rotate route -> 200
# ---------------------------------------------------------------------------


def test_rotate_route(client, fake_popen, clean_env, mutations_on):
    fake_popen.stdout = _ok_result({"allowed": True, "action": "rotate_credential", "service": "openai"})
    resp = client.post(
        "/mutations/rotate",
        json={"service_or_id": "openai", "alias": "primary", "new_secret": POISON_SECRET},
        headers=AUTH,
    )
    assert resp.status_code == 200
    assert resp.json()["action"] == "rotate_credential"
    assert len(fake_popen.instances) == 1
    sent = json.loads(fake_popen.instances[0].input)
    assert sent["method"] == "rotate"
    assert sent["params"]["service_or_id"] == "openai"
    assert sent["params"]["new_secret"] == POISON_SECRET


# ---------------------------------------------------------------------------
# row 12: delete missing confirmation -> 403 before child spawn
# ---------------------------------------------------------------------------


def test_delete_route_requires_confirmation(client, fake_popen, clean_env, mutations_on):
    fake_popen.stdout = _ok_result({"allowed": True, "action": "delete_credential", "service": "openai"})
    resp = client.post(
        "/mutations/delete",
        json={"service_or_id": "openai"},
        headers=AUTH,
    )
    assert resp.status_code == 403
    assert "confirmation" in resp.json()["detail"]
    # No child was spawned for the denied request.
    assert fake_popen.instances == []


def test_delete_route_with_confirmation(client, fake_popen, clean_env, mutations_on):
    fake_popen.stdout = _ok_result(
        {"allowed": True, "action": "delete_credential", "service": "openai", "metadata": {"credential_id": "abc"}}
    )
    resp = client.post(
        "/mutations/delete",
        json={"service_or_id": "openai", "alias": "primary", "confirmation": "openai:primary"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    assert resp.json()["metadata"]["credential_id"] == "abc"
    assert len(fake_popen.instances) == 1
    sent = json.loads(fake_popen.instances[0].input)
    assert sent["method"] == "delete"
    assert sent["params"]["confirmation"] == "openai:primary"
    assert sent["params"]["service_or_id"] == "openai"


# ---------------------------------------------------------------------------
# row 13: mutation routes reject query params
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("route", ["/mutations/add", "/mutations/rotate", "/mutations/delete"])
def test_mutation_routes_reject_query_params(client, fake_popen, clean_env, mutations_on, route):
    fake_popen.stdout = _ok_result({"allowed": True})
    body = {"service": "openai", "secret": POISON_SECRET}
    if route.endswith("/rotate"):
        body = {"service_or_id": "openai", "new_secret": POISON_SECRET}
    if route.endswith("/delete"):
        body = {"service_or_id": "openai", "confirmation": "openai:primary"}
    resp = client.post(f"{route}?profile=default", json=body, headers=AUTH)
    assert resp.status_code == 400
    assert fake_popen.instances == []


# ---------------------------------------------------------------------------
# row 14: mutation routes require Bearer
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Basic abc123"},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer   "},
    ],
    ids=["missing", "basic", "bearer-empty", "bearer-blank"],
)
def test_mutation_routes_require_bearer(client, fake_popen, clean_env, mutations_on, headers):
    fake_popen.stdout = _ok_result({"allowed": True})
    resp = client.post(
        "/mutations/add",
        json={"service": "openai", "secret": POISON_SECRET},
        headers=headers,
    )
    assert resp.status_code == 401
    assert fake_popen.instances == []


def test_mutation_routes_reject_query_token_fallback(client, fake_popen, clean_env, mutations_on):
    """The ?token= fallback is NOT accepted on mutation routes."""
    fake_popen.stdout = _ok_result({"allowed": True})
    resp = client.post(
        "/mutations/add?token=sometoken",
        json={"service": "openai", "secret": POISON_SECRET},
        headers=AUTH,
    )
    assert resp.status_code == 400
    assert fake_popen.instances == []


# ---------------------------------------------------------------------------
# row 15: body bound (oversized secret) -> 400, no child spawn
# ---------------------------------------------------------------------------


def test_mutation_body_size_bound(client, fake_popen, clean_env, mutations_on):
    fake_popen.stdout = _ok_result({"allowed": True})
    huge = {"service": "openai", "secret": "x" * (plugin_api.MAX_REQUEST_BYTES + 1024)}
    resp = client.post("/mutations/add", json=huge, headers=AUTH)
    assert resp.status_code == 400
    assert "size bound" in resp.json()["detail"]
    assert fake_popen.instances == []


def test_mutation_unknown_fields_rejected(client, fake_popen, clean_env, mutations_on):
    fake_popen.stdout = _ok_result({"allowed": True})
    resp = client.post(
        "/mutations/add",
        json={"service": "openai", "secret": POISON_SECRET, "agent_id": "renderer-supplied"},
        headers=AUTH,
    )
    assert resp.status_code == 400
    assert "agent_id" in resp.json()["detail"]
    assert fake_popen.instances == []


def test_mutation_missing_required_field_rejected(client, fake_popen, clean_env, mutations_on):
    fake_popen.stdout = _ok_result({"allowed": True})
    resp = client.post("/mutations/add", json={"service": "openai"}, headers=AUTH)
    assert resp.status_code == 400
    assert "secret" in resp.json()["detail"]
    assert fake_popen.instances == []


# ---------------------------------------------------------------------------
# row 16: adapter logs no request bodies / no secret on error path
# ---------------------------------------------------------------------------


def test_mutation_logs_never_contain_body(client, fake_popen, clean_env, mutations_on, caplog):
    fake_popen.stdout = _err_envelope("INTERNAL", "child failure")
    with caplog.at_level("WARNING"):
        resp = client.post(
            "/mutations/add",
            json={"service": "openai", "secret": POISON_SECRET, "notes": "top-secret-note"},
            headers=AUTH,
        )
    assert resp.status_code == 502
    assert POISON_SECRET not in caplog.text
    assert "top-secret-note" not in caplog.text
    assert "secret" not in caplog.text
    assert "service" not in caplog.text
    assert "openai" not in caplog.text


def test_mutation_validation_error_logs_never_contain_body(client, fake_popen, clean_env, mutations_on, caplog):
    with caplog.at_level("WARNING"):
        resp = client.post(
            "/mutations/add",
            json={"service": "openai", "secret": POISON_SECRET, "bogus_field": "leaky"},
            headers=AUTH,
        )
    assert resp.status_code == 400
    assert fake_popen.instances == []
    assert POISON_SECRET not in caplog.text
    assert "leaky" not in caplog.text


# ---------------------------------------------------------------------------
# row 17: --allow-mutations only on mutation routes; GET routes unchanged
# ---------------------------------------------------------------------------


def test_argv_allow_mutations_only_for_mutations(client, fake_popen, clean_env, mutations_on):
    # Mutation route: flag appended.
    fake_popen.stdout = _ok_result({"allowed": True})
    client.post("/mutations/add", json={"service": "openai", "secret": POISON_SECRET}, headers=AUTH)
    assert fake_popen.instances[-1].args == ["hermes-vault-canonical", "--no-banner", "desktop-bridge", "--allow-mutations"]

    # GET route: argv unchanged.
    fake_popen.stdout = _ok_result({"profile": "default"})
    client.get("/overview")
    assert fake_popen.instances[-1].args == ["hermes-vault-canonical", "--no-banner", "desktop-bridge"]

    client.get("/hello")
    assert fake_popen.instances[-1].args == ["hermes-vault-canonical", "--no-banner", "desktop-bridge"]


# ---------------------------------------------------------------------------
# row 18: error mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code,status,locked",
    [
        ("AUDIT_INTEGRITY", 409, False),
        ("CONFIRMATION_MISMATCH", 403, False),
        ("DUPLICATE", 409, False),
        ("MISSING_PASSPHRASE", 423, True),
        ("VAULT_NOT_READY", 423, True),
        ("INVALID_PARAMS", 400, False),
        ("UNKNOWN_METHOD", 400, False),
        ("INTERNAL", 502, False),
    ],
    ids=[
        "audit-integrity-409",
        "confirmation-mismatch-403",
        "duplicate-409",
        "locked-423",
        "not-ready-423",
        "invalid-params-400",
        "unknown-method-400",
        "internal-502",
    ],
)
def test_mutation_error_mapping(client, fake_popen, clean_env, mutations_on, code, status, locked):
    fake_popen.stdout = _err_envelope(code, f"{code} detail message", locked=locked)
    resp = client.post(
        "/mutations/add",
        json={"service": "openai", "secret": POISON_SECRET},
        headers=AUTH,
    )
    assert resp.status_code == status


def test_mutation_timeout_maps_to_504(client, fake_popen, clean_env, mutations_on, monkeypatch):
    monkeypatch.setenv("HERMES_VAULT_BRIDGE_TIMEOUT", "0.1")
    fake_popen.exc = subprocess.TimeoutExpired(cmd=["hermes-vault"], timeout=0.1)
    resp = client.post(
        "/mutations/add",
        json={"service": "openai", "secret": POISON_SECRET},
        headers=AUTH,
    )
    assert resp.status_code == 504
    assert fake_popen.instances[0].terminated is True


def test_mutation_missing_binary_maps_to_503(client, fake_popen, clean_env, mutations_on):
    fake_popen.init_exc = FileNotFoundError()
    resp = client.post(
        "/mutations/add",
        json={"service": "openai", "secret": POISON_SECRET},
        headers=AUTH,
    )
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# row 19: hello advertises mutation capabilities only when enabled
# ---------------------------------------------------------------------------


def test_hello_advertises_mutations_when_enabled(client, fake_popen, clean_env, mutations_on):
    fake_popen.stdout = _ok_result(
        {
            "name": "hermes-vault-desktop-bridge",
            "read_only": True,
            "mutations": False,
            "capabilities": list(plugin_api.ALL_METHODS),
        }
    )
    resp = client.get("/hello")
    assert resp.status_code == 200
    body = resp.json()
    assert body["mutations"] is True
    assert body["read_only"] is False
    for method in plugin_api.MUTATION_METHODS:
        assert method in body["capabilities"]


def test_hello_does_not_advertise_mutations_when_disabled(client, fake_popen, clean_env):
    fake_popen.stdout = _ok_result(
        {
            "name": "hermes-vault-desktop-bridge",
            "read_only": True,
            "mutations": False,
            "capabilities": list(plugin_api.ALL_METHODS),
        }
    )
    resp = client.get("/hello")
    assert resp.status_code == 200
    body = resp.json()
    assert body.get("mutations", False) is False
    for method in plugin_api.MUTATION_METHODS:
        assert method not in body["capabilities"]


def test_mutation_routes_404_when_disabled(client, fake_popen, clean_env):
    fake_popen.stdout = _ok_result({"allowed": True})
    resp = client.post(
        "/mutations/add",
        json={"service": "openai", "secret": POISON_SECRET},
        headers=AUTH,
    )
    assert resp.status_code == 404
    assert fake_popen.instances == []


# ---------------------------------------------------------------------------
# row 20: full lifecycle through adapter with a real disposable-vault bridge
# ---------------------------------------------------------------------------


def _write_policy(path: Path) -> None:
    path.write_text(
        """
agents:
  operator:
    capabilities: [list_credentials, add_credential]
    services:
      openai:
        actions: [get_env, verify, metadata, add_credential, rotate, delete]
""".lstrip(),
        encoding="utf-8",
    )


def _init_vault(home: Path, passphrase: str) -> None:
    """Create a fresh disposable vault at ``home`` (db + salt + audit table)."""
    from hermes_vault.audit import AuditLogger
    from hermes_vault.vault import Vault

    vault = Vault(home / "vault.db", home / "master_key_salt.bin", passphrase)
    audit = AuditLogger(home / "vault.db", master_key=vault.key)
    audit.initialize()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="real-bridge lifecycle test relies on a POSIX shell wrapper; the mutation route logic is covered by the fake-process tests on all platforms and by the real-surface verification on Linux",
)
def test_full_mutation_lifecycle(client, clean_env, tmp_path, monkeypatch):
    """add -> rotate -> delete through the adapter against a real bridge.

    Uses a real disposable vault + the real ``desktop-bridge`` binary (via a
    wrapper on HERMES_VAULT_BINARY) so the audit trail genuinely records
    three mutation rows.
    """
    vault_home = tmp_path / "vault-home"
    vault_home.mkdir()
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path)
    _init_vault(vault_home, "test-passphrase")

    # Point the adapter's child spawn at the real bridge in this worktree.
    # The adapter passes [--no-banner, desktop-bridge, --allow-mutations] on
    # the argv; the wrapper forwards them verbatim to this repo's CLI.
    wrapper = tmp_path / "hermes-vault"
    wrapper.write_text(
        "#!/bin/sh\n"
        f"exec {sys.executable} -m hermes_vault.cli \"$@\"\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    monkeypatch.setenv("HERMES_VAULT_BINARY", str(wrapper))
    monkeypatch.setenv("HERMES_VAULT_HOME", str(vault_home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))
    monkeypatch.setenv(MUTATIONS_ENV, "1")

    # add
    add_resp = client.post(
        "/mutations/add",
        json={"service": "openai", "alias": "primary", "credential_type": "api_key", "secret": "s3cret-1"},
        headers=AUTH,
    )
    assert add_resp.status_code == 200, add_resp.text
    add_body = add_resp.json()
    assert add_body["allowed"] is True
    assert add_body["record"]["service"] == "openai"
    assert "s3cret-1" not in add_resp.text

    # rotate
    rot_resp = client.post(
        "/mutations/rotate",
        json={"service_or_id": "openai", "alias": "primary", "new_secret": "s3cret-2"},
        headers=AUTH,
    )
    assert rot_resp.status_code == 200, rot_resp.text
    assert rot_resp.json()["allowed"] is True
    assert "s3cret-2" not in rot_resp.text

    # delete with confirmation (service:alias form)
    del_resp = client.post(
        "/mutations/delete",
        json={"service_or_id": "openai", "alias": "primary", "confirmation": "openai:primary"},
        headers=AUTH,
    )
    assert del_resp.status_code == 200, del_resp.text
    assert del_resp.json()["allowed"] is True
    assert "s3cret-1" not in del_resp.text
    assert "s3cret-2" not in del_resp.text

    # Audit trail has exactly 3 mutation rows.
    with sqlite3.connect(vault_home / "vault.db") as conn:
        rows = conn.execute(
            "SELECT action, decision FROM access_logs ORDER BY timestamp"
        ).fetchall()
    actions = [action for action, _decision in rows]
    assert actions == ["add_credential", "rotate_credential", "delete_credential"], actions

    # Vault is empty again (delete really removed the credential).
    with sqlite3.connect(vault_home / "vault.db") as conn:
        count = conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
    assert count == 0


# ---------------------------------------------------------------------------
# R1: Host-header hardening
# ---------------------------------------------------------------------------


def test_host_header_rejected(client, fake_popen, clean_env, mutations_on):
    fake_popen.stdout = _ok_result({"profile": "default"})
    resp = client.get("/overview", headers={"host": "evil.example.com"})
    assert resp.status_code == 400
    assert fake_popen.instances == []


def test_host_header_rejected_on_mutation_route(client, fake_popen, clean_env, mutations_on):
    fake_popen.stdout = _ok_result({"allowed": True})
    resp = client.post(
        "/mutations/add",
        json={"service": "openai", "secret": POISON_SECRET},
        headers={**AUTH, "host": "evil.example.com"},
    )
    assert resp.status_code == 400
    assert fake_popen.instances == []


@pytest.mark.parametrize(
    "host",
    ["localhost", "127.0.0.1", "testserver", "localhost:9119", "127.0.0.1:9119"],
    ids=["localhost", "loopback-v4", "testserver", "localhost-port", "loopback-port"],
)
def test_host_header_loopback_accepted(client, fake_popen, clean_env, host):
    fake_popen.stdout = _ok_result({"profile": "default"})
    resp = client.get("/overview", headers={"host": host})
    assert resp.status_code == 200
