"""Tests for the Hermes Vault MCP server."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import pytest
from mcp.types import TextContent

from hermes_vault.mcp_server import call_tool, list_tools, server
from hermes_vault.models import CredentialStatus


# ── helpers ────────────────────────────────────────────────────────────────────


def _run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _text(content: list[TextContent]) -> str:
    assert len(content) == 1
    assert content[0].type == "text"
    return content[0].text


def _json(content: list[TextContent]) -> Any:
    return json.loads(_text(content))


# ── server metadata ────────────────────────────────────────────────────────────


def test_list_tools_returns_expected_tools():
    tools = _run_async(list_tools())
    names = {t.name for t in tools}
    expected = {
        "list_services",
        "get_credential_metadata",
        "get_ephemeral_env",
        "verify_credential",
        "rotate_credential",
        "scan_for_secrets",
        "oauth_login",
        "oauth_refresh",
    }
    assert names == expected


# ── list_services ──────────────────────────────────────────────────────────────


def test_list_services_requires_agent_id():
    result = _run_async(call_tool("list_services", {}))
    assert "Missing required parameter: agent_id" in _text(result)


def test_list_services_returns_policy_filtered_results(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("list_services", {"agent_id": "test-agent"}))
    data = _json(result)
    # test-agent policy allows openai and supabase
    services = {d["service"] for d in data}
    assert "openai" in services
    assert "supabase" in services


def test_list_services_respects_filter(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("list_services", {"agent_id": "test-agent", "filter": "open"}))
    data = _json(result)
    assert len(data) == 1
    assert data[0]["service"] == "openai"


# ── get_credential_metadata ────────────────────────────────────────────────────


def test_get_metadata_requires_agent_id():
    result = _run_async(call_tool("get_credential_metadata", {"service": "openai"}))
    assert "Missing required parameter: agent_id" in _text(result)


def test_get_metadata_denied_for_unknown_agent(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("get_credential_metadata", {"agent_id": "unknown-agent", "service": "openai"}))
    assert "Denied:" in _text(result)


def test_get_metadata_returns_metadata(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("get_credential_metadata", {"agent_id": "test-agent", "service": "openai"}))
    data = _json(result)
    assert data["service"] == "openai"
    assert "id" in data


# ── get_ephemeral_env ──────────────────────────────────────────────────────────


def test_get_ephemeral_env_requires_agent_id():
    result = _run_async(call_tool("get_ephemeral_env", {"service": "openai"}))
    assert "Missing required parameter: agent_id" in _text(result)


def test_get_ephemeral_env_denied_for_unauthorized_service(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("get_ephemeral_env", {"agent_id": "test-agent", "service": "github"}))
    assert "Denied:" in _text(result)


def test_get_ephemeral_env_returns_env(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("get_ephemeral_env", {"agent_id": "test-agent", "service": "openai"}))
    data = _json(result)
    assert "env" in data
    assert "OPENAI_API_KEY" in data["env"]
    assert data["env"]["OPENAI_API_KEY"] == "sk-test-openai"
    assert "expires_at" in data
    assert data["expires_at"] is not None


def test_get_ephemeral_env_with_alias_succeeds(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("get_ephemeral_env", {
        "agent_id": "test-agent",
        "service": "openai",
        "alias": "primary",
    }))
    data = _json(result)
    assert "env" in data
    assert "OPENAI_API_KEY" in data["env"]


def test_get_ephemeral_env_with_alias_denied_for_unauthorized_service(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("get_ephemeral_env", {
        "agent_id": "test-agent",
        "service": "github",
        "alias": "work",
    }))
    assert "Denied:" in _text(result)


def test_get_metadata_excludes_encrypted_payload(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("get_credential_metadata", {"agent_id": "test-agent", "service": "openai"}))
    data = _json(result)
    assert "encrypted_payload" not in data


# ── policy strict validation ───────────────────────────────────────────────────


def test_policy_yaml_rejects_unknown_fields(tmp_path):
    from hermes_vault.policy import PolicyEngine
    policy_path = tmp_path / "bad_policy.yaml"
    policy_path.write_text("""
agents:
  test-agent:
    services: [openai]
    max_ttl: 3600
    env_only: true
""", encoding="utf-8")
    with pytest.raises(Exception):
        PolicyEngine.from_yaml(policy_path)


# ── verify_credential ──────────────────────────────────────────────────────────


def test_verify_requires_agent_id():
    result = _run_async(call_tool("verify_credential", {"service": "openai"}))
    assert "Missing required parameter: agent_id" in _text(result)


def test_verify_denied_when_agent_lacks_verify_action(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    # test-agent has actions: [get_credential, get_env] — verify is not included
    result = _run_async(call_tool("verify_credential", {"agent_id": "test-agent", "service": "openai"}))
    assert "Denied:" in _text(result)


# ── rotate_credential ──────────────────────────────────────────────────────────


def test_rotate_requires_agent_id():
    result = _run_async(call_tool("rotate_credential", {"service": "openai", "new_secret": "new"}))
    assert "Missing required parameter: agent_id" in _text(result)


def test_rotate_denied_for_unauthorized_agent(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    # test-agent does NOT have rotate permission on supabase
    result = _run_async(call_tool("rotate_credential", {"agent_id": "test-agent", "service": "supabase", "new_secret": "new-secret"}))
    assert "Denied:" in _text(result)


def test_rotate_succeeds_for_authorized_agent(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    # test-agent HAS rotate permission on openai
    result = _run_async(call_tool("rotate_credential", {"agent_id": "test-agent", "service": "openai", "new_secret": "new-secret"}))
    data = _json(result)
    assert data["allowed"] is True


# ── scan_for_secrets ───────────────────────────────────────────────────────────


def test_scan_requires_agent_id():
    result = _run_async(call_tool("scan_for_secrets", {}))
    assert "Missing required parameter: agent_id" in _text(result)


def test_scan_denied_for_agent_without_capability(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("scan_for_secrets", {"agent_id": "restricted-agent"}))
    assert "Denied:" in _text(result)


# ── oauth_login ────────────────────────────────────────────────────────────────


def test_oauth_login_requires_agent_id():
    result = _run_async(call_tool("oauth_login", {"provider": "google"}))
    assert "Missing required parameter: agent_id" in _text(result)


def test_oauth_login_requires_provider():
    result = _run_async(call_tool("oauth_login", {"agent_id": "test-agent"}))
    assert "Missing required parameter: provider" in _text(result)


def test_oauth_login_denied_without_add_credential_permission(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    # restricted-agent only has get_env for openai — no add_credential
    result = _run_async(call_tool("oauth_login", {
        "agent_id": "restricted-agent",
        "provider": "openai",
    }))
    assert "Denied:" in _text(result)


def test_oauth_login_returns_authorization_url(vault_with_policy, tmp_path, monkeypatch):
    """Test that oauth_login returns a valid authorization URL with PKCE params."""
    # Monkeypatch ClientEventLoop.create_task to prevent callback server from starting in tests
    # Instead, we just check the returned URL structure
    import hermes_vault.mcp_server as mcp_mod
    mcp_mod._OAUTH_CALLBACK_TIMEOUT = 1  # Short timeout for tests
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)

    # Provide a dummy client_id for openai (the provider doesn't require client_id, but set it anyway)
    monkeypatch.setenv("HERMES_VAULT_OAUTH_GOOGLE_CLIENT_ID", "test-client-123")
    monkeypatch.setenv("HERMES_VAULT_OAUTH_GOOGLE_CLIENT_SECRET", "test-secret")

    result = _run_async(call_tool("oauth_login", {
        "agent_id": "test-agent",
        "provider": "google",
        "alias": "test",
        "scopes": ["openid", "email"],
    }))
    data = _json(result)
    assert "authorization_url" in data
    assert "redirect_uri" in data
    assert "message" in data
    assert "test" in data["message"]
    # URL should contain PKCE params
    url = data["authorization_url"]
    assert "code_challenge=" in url
    assert "code_challenge_method=S256" in url
    assert "state=" in url
    assert "client_id=" in url


# ── oauth_refresh ──────────────────────────────────────────────────────────────


def test_oauth_refresh_requires_agent_id():
    result = _run_async(call_tool("oauth_refresh", {"service": "openai"}))
    assert "Missing required parameter: agent_id" in _text(result)


def test_oauth_refresh_requires_service():
    result = _run_async(call_tool("oauth_refresh", {"agent_id": "test-agent"}))
    assert "Missing required parameter: service" in _text(result)


def test_oauth_refresh_returns_error_when_no_refresh_token(vault_with_policy, tmp_path):
    """When no refresh token exists, the tool should return a clear error."""
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("oauth_refresh", {
        "agent_id": "test-agent",
        "service": "openai",
        "alias": "default",
    }))
    text = _text(result)
    assert "Error:" in text
    # Should mention that re-authentication is required
    assert "re-authentication" in text.lower() or "Use oauth_login" in text or "No refresh token" in text


# ── fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def vault_with_policy(tmp_path):
    """Create a vault with policy and a few credentials for MCP tests."""
    from hermes_vault.audit import AuditLogger
    from hermes_vault.broker import Broker
    from hermes_vault.config import get_settings
    from hermes_vault.crypto import derive_key
    from hermes_vault.policy import PolicyEngine
    from hermes_vault.verifier import Verifier
    from hermes_vault.vault import Vault

    home = tmp_path
    db_path = home / "vault.db"
    salt_path = home / "master_key_salt.bin"
    policy_path = home / "policy.yaml"

    os.environ["HERMES_VAULT_HOME"] = str(home)
    os.environ["HERMES_VAULT_PASSPHRASE"] = "test-passphrase"
    os.environ["HERMES_VAULT_POLICY"] = str(policy_path)

    salt_path.write_bytes(os.urandom(16))
    vault = Vault(db_path, salt_path, "test-passphrase")
    vault.initialize()

    vault.add_credential(service="openai", secret="sk-test-openai", credential_type="api_key", alias="primary")
    vault.add_credential(service="supabase", secret="sb-test-supabase", credential_type="api_key", alias="primary")

    policy_yaml = """\
agents:
  test-agent:
    services:
      openai:
        actions:
          - get_credential
          - get_env
          - metadata
          - rotate
          - delete
          - add_credential
      google:
        actions:
          - get_credential
          - get_env
          - metadata
          - rotate
          - delete
          - add_credential
      supabase:
        actions:
          - get_credential
          - get_env
    max_ttl_seconds: 3600
    raw_secret_access: false
    ephemeral_env_only: true
  restricted-agent:
    services:
      openai:
        actions:
          - get_env
    capabilities:
      - list_credentials
    max_ttl_seconds: 3600
    raw_secret_access: false
    ephemeral_env_only: true
"""
    policy_path.write_text(policy_yaml, encoding="utf-8")
    policy = PolicyEngine.from_yaml(policy_path)
    audit = AuditLogger(db_path)
    verifier = Verifier()
    broker = Broker(vault=vault, policy=policy, verifier=verifier, audit=audit)

    yield broker

    # Cleanup
    for key in ("HERMES_VAULT_HOME", "HERMES_VAULT_PASSPHRASE", "HERMES_VAULT_POLICY"):
        os.environ.pop(key, None)
