"""Tests for the Hermes Vault MCP server."""

from __future__ import annotations

import asyncio
import json
import os
import urllib.parse
from datetime import timedelta
from typing import Any

import pytest
from mcp.types import TextContent, TextResourceContents

from hermes_vault.audit import AuditLogger
from hermes_vault.mcp_server import (
    _resource_service_name,
    call_tool,
    list_resource_templates,
    list_resources,
    list_tools,
    read_resource,
    server,
)
from hermes_vault.models import utc_now
from hermes_vault.vault import Vault


# ── helpers ────────────────────────────────────────────────────────────────────


def _run_async(coro):
    return asyncio.run(coro)


def _text(content: list[TextContent]) -> str:
    assert len(content) == 1
    assert content[0].type == "text"
    return content[0].text


def _json(content: list[TextContent]) -> Any:
    return json.loads(_text(content))


def _resource_json(content: list[TextResourceContents]) -> Any:
    assert len(content) == 1
    assert content[0].mimeType == "application/json"
    return json.loads(content[0].text)


@pytest.fixture(autouse=True)
def reset_mcp_server_state():
    import hermes_vault.mcp_server as mcp_mod

    mcp_mod._broker = None
    mcp_mod._pending_oauth.clear()
    yield
    mcp_mod._broker = None
    mcp_mod._pending_oauth.clear()


# ── server metadata ────────────────────────────────────────────────────────────


def test_build_broker_explicit_profile_uses_profile_home(monkeypatch, tmp_path):
    import hermes_vault.mcp_server as mcp_mod

    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE_WORK", "work-passphrase")

    broker = mcp_mod._build_broker(profile="work")

    assert broker.vault.db_path == tmp_path / "profiles" / "work" / "vault.db"
    assert broker.scanner.settings.runtime_home == tmp_path / "profiles" / "work"


def test_list_tools_returns_expected_tools():
    tools = _run_async(list_tools())
    names = {t.name for t in tools}
    expected = {
        "list_services",
        "get_credential_metadata",
        "get_ephemeral_env",
        "lease_issue",
        "lease_list",
        "lease_show",
        "lease_renew",
        "lease_revoke",
        "verify_credential",
        "rotate_credential",
        "scan_for_secrets",
        "oauth_login",
        "oauth_device_login",
        "oauth_provider_status",
        "oauth_refresh",
        "request_access",
        "policy_explain",
        "lease_checkout",
    }
    assert names == expected


def test_list_resources_returns_expected_static_resources():
    resources = _run_async(list_resources())
    by_uri = {str(resource.uri): resource for resource in resources}
    assert {
        "vault://status",
        "vault://services",
        "vault://health",
        "vault://policy",
        "vault://agent-context",
        "vault://policy-explain",
        "vault://requests",
        "vault://recovery",
    }.issubset(by_uri)
    assert by_uri["vault://status"].mimeType == "application/json"
    assert by_uri["vault://services"].mimeType == "application/json"
    assert by_uri["vault://health"].mimeType == "application/json"
    assert by_uri["vault://policy"].mimeType == "application/json"


def test_list_resource_templates_returns_service_detail_template():
    templates = _run_async(list_resource_templates())
    by_template = {template.uriTemplate: template for template in templates}
    assert "vault://services/{name}" in by_template
    assert by_template["vault://services/{name}"].mimeType == "application/json"
    assert "vault://policy-explain?service={service}&action={action}" in by_template
    assert "vault://recovery?backup={path}" in by_template


def test_resource_capability_is_advertised():
    capabilities = server.create_initialization_options().capabilities
    assert capabilities.resources is not None
    assert capabilities.resources.subscribe is False


# ── MCP resources ─────────────────────────────────────────────────────────────


def test_read_services_resource_requires_agent_or_default():
    result = _run_async(read_resource("vault://services"))
    data = _resource_json(result)
    assert data["version"] == "vault-resource-error-v1"
    assert "Missing required parameter: agent_id" in data["error"]


def test_read_services_resource_uses_default_agent(vault_with_policy, tmp_path, monkeypatch):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    monkeypatch.setenv("HERMES_VAULT_MCP_ALLOWED_AGENTS", "test-agent")
    monkeypatch.setenv("HERMES_VAULT_MCP_DEFAULT_AGENT", "test-agent")
    result = _run_async(read_resource("vault://services"))
    data = _resource_json(result)
    assert data["agent_id"] == "test-agent"
    assert data["binding_mode"] == "default_fallback"
    assert {item["service"] for item in data["services"]} == {"openai", "supabase"}


def test_read_services_resource_accepts_agent_query(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(read_resource("vault://services?agent_id=test-agent"))
    data = _resource_json(result)
    assert data["version"] == "vault-services-v1"
    assert data["agent_id"] == "test-agent"
    assert data["binding_mode"] == "unrestricted"


def test_read_resource_denies_agent_outside_binding_set(vault_with_policy, tmp_path, monkeypatch):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    monkeypatch.setenv("HERMES_VAULT_MCP_ALLOWED_AGENTS", "test-agent")
    result = _run_async(read_resource("vault://services?agent_id=intruder"))
    data = _resource_json(result)
    assert "not allowed for this MCP server" in data["error"]

    audit = AuditLogger(tmp_path / "vault.db")
    entries = audit.list_recent(limit=10)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["action"] == "mcp_bind:resource:vault://services"
    assert entry["decision"] == "deny"
    assert entry["metadata"]["requested_agent_id"] == "intruder"


def test_read_services_resource_returns_policy_filtered_services(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(read_resource("vault://services?agent_id=test-agent"))
    data = _resource_json(result)
    assert data["count"] == 2
    services = {item["service"] for item in data["services"]}
    assert services == {"openai", "supabase"}
    serialized = json.dumps(data)
    assert "github" not in serialized
    assert "encrypted_payload" not in serialized
    assert "OPENAI_API_KEY" not in serialized
    assert "id" not in data["services"][0]
    assert data["services"][0]["resource_uri"].startswith("vault://services/")


def test_read_services_resource_respects_list_credentials_capability(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(read_resource("vault://services?agent_id=no-list-agent"))
    data = _resource_json(result)
    assert data["version"] == "vault-services-v1"
    assert data["services"] == []

    audit = AuditLogger(tmp_path / "vault.db")
    entries = audit.list_recent(limit=10, action="list_available_credentials")
    assert entries[0]["decision"] == "deny"


def test_read_service_detail_returns_metadata_for_visible_service(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(read_resource("vault://services/openai?agent_id=test-agent"))
    data = _resource_json(result)
    assert data["version"] == "vault-service-v1"
    assert data["service"] == "openai"
    assert data["count"] == 1
    credential = data["credentials"][0]
    assert credential["service"] == "openai"
    assert credential["alias"] == "primary"
    assert "id" in credential
    assert "encrypted_payload" not in credential


def test_read_service_detail_respects_alias_query(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    vault_with_policy.vault.add_credential(service="openai", secret="secondary", credential_type="api_key", alias="secondary")
    result = _run_async(read_resource("vault://services/openai?agent_id=test-agent&alias=primary"))
    data = _resource_json(result)
    assert data["alias"] == "primary"
    assert data["count"] == 1
    assert data["credentials"][0]["alias"] == "primary"


def test_read_service_detail_denies_unauthorized_service(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(read_resource("vault://services/github?agent_id=test-agent"))
    data = _resource_json(result)
    assert "service 'github' is not allowed" in data["error"]
    assert "encrypted_payload" not in json.dumps(data)


def test_read_service_detail_url_decodes_service_name():
    assert _resource_service_name("vault://services/open%5Fai") == "openai"


def test_read_health_resource_returns_no_live_verify_health(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(read_resource("vault://health?agent_id=test-agent"))
    data = _resource_json(result)
    assert data["version"] == "health-v1"
    assert data["verified_live"] is False
    assert data["policy_scoped"] is True


def test_read_status_resource_returns_consolidated_metadata(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(read_resource("vault://status?agent_id=test-agent"))
    data = _resource_json(result)

    assert data["version"] == "vault-status-v1"
    assert data["agent_id"] == "test-agent"
    assert data["policy_scoped"] is True
    assert data["profile"]["name"] == "default"
    assert data["health"]["total_credentials"] == 2
    assert "policy_hash" in data["policy"]
    assert isinstance(data["next_steps"], list)
    assert data["raw_secret_values_returned"] is False
    serialized = json.dumps(data)
    assert "test-openai-key" not in serialized
    assert "gh-test-token" not in serialized


def test_read_status_resource_denies_agent_without_list_capability(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(read_resource("vault://status?agent_id=no-list-agent"))
    data = _resource_json(result)

    assert data["version"] == "vault-resource-error-v1"
    assert "list_credentials" in data["error"]


def test_read_agent_context_resource_returns_redacted_manifest(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(read_resource("vault://agent-context?agent_id=test-agent"))
    data = _resource_json(result)

    assert data["version"] == "agent-context-v1"
    assert data["agent_id"] == "test-agent"
    assert data["summary"]["service_count"] >= 2
    serialized = json.dumps(data)
    assert "test-openai-key" not in serialized
    assert "encrypted_payload" not in serialized


def test_read_policy_explain_resource_returns_policy_explain(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(read_resource("vault://policy-explain?agent_id=test-agent&service=openai&action=get_env&ttl_seconds=900"))
    data = _resource_json(result)

    assert data["version"] == "policy-explain-v1"
    assert data["agent_id"] == "test-agent"
    assert data["service"] == "openai"
    assert data["action"] == "get_env"
    assert data["allowed"] is True


def test_read_policy_explain_resource_requires_service(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(read_resource("vault://policy-explain?agent_id=test-agent"))
    data = _resource_json(result)

    assert data["version"] == "vault-resource-error-v1"
    assert "service" in data["error"]


def test_read_requests_resource_lists_access_requests_without_secret_material(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    vault_with_policy.request_access(
        agent_id="test-agent",
        service="openai",
        alias="primary",
        action="get_env",
        purpose="deploy",
        requested_ttl_seconds=60,
    )

    result = _run_async(read_resource("vault://requests?agent_id=test-agent"))
    data = _resource_json(result)

    assert data["version"] == "vault-requests-v1"
    assert len(data["requests"]) == 1
    assert data["requests"][0]["status"] == "pending"
    assert "test-openai-key" not in json.dumps(data)


def test_read_recovery_resource_returns_redacted_report(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    backup_path = tmp_path / "backup.json"
    backup_path.write_text(json.dumps(vault_with_policy.vault.export_backup()), encoding="utf-8")
    encoded = urllib.parse.quote(str(backup_path), safe="")

    result = _run_async(read_resource(f"vault://recovery?agent_id=test-agent&backup={encoded}"))
    data = _resource_json(result)

    assert data["version"] == "recovery-drill-v1"
    assert data["backup_verify"]["decryptable"] is True
    assert data["raw_secret_values_returned"] is False
    assert "test-openai-key" not in json.dumps(data)


def test_read_health_resource_is_policy_scoped(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(read_resource("vault://health?agent_id=test-agent"))
    data = _resource_json(result)
    assert data["total_credentials"] == 2
    assert all(finding["service"] in {"openai", "supabase", "*"} for finding in data["findings"])
    assert "github" not in json.dumps(data)


def test_read_health_resource_requires_list_credentials_capability(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(read_resource("vault://health?agent_id=no-list-agent"))
    data = _resource_json(result)
    assert "list_credentials" in data["error"]

    audit = AuditLogger(tmp_path / "vault.db")
    entries = audit.list_recent(limit=10, action="mcp_resource_health")
    assert entries[0]["decision"] == "deny"


def test_read_policy_resource_returns_effective_agent_only(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(read_resource("vault://policy?agent_id=test-agent"))
    data = _resource_json(result)
    assert data["version"] == "policy-summary-v1"
    assert data["agent_id"] == "test-agent"
    assert data["policy_hash"]
    assert data["services"] == ["openai", "google", "supabase"]
    assert data["raw_secret_access"] is False
    assert data["ephemeral_env_only"] is True
    assert data["max_ttl_seconds"] == 3600
    assert "openai" in data["service_actions"]
    assert "restricted-agent" not in json.dumps(data)


def test_read_policy_resource_denies_unknown_agent(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(read_resource("vault://policy?agent_id=unknown-agent"))
    data = _resource_json(result)
    assert "agent 'unknown-agent' is not defined in policy" in data["error"]


def test_unknown_resource_uri_raises():
    with pytest.raises(ValueError):
        _run_async(read_resource("vault://unknown?agent_id=test-agent"))


def test_resource_content_is_application_json(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    for uri in (
        "vault://status?agent_id=test-agent",
        "vault://services?agent_id=test-agent",
        "vault://services/openai?agent_id=test-agent",
        "vault://health?agent_id=test-agent",
        "vault://policy?agent_id=test-agent",
    ):
        result = _run_async(read_resource(uri))
        assert len(result) == 1
        assert result[0].mimeType == "application/json"
        json.loads(result[0].text)


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


def test_list_services_works_without_binding_env(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("list_services", {"agent_id": "test-agent"}))
    data = _json(result)
    services = {d["service"] for d in data}
    assert "openai" in services
    assert "supabase" in services


def test_list_services_uses_default_agent_when_agent_id_missing(vault_with_policy, tmp_path, monkeypatch):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    monkeypatch.setenv("HERMES_VAULT_MCP_ALLOWED_AGENTS", "test-agent")
    monkeypatch.setenv("HERMES_VAULT_MCP_DEFAULT_AGENT", "test-agent")
    result = _run_async(call_tool("list_services", {}))
    data = _json(result)
    services = {d["service"] for d in data}
    assert "openai" in services
    assert "supabase" in services


def test_list_services_denies_agent_outside_binding_set(vault_with_policy, tmp_path, monkeypatch):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    monkeypatch.setenv("HERMES_VAULT_MCP_ALLOWED_AGENTS", "test-agent")
    result = _run_async(call_tool("list_services", {"agent_id": "intruder"}))
    text = _text(result)
    assert "not allowed for this MCP server" in text

    audit = AuditLogger(tmp_path / "vault.db")
    entries = audit.list_recent(limit=10)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["action"] == "mcp_bind:list_services"
    assert entry["decision"] == "deny"
    assert entry["metadata"]["requested_agent_id"] == "intruder"
    assert entry["metadata"]["mcp_allowed_agents"] == ["test-agent"]
    assert entry["metadata"]["policy_decision"] == "not_evaluated"


def test_oauth_refresh_uses_default_agent_when_agent_id_missing(vault_with_policy, tmp_path, monkeypatch):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    monkeypatch.setenv("HERMES_VAULT_MCP_ALLOWED_AGENTS", "test-agent")
    monkeypatch.setenv("HERMES_VAULT_MCP_DEFAULT_AGENT", "test-agent")
    result = _run_async(call_tool("oauth_refresh", {"service": "openai", "alias": "default"}))
    text = _text(result)
    assert "No refresh token" in text or "Use oauth_login" in text or "re-authentication" in text.lower()


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
    assert data["tags"] == ["prod", "ai"]
    assert data["notes"] == "mcp note"
    assert "id" in data


# ── get_ephemeral_env ──────────────────────────────────────────────────────────


def test_get_ephemeral_env_requires_agent_id():
    result = _run_async(call_tool("get_ephemeral_env", {"service": "openai"}))
    assert "Missing required parameter: agent_id" in _text(result)


def test_get_ephemeral_env_denied_for_unauthorized_service(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("get_ephemeral_env", {"agent_id": "test-agent", "service": "github"}))
    assert "Denied:" in _text(result)


def test_get_ephemeral_env_denied_without_get_env_action(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("get_ephemeral_env", {"agent_id": "metadata-agent", "service": "openai"}))
    text = _text(result)
    assert "Denied:" in text
    assert "get_env" in text


def test_get_ephemeral_env_returns_env(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("get_ephemeral_env", {"agent_id": "test-agent", "service": "openai"}))
    data = _json(result)
    assert "env" in data
    assert "OPENAI_API_KEY" in data["env"]
    assert data["env"]["OPENAI_API_KEY"] == "test-openai-key"
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


def test_get_ephemeral_env_requires_alias_when_service_has_multiple_credentials(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    vault_with_policy.vault.add_credential(
        service="openai",
        secret="secondary-openai-key",
        credential_type="api_key",
        alias="secondary",
    )
    result = _run_async(call_tool("get_ephemeral_env", {"agent_id": "test-agent", "service": "openai"}))
    text = _text(result)
    assert "Denied:" in text
    assert "specify credential ID or service+alias" in text


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
    assert "login_id" in data
    assert "redirect_uri" in data
    assert "message" in data
    assert "test" in data["message"]
    # URL should contain PKCE params
    url = data["authorization_url"]
    assert "code_challenge=" in url
    assert "code_challenge_method=S256" in url
    assert "state=" in url
    assert "client_id=" in url


def test_oauth_login_pending_state_uses_unique_login_ids(vault_with_policy, tmp_path, monkeypatch):
    import hermes_vault.mcp_server as mcp_mod

    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    monkeypatch.setenv("HERMES_VAULT_OAUTH_GOOGLE_CLIENT_ID", "test-client-123")
    monkeypatch.setenv("HERMES_VAULT_OAUTH_GOOGLE_CLIENT_SECRET", "test-secret")

    class FakeCallbackServer:
        next_port = 9000

        def __init__(self, *args, **kwargs) -> None:
            pass

        def start(self) -> int:
            FakeCallbackServer.next_port += 1
            return FakeCallbackServer.next_port

        def wait(self):
            raise AssertionError("wait should not run in this collision test")

    class FakeThread:
        def __init__(self, target, daemon: bool = False) -> None:
            self.target = target
            self.daemon = daemon

        def start(self) -> None:
            return None

    monkeypatch.setattr(mcp_mod, "CallbackServer", FakeCallbackServer)
    monkeypatch.setattr(mcp_mod.threading, "Thread", FakeThread)

    first = _json(_run_async(call_tool("oauth_login", {
        "agent_id": "test-agent",
        "provider": "google",
        "alias": "shared",
    })))
    second = _json(_run_async(call_tool("oauth_login", {
        "agent_id": "test-agent",
        "provider": "google",
        "alias": "shared",
    })))

    assert first["login_id"] != second["login_id"]
    assert len(mcp_mod._pending_oauth) == 2
    assert all(key.startswith("browser:default:google:shared:") for key in mcp_mod._pending_oauth)


def test_oauth_device_login_requires_provider(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
    result = _run_async(call_tool("oauth_device_login", {"agent_id": "test-agent"}))
    assert "Missing required parameter: provider_id" in _text(result)


def test_oauth_device_login_denied_without_add_credential_permission(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("oauth_device_login", {
        "agent_id": "restricted-agent",
        "provider_id": "openai",
    }))
    assert "Denied:" in _text(result)


def test_oauth_device_login_reports_unsupported_provider(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("oauth_device_login", {
        "agent_id": "test-agent",
        "provider_id": "openai",
    }))
    data = _json(result)
    assert data["success"] is False
    assert "does not support device-code" in data["error"]
    assert "google" in data["supported_providers"]
    assert data["fallback_command"] == "hermes-vault oauth login openai --alias default --no-browser"
    assert data["provider_status"]["provider"] == "openai"


def test_oauth_provider_status_reports_read_only_metadata(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("oauth_provider_status", {
        "agent_id": "test-agent",
        "provider_id": "google",
    }))
    data = _json(result)
    assert data["provider"] == "google"
    assert data["supports_pkce"] is True
    assert data["supports_device_code"] is True
    assert data["missing_env"] == ["HERMES_VAULT_OAUTH_GOOGLE_CLIENT_ID"]
    serialized = json.dumps(data)
    assert "secret" not in serialized.lower()
    assert "access_token" not in serialized


def test_oauth_device_login_returns_redacted_device_instructions(vault_with_policy, tmp_path, monkeypatch):
    import hermes_vault.mcp_server as mcp_mod
    from hermes_vault.oauth.exchange import DeviceAuthorizationResponse

    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    monkeypatch.setenv("HERMES_VAULT_OAUTH_GOOGLE_CLIENT_ID", "test-client-123")

    class FakeTokenExchanger:
        def __init__(self, provider):
            self.provider = provider

        def request_device_code(self, **kwargs):
            return DeviceAuthorizationResponse(
                device_code="device-secret-code",
                user_code="ABCD-EFGH",
                verification_uri="https://example.test/device",
                verification_uri_complete="https://example.test/device?user_code=ABCD-EFGH",
                expires_in=600,
                interval=1,
                message="Visit the URL and enter ABCD-EFGH.",
            )

        def poll_device_code(self, **kwargs):
            return type("Poll", (), {"status": "authorization_pending", "retry_after": None, "token_response": None})()

    monkeypatch.setattr(mcp_mod, "TokenExchanger", FakeTokenExchanger)
    result = _run_async(call_tool("oauth_device_login", {
        "agent_id": "test-agent",
        "provider_id": "google",
        "alias": "work",
        "timeout_seconds": 0,
    }))
    data = _json(result)
    assert data["success"] is True
    assert data["user_code"] == "ABCD-EFGH"
    assert data["raw_tokens_returned"] is False
    serialized = json.dumps(data)
    assert "access_token" not in serialized
    assert "refresh_token" not in serialized
    assert "device-secret-code" not in serialized


# ── oauth_refresh ──────────────────────────────────────────────────────────────


def test_oauth_refresh_requires_agent_id():
    result = _run_async(call_tool("oauth_refresh", {"service": "openai"}))
    assert "Missing required parameter: agent_id" in _text(result)


def test_oauth_refresh_requires_service():
    result = _run_async(call_tool("oauth_refresh", {"agent_id": "test-agent"}))
    assert "Missing required parameter: service" in _text(result)


def test_oauth_refresh_requires_rotate_permission(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    result = _run_async(call_tool("oauth_refresh", {
        "agent_id": "restricted-agent",
        "service": "openai",
        "alias": "default",
    }))

    assert "Denied:" in _text(result)


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


def test_oauth_refresh_redacts_provider_error_text(vault_with_policy, tmp_path, monkeypatch):
    import hermes_vault.mcp_server as mcp_mod

    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)

    class FakeRefreshEngine:
        def __init__(self, vault):
            self.vault = vault

        def set_audit(self, audit):
            self.audit = audit

        def refresh(self, **kwargs):
            raise RuntimeError("provider failed access_token=sk-supersecretvalue123456")

    monkeypatch.setattr(mcp_mod, "RefreshEngine", FakeRefreshEngine)

    result = _run_async(call_tool("oauth_refresh", {
        "agent_id": "test-agent",
        "service": "openai",
        "alias": "primary",
    }))

    text = _text(result)
    assert "sk-supersecretvalue123456" not in text
    assert "[redacted]" in text


# ── fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def vault_with_policy(tmp_path):
    """Create a vault with policy and a few credentials for MCP tests."""
    from hermes_vault.audit import AuditLogger
    from hermes_vault.broker import Broker
    from hermes_vault.policy import PolicyEngine
    from hermes_vault.verifier import Verifier

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

    vault.add_credential(service="openai", secret="test-openai-key", credential_type="api_key", alias="primary", tags=["prod", "ai"], notes="mcp note")
    vault.add_credential(service="supabase", secret="sb-test-supabase", credential_type="api_key", alias="primary")
    vault.add_credential(service="github", secret="gh-test-token", credential_type="api_key", alias="primary")

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
          - issue_lease
          - list_leases
          - show_lease
          - renew_lease
          - revoke_lease
      google:
        actions:
          - get_credential
          - get_env
          - metadata
          - rotate
          - delete
          - add_credential
          - issue_lease
          - list_leases
          - show_lease
          - renew_lease
          - revoke_lease
      supabase:
        actions:
          - get_credential
          - get_env
          - list_leases
          - show_lease
    max_ttl_seconds: 3600
    raw_secret_access: false
    ephemeral_env_only: true
  no-list-agent:
    services:
      openai:
        actions:
          - get_env
    capabilities:
      - scan_secrets
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
  metadata-agent:
    services:
      openai:
        actions:
          - metadata
    capabilities:
      - list_credentials
    max_ttl_seconds: 3600
    raw_secret_access: false
    ephemeral_env_only: true
  no-list-agent:
    services:
      openai:
        actions:
          - metadata
    capabilities:
      - scan_secrets
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
    for key in (
        "HERMES_VAULT_HOME",
        "HERMES_VAULT_PASSPHRASE",
        "HERMES_VAULT_POLICY",
        "HERMES_VAULT_MCP_ALLOWED_AGENTS",
        "HERMES_VAULT_MCP_DEFAULT_AGENT",
    ):
        os.environ.pop(key, None)


# ── MCP OAuth freshness tests ────────────────────────────────────────────────

def test_get_ephemeral_env_mcp_includes_oauth_refresh_metadata(vault_with_policy, tmp_path):
    """MCP get_ephemeral_env response includes oauth_refresh metadata when credential is OAuth."""
    import hermes_vault.mcp_server as mcp_mod
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    # Replace the google API key with an OAuth access token far from expiry
    future = utc_now() + timedelta(hours=24)
    rec = vault_with_policy.vault.add_credential(
        service="google",
        secret="ya29.valid-token",
        credential_type="oauth_access_token",
        alias="primary",
        replace_existing=True,
    )
    vault_with_policy.vault.set_expiry(rec.id, future)
    # Use the same broker instance for MCP calls
    mcp_mod._broker = vault_with_policy

    result = _run_async(call_tool("get_ephemeral_env", {
        "agent_id": "test-agent",
        "service": "google",
    }))
    data = json.loads(result[0].text)
    assert "env" in data
    assert "metadata" in data
    assert "oauth_refresh" in data["metadata"]
    # Token is far from expiry, so no refresh needed
    assert data["metadata"]["oauth_refresh"]["refreshed"] is False


def test_get_ephemeral_env_mcp_denies_expired_no_refresh(vault_with_policy, tmp_path):
    """MCP get_ephemeral_env denies with sanitized message when OAuth token is expired and no refresh token."""
    import hermes_vault.mcp_server as mcp_mod
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    # Replace the google API key with an expired OAuth access token (no refresh token)
    past = utc_now() - timedelta(hours=1)
    rec = vault_with_policy.vault.add_credential(
        service="google",
        secret="ya29.expired-token",
        credential_type="oauth_access_token",
        alias="primary",
        replace_existing=True,
    )
    vault_with_policy.vault.set_expiry(rec.id, past)
    # No refresh token is added for google, so refresh will fail
    # Use the same broker instance
    mcp_mod._broker = vault_with_policy

    result = _run_async(call_tool("get_ephemeral_env", {
        "agent_id": "test-agent",
        "service": "google",
    }))
    text = result[0].text
    # Should be denied with a sanitized message (no raw tokens)
    assert "Denied:" in text
    assert "ya29" not in text


def test_lease_issue_tool_returns_broker_decision_shape(vault_with_policy, tmp_path):
    import hermes_vault.mcp_server as mcp_mod

    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    mcp_mod._broker = vault_with_policy

    result = _run_async(call_tool("lease_issue", {
        "agent_id": "test-agent",
        "service": "openai",
        "alias": "primary",
        "ttl_seconds": 600,
        "purpose": "deploy",
    }))
    data = _json(result)

    assert data["allowed"] is True
    assert data["service"] == "openai"
    assert data["ttl_seconds"] == 600
    assert data["metadata"]["lease"]["purpose"] == "deploy"


def test_lease_list_tool_returns_leases(vault_with_policy, tmp_path):
    import hermes_vault.mcp_server as mcp_mod

    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    lease = vault_with_policy.issue_lease("test-agent", "openai", 600, alias="primary")
    mcp_mod._broker = vault_with_policy

    result = _run_async(call_tool("lease_list", {"agent_id": "test-agent"}))
    data = _json(result)

    assert data["allowed"] is True
    assert [item["id"] for item in data["metadata"]["leases"]] == [lease.metadata["lease"]["id"]]


def test_lease_show_tool_returns_lease_detail(vault_with_policy, tmp_path):
    import hermes_vault.mcp_server as mcp_mod

    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    lease = vault_with_policy.issue_lease("test-agent", "openai", 600, alias="primary")
    mcp_mod._broker = vault_with_policy

    result = _run_async(call_tool("lease_show", {
        "agent_id": "test-agent",
        "lease_id": lease.metadata["lease"]["id"],
    }))
    data = _json(result)

    assert data["allowed"] is True
    assert data["metadata"]["lease"]["id"] == lease.metadata["lease"]["id"]


def test_lease_renew_tool_returns_updated_lease(vault_with_policy, tmp_path):
    import hermes_vault.mcp_server as mcp_mod

    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    lease = vault_with_policy.issue_lease("test-agent", "openai", 600, alias="primary")
    mcp_mod._broker = vault_with_policy

    result = _run_async(call_tool("lease_renew", {
        "agent_id": "test-agent",
        "lease_id": lease.metadata["lease"]["id"],
        "ttl_seconds": 300,
    }))
    data = _json(result)

    assert data["allowed"] is True
    assert data["ttl_seconds"] == 300
    assert data["metadata"]["lease"]["renew_count"] == 1


def test_lease_revoke_tool_returns_revoked_lease(vault_with_policy, tmp_path):
    import hermes_vault.mcp_server as mcp_mod

    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    lease = vault_with_policy.issue_lease("test-agent", "openai", 600, alias="primary")
    mcp_mod._broker = vault_with_policy

    result = _run_async(call_tool("lease_revoke", {
        "agent_id": "test-agent",
        "lease_id": lease.metadata["lease"]["id"],
        "reason": "cleanup",
    }))
    data = _json(result)

    assert data["allowed"] is True
    assert data["metadata"]["lease"]["status"] == "revoked"
    assert data["metadata"]["lease"]["reason"] == "cleanup"


def test_request_access_tool_creates_redacted_request(vault_with_policy, tmp_path):
    import hermes_vault.mcp_server as mcp_mod

    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    mcp_mod._broker = vault_with_policy

    result = _run_async(call_tool("request_access", {
        "agent_id": "test-agent",
        "service": "openai",
        "alias": "primary",
        "purpose": "deploy",
        "ttl_seconds": 60,
    }))
    data = _json(result)

    assert data["allowed"] is True
    assert data["metadata"]["request"]["status"] == "pending"
    assert data["env"] == {}
    assert "test-openai-key" not in json.dumps(data)


def test_policy_explain_tool_returns_policy_explain(vault_with_policy, tmp_path):
    import hermes_vault.mcp_server as mcp_mod

    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    mcp_mod._broker = vault_with_policy

    result = _run_async(call_tool("policy_explain", {
        "agent_id": "test-agent",
        "service": "openai",
        "action": "get_env",
        "ttl_seconds": 60,
    }))
    data = _json(result)

    assert data["version"] == "policy-explain-v1"
    assert data["allowed"] is True
    assert data["service"] == "openai"


def test_lease_checkout_tool_returns_env_through_broker(vault_with_policy, tmp_path):
    import hermes_vault.mcp_server as mcp_mod

    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    mcp_mod._broker = vault_with_policy

    result = _run_async(call_tool("lease_checkout", {
        "agent_id": "test-agent",
        "service": "openai",
        "alias": "primary",
        "purpose": "deploy",
        "ttl_seconds": 60,
    }))
    data = _json(result)

    assert data["env"]["OPENAI_API_KEY"] == "test-openai-key"
    assert data["metadata"]["lease_checkout"]["lease_issued"] is True


def test_lease_issue_denied_returns_decision_shape(vault_with_policy, tmp_path, monkeypatch):
    import hermes_vault.mcp_server as mcp_mod

    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    mcp_mod._broker = vault_with_policy
    monkeypatch.setenv("HERMES_VAULT_MCP_ALLOWED_AGENTS", "restricted-agent")

    result = _run_async(call_tool("lease_issue", {
        "agent_id": "restricted-agent",
        "service": "openai",
        "alias": "primary",
        "ttl_seconds": 600,
    }))
    data = _json(result)

    assert data["allowed"] is False
    assert "issue_lease" in data["reason"]


def test_vault_leases_resource_returns_list(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    vault_with_policy.issue_lease("test-agent", "openai", 600, alias="primary")

    result = _run_async(read_resource("vault://leases?agent_id=test-agent"))
    data = _resource_json(result)

    assert data["version"] == "vault-leases-v1"
    assert data["count"] == 1
    assert data["leases"][0]["service"] == "openai"


def test_vault_lease_detail_resource_returns_detail(vault_with_policy, tmp_path):
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    lease = vault_with_policy.issue_lease("test-agent", "openai", 600, alias="primary")

    result = _run_async(read_resource(f"vault://leases/{lease.metadata['lease']['id']}?agent_id=test-agent"))
    data = _resource_json(result)

    assert data["version"] == "vault-lease-v1"
    assert data["lease"]["id"] == lease.metadata["lease"]["id"]
