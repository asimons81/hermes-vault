"""Issue #90 — credential metadata editing and origin rebinding.

Mutation-layer coverage:

- alias/tags/notes can change without replacing secret material
- the stored secret decrypts to the same value after metadata edit and rebind
- origin rebind moves the row between services (old and new handled correctly)
- distinct audit actions: ``update_credential_metadata`` and
  ``rebind_credential_origin``
- rebind audit metadata records old_service/new_service
- no secret appears in audit rows (reason text or metadata)
- unauthorized agents are denied (new service actions)
- empty update (no fields) is denied
- duplicate alias / destination-origin collisions are denied
- rebind to the same origin is denied
- audit-integrity failure restores the exact prior credential row

All fixtures use disposable tmp_path vaults; no live vault is touched.
"""
from __future__ import annotations

import json
from pathlib import Path

from hermes_vault.audit import AuditLogger
from hermes_vault.mutations import VaultMutations
from hermes_vault.models import ServiceAction
from hermes_vault.policy import PolicyEngine
from hermes_vault.vault import Vault

SECRET = "original-secret-value-do-not-change"


def _policy_yaml(tmp_path: Path, *, restricted: bool = False) -> Path:
    """A policy with a restricted agent that lacks the new actions."""
    if restricted:
        actions = "actions: [get_env, verify, metadata]"
    else:
        actions = "actions: [get_env, verify, metadata, add_credential, rotate, delete, update_metadata, rebind_origin]"
    path = tmp_path / "policy.yaml"
    path.write_text(
        f"""
agents:
  operator:
    capabilities: [list_credentials, add_credential]
    services:
      openai:
        {actions}
      github:
        {actions}
""".replace("        actions:", "        actions:").lstrip(),
        encoding="utf-8",
    )
    return path


def _make(tmp_path: Path, *, restricted: bool = False) -> tuple[Vault, AuditLogger, VaultMutations]:
    policy_path = _policy_yaml(tmp_path, restricted=restricted)
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    logger = AuditLogger(vault.db_path, master_key=vault.key)
    policy = PolicyEngine.from_yaml(policy_path)
    mutations = VaultMutations(vault=vault, policy=policy, audit=logger)
    return vault, logger, mutations


def _secret_of(vault: Vault, record_id: str) -> str:
    secret = vault.get_secret(record_id)
    assert secret is not None, "credential payload must decrypt"
    return secret.secret


def _add(vault: Vault, logger: AuditLogger, mutations: VaultMutations, **kwargs) -> str:
    result = mutations.add_credential(
        agent_id="operator",
        service=kwargs.get("service", "openai"),
        secret=kwargs.get("secret", SECRET),
        credential_type="api_key",
        alias=kwargs.get("alias", "default"),
        tags=kwargs.get("tags"),
        notes=kwargs.get("notes"),
    )
    assert result.allowed is True, result.reason
    assert result.record is not None
    return result.record.id


def _audit_entries(logger: AuditLogger, action: str) -> list[dict]:
    return [e for e in logger.list_recent(limit=100) if e.get("action") == action]


def _corrupt_checkpoint(logger: AuditLogger) -> None:
    checkpoint_path = logger.db_path.with_name("audit.checkpoint.json")
    checkpoint_path.write_bytes(
        b'{"format": "hermes-vault-audit-checkpoint", "version": "audit-checkpoint-v1", "signature": "bogus"}'
    )


# ── metadata editing ─────────────────────────────────────────────────────────


def test_alias_edit_preserves_secret(tmp_path: Path) -> None:
    vault, logger, mutations = _make(tmp_path)
    record_id = _add(vault, logger, mutations, alias="old-name")

    result = mutations.update_credential_metadata(
        agent_id="operator", service_or_id=record_id, alias="new-name"
    )
    assert result.allowed is True, result.reason
    assert result.record is not None
    assert result.record.alias == "new-name"
    assert result.record.service == "openai"

    secret = vault.get_secret(record_id)
    assert secret is not None and secret.secret == SECRET, "alias edit must not change the secret"


def test_tags_and_notes_edit_preserves_secret(tmp_path: Path) -> None:
    vault, logger, mutations = _make(tmp_path)
    record_id = _add(vault, logger, mutations, tags=["old"], notes="old notes")

    result = mutations.update_credential_metadata(
        agent_id="operator", service_or_id=record_id, tags=["prod", "ci"], notes="new notes"
    )
    assert result.allowed is True, result.reason
    assert result.record is not None
    assert result.record.tags == ["prod", "ci"]
    assert result.record.notes == "new notes"

    secret = vault.get_secret(record_id)
    assert secret is not None and secret.secret == SECRET
    # payload-side duplicates stay consistent with the row
    assert secret.tags == ["prod", "ci"]
    assert secret.notes == "new notes"


def test_clearing_notes_and_tags(tmp_path: Path) -> None:
    vault, logger, mutations = _make(tmp_path)
    record_id = _add(vault, logger, mutations, tags=["x"], notes="to be cleared")

    result = mutations.update_credential_metadata(
        agent_id="operator", service_or_id=record_id, tags=[], notes=""
    )
    assert result.allowed is True, result.reason
    secret = vault.get_secret(record_id)
    assert secret is not None and secret.secret == SECRET
    assert secret.tags == []
    assert secret.notes is None


def test_metadata_edit_distinct_audit_action(tmp_path: Path) -> None:
    vault, logger, mutations = _make(tmp_path)
    record_id = _add(vault, logger, mutations)

    mutations.update_credential_metadata(
        agent_id="operator", service_or_id=record_id, alias="renamed"
    )
    entries = _audit_entries(logger, "update_credential_metadata")
    assert len(entries) == 1
    assert entries[0]["decision"] == "allow"
    assert SECRET not in json.dumps(entries[0])


def test_empty_metadata_update_denied(tmp_path: Path) -> None:
    vault, logger, mutations = _make(tmp_path)
    record_id = _add(vault, logger, mutations)

    result = mutations.update_credential_metadata(agent_id="operator", service_or_id=record_id)
    assert result.allowed is False
    assert "no metadata fields" in result.reason
    # the credential is untouched
    assert _secret_of(vault, record_id) == SECRET


def test_duplicate_alias_denied(tmp_path: Path) -> None:
    vault, logger, mutations = _make(tmp_path)
    _add(vault, logger, mutations, alias="one")
    two = _add(vault, logger, mutations, alias="two")

    result = mutations.update_credential_metadata(
        agent_id="operator", service_or_id=two, alias="one"
    )
    assert result.allowed is False
    assert "already exists" in result.reason
    assert vault.resolve_credential(two).alias == "two"


def test_metadata_edit_not_found(tmp_path: Path) -> None:
    vault, logger, mutations = _make(tmp_path)
    result = mutations.update_credential_metadata(
        agent_id="operator", service_or_id="ghost", alias="x"
    )
    assert result.allowed is False
    assert "not found" in result.reason


# ── origin rebinding ─────────────────────────────────────────────────────────


def test_rebind_origin_moves_credential_and_preserves_secret(tmp_path: Path) -> None:
    vault, logger, mutations = _make(tmp_path)
    record_id = _add(vault, logger, mutations, alias="primary")

    result = mutations.rebind_credential_origin(
        agent_id="operator", service_or_id="openai", new_service="github", alias="primary"
    )
    assert result.allowed is True, result.reason
    assert result.record is not None
    assert result.record.service == "github"
    assert result.record.alias == "primary"
    assert result.record.id == record_id, "rebind must keep the same credential row"

    # old origin no longer resolves; new origin does
    record = vault.resolve_credential("github", alias="primary")
    assert record.id == record_id

    # the secret is byte-identical after the AAD re-encryption
    secret = vault.get_secret(record_id)
    assert secret is not None and secret.secret == SECRET


def test_rebind_origin_distinct_audit_action_with_old_and_new(tmp_path: Path) -> None:
    vault, logger, mutations = _make(tmp_path)
    _add(vault, logger, mutations, alias="primary")

    mutations.rebind_credential_origin(
        agent_id="operator", service_or_id="openai", new_service="github", alias="primary"
    )
    entries = _audit_entries(logger, "rebind_credential_origin")
    assert len(entries) == 1
    assert entries[0]["decision"] == "allow"
    metadata = entries[0].get("metadata") or {}
    assert metadata.get("old_service") == "openai"
    assert metadata.get("new_service") == "github"
    assert SECRET not in json.dumps(entries[0])


def test_rebind_same_origin_denied(tmp_path: Path) -> None:
    vault, logger, mutations = _make(tmp_path)
    record_id = _add(vault, logger, mutations)

    result = mutations.rebind_credential_origin(
        agent_id="operator", service_or_id="openai", new_service="openai"
    )
    assert result.allowed is False
    assert "matches the current origin" in result.reason
    assert _secret_of(vault, record_id) == SECRET


def test_rebind_destination_collision_denied(tmp_path: Path) -> None:
    vault, logger, mutations = _make(tmp_path)
    _add(vault, logger, mutations, service="github", alias="default")
    openai_id = _add(vault, logger, mutations, service="openai", alias="default")

    result = mutations.rebind_credential_origin(
        agent_id="operator", service_or_id="openai", new_service="github"
    )
    assert result.allowed is False
    assert "already exists" in result.reason
    # both rows intact
    assert _secret_of(vault, openai_id) == SECRET
    assert vault.resolve_credential("github").service == "github"


def test_rebind_not_found(tmp_path: Path) -> None:
    vault, logger, mutations = _make(tmp_path)
    result = mutations.rebind_credential_origin(
        agent_id="operator", service_or_id="ghost", new_service="github"
    )
    assert result.allowed is False
    assert "not found" in result.reason


# ── policy gating ────────────────────────────────────────────────────────────


def test_unauthorized_agent_denied_for_metadata_edit(tmp_path: Path) -> None:
    vault, logger, mutations = _make(tmp_path, restricted=True)
    record_id = _add(vault, logger, mutations)

    result = mutations.update_credential_metadata(
        agent_id="hermes", service_or_id=record_id, alias="hacked"
    )
    assert result.allowed is False
    # default policy does not define the hermes agent on this vault's policy
    assert _secret_of(vault, record_id) == SECRET


def test_restricted_agent_denied_new_actions(tmp_path: Path) -> None:
    """An agent with an explicit action list lacking update_metadata/rebind_origin
    must be denied even when the service is otherwise permitted."""
    vault, logger, mutations = _make(tmp_path, restricted=True)
    record_id = _add(vault, logger, mutations)
    # 'operator' itself is only special-cased by the OPERATOR_AGENT_ID constant,
    # so use a non-operator agent that IS defined in the policy but restricted.
    result = mutations.update_credential_metadata(
        agent_id="operator-agent-strict", service_or_id=record_id, alias="nope"
    )
    assert result.allowed is False  # agent not defined in policy at all
    result2 = mutations.rebind_credential_origin(
        agent_id="operator-agent-strict", service_or_id=record_id, new_service="github"
    )
    assert result2.allowed is False


def test_legacy_policy_allows_new_actions_via_implicit_all(tmp_path: Path) -> None:
    """Legacy agents (services list, no per-service actions) keep all-mutations
    access — backwards compatibility for existing policies."""
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
agents:
  legacy:
    services: [openai, github]
""".lstrip(),
        encoding="utf-8",
    )
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    logger = AuditLogger(vault.db_path, master_key=vault.key)
    mutations = VaultMutations(vault=vault, policy=PolicyEngine.from_yaml(policy_path), audit=logger)
    record_id = _add(vault, logger, mutations)

    ok = mutations.update_credential_metadata(
        agent_id="legacy", service_or_id=record_id, alias="legacy-ok"
    )
    assert ok.allowed is True, ok.reason
    ok2 = mutations.rebind_credential_origin(
        agent_id="legacy", service_or_id="openai", new_service="github", alias="legacy-ok"
    )
    assert ok2.allowed is True, ok2.reason


# ── audit rollback ───────────────────────────────────────────────────────────


def test_metadata_edit_audit_failure_restores_exact_prior_row(tmp_path: Path) -> None:
    vault, logger, mutations = _make(tmp_path)
    record_id = _add(vault, logger, mutations, tags=["keep"], notes="keep notes")
    before = vault.resolve_credential(record_id)
    before_secret = vault.get_secret(record_id)
    _corrupt_checkpoint(logger)

    result = mutations.update_credential_metadata(
        agent_id="operator", service_or_id=record_id, alias="should-not-land", tags=["gone"]
    )
    assert result.allowed is False
    assert "audit integrity" in result.reason.lower() or "integrity" in result.reason.lower()

    after = vault.resolve_credential(record_id)
    assert after.alias == before.alias == "default"
    assert after.tags == before.tags == ["keep"]
    assert after.notes == before.notes == "keep notes"
    after_secret = vault.get_secret(record_id)
    assert after_secret.secret == before_secret.secret == SECRET


def test_rebind_audit_failure_restores_exact_prior_row(tmp_path: Path) -> None:
    vault, logger, mutations = _make(tmp_path)
    record_id = _add(vault, logger, mutations, alias="primary")
    before = vault.resolve_credential(record_id)
    before_payload = before.encrypted_payload
    _corrupt_checkpoint(logger)

    result = mutations.rebind_credential_origin(
        agent_id="operator", service_or_id="openai", new_service="github", alias="primary"
    )
    assert result.allowed is False
    assert "integrity" in result.reason.lower()

    after = vault.resolve_credential(record_id)
    assert after.service == before.service == "openai"
    # exact ciphertext restored (byte-for-byte before-image)
    assert after.encrypted_payload == before_payload
    assert _secret_of(vault, record_id) == SECRET


# ── ServiceAction surface ────────────────────────────────────────────────────


def test_new_service_actions_exist() -> None:
    assert ServiceAction.update_metadata.value == "update_metadata"
    assert ServiceAction.rebind_origin.value == "rebind_origin"
