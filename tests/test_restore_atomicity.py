"""Red tests for Issue #62 Slice E — atomic restore and lease identity (E1).

These tests encode the failure modes the E1 change must handle and are
intentionally RED against the current codebase:

- Partial commit: a restore import that fails partway must not leave any
  partial rows; the whole import is one transaction.
- Forged active lease: restoring a lease that is active and would forge /
  duplicate an existing lease identity must be rejected.
- Foreign linkage: restored rows whose ``credential_id`` points outside the
  allowed broker/credential set must be rejected in restore and
  broker/read paths.
- Broker mismatch: restore requests / broker reads whose broker identity
  does not match the expected source/evidence contract must be rejected.
- Audit failure atomicity: when the protected restore audit event cannot be
  written, the entire restore transaction must roll back.

After E1 is implemented every test in this file must pass.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest

from hermes_vault.audit import AuditLogger
from hermes_vault.audit_integrity.service import AuditIntegrityError
from hermes_vault.broker import Broker
from hermes_vault.models import (
    AccessLogRecord,
    AgentPolicy,
    Decision,
    LeaseStatus,
    PolicyConfig,
    ServiceAction,
    ServicePolicyEntry,
    VerificationCategory,
    VerificationResult,
    utc_now,
)
from hermes_vault.policy import PolicyEngine
from hermes_vault.vault import Vault


PASSPHRASE = "test-passphrase"


def _make_vault(tmp_path: Path, name: str = "vault.db", salt: str = "salt.bin") -> Vault:
    return Vault(tmp_path / name, tmp_path / salt, PASSPHRASE)


def _backup_dict(vault: Vault, **overrides) -> dict:
    backup = vault.export_backup()
    backup.update(overrides)
    return backup


def _write_backup(path: Path, backup: dict) -> Path:
    path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")
    return path


class StubVerifier:
    def verify(self, service: str, secret: str) -> VerificationResult:
        return VerificationResult(
            service=service,
            category=VerificationCategory.valid,
            success=True,
            reason="ok",
        )


# ── 1. Partial commit ──────────────────────────────────────────────────


def test_restore_invalid_final_record_leaves_vault_unchanged(tmp_path: Path) -> None:
    """A restore import that fails partway must not leave any partial rows.

    Mirrors the issue's `restore_partial_commit` repro: one valid credential
    followed by one invalid record currently leaves the first row committed.
    E1 must make the whole import a single transaction.
    """
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "«redacted:sk-…»", "api_key", alias="primary")
    source.add_credential("anthropic", "«redacted:sk-ant-…»", "api_key", alias="primary")

    backup = _backup_dict(source)
    # Invalidate the FINAL credential record (missing required encrypted_payload).
    backup["credentials"][-1].pop("encrypted_payload", None)
    backup_path = _write_backup(tmp_path / "backup.json", backup)

    # Target vault shares the same master key so the valid record decrypts.
    import shutil

    shutil.copy(tmp_path / "src_salt.bin", tmp_path / "tgt_salt.bin")
    vault = _make_vault(tmp_path, name="target.db", salt="tgt_salt.bin")

    with pytest.raises(ValueError):
        vault.import_backup(json.loads(backup_path.read_text(encoding="utf-8")))

    # No partial rows: neither record may be present.
    services = sorted(c.service for c in vault.list_credentials())
    assert services == [], f"partial restore left rows behind: {services}"


# ── 2. Forged active lease ─────────────────────────────────────────────


def test_restore_forged_active_lease_never_active(tmp_path: Path) -> None:
    """Restoring an active future-dated lease must not mint live authorization.

    The issue's `restore_active_lease` repro imports a backup with an active
    lease; E1 must never restore it as active (omit or force expired/revoked).
    """
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    record = source.add_credential("openai", "«redacted:sk-…»", "api_key", alias="primary")

    future = (utc_now() + timedelta(hours=1)).isoformat()
    forged_lease = {
        "id": "forged-active-lease",
        "service": "openai",
        "alias": "primary",
        "credential_id": record.id,
        "credential_type": "api_key",
        "agent_id": "attacker-agent",
        "issued_by": "attacker-agent",
        "purpose": "task",
        "status": "active",
        "ttl_seconds": 3600,
        "issued_at": utc_now().isoformat(),
        "expires_at": future,
    }
    backup = _backup_dict(source, leases=[forged_lease])
    backup_path = _write_backup(tmp_path / "backup.json", backup)

    import shutil

    shutil.copy(tmp_path / "src_salt.bin", tmp_path / "tgt_salt.bin")
    vault = _make_vault(tmp_path, name="target.db", salt="tgt_salt.bin")
    vault.import_backup(json.loads(backup_path.read_text(encoding="utf-8")))

    active = vault.find_active_lease(agent_id="attacker-agent", service="openai", alias="primary")
    assert active is None, "restore minted an active lease from backup data"

    restored = vault.get_lease("forged-active-lease")
    if restored is not None:
        assert restored.status is not LeaseStatus.active, "restored lease is still active"


# ── 2b. Forged v2 evidence (review F3) ────────────────────────────────


def test_restore_v2_marker_only_evidence_blocked(tmp_path: Path) -> None:
    """A marker-only integrity payload must fail closed before any write.

    Review F3 (SECURITY_REVIEW_62_66.md): the live restore path accepted a
    v2 backup whose audit_integrity carried only ``integrity_available:
    true`` (no state/segments/records). The live gate must detached-verify
    the evidence and reject anything less than healthy — a forged marker is
    not evidence.
    """
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "sk-secret", "api_key", alias="primary")
    backup = source.export_backup(include_audit=True)
    backup["audit_integrity"] = {
        "integrity_available": True,
        "state": [],
        "segments": [],
        "records": [],
    }
    backup_path = _write_backup(tmp_path / "backup.json", backup)

    import shutil

    shutil.copy(tmp_path / "src_salt.bin", tmp_path / "tgt_salt.bin")
    vault = _make_vault(tmp_path, name="target.db", salt="tgt_salt.bin")

    with pytest.raises(ValueError):
        vault.import_backup(json.loads(backup_path.read_text(encoding="utf-8")))

    # Nothing may be committed when the evidence contract is forged.
    services = sorted(c.service for c in vault.list_credentials())
    assert services == [], f"marker-only evidence restore left rows behind: {services}"


def test_restore_v2_forged_garbage_evidence_blocked(tmp_path: Path) -> None:
    """Structurally-present but forged evidence must fail closed (review F3).

    The marker is present AND state/segments exist, but the payload cannot
    detached-verify against the vault key. The live gate must treat this the
    same as backup-verify: failed/incomplete evidence blocks the restore.
    """
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "sk-secret", "api_key", alias="primary")
    backup = source.export_backup(include_audit=True)
    backup["audit_integrity"] = {
        "integrity_available": True,
        "state": [{"migration_state": "active", "active_segment_id": "forged-seg"}],
        "segments": [{"segment_id": "forged-seg", "chain_version": "sha256-chain-v1"}],
        "records": [],
    }
    backup_path = _write_backup(tmp_path / "backup.json", backup)

    import shutil

    shutil.copy(tmp_path / "src_salt.bin", tmp_path / "tgt_salt.bin")
    vault = _make_vault(tmp_path, name="target.db", salt="tgt_salt.bin")

    with pytest.raises(ValueError):
        vault.import_backup(json.loads(backup_path.read_text(encoding="utf-8")))

    services = sorted(c.service for c in vault.list_credentials())
    assert services == [], f"forged evidence restore left rows behind: {services}"


# ── 3. Foreign linkage (restore path) ──────────────────────────────────


def test_restore_lease_credential_linkage_validated(tmp_path: Path) -> None:
    """Restored rows whose credential_id points outside the allowed set are rejected.

    A lease whose ``credential_id`` does not reference a credential in the
    same backup or already in the vault must be rejected at import time.
    """
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "«redacted:sk-…»", "api_key", alias="primary")

    forged_lease = {
        "id": "foreign-link-lease",
        "service": "openai",
        "alias": "primary",
        "credential_id": "no-such-credential-id",
        "credential_type": "api_key",
        "agent_id": "attacker-agent",
        "issued_by": "attacker-agent",
        "purpose": "task",
        "status": "active",
        "ttl_seconds": 3600,
        "issued_at": utc_now().isoformat(),
        "expires_at": (utc_now() + timedelta(hours=1)).isoformat(),
    }
    backup = _backup_dict(source, leases=[forged_lease])
    backup_path = _write_backup(tmp_path / "backup.json", backup)

    import shutil

    shutil.copy(tmp_path / "src_salt.bin", tmp_path / "tgt_salt.bin")
    vault = _make_vault(tmp_path, name="target.db", salt="tgt_salt.bin")

    with pytest.raises(ValueError):
        vault.import_backup(json.loads(backup_path.read_text(encoding="utf-8")))

    # Nothing may be committed when a foreign linkage is present.
    assert vault.get_lease("foreign-link-lease") is None
    services = sorted(c.service for c in vault.list_credentials())
    assert services == [], f"foreign-linkage restore left rows behind: {services}"


# ── 4. Broker mismatch on read path ────────────────────────────────────


def test_broker_denies_lease_credential_mismatch(tmp_path: Path) -> None:
    """Broker reads must reject a lease whose identity does not match the credential.

    This is the issue's `restore_active_lease` repro made red: a lease that
    references a different credential identity than the one being served must
    be denied instead of returning the raw secret.
    """
    vault = _make_vault(tmp_path)
    record = vault.add_credential("openai", "«redacted:sk-…»", "api_key", alias="primary")
    # Legit lease issued for the real credential.
    lease = vault.issue_lease(record.id, agent_id="dwight", ttl_seconds=600)

    # Relabel the credential row so its identity no longer matches the lease.
    with sqlite3.connect(vault.db_path) as conn:
        conn.execute("UPDATE credentials SET id = ? WHERE id = ?", ("relabeled-cred-id", record.id))
        conn.commit()

    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "dwight": AgentPolicy(
                    services=["openai"],
                    service_actions={
                        "openai": ServicePolicyEntry(
                            actions=[ServiceAction.get_env],
                            require_lease_for_env=True,
                        )
                    },
                    raw_secret_access=False,
                    ephemeral_env_only=True,
                    max_ttl_seconds=900,
                )
            }
        )
    )
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))

    decision = broker.get_ephemeral_env("openai", "dwight", ttl=300)

    assert decision.allowed is False, (
        f"broker accepted lease {lease.id} for a mismatched credential identity: {decision.reason}"
    )
    assert "lease" in decision.reason.lower() or "mismatch" in decision.reason.lower()


# ── 5. Audit failure atomicity ─────────────────────────────────────────


def test_restore_appends_protected_audit_event(tmp_path: Path) -> None:
    """When the protected restore audit event cannot be written, the whole restore rolls back.

    E1 writes a protected restore audit event through the shared transactional
    seam; if that append fails, no restore changes may commit. The audit chain
    is staled here (the repo's canonical way to make a protected append raise
    ``AuditIntegrityError``) so the restore path must fail closed.
    """
    source = _make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "«redacted:sk-…»", "api_key", alias="primary")
    backup = _backup_dict(source)
    backup_path = _write_backup(tmp_path / "backup.json", backup)

    import shutil

    shutil.copy(tmp_path / "src_salt.bin", tmp_path / "tgt_salt.bin")
    vault = _make_vault(tmp_path, name="target.db", salt="tgt_salt.bin")

    # Seed a healthy protected audit chain, then stale the checkpoint so the
    # next protected append raises AuditIntegrityError (mirrors
    # test_audit_integrity_core.py::test_stale_checkpoint_blocks_append).
    audit = AuditLogger(vault.db_path, master_key=vault.key)
    audit.record(
        AccessLogRecord(
            agent_id="operator",
            service="*",
            action="seed",
            decision=Decision.allow,
            reason="seed protected chain",
        )
    )
    checkpoint_path = vault.db_path.with_name("audit.checkpoint.json")
    original_checkpoint = checkpoint_path.read_bytes()
    audit.record(
        AccessLogRecord(
            agent_id="operator",
            service="*",
            action="seed-2",
            decision=Decision.allow,
            reason="advance chain past checkpoint",
        )
    )
    # Revert the checkpoint: the chain tip is now ahead of the checkpoint, so a
    # protected append fails until an operator advances the checkpoint.
    checkpoint_path.write_bytes(original_checkpoint)

    with pytest.raises(AuditIntegrityError):
        vault.import_backup(json.loads(backup_path.read_text(encoding="utf-8")))

    # No restore changes may commit when the audit event cannot be written.
    services = sorted(c.service for c in vault.list_credentials())
    assert services == [], f"restore committed rows despite audit failure: {services}"
