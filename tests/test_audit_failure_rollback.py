"""Regression tests for #56 Slice A — preserve credentials on audit failure.

The pre-fix behavior in ``VaultMutations._record_mutation`` rolled back any
state-changing mutation whose protected audit append failed by deleting the
credential row. That is only correct for a brand-new add. Rotate, replace
(replace_existing), and delete destroyed the prior credential even though the
caller-visible message claimed the credential was preserved.

The fix adds ``Vault.restore_credential(record)`` (idempotent upsert by id)
and uses the captured before-image of the row to restore the original
ciphertext when the integrity chain refuses to seal the audit row. Delete is
kept only for genuine new-record adds.

Each test is red-capable: it fails on the pre-fix code (the credential row is
deleted or the audit error propagates) and passes once the before-image
restore path exists.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from hermes_vault.audit import AuditLogger
from hermes_vault.audit_integrity.service import AuditIntegrityError
from hermes_vault.mutations import VaultMutations
from hermes_vault.policy import PolicyEngine
from hermes_vault.vault import Vault


def make_vault_and_logger(tmp_path: Path) -> tuple[Vault, AuditLogger]:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    logger = AuditLogger(vault.db_path, master_key=vault.key)
    return vault, logger


def make_mutations(tmp_path: Path) -> tuple[Vault, AuditLogger, VaultMutations]:
    vault, logger = make_vault_and_logger(tmp_path)
    mutations = VaultMutations(vault=vault, policy=PolicyEngine(), audit=logger)
    return vault, logger, mutations


def _corrupt_checkpoint(logger: AuditLogger) -> None:
    """Break the authenticated checkpoint so verify() returns failed.

    Mirrors the injection used by test_audit_integrity_toctou.py: a checkpoint
    with an invalid signature makes ``append()`` raise AuditIntegrityError.
    """
    checkpoint_path = logger.db_path.with_name("audit.checkpoint.json")
    checkpoint_path.write_bytes(
        b'{"format": "hermes-vault-audit-checkpoint", "version": "audit-checkpoint-v1", "signature": "bogus"}'
    )


def _add_original(vault: Vault, logger: AuditLogger, mutations: VaultMutations) -> str:
    result = mutations.add_credential(
        agent_id="operator",
        service="test-service",
        secret="original-secret",
        credential_type="api_key",
        alias="rollback-test",
    )
    assert result.allowed is True
    assert result.record is not None
    return result.record.id


def test_rotate_audit_failure_preserves_prior_credential(tmp_path: Path) -> None:
    """Rotate with a broken integrity chain must deny and keep the ORIGINAL
    ciphertext. Pre-fix the rollback deleted the only row (data loss)."""
    vault, logger, mutations = make_mutations(tmp_path)
    record_id = _add_original(vault, logger, mutations)
    _corrupt_checkpoint(logger)

    result = mutations.rotate_credential(
        agent_id="operator",
        service_or_id="test-service",
        new_secret="rotated-secret",
        alias="rollback-test",
    )

    assert result.allowed is False, "rotate must be denied when integrity chain is broken"
    assert "integrity" in result.reason.lower() or "audit" in result.reason.lower(), (
        f"reason should mention audit/integrity; got: {result.reason!r}"
    )

    # The credential row must survive and still decrypt to the ORIGINAL secret.
    surviving = vault.resolve_credential(record_id)
    assert surviving is not None, "rotated credential row was destroyed by audit-failure rollback"
    secret = vault.get_secret(record_id)
    assert secret is not None and secret.secret == "original-secret", (
        "rotated credential must keep its original secret after audit failure"
    )


def test_replace_audit_failure_preserves_prior_credential(tmp_path: Path) -> None:
    """add_credential(replace_existing=True) with a broken chain must deny and
    keep the ORIGINAL ciphertext. Pre-fix the rollback deleted the row."""
    vault, logger, mutations = make_mutations(tmp_path)
    record_id = _add_original(vault, logger, mutations)
    _corrupt_checkpoint(logger)

    result = mutations.add_credential(
        agent_id="operator",
        service="test-service",
        secret="replacement-secret",
        credential_type="api_key",
        alias="rollback-test",
        replace_existing=True,
    )

    assert result.allowed is False, "replace must be denied when integrity chain is broken"
    assert "integrity" in result.reason.lower() or "audit" in result.reason.lower(), (
        f"reason should mention audit/integrity; got: {result.reason!r}"
    )

    surviving = vault.resolve_credential(record_id)
    assert surviving is not None, "replaced credential row was destroyed by audit-failure rollback"
    secret = vault.get_secret(record_id)
    assert secret is not None and secret.secret == "original-secret", (
        "replaced credential must keep its original secret after audit failure"
    )


def test_delete_audit_failure_preserves_credential(tmp_path: Path) -> None:
    """delete_credential with a broken chain must deny and restore the row.
    Pre-fix the audit error propagated out of delete_credential and the row
    stayed deleted with no audit record."""
    vault, logger, mutations = make_mutations(tmp_path)
    record_id = _add_original(vault, logger, mutations)
    _corrupt_checkpoint(logger)

    result = mutations.delete_credential(
        agent_id="operator",
        service_or_id="test-service",
        alias="rollback-test",
    )

    assert result.allowed is False, "delete must be denied when integrity chain is broken"
    assert "integrity" in result.reason.lower() or "audit" in result.reason.lower(), (
        f"reason should mention audit/integrity; got: {result.reason!r}"
    )

    surviving = vault.resolve_credential(record_id)
    assert surviving is not None, "deleted credential was not restored after audit failure"
    secret = vault.get_secret(record_id)
    assert secret is not None and secret.secret == "original-secret", (
        "deleted credential must be restored with its original secret"
    )


def test_rotate_audit_failure_deterministic_append_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Same guarantee driven by a deterministic append failure instead of the
    checkpoint-corruption trick: monkeypatch AuditIntegrityService.append to
    raise AuditIntegrityError and verify the original secret survives."""
    vault, logger, mutations = make_mutations(tmp_path)
    record_id = _add_original(vault, logger, mutations)

    def _boom(record: object) -> None:
        raise AuditIntegrityError("deterministic append failure")

    assert logger.integrity is not None
    monkeypatch.setattr(logger.integrity, "append", _boom)

    result = mutations.rotate_credential(
        agent_id="operator",
        service_or_id="test-service",
        new_secret="rotated-secret",
        alias="rollback-test",
    )

    assert result.allowed is False, "rotate must be denied when append raises"
    assert "integrity" in result.reason.lower() or "audit" in result.reason.lower()

    surviving = vault.resolve_credential(record_id)
    assert surviving is not None, "rotated credential row was destroyed by audit-failure rollback"
    secret = vault.get_secret(record_id)
    assert secret is not None and secret.secret == "original-secret", (
        "rotated credential must keep its original secret after audit failure"
    )


def test_restore_credential_idempotent(tmp_path: Path) -> None:
    """restore_credential is an idempotent upsert by id: applying the same
    before-image twice must not duplicate or corrupt the row."""
    vault, _logger = make_vault_and_logger(tmp_path)
    record = vault.add_credential(
        service="openai",
        secret="sk-idempotent",
        credential_type="api_key",
        alias="primary",
        tags=["a", "b"],
        notes="keep me",
    )

    assert vault.delete(record.id) is True
    assert vault.get_credential(record.id) is None

    vault.restore_credential(record)
    vault.restore_credential(record)  # second application must be a no-op

    restored = vault.get_credential(record.id)
    assert restored is not None
    secret = vault.get_secret(record.id)
    assert secret is not None and secret.secret == "sk-idempotent"
    assert restored.tags == ["a", "b"]
    assert restored.notes == "keep me"
    assert restored.crypto_version == record.crypto_version
