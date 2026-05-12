from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from hermes_vault.vault import Vault
from hermes_vault.vault import DuplicateCredentialError, AmbiguousTargetError
from hermes_vault.models import CredentialStatus


def test_vault_encrypts_and_decrypts(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    record = vault.add_credential("openai", "sk-secret-1234567890", "api_key", alias="primary")
    assert record.encrypted_payload != "sk-secret-1234567890"
    secret = vault.get_secret("openai")
    assert secret is not None
    assert secret.secret == "sk-secret-1234567890"


def test_vault_preserves_secret_metadata_on_add_and_rotate(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    record = vault.add_credential(
        "google",
        "ya29.access",
        "oauth_access_token",
        alias="work",
        metadata={
            "provider": "google",
            "token_type": "Bearer",
            "issued_at": "2026-01-01T00:00:00+00:00",
        },
    )

    secret = vault.get_secret(record.id)
    assert secret is not None
    assert secret.metadata["provider"] == "google"
    assert secret.metadata["token_type"] == "Bearer"

    rotated = vault.rotate(record.id, "ya29.rotated")
    rotated_secret = vault.get_secret(rotated.id)
    assert rotated_secret is not None
    assert rotated_secret.secret == "ya29.rotated"
    assert rotated_secret.metadata["provider"] == "google"
    assert rotated_secret.metadata["token_type"] == "Bearer"
    assert rotated_secret.metadata["issued_at"] == "2026-01-01T00:00:00+00:00"

    replaced = vault.add_credential(
        "google",
        "ya29.replaced",
        "oauth_access_token",
        alias="work",
        replace_existing=True,
    )
    replaced_secret = vault.get_secret(replaced.id)
    assert replaced_secret is not None
    assert replaced_secret.secret == "ya29.replaced"
    assert replaced_secret.metadata["provider"] == "google"


def test_vault_rotate_updates_secret(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("github", "ghp_oldsecret123456789012345", "personal_access_token")
    vault.rotate("github", "ghp_newsecret123456789012345")
    secret = vault.get_secret("github")
    assert secret is not None
    assert secret.secret == "ghp_newsecret123456789012345"


def test_vault_rejects_duplicate_service_alias_by_default(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-sec...7890", "api_key", alias="primary")

    with pytest.raises(DuplicateCredentialError):
        vault.add_credential("openai", "***", "api_key", alias="primary")


def test_vault_normalizes_legacy_service_name_on_add(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    record = vault.add_credential("Open_AI", "sk-sec...7890", "api_key")
    assert record.service == "openai"


def test_vault_normalizes_alias_service_name_on_add(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    record = vault.add_credential("gmail", "ya29.xxxx", "oauth_access_token")
    assert record.service == "google"


def test_vault_get_credential_normalizes_lookup(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-sec...7890", "api_key")
    # Lookup with a legacy alias should still find the canonical record
    record = vault.get_credential("Open_AI")
    assert record is not None
    assert record.service == "openai"


def test_vault_delete_normalizes_service_name(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("github", "ghp_xxx", "personal_access_token")
    assert vault.delete("GH") is True
    assert vault.get_credential("github") is None


def test_vault_import_backup_normalizes_service_names(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    backup = {
        "version": "hvbackup-v1",
        "exported_at": "2026-01-01T00:00:00+00:00",
        "credentials": [
            {
                "id": "test-1",
                "service": "Open_AI",
                "alias": "default",
                "credential_type": "api_key",
                "encrypted_payload": "dummy",
                "status": "unknown",
                "scopes": [],
                "imported_from": None,
                "expiry": None,
                "crypto_version": "aesgcm-v1",
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
                "last_verified_at": None,
            }
        ],
    }
    imported = vault.import_backup(backup)
    assert len(imported) == 1
    assert imported[0].service == "openai"


# ── Issue #2: Deterministic credential targeting ──────────────────────────


def _make_multi_vault(tmp_path: Path) -> tuple[Vault, str, str]:
    """Helper: create a vault with two github credentials (different aliases)."""
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    r1 = vault.add_credential("github", "ghp_token1", "personal_access_token", alias="work")
    r2 = vault.add_credential("github", "ghp_token2", "personal_access_token", alias="personal")
    return vault, r1.id, r2.id


def test_resolve_credential_by_id(tmp_path: Path) -> None:
    vault, id1, id2 = _make_multi_vault(tmp_path)
    record = vault.resolve_credential(id1)
    assert record.id == id1
    assert record.alias == "work"


def test_resolve_credential_by_service_alias(tmp_path: Path) -> None:
    vault, id1, id2 = _make_multi_vault(tmp_path)
    record = vault.resolve_credential("github", alias="personal")
    assert record.id == id2
    assert record.alias == "personal"


def test_resolve_credential_ambiguous_service_raises(tmp_path: Path) -> None:
    vault, _, _ = _make_multi_vault(tmp_path)
    with pytest.raises(AmbiguousTargetError, match="2 credentials"):
        vault.resolve_credential("github")


def test_resolve_credential_single_match_ok(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-test", "api_key")
    record = vault.resolve_credential("openai")
    assert record.service == "openai"


def test_resolve_credential_not_found_raises(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    with pytest.raises(KeyError):
        vault.resolve_credential("nonexistent")


def test_resolve_credential_alias_not_found_raises(tmp_path: Path) -> None:
    vault, _, _ = _make_multi_vault(tmp_path)
    with pytest.raises(KeyError):
        vault.resolve_credential("github", alias="staging")


def test_delete_by_id(tmp_path: Path) -> None:
    vault, id1, id2 = _make_multi_vault(tmp_path)
    assert vault.delete(id1) is True
    assert vault.get_credential(id1) is None
    assert vault.get_credential(id2) is not None


def test_delete_by_service_alias(tmp_path: Path) -> None:
    vault, id1, id2 = _make_multi_vault(tmp_path)
    assert vault.delete("github", alias="work") is True
    assert vault.get_credential(id1) is None
    assert vault.get_credential(id2) is not None


def test_delete_ambiguous_service_raises(tmp_path: Path) -> None:
    vault, _, _ = _make_multi_vault(tmp_path)
    with pytest.raises(AmbiguousTargetError, match="2 credentials"):
        vault.delete("github")


def test_delete_single_service_ok(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-test", "api_key")
    assert vault.delete("openai") is True


def test_update_status_ambiguous_service_raises(tmp_path: Path) -> None:
    vault, _, _ = _make_multi_vault(tmp_path)
    with pytest.raises(AmbiguousTargetError, match="2 credentials"):
        vault.update_status("github", CredentialStatus.active)


def test_update_status_by_id(tmp_path: Path) -> None:
    vault, id1, id2 = _make_multi_vault(tmp_path)
    vault.update_status(id1, CredentialStatus.active)
    rec = vault.get_credential(id1)
    assert rec is not None
    assert rec.status == CredentialStatus.active


def test_update_status_by_service_alias(tmp_path: Path) -> None:
    vault, id1, id2 = _make_multi_vault(tmp_path)
    vault.update_status("github", CredentialStatus.invalid, alias="personal")
    rec = vault.get_credential(id2)
    assert rec is not None
    assert rec.status == CredentialStatus.invalid
    # work alias should be unchanged
    rec2 = vault.get_credential(id1)
    assert rec2 is not None
    assert rec2.status == CredentialStatus.unknown


def test_resolve_credential_prefers_exact_stored_service_before_normalizing(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    record = vault.add_credential("google", "gmail-secret", "app_password", alias="primary")
    with sqlite3.connect(vault.db_path) as conn:
        conn.execute("UPDATE credentials SET service = ? WHERE id = ?", ("gmail", record.id))
        conn.commit()

    resolved = vault.resolve_credential("gmail", alias="primary")

    assert resolved.id == record.id
    assert resolved.service == "gmail"


def test_rotate_ambiguous_service_raises(tmp_path: Path) -> None:
    vault, _, _ = _make_multi_vault(tmp_path)
    with pytest.raises(AmbiguousTargetError):
        vault.rotate("github", "ghp_new_token")


def test_rotate_by_id(tmp_path: Path) -> None:
    vault, id1, id2 = _make_multi_vault(tmp_path)
    record = vault.rotate(id1, "ghp_rotated")
    assert record.id == id1
    secret = vault.get_secret(id1)
    assert secret is not None
    assert secret.secret == "ghp_rotated"


def test_rotate_by_service_alias(tmp_path: Path) -> None:
    vault, id1, id2 = _make_multi_vault(tmp_path)
    record = vault.rotate("github", "ghp_rotated", alias="personal")
    assert record.id == id2
    secret = vault.get_secret(id2)
    assert secret is not None
    assert secret.secret == "ghp_rotated"
