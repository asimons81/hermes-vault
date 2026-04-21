from __future__ import annotations

from pathlib import Path

import pytest

from hermes_vault.vault import Vault
from hermes_vault.vault import DuplicateCredentialError


def test_vault_encrypts_and_decrypts(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    record = vault.add_credential("openai", "sk-secret-1234567890", "api_key", alias="primary")
    assert record.encrypted_payload != "sk-secret-1234567890"
    secret = vault.get_secret("openai")
    assert secret is not None
    assert secret.secret == "sk-secret-1234567890"


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
