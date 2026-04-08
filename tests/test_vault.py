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
    vault.add_credential("openai", "sk-secret-1234567890", "api_key", alias="primary")

    with pytest.raises(DuplicateCredentialError):
        vault.add_credential("openai", "sk-secret-abcdef", "api_key", alias="primary")
