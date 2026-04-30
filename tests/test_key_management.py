from __future__ import annotations

import os
from pathlib import Path

import pytest

from hermes_vault.config import AppSettings
from hermes_vault.crypto import CorruptKeyMaterialError, MissingKeyMaterialError
from hermes_vault.vault import Vault


def test_missing_salt_after_restore_raises(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "test-passphrase")
    vault.add_credential("openai", "sk-secret-1234567890", "api_key")
    salt.unlink()

    with pytest.raises(MissingKeyMaterialError):
        Vault(db, salt, "test-passphrase")


def test_corrupt_salt_raises(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    Vault(db, salt, "test-passphrase")
    salt.write_bytes(b"short")

    with pytest.raises(CorruptKeyMaterialError):
        Vault(db, salt, "test-passphrase")


def test_ensure_runtime_layout_ignores_chmod_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "runtime"
    settings = AppSettings(runtime_home=runtime)

    def raise_oserror(*args: object, **kwargs: object) -> None:
        raise OSError("read-only file system")

    monkeypatch.setattr("hermes_vault.config.os.chmod", raise_oserror)

    settings.ensure_runtime_layout()

    assert runtime.exists()
    assert settings.generated_skills_dir.exists()


# ── Master-key rotation tests ──────────────────────────────────────


def test_rotate_master_key_preserves_secrets(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "old-pass")
    vault.add_credential("openai", "sk-test-1234", "api_key", alias="primary")

    result = vault.rotate_master_key("old-pass", "new-pass")
    assert result["re_encrypted"] == 1
    assert result["failed"] == 0

    vault2 = Vault(db, salt, "new-pass")
    secret = vault2.get_secret("openai")
    assert secret is not None
    assert secret.secret == "sk-test-1234"


def test_rotate_master_key_wrong_old_passphrase(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "old-pass")
    vault.add_credential("openai", "sk-test", "api_key")

    with pytest.raises(ValueError, match="Old passphrase"):
        vault.rotate_master_key("wrong-pass", "new-pass")


def test_rotate_master_key_empty_vault(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "old-pass")

    result = vault.rotate_master_key("old-pass", "new-pass")
    assert result["re_encrypted"] == 0


def test_rotate_master_key_with_backup(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    os.environ["HERMES_VAULT_PASSPHRASE"] = "old-pass"
    vault = Vault(db, salt, "old-pass")
    vault.add_credential("openai", "sk-test-1", "api_key", alias="primary")
    vault.add_credential("github", "ghp-test-2", "personal_access_token", alias="work")

    backup_path = tmp_path / "pre-rotate.json"
    result = vault.rotate_master_key(
        "old-pass", "new-pass", backup_path=backup_path
    )
    assert result["re_encrypted"] == 2
    assert backup_path.exists()


def test_rotate_master_key_no_secrets_in_audit(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    os.environ["HERMES_VAULT_PASSPHRASE"] = "old-pass"
    vault = Vault(db, salt, "old-pass")
    vault.add_credential("openai", "sk-test", "api_key")
    vault.rotate_master_key("old-pass", "new-pass")

    from hermes_vault.audit import AuditLogger
    audit = AuditLogger(db)
    entries = audit.list_recent(limit=10, action="rotate_master_key")
    for entry in entries:
        assert "sk-test" not in str(entry)
