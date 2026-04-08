from __future__ import annotations

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
