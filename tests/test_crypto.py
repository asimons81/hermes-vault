from __future__ import annotations

import pytest

from hermes_vault.crypto import MissingPassphraseError, profile_passphrase_env_name, resolve_passphrase, resolve_passphrase_with_source


def test_profile_passphrase_env_name_normalizes_profile_name() -> None:
    assert profile_passphrase_env_name("work-prod") == "HERMES_VAULT_PASSPHRASE_WORK_PROD"


def test_profile_specific_passphrase_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE_WORK", "work-secret")
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "fallback-secret")

    result = resolve_passphrase_with_source(profile_name="work")

    assert result.passphrase == "work-secret"
    assert result.source == "env:HERMES_VAULT_PASSPHRASE_WORK"


def test_profile_specific_passphrase_normalizes_dashed_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE_WORK_PROD", "prod-secret")

    assert resolve_passphrase(profile_name="work-prod") == "prod-secret"


def test_generic_passphrase_is_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HERMES_VAULT_PASSPHRASE_WORK", raising=False)
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "fallback-secret")

    result = resolve_passphrase_with_source(profile_name="work")

    assert result.passphrase == "fallback-secret"
    assert result.source == "env:HERMES_VAULT_PASSPHRASE"


def test_explicit_passphrase_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE_WORK", "work-secret")

    result = resolve_passphrase_with_source(explicit_passphrase="explicit", profile_name="work")

    assert result.passphrase == "explicit"
    assert result.source == "explicit"


def test_missing_noninteractive_passphrase_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HERMES_VAULT_PASSPHRASE_WORK", raising=False)
    monkeypatch.delenv("HERMES_VAULT_PASSPHRASE", raising=False)

    with pytest.raises(MissingPassphraseError):
        resolve_passphrase(prompt=False, profile_name="work")
