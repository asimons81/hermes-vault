from __future__ import annotations

from pathlib import Path

from hermes_vault.models import CredentialSecret
from hermes_vault.oauth.normalize import normalize_oauth_records
from hermes_vault.oauth.oauth_refresh import refresh_alias_for
from hermes_vault.vault import Vault


def test_oauth_normalize_dry_run_reports_legacy_rewrites(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential(
        "google",
        "access",
        "oauth_access_token",
        alias="work",
        scopes=["openid"],
        metadata={
            "provider": "google",
            "refresh_token": "refresh",
            "raw_response": {"access_token": "access"},
            "scope": "openid",
        },
    )
    vault.add_credential(
        "google",
        "refresh",
        "oauth_refresh_token",
        alias="refresh",
        metadata={"associated_access_token_alias": "work", "provider": "google"},
    )

    report = normalize_oauth_records(vault, dry_run=True)

    assert report.dry_run is True
    assert report.changed_count == 3
    assert {change.action for change in report.changes} == {"sanitize_metadata", "rename_alias"}
    assert vault._find_by_service_alias("google", "refresh") is not None
    assert vault._find_by_service_alias("google", refresh_alias_for("work")) is None


def test_oauth_normalize_write_sanitizes_metadata_and_renames_refresh(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    access = vault.add_credential(
        "google",
        "access",
        "oauth_access_token",
        alias="work",
        scopes=["openid"],
        metadata={
            "provider": "google",
            "refresh_token": "refresh",
            "raw_response": {"access_token": "access"},
            "scope": "openid",
        },
    )
    vault.add_credential(
        "google",
        "refresh",
        "oauth_refresh_token",
        alias="refresh",
        metadata={"associated_access_token_alias": "work", "provider": "google"},
    )

    report = normalize_oauth_records(vault, dry_run=False)

    assert report.changed_count == 3
    access_secret = vault.get_secret(access.id)
    assert isinstance(access_secret, CredentialSecret)
    assert access_secret.secret == "access"
    assert "refresh_token" not in access_secret.metadata
    assert "raw_response" not in access_secret.metadata
    assert access_secret.metadata["provider"] == "google"
    assert access_secret.metadata["scopes"] == ["openid"]
    assert vault._find_by_service_alias("google", "refresh") is None
    assert vault._find_by_service_alias("google", refresh_alias_for("work")) is not None

    second = normalize_oauth_records(vault, dry_run=False)
    assert second.changed_count == 0


def test_oauth_normalize_skips_ambiguous_legacy_refresh(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("google", "work", "oauth_access_token", alias="work")
    vault.add_credential("google", "personal", "oauth_access_token", alias="personal")
    vault.add_credential("google", "refresh", "oauth_refresh_token", alias="refresh")

    report = normalize_oauth_records(vault, dry_run=False)

    assert any(skip.action == "skip" and "ambiguous" in skip.detail for skip in report.skips)
    assert vault._find_by_service_alias("google", "refresh") is not None
