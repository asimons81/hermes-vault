from __future__ import annotations

import json
from pathlib import Path


from hermes_vault.backup import restore_dry_run, verify_backup_file
from hermes_vault.vault import Vault


def _write_backup(path: Path, backup: dict) -> Path:
    path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _make_vault(tmp_path: Path, passphrase: str = "test-passphrase") -> Vault:
    return Vault(tmp_path / "vault.db", tmp_path / "salt.bin", passphrase)


def test_verify_backup_file_reports_valid_backup(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    vault.add_credential("openai", "sk-secret-1234567890", "api_key", alias="primary")
    backup_path = _write_backup(tmp_path / "backup.json", vault.export_backup())

    report = verify_backup_file(backup_path, vault)

    assert report.version == "backup-verification-v2"
    assert report.mode == "verify"
    assert report.backup_version == "hvbackup-v1"
    assert report.credential_count == 1
    assert report.decryptable_credential_count == 1
    assert report.audit_included is False
    assert report.decryptable is True
    assert report.findings == []
    assert report.would_restore_count == 1


def test_verify_backup_file_rejects_corrupted_json(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    backup_path = tmp_path / "broken.json"
    backup_path.write_text("{not-json", encoding="utf-8")

    report = verify_backup_file(backup_path, vault)

    assert report.backup_version is None
    assert report.decryptable is False
    assert report.findings
    assert "Corrupted backup JSON" in report.findings[0]


def test_verify_backup_file_rejects_wrong_version(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    vault.add_credential("github", "ghp_secret1234567890", "personal_access_token")
    backup = vault.export_backup()
    backup["version"] = "hvbackup-v0"
    backup_path = _write_backup(tmp_path / "backup.json", backup)

    report = verify_backup_file(backup_path, vault)

    assert report.backup_version == "hvbackup-v0"
    assert report.decryptable is False
    assert report.findings == ["Unsupported backup version: hvbackup-v0"]


def test_verify_backup_file_rejects_metadata_only_backup(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    vault.add_credential("google", "ya29.secret1234567890", "oauth_access_token")
    backup_path = _write_backup(tmp_path / "meta.json", vault.export_backup(metadata_only=True))

    report = verify_backup_file(backup_path, vault)

    assert report.backup_version == "hvbackup-v1"
    assert report.credential_count == 1
    assert report.decryptable is False
    assert report.findings
    assert "metadata-only backup" in report.findings[0]


def test_verify_backup_file_rejects_wrong_passphrase(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    vault.add_credential("openai", "sk-secret-1234567890", "api_key")
    backup_path = _write_backup(tmp_path / "backup.json", vault.export_backup())

    wrong_vault = _make_vault(tmp_path, passphrase="wrong-passphrase")
    report = verify_backup_file(backup_path, wrong_vault)

    assert report.backup_version == "hvbackup-v1"
    assert report.decryptable is False
    assert report.decryptable_credential_count == 0
    assert report.would_restore_count == 0
    assert report.findings
    assert "could not be decrypted" in report.findings[0]


def test_restore_dry_run_does_not_mutate_live_vault(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    record = vault.add_credential("github", "ghp_secret1234567890", "personal_access_token")
    backup_path = _write_backup(tmp_path / "backup.json", vault.export_backup())

    before = vault.get_secret(record.id)
    report = restore_dry_run(backup_path, vault)
    after = vault.get_secret(record.id)

    assert report.mode == "restore-dry-run"
    assert report.decryptable is True
    assert report.would_restore_count == 1
    assert before is not None
    assert after is not None
    assert before.secret == after.secret
    assert vault.list_credentials()[0].encrypted_payload == record.encrypted_payload


def test_backup_import_round_trip_preserves_lease_data(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    record = vault.add_credential("openai", "sk-secret-1234567890", "api_key", alias="primary", scopes=["models.read"])
    lease = vault.issue_lease(record.id, agent_id="backup-agent", ttl_seconds=600, metadata={"ticket": "42"})
    backup_path = _write_backup(tmp_path / "backup.json", vault.export_backup())

    restore_vault = Vault(tmp_path / "restored.db", tmp_path / "restored-salt.bin", "test-passphrase")
    restore_vault.import_backup(json.loads(backup_path.read_text(encoding="utf-8")))
    restored = restore_vault.get_lease(lease.id)

    assert restored is not None
    assert restored.service == "openai"
    assert restored.agent_id == "backup-agent"
    assert restored.metadata == {"ticket": "42"}


def test_metadata_only_backup_retains_lease_metadata(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    record = vault.add_credential("openai", "sk-fake1234567890", "api_key", alias="primary", scopes=["models.read"])
    lease = vault.issue_lease(record.id, agent_id="backup-agent", ttl_seconds=600, metadata={"ticket": "meta-only"})
    backup = vault.export_backup(metadata_only=True)

    assert "leases" in backup
    assert backup["leases"][0]["id"] == lease.id
    assert backup["leases"][0]["metadata"] == {"ticket": "meta-only"}


# ── v2 backup and restore (Issue #31) ─────────────────────────────────────────


def test_v2_backup_includes_integrity_evidence(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    vault.add_credential("openai", "sk-fake1234567890", "api_key")
    report = vault.export_backup(include_audit=True)
    assert report["version"] == "hvbackup-v2"
    assert "audit_integrity" in report
    integrity = report["audit_integrity"]
    assert integrity["integrity_available"] is True
    assert "state" in integrity
    assert "segments" in integrity


def test_v2_backup_verify_healthy(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    vault.add_credential("openai", "sk-fake1234567890", "api_key")
    vault.add_credential("github", "ghp-fake1234567890", "personal_access_token")
    backup_path = _write_backup(tmp_path / "v2-backup.json", vault.export_backup(include_audit=True))

    report = verify_backup_file(backup_path, vault)

    assert report.backup_version == "hvbackup-v2"
    assert report.decryptable is True
    assert report.credential_count == 2
    assert report.decryptable_credential_count == 2
    assert report.would_restore_count == 2


def test_v2_backup_verify_wrong_key(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    vault.add_credential("openai", "sk-fake1234567890", "api_key")
    backup_path = _write_backup(tmp_path / "v2-backup.json", vault.export_backup(include_audit=True))

    wrong_vault = _make_vault(tmp_path, passphrase="wrong-passphrase")
    report = verify_backup_file(backup_path, wrong_vault)

    assert report.decryptable is False
    assert report.findings
    assert "could not be decrypted" in report.findings[0]


def test_v2_backup_restore_dry_run(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    vault.add_credential("openai", "sk-fake1234567890", "api_key")
    backup_path = _write_backup(tmp_path / "v2-backup.json", vault.export_backup(include_audit=True))

    report = restore_dry_run(backup_path, vault)

    assert report.mode == "restore-dry-run"
    assert report.backup_version == "hvbackup-v2"
    assert report.decryptable is True


def test_v2_backup_metadata_only_is_not_restorable(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    vault.add_credential("openai", "sk-fake1234567890", "api_key")
    backup = vault.export_backup(metadata_only=True, include_audit=True)
    assert backup["version"] == "hvbackup-v2"
    backup_path = _write_backup(tmp_path / "v2-meta.json", backup)

    report = verify_backup_file(backup_path, vault)

    assert report.decryptable is False
    assert any("metadata-only backup" in f for f in report.findings)


def test_v1_backup_still_works_after_v2_changes(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    vault.add_credential("openai", "sk-fake1234567890", "api_key")
    backup_path = _write_backup(tmp_path / "v1-backup.json", vault.export_backup(include_audit=False))

    report = verify_backup_file(backup_path, vault)

    assert report.backup_version == "hvbackup-v1"
    assert report.decryptable is True
    assert report.credential_count == 1


def test_import_backup_accepts_v2(tmp_path: Path) -> None:
    vault = _make_vault(tmp_path)
    vault.add_credential("openai", "sk-fake1234567890", "api_key")
    backup = vault.export_backup(include_audit=True)

    restore_vault = Vault(tmp_path / "restored.db", tmp_path / "restored-salt.bin", "test-passphrase")
    imported = restore_vault.import_backup(backup)
    assert len(imported) == 1
    assert imported[0].service == "openai"
