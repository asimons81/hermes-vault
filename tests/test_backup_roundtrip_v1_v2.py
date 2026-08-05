"""Backup round-trip preservation across aesgcm-v1 and aesgcm-v2 (Issue #60).

Integration tests that prove the acceptance criteria for the v2 codec
migration at the backup/restore boundary:

1. An existing aesgcm-v1 backup (committed fixture under tests/testdata)
   restores unchanged: payload bytes, plaintext secrets, and authorization
   metadata all survive a full round trip.
2. A newly created aesgcm-v2 backup round-trips unchanged: same payload
   bytes, same plaintext, same AAD-bound authorization metadata.
3. v1 backups remain openable after v2 is active (per-row dispatch) — a
   vault that writes v2 rows can still restore and read v1 rows.
4. Any format migration preserves backup data: v1 fixture -> v2-format
   re-export -> restore keeps every payload byte and secret intact.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from hermes_vault.backup import restore_dry_run, verify_backup_file
from hermes_vault.crypto import CRYPTO_VERSION, CRYPTO_VERSION_V2
from hermes_vault.vault import Vault

# Fixture constants — keep in sync with generate_v1_fixture.py.
TESTDATA = Path(__file__).resolve().parent / "testdata"
V1_FIXTURE_JSON = TESTDATA / "backup_aesgcm_v1.json"
V1_FIXTURE_SALT = TESTDATA / "backup_aesgcm_v1.salt"
PASSPHRASE = "test-passphrase"

SECRET_OPENAI = "sk-roundtrip-fixture-αβγ-12345"
SECRET_GITHUB = "ghp_roundtrip_fixture_token"


def _load_fixture() -> dict:
    return json.loads(V1_FIXTURE_JSON.read_text(encoding="utf-8"))


def _fixture_ids(backup: dict | None = None) -> dict[str, str]:
    """Resolve credential ids from the fixture itself (the generator
    creates fresh UUIDs per run). Maps service -> id."""
    backup = backup or _load_fixture()
    return {cred["service"]: cred["id"] for cred in backup["credentials"]}


def _copy_salt(tmp_path: Path) -> Path:
    """Copy the fixture salt so restore uses identical key material
    without mutating the committed fixture file."""
    dest = tmp_path / "salt.bin"
    shutil.copyfile(V1_FIXTURE_SALT, dest)
    return dest


def _vault_with_fixture_key(tmp_path: Path, db_name: str = "vault.db") -> Vault:
    salt = _copy_salt(tmp_path)
    return Vault(tmp_path / db_name, salt, PASSPHRASE)


# ── 1. v1 fixture restores unchanged ────────────────────────────────────


def test_v1_fixture_restores_payload_bytes_and_metadata(tmp_path: Path) -> None:
    backup = _load_fixture()
    ids = _fixture_ids(backup)
    openai_id, github_id = ids["openai"], ids["github"]
    vault = _vault_with_fixture_key(tmp_path)

    imported = vault.import_backup(backup)

    assert len(imported) == 2
    by_id = {rec.id: rec for rec in imported}
    assert set(by_id) == {openai_id, github_id}

    # Payload bytes survive byte-for-byte (no re-encryption on import).
    fixture_by_id = {cred["id"]: cred for cred in backup["credentials"]}
    for record_id in (openai_id, github_id):
        assert by_id[record_id].encrypted_payload == fixture_by_id[record_id]["encrypted_payload"]
        assert by_id[record_id].crypto_version == CRYPTO_VERSION

    # Plaintext secrets survive.
    assert vault.get_secret(openai_id) is not None
    assert vault.get_secret(github_id) is not None
    assert vault.get_secret(openai_id).secret == SECRET_OPENAI
    assert vault.get_secret(github_id).secret == SECRET_GITHUB

    # Authorization metadata survives (AAD-bound fields + tags/notes).
    openai = by_id[openai_id]
    assert openai.service == "openai"
    assert openai.alias == "primary"
    assert openai.credential_type == "api_key"
    assert openai.scopes == ["models.read", "models.write"]
    assert openai.tags == ["production"]
    assert openai.notes == "fixture main key"

    github = by_id[github_id]
    assert github.service == "github"
    assert github.alias == "default"
    assert github.credential_type == "personal_access_token"
    assert github.scopes == []
    assert github.tags == []
    assert github.notes is None


def test_v1_fixture_legacy_credential_defaults_to_v1(tmp_path: Path) -> None:
    """The legacy fixture entry has no crypto_version key; import must
    default it to aesgcm-v1 so the payload stays readable."""
    backup = _load_fixture()
    github_id = _fixture_ids(backup)["github"]
    vault = _vault_with_fixture_key(tmp_path)
    imported = vault.import_backup(backup)

    github = next(rec for rec in imported if rec.id == github_id)
    assert github.crypto_version == CRYPTO_VERSION
    assert vault.get_secret(github_id).secret == SECRET_GITHUB


def test_v1_fixture_restore_preserves_lease(tmp_path: Path) -> None:
    backup = _load_fixture()
    openai_id = _fixture_ids(backup)["openai"]
    vault = _vault_with_fixture_key(tmp_path)
    vault.import_backup(backup)

    leases = vault.list_leases()
    assert len(leases) == 1
    lease = leases[0]
    assert lease.agent_id == "fixture-agent"
    assert lease.credential_id == openai_id
    assert lease.metadata == {"ticket": "fixture-42"}
    assert lease.ttl_seconds == 900


def test_v1_fixture_verify_and_dry_run_report_decryptable(tmp_path: Path) -> None:
    vault = _vault_with_fixture_key(tmp_path)

    report = verify_backup_file(V1_FIXTURE_JSON, vault)
    assert report.backup_version == "hvbackup-v1"
    assert report.credential_count == 2
    assert report.decryptable is True
    assert report.decryptable_credential_count == 2
    assert report.would_restore_count == 2
    assert report.findings == []

    dry = restore_dry_run(V1_FIXTURE_JSON, vault)
    assert dry.mode == "restore-dry-run"
    assert dry.decryptable is True
    assert dry.would_restore_count == 2


# ── 2. v2 backup round-trips unchanged ──────────────────────────────────


def test_v2_backup_round_trip_unchanged(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    src = Vault(tmp_path / "src.db", tmp_path / "src.salt", PASSPHRASE)
    rec = src.add_credential(
        "openai",
        "sk-v2-roundtrip-123",
        "api_key",
        alias="primary",
        scopes=["models.read", "models.write"],
        tags=["production"],
        notes="v2 key",
    )
    backup = src.export_backup()
    assert backup["credentials"][0]["crypto_version"] == CRYPTO_VERSION_V2

    # Destination shares the source key material (same salt), as a real
    # restore does — the master key is not part of the backup.
    dst = Vault(tmp_path / "dst.db", tmp_path / "src.salt", PASSPHRASE)
    imported = dst.import_backup(backup)

    assert len(imported) == 1
    row = imported[0]
    assert row.id == rec.id
    # Payload bytes survive byte-for-byte on a fresh destination.
    assert row.encrypted_payload == backup["credentials"][0]["encrypted_payload"]
    assert row.crypto_version == CRYPTO_VERSION_V2

    secret = dst.get_secret(row.id)
    assert secret is not None
    assert secret.secret == "sk-v2-roundtrip-123"
    # Authorization metadata bound into the v2 AAD survives and still
    # authenticates the row.
    assert row.service == "openai"
    assert row.alias == "primary"
    assert row.credential_type == "api_key"
    assert row.scopes == ["models.read", "models.write"]
    assert row.tags == ["production"]
    assert row.notes == "v2 key"


def test_v2_backup_verify_and_dry_run(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    src = Vault(tmp_path / "src.db", tmp_path / "src.salt", PASSPHRASE)
    src.add_credential("openai", "sk-v2-verify-1", "api_key")
    backup_path = tmp_path / "v2-backup.json"
    backup_path.write_text(json.dumps(src.export_backup(), indent=2, sort_keys=True), encoding="utf-8")

    dst = Vault(tmp_path / "dst.db", tmp_path / "src.salt", PASSPHRASE)
    report = verify_backup_file(backup_path, dst)
    assert report.decryptable is True
    assert report.decryptable_credential_count == 1
    assert report.would_restore_count == 1
    assert report.findings == []

    dry = restore_dry_run(backup_path, dst)
    assert dry.decryptable is True
    assert dry.would_restore_count == 1


def test_v2_backup_restore_over_existing_row_rebinds_and_preserves_secret(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Restoring a v2 backup over an existing destination row (different
    id) must rebind the AAD to the destination metadata, not fail."""
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    src = Vault(tmp_path / "src.db", tmp_path / "src.salt", PASSPHRASE)
    src.add_credential("openai", "sk-v2-overwrite-9", "api_key", alias="primary")
    backup = src.export_backup()

    # Destination has an existing row for the same service/alias with a
    # DIFFERENT id. Share source salt so key material matches.
    dst = Vault(tmp_path / "dst.db", tmp_path / "src.salt", PASSPHRASE)
    existing = dst.add_credential("openai", "old-value", "api_key", alias="primary")
    assert existing.id != backup["credentials"][0]["id"]

    imported = dst.import_backup(backup, replace=True)
    assert len(imported) == 1
    row = imported[0]
    assert row.id == existing.id  # destination id kept
    assert row.crypto_version == CRYPTO_VERSION_V2
    assert dst.get_secret(row.id).secret == "sk-v2-overwrite-9"


# ── 3. v1 backups remain openable after v2 is active ────────────────────


def test_v1_fixture_openable_after_v2_active(monkeypatch, tmp_path: Path) -> None:
    """With v2 as the write version, a vault can still restore the v1
    fixture and read both v1 and v2 rows (per-row version dispatch)."""
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    vault = _vault_with_fixture_key(tmp_path)
    ids = _fixture_ids()

    vault.import_backup(_load_fixture())

    # v1 rows still decrypt after v2 is active.
    assert vault.get_secret(ids["openai"]).secret == SECRET_OPENAI
    assert vault.get_secret(ids["github"]).secret == SECRET_GITHUB
    rows = {rec.id: rec for rec in vault.list_credentials()}
    assert rows[ids["openai"]].crypto_version == CRYPTO_VERSION
    assert rows[ids["github"]].crypto_version == CRYPTO_VERSION

    # A new write under the v2 flag is aesgcm-v2 and coexists with v1.
    v2_rec = vault.add_credential("anthropic", "sk-v2-new-77", "api_key", alias="default")
    assert v2_rec.crypto_version == CRYPTO_VERSION_V2
    assert vault.get_secret(v2_rec.id).secret == "sk-v2-new-77"
    # v1 rows still read alongside the new v2 row.
    assert vault.get_secret(ids["openai"]).secret == SECRET_OPENAI
    assert vault.get_secret(ids["github"]).secret == SECRET_GITHUB


def test_v1_fixture_verify_still_decryptable_with_v2_env(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    vault = _vault_with_fixture_key(tmp_path)
    report = verify_backup_file(V1_FIXTURE_JSON, vault)
    assert report.decryptable is True
    assert report.would_restore_count == 2


# ── 4. Format migration preserves backup data ───────────────────────────


def test_format_migration_v1_fixture_to_v2_export_preserves_data(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Restore the v1 fixture, then re-export with the v2 write version
    active. The migrated backup keeps every payload byte and secret."""
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    vault = _vault_with_fixture_key(tmp_path)
    ids = _fixture_ids()
    vault.import_backup(_load_fixture())

    migrated = vault.export_backup(include_audit=True)
    assert migrated["version"] == "hvbackup-v2"
    fixture_creds = {c["id"]: c for c in _load_fixture()["credentials"]}
    for cred in migrated["credentials"]:
        assert cred["encrypted_payload"] == fixture_creds[cred["id"]]["encrypted_payload"]
        assert cred["crypto_version"] == CRYPTO_VERSION

    # The migrated v2-format backup restores into a fresh vault with the
    # same key material, and both v1 rows still decrypt.
    dst = _vault_with_fixture_key(tmp_path, db_name="migrated.db")
    imported = dst.import_backup(migrated)
    assert len(imported) == 2
    assert dst.get_secret(ids["openai"]).secret == SECRET_OPENAI
    assert dst.get_secret(ids["github"]).secret == SECRET_GITHUB
    rows = {rec.id: rec for rec in dst.list_credentials()}
    assert rows[ids["openai"]].crypto_version == CRYPTO_VERSION
    assert rows[ids["github"]].crypto_version == CRYPTO_VERSION


def test_v1_fixture_export_round_trip_preserves_all_credentials(tmp_path: Path) -> None:
    """A pure v1 backup -> restore -> re-export -> restore cycle keeps the
    credential set identical (the no-v2-writes migration baseline)."""
    vault = _vault_with_fixture_key(tmp_path)
    ids = _fixture_ids()
    vault.import_backup(_load_fixture())

    reexported = vault.export_backup()
    assert reexported["version"] == "hvbackup-v1"

    dst = _vault_with_fixture_key(tmp_path, db_name="cycle.db")
    imported = dst.import_backup(reexported)
    assert {rec.id for rec in imported} == {ids["openai"], ids["github"]}
    assert dst.get_secret(ids["openai"]).secret == SECRET_OPENAI
    assert dst.get_secret(ids["github"]).secret == SECRET_GITHUB
