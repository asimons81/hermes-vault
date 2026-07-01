from __future__ import annotations

import os
import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest

from hermes_vault.crypto import SALT_SIZE
from hermes_vault.models import CredentialStatus, LeaseStatus, utc_now
from hermes_vault.vault import Vault
from hermes_vault.vault import DuplicateCredentialError, AmbiguousTargetError


def test_vault_encrypts_and_decrypts(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    record = vault.add_credential("openai", "sk-secret-1234567890", "api_key", alias="primary")
    assert record.encrypted_payload != "sk-secret-1234567890"
    secret = vault.get_secret("openai")
    assert secret is not None
    assert secret.secret == "sk-secret-1234567890"


def test_vault_persists_tags_and_notes(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    record = vault.add_credential(
        "openai",
        "sk-sec...7890",
        "api_key",
        alias="primary",
        tags=["ai", " prod ", "ai", ""],
        notes="  plaintext operator note  ",
    )

    assert record.tags == ["ai", "prod"]
    assert record.notes == "plaintext operator note"

    fetched = vault.resolve_credential("openai", alias="primary")
    assert fetched.tags == ["ai", "prod"]
    assert fetched.notes == "plaintext operator note"

    secret = vault.get_secret(record.id)
    assert secret is not None
    assert secret.tags == ["ai", "prod"]
    assert secret.notes == "plaintext operator note"


def test_vault_replace_preserves_tags_and_notes_by_default(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    original = vault.add_credential(
        "openai",
        "sk-old",
        "api_key",
        alias="primary",
        tags=["prod"],
        notes="keep me",
    )

    replaced = vault.add_credential(
        "openai",
        "sk-new",
        "api_key",
        alias="primary",
        replace_existing=True,
    )

    assert replaced.id == original.id
    assert replaced.tags == ["prod"]
    assert replaced.notes == "keep me"
    secret = vault.get_secret(replaced.id)
    assert secret is not None
    assert secret.tags == ["prod"]
    assert secret.notes == "keep me"


def test_vault_initializes_old_schema_with_tags_notes_defaults(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    salt_path = tmp_path / "salt.bin"
    salt_path.write_bytes(os.urandom(SALT_SIZE))
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE credentials (
                id TEXT PRIMARY KEY,
                service TEXT NOT NULL,
                alias TEXT NOT NULL,
                credential_type TEXT NOT NULL,
                encrypted_payload TEXT NOT NULL,
                status TEXT NOT NULL,
                scopes TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_verified_at TEXT,
                imported_from TEXT,
                expiry TEXT,
                crypto_version TEXT NOT NULL
            )
            """
        )
        conn.commit()

    vault = Vault(db_path, salt_path, "test-passphrase")
    with sqlite3.connect(db_path) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(credentials)").fetchall()}

    assert "tags" in columns
    assert "notes" in columns
    record = vault.add_credential("openai", "sk-test", "api_key")
    assert record.tags == []
    assert record.notes is None


def test_vault_backup_preserves_tags_and_notes(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    record = vault.add_credential(
        "openai",
        "sk-test",
        "api_key",
        tags=["prod"],
        notes="backup note",
    )

    backup = vault.export_backup()
    assert backup["credentials"][0]["tags"] == ["prod"]
    assert backup["credentials"][0]["notes"] == "backup note"

    imported = vault.import_backup(backup)
    restored = next(item for item in imported if item.id == record.id)
    assert restored.tags == ["prod"]
    assert restored.notes == "backup note"


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


def _make_lease_vault(tmp_path: Path) -> tuple[Vault, object]:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    record = vault.add_credential(
        "openai",
        "sk-lease-secret",
        "api_key",
        alias="primary",
        scopes=["models.read", "files.write"],
    )
    return vault, record


class TestLeases:
    def test_issue_lease_happy_path(self, tmp_path: Path) -> None:
        vault, record = _make_lease_vault(tmp_path)

        lease = vault.issue_lease(
            "openai",
            agent_id="lease-agent",
            ttl_seconds=600,
            alias="primary",
            purpose="deploy",
            reason="ticket-123",
            metadata={"ticket": "123"},
        )

        assert lease.service == record.service
        assert lease.alias == record.alias
        assert lease.credential_id == record.id
        assert lease.status == LeaseStatus.active
        assert lease.ttl_seconds == 600
        assert lease.scopes == ["models.read", "files.write"]
        assert lease.metadata == {"ticket": "123"}

    def test_issue_lease_by_credential_id(self, tmp_path: Path) -> None:
        vault, record = _make_lease_vault(tmp_path)

        lease = vault.issue_lease(record.id, agent_id="lease-agent", ttl_seconds=60)

        assert lease.credential_id == record.id
        assert lease.service == "openai"

    def test_issue_lease_for_missing_credential_raises(self, tmp_path: Path) -> None:
        vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")

        with pytest.raises(KeyError):
            vault.issue_lease("missing-service", agent_id="lease-agent", ttl_seconds=60)

    def test_list_leases_supports_filters(self, tmp_path: Path) -> None:
        vault, record = _make_lease_vault(tmp_path)
        github = vault.add_credential("github", "ghp-test", "personal_access_token", alias="work")
        first = vault.issue_lease(record.id, agent_id="lease-agent", ttl_seconds=600)
        second = vault.issue_lease(github.id, agent_id="lease-agent", ttl_seconds=600, purpose="ci")
        revoked = vault.issue_lease(record.id, agent_id="lease-agent", ttl_seconds=600, purpose="cleanup")
        vault.revoke_lease(revoked.id, reason="done")

        all_leases = vault.list_leases()
        service_leases = vault.list_leases(service="openai")
        revoked_leases = vault.list_leases(status=LeaseStatus.revoked)
        combined = vault.list_leases(service="openai", status=LeaseStatus.revoked)

        assert {lease.id for lease in all_leases} == {first.id, second.id, revoked.id}
        assert {lease.id for lease in service_leases} == {first.id, revoked.id}
        assert [lease.id for lease in revoked_leases] == [revoked.id]
        assert [lease.id for lease in combined] == [revoked.id]

    def test_list_leases_refreshes_expired_status(self, tmp_path: Path) -> None:
        vault, record = _make_lease_vault(tmp_path)
        lease = vault.issue_lease(record.id, agent_id="lease-agent", ttl_seconds=60)
        past = (utc_now() - timedelta(seconds=30)).isoformat()

        with sqlite3.connect(vault.db_path) as conn:
            conn.execute("UPDATE leases SET expires_at = ?, status = ? WHERE id = ?", (past, LeaseStatus.active.value, lease.id))
            conn.commit()

        listed = vault.list_leases(status=LeaseStatus.expired)

        assert [item.id for item in listed] == [lease.id]
        assert vault.get_lease(lease.id).status == LeaseStatus.expired

    def test_get_lease_found_and_not_found(self, tmp_path: Path) -> None:
        vault, record = _make_lease_vault(tmp_path)
        lease = vault.issue_lease(record.id, agent_id="lease-agent", ttl_seconds=60)

        assert vault.get_lease(lease.id).id == lease.id
        assert vault.get_lease("missing-lease") is None

    def test_renew_lease_happy_path(self, tmp_path: Path) -> None:
        vault, record = _make_lease_vault(tmp_path)
        lease = vault.issue_lease(record.id, agent_id="lease-agent", ttl_seconds=60)

        renewed = vault.renew_lease(lease.id, ttl_seconds=600)

        assert renewed.id == lease.id
        assert renewed.ttl_seconds == 600
        assert renewed.renew_count == 1
        assert renewed.renewed_at is not None
        assert renewed.expires_at > lease.expires_at

    def test_renew_lease_on_revoked_raises(self, tmp_path: Path) -> None:
        vault, record = _make_lease_vault(tmp_path)
        lease = vault.issue_lease(record.id, agent_id="lease-agent", ttl_seconds=60)
        vault.revoke_lease(lease.id, reason="done")

        with pytest.raises(ValueError, match="revoked"):
            vault.renew_lease(lease.id, ttl_seconds=60)

    def test_renew_lease_on_expired_resets_from_now(self, tmp_path: Path) -> None:
        vault, record = _make_lease_vault(tmp_path)
        lease = vault.issue_lease(record.id, agent_id="lease-agent", ttl_seconds=60)
        past = (utc_now() - timedelta(seconds=10)).isoformat()

        with sqlite3.connect(vault.db_path) as conn:
            conn.execute("UPDATE leases SET expires_at = ?, status = ? WHERE id = ?", (past, LeaseStatus.active.value, lease.id))
            conn.commit()

        renewed = vault.renew_lease(lease.id, ttl_seconds=120)

        assert renewed.status == LeaseStatus.active
        assert renewed.renew_count == 1
        assert renewed.expires_at > utc_now()

    def test_renew_lease_with_shorter_ttl(self, tmp_path: Path) -> None:
        vault, record = _make_lease_vault(tmp_path)
        lease = vault.issue_lease(record.id, agent_id="lease-agent", ttl_seconds=600)

        renewed = vault.renew_lease(lease.id, ttl_seconds=60)

        assert renewed.ttl_seconds == 60
        assert renewed.expires_at < lease.expires_at + timedelta(seconds=61)

    def test_revoke_lease_happy_path(self, tmp_path: Path) -> None:
        vault, record = _make_lease_vault(tmp_path)
        lease = vault.issue_lease(record.id, agent_id="lease-agent", ttl_seconds=60)

        revoked = vault.revoke_lease(lease.id, reason="done")

        assert revoked.status == LeaseStatus.revoked
        assert revoked.revoked_at is not None
        assert revoked.reason == "done"

    def test_revoke_lease_on_already_revoked_raises(self, tmp_path: Path) -> None:
        vault, record = _make_lease_vault(tmp_path)
        lease = vault.issue_lease(record.id, agent_id="lease-agent", ttl_seconds=60)
        vault.revoke_lease(lease.id, reason="done")

        with pytest.raises(ValueError, match="already been revoked"):
            vault.revoke_lease(lease.id)

    def test_revoke_lease_on_expired_lease(self, tmp_path: Path) -> None:
        vault, record = _make_lease_vault(tmp_path)
        lease = vault.issue_lease(record.id, agent_id="lease-agent", ttl_seconds=60)
        past = (utc_now() - timedelta(seconds=10)).isoformat()

        with sqlite3.connect(vault.db_path) as conn:
            conn.execute("UPDATE leases SET expires_at = ?, status = ? WHERE id = ?", (past, LeaseStatus.active.value, lease.id))
            conn.commit()

        revoked = vault.revoke_lease(lease.id, reason="cleanup")

        assert revoked.status == LeaseStatus.revoked
        assert revoked.reason == "cleanup"

    def test_lease_backup_round_trip_preserves_fields(self, tmp_path: Path) -> None:
        vault, record = _make_lease_vault(tmp_path)
        lease = vault.issue_lease(
            record.id,
            agent_id="lease-agent",
            ttl_seconds=300,
            purpose="report",
            reason="ticket-9",
            metadata={"ticket": "9", "owner": "ops"},
        )
        renewed = vault.renew_lease(lease.id, ttl_seconds=500)
        revoked = vault.revoke_lease(lease.id, reason="expired-task")

        backup = vault.export_backup()
        clone = Vault(tmp_path / "clone.db", tmp_path / "clone-salt.bin", "test-passphrase")
        imported = clone.import_backup(backup)
        restored = clone.get_lease(revoked.id)

        assert imported
        assert restored is not None
        assert restored.model_dump(mode="json") == revoked.model_dump(mode="json")
        assert restored.renew_count == renewed.renew_count

    def test_lease_scopes_and_metadata_round_trip(self, tmp_path: Path) -> None:
        vault, record = _make_lease_vault(tmp_path)
        lease = vault.issue_lease(
            record.id,
            agent_id="lease-agent",
            ttl_seconds=300,
            metadata={"nested": {"ticket": 7}, "list": ["a", "b"]},
        )

        backup = vault.export_backup()
        restored = backup["leases"][0]

        assert restored["scopes"] == ["models.read", "files.write"]
        assert restored["metadata"] == {"nested": {"ticket": 7}, "list": ["a", "b"]}
        mirror = Vault(tmp_path / "mirror.db", tmp_path / "mirror-salt.bin", "test-passphrase")
        mirror.import_backup(backup)
        assert mirror.get_lease(lease.id).metadata == lease.metadata

    def test_concurrent_leases_on_same_credential(self, tmp_path: Path) -> None:
        vault, record = _make_lease_vault(tmp_path)

        first = vault.issue_lease(record.id, agent_id="agent-a", ttl_seconds=60)
        second = vault.issue_lease(record.id, agent_id="agent-b", ttl_seconds=120)

        leases = vault.list_leases(service="openai")
        assert {lease.id for lease in leases} == {first.id, second.id}
        assert {lease.agent_id for lease in leases} == {"agent-a", "agent-b"}

    def test_auto_expiry_zero_second_ttl(self, tmp_path: Path) -> None:
        vault, record = _make_lease_vault(tmp_path)

        lease = vault.issue_lease(record.id, agent_id="lease-agent", ttl_seconds=0)
        expired = vault.list_leases(status=LeaseStatus.expired)

        assert lease.id in {item.id for item in expired}
