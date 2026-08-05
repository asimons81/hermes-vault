"""Slice B — AES-GCM v2 codec with canonical AAD and v1 backward read (Issue #60).

Covers:
- canonical AAD builder determinism + domain/version marker
- v1/v2 envelope round trips and canonical-AAD mismatch (InvalidTag)
- version-aware decrypt dispatch
- vault write/read/rotate/rotate-master-key/import/backup-verify paths
- broker deny-on-relabel (never leak)
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from hermes_vault import crypto as crypto_mod
from hermes_vault.crypto import (
    CRYPTO_VERSION,
    CRYPTO_VERSION_V2,
    build_canonical_aad,
    decrypt_secret,
    decrypt_secret_v2,
    decrypt_secret_versioned,
    encrypt_secret,
    encrypt_secret_v2,
    encrypt_secret_versioned,
)
from hermes_vault.vault import Vault

KEY = bytes(range(32))


class StubVerifier:
    """Minimal verifier stub used by broker tests."""

    def verify(self, service: str, secret: str):
        from hermes_vault.models import VerificationCategory, VerificationResult

        return VerificationResult(
            service=service,
            category=VerificationCategory.valid,
            success=True,
            reason="ok",
        )

AAD_A = {
    "id": "11111111-1111-1111-1111-111111111111",
    "service": "openai",
    "alias": "default",
    "credential_type": "api_key",
    "scopes": ["read", "write"],
}
AAD_B = {
    "id": "22222222-2222-2222-2222-222222222222",
    "service": "github",
    "alias": "primary",
    "credential_type": "token",
    "scopes": ["repo"],
}


def _aad_vault_write_version(tmp_path: Path, version: str) -> Vault:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    record = vault.add_credential(
        "openai", "sk-secret-1", "api_key", alias="default", scopes=["read", "write"],
    )
    assert record.crypto_version == version
    return vault


def _relabel(vault: Vault, record_id: str, **updates) -> None:
    """Directly mutate a credential row in SQLite (attacker-style, no key)."""
    cols = ", ".join(f"{k} = ?" for k in updates)
    vals = list(updates.values())
    with sqlite3.connect(vault.db_path) as conn:
        conn.execute(f"UPDATE credentials SET {cols} WHERE id = ?", (*vals, record_id))
        conn.commit()


# ── Canonical AAD builder ────────────────────────────────────────────────


def test_canonical_aad_deterministic_and_sorted() -> None:
    shuffled = {k: AAD_A[k] for k in reversed(list(AAD_A))}
    assert build_canonical_aad(AAD_A) == build_canonical_aad(shuffled)


def test_canonical_aad_includes_domain_marker_and_differs_from_plain_json() -> None:
    aad = build_canonical_aad(AAD_A)
    plain = json.dumps(AAD_A, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    assert aad != plain
    # Marker prefix must be present so the same bytes cannot be replayed as
    # AAD for a different product/envelope version.
    assert aad.startswith(b"hermes-vault:credential-aad:v2")


def test_canonical_aad_stable_for_unicode_and_lists() -> None:
    meta = {
        "id": "id-1",
        "service": "caf\u00e9",
        "alias": "default",
        "credential_type": "api_key",
        "scopes": ["\u00fcber", "read"],
    }
    first = build_canonical_aad(meta)
    second = build_canonical_aad({k: meta[k] for k in sorted(meta, reverse=True)})
    assert first == second
    assert b"caf" in first  # ascii-escaped unicode still present deterministically


def test_canonical_aad_changes_when_metadata_changes() -> None:
    changed = dict(AAD_A)
    changed["service"] = "openai-relabeled"
    assert build_canonical_aad(AAD_A) != build_canonical_aad(changed)


# ── v1/v2 envelope round trips ───────────────────────────────────────────


def test_v1_round_trip_unchanged() -> None:
    encoded = encrypt_secret("plain-secret", KEY)
    assert decrypt_secret(encoded, KEY) == "plain-secret"


def test_v2_round_trip_with_same_aad() -> None:
    encoded = encrypt_secret_v2("plain-secret", KEY, AAD_A)
    assert decrypt_secret_v2(encoded, KEY, AAD_A) == "plain-secret"


def test_v2_decrypt_wrong_aad_raises_invalid_tag() -> None:
    encoded = encrypt_secret_v2("plain-secret", KEY, AAD_A)
    with pytest.raises(InvalidTag):
        decrypt_secret_v2(encoded, KEY, AAD_B)


# ── Version-aware dispatch ───────────────────────────────────────────────


def test_decrypt_versioned_v1_routes_to_legacy() -> None:
    encoded = encrypt_secret("plain-secret", KEY)
    assert decrypt_secret_versioned(encoded, KEY, CRYPTO_VERSION) == "plain-secret"


def test_decrypt_versioned_v2_uses_aad() -> None:
    encoded = encrypt_secret_v2("plain-secret", KEY, AAD_A)
    assert decrypt_secret_versioned(encoded, KEY, CRYPTO_VERSION_V2, AAD_A) == "plain-secret"
    with pytest.raises(InvalidTag):
        decrypt_secret_versioned(encoded, KEY, CRYPTO_VERSION_V2, AAD_B)


def test_decrypt_versioned_unknown_version_raises_value_error() -> None:
    encoded = encrypt_secret("plain-secret", KEY)
    with pytest.raises(ValueError):
        decrypt_secret_versioned(encoded, KEY, "aesgcm-v99", None)


def test_encrypt_versioned_v1_matches_legacy_and_v2_is_aad_bound() -> None:
    v1_encoded = encrypt_secret_versioned("plain-secret", KEY, CRYPTO_VERSION, AAD_A)
    assert decrypt_secret(v1_encoded, KEY) == "plain-secret"  # v1 ignores AAD
    v2_encoded = encrypt_secret_versioned("plain-secret", KEY, CRYPTO_VERSION_V2, AAD_A)
    assert decrypt_secret_v2(v2_encoded, KEY, AAD_A) == "plain-secret"
    with pytest.raises(InvalidTag):
        decrypt_secret_v2(v2_encoded, KEY, AAD_B)


# ── Vault write/read paths ───────────────────────────────────────────────


def test_default_writes_stay_v1(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("HERMES_VAULT_CRYPTO_VERSION", raising=False)
    vault = _aad_vault_write_version(tmp_path, CRYPTO_VERSION)
    secret = vault.get_secret("openai")
    assert secret is not None and secret.secret == "sk-secret-1"


def test_v2_write_flag_round_trip(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    vault = _aad_vault_write_version(tmp_path, CRYPTO_VERSION_V2)
    secret = vault.get_secret("openai")
    assert secret is not None and secret.secret == "sk-secret-1"


def test_v2_write_relabel_service_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    vault = _aad_vault_write_version(tmp_path, CRYPTO_VERSION_V2)
    record = vault.resolve_credential("openai")
    assert record is not None
    _relabel(vault, record.id, service="relabeled-service")
    with pytest.raises(InvalidTag):
        vault.get_secret(record.id)


def test_v2_write_relabel_alias_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    vault = _aad_vault_write_version(tmp_path, CRYPTO_VERSION_V2)
    record = vault.resolve_credential("openai")
    assert record is not None
    _relabel(vault, record.id, alias="evil-alias")
    with pytest.raises(InvalidTag):
        vault.get_secret(record.id)


def test_v2_write_relabel_id_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    vault = _aad_vault_write_version(tmp_path, CRYPTO_VERSION_V2)
    record = vault.resolve_credential("openai")
    assert record is not None
    # The id column is the lookup key itself; after relabel, resolve by
    # service so the row is found and the AAD mismatch is what fails.
    _relabel(vault, record.id, id="00000000-0000-0000-0000-000000000000")
    with pytest.raises(InvalidTag):
        vault.get_secret("openai")


def test_v1_ciphertext_relabel_still_reads(tmp_path: Path) -> None:
    """Legacy v1 rows are not AAD-bound: relabeling metadata does not break reads."""
    vault = _aad_vault_write_version(tmp_path, CRYPTO_VERSION)
    record = vault.resolve_credential("openai")
    assert record is not None
    _relabel(vault, record.id, service="relabeled-service")
    secret = vault.get_secret(record.id)
    assert secret is not None and secret.secret == "sk-secret-1"


def test_mixed_v1_and_v2_vault_decrypts_per_row(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    v2_rec = vault.add_credential("openai", "sk-v2", "api_key", alias="default")
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION)
    v1_rec = vault.add_credential("github", "gh-v1", "token", alias="primary")
    assert v2_rec.crypto_version == CRYPTO_VERSION_V2
    assert v1_rec.crypto_version == CRYPTO_VERSION
    assert vault.get_secret(v2_rec.id) is not None
    assert vault.get_secret(v1_rec.id) is not None
    assert vault.get_secret(v2_rec.id).secret == "sk-v2"
    assert vault.get_secret(v1_rec.id).secret == "gh-v1"


def test_rotate_preserves_version(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    original = vault.add_credential("openai", "sk-old", "api_key")
    rotated = vault.rotate(original.id, "sk-new")
    assert rotated.crypto_version == CRYPTO_VERSION_V2
    assert vault.get_secret(rotated.id).secret == "sk-new"


def test_rotate_master_key_preserves_versions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    v2_rec = vault.add_credential("openai", "sk-v2", "api_key", alias="default")
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION)
    v1_rec = vault.add_credential("github", "gh-v1", "token", alias="primary")

    result = vault.rotate_master_key("test-passphrase", "new-passphrase")
    assert result["re_encrypted"] == 2

    after = {r.id: r for r in vault.list_credentials()}
    assert after[v2_rec.id].crypto_version == CRYPTO_VERSION_V2
    assert after[v1_rec.id].crypto_version == CRYPTO_VERSION
    assert vault.get_secret(v2_rec.id).secret == "sk-v2"
    assert vault.get_secret(v1_rec.id).secret == "gh-v1"


# ── Backup / import paths ────────────────────────────────────────────────


def test_backup_verify_v2_export_decryptable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from hermes_vault.backup import verify_backup_file

    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-v2", "api_key")
    backup_path = tmp_path / "backup.json"
    backup_path.write_text(json.dumps(vault.export_backup(), indent=2, sort_keys=True), encoding="utf-8")

    report = verify_backup_file(backup_path, vault)
    assert report.decryptable is True
    assert report.credential_count == 1


def test_v2_backup_round_trip_into_fresh_vault(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    src = Vault(tmp_path / "src.db", tmp_path / "src.salt", "pass")
    src.add_credential("openai", "sk-v2", "api_key", alias="default", scopes=["read"])
    backup = src.export_backup()

    # Destination shares the source's key material (same salt file), which is
    # what a real restore does — the master key is not part of the backup.
    dst = Vault(tmp_path / "dst.db", tmp_path / "src.salt", "pass")
    imported = dst.import_backup(backup)
    assert len(imported) == 1
    assert imported[0].crypto_version == CRYPTO_VERSION_V2
    assert dst.get_secret(imported[0].id).secret == "sk-v2"


def test_import_over_existing_row_preserves_v2_and_stays_decryptable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    src = Vault(tmp_path / "src.db", tmp_path / "src.salt", "pass")
    src.add_credential("openai", "sk-v2", "api_key", alias="default")
    backup = src.export_backup()

    # Destination already has a row for the same service with a DIFFERENT id.
    # Share the source salt so key material matches (as a real restore does).
    dst = Vault(tmp_path / "dst.db", tmp_path / "src.salt", "pass")
    existing = dst.add_credential("openai", "old-v1", "api_key", alias="default")
    assert existing.id != backup["credentials"][0]["id"]

    dst.import_backup(backup, replace=True)
    row = dst.resolve_credential("openai")
    assert row is not None
    assert row.crypto_version == CRYPTO_VERSION_V2
    assert dst.get_secret(row.id).secret == "sk-v2"


def test_import_v2_backup_replaces_v1_destination_and_updates_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    src = Vault(tmp_path / "src.db", tmp_path / "src.salt", "pass")
    src.add_credential("openai", "sk-v2", "api_key", alias="default")
    backup = src.export_backup()

    # A real migration can import v2 ciphertext into a destination that still
    # has a legacy v1 row for the same service/alias.
    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION)
    dst = Vault(tmp_path / "dst.db", tmp_path / "src.salt", "pass")
    existing = dst.add_credential("openai", "old-v1", "api_key", alias="default")
    assert existing.crypto_version == CRYPTO_VERSION

    dst.import_backup(backup, replace=True)
    row = dst.resolve_credential("openai")
    assert row is not None
    assert row.crypto_version == CRYPTO_VERSION_V2
    secret = dst.get_secret(row.id)
    assert secret is not None and secret.secret == "sk-v2"


# ── Broker deny-on-relabel ───────────────────────────────────────────────


def test_broker_denies_relabeled_v2_without_exception(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    from hermes_vault.audit import AuditLogger
    from hermes_vault.broker import Broker
    from hermes_vault.models import AgentPolicy, PolicyConfig, ServiceAction, ServicePolicyEntry
    from hermes_vault.policy import PolicyEngine

    monkeypatch.setenv("HERMES_VAULT_CRYPTO_VERSION", CRYPTO_VERSION_V2)
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-v2", "api_key", alias="default")

    policy = PolicyEngine(
        PolicyConfig(
            agents={
                "dwight": AgentPolicy(
                    services=["openai"],
                    service_actions={
                        "openai": ServicePolicyEntry(actions=[ServiceAction.get_env]),
                    },
                    raw_secret_access=False,
                    ephemeral_env_only=True,
                )
            }
        )
    )
    broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))

    # Relabel the row to a service the agent cannot access.
    record = vault.resolve_credential("openai")
    assert record is not None
    _relabel(vault, record.id, service="other-service")

    decision = broker.get_ephemeral_env("openai", "dwight", ttl=900)
    assert decision.allowed is False
    # The reason must not leak the raw secret; a metadata-mismatch denial is fine.
    assert "sk-v2" not in decision.reason


# ── Explicit cutover point ───────────────────────────────────────────────


def test_write_crypto_version_still_v1_by_default() -> None:
    assert crypto_mod.WRITE_CRYPTO_VERSION == CRYPTO_VERSION
