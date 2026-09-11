"""P5 (v0.26.0) — explicit v1→v2 crypto migration (Issue #60 follow-up).

Covers the `migrate-crypto` acceptance criteria:
- mixed v1/v2 stores read correctly before and after migration
- migration re-encrypts v1 rows as AAD-bound v2 with identical secrets
- migration is idempotent (second run migrates nothing, everything reads)
- refusal-on-corruption: a row that cannot decrypt aborts with
  CryptoMigrationError and the vault is left unchanged (all-or-nothing)
- unknown crypto_version labels are refused
- post-migration verification failure rolls the whole transaction back
- CLI surface: --dry-run reports without touching rows, --yes migrates and
  writes an audit event, refusal exits non-zero and audits the refusal
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner

from hermes_vault.cli import _hermes_group
from hermes_vault.crypto import CRYPTO_VERSION, CRYPTO_VERSION_V2
from hermes_vault.models import Decision
from hermes_vault.vault import CryptoMigrationError, Vault

PASSPHRASE = "test-passphrase"


def _mixed_vault(tmp_path: Path, db_name: str = "vault.db") -> tuple[Vault, list, list]:
    """A vault holding both v1 and v2 rows (v1 via env downgrade)."""
    import os

    v1_rows, v2_rows = [], []
    vault = Vault(tmp_path / db_name, tmp_path / "salt.bin", PASSPHRASE)
    v2_rows.append(vault.add_credential("openai", "sk-v2", "api_key", alias="default"))
    v2_rows.append(vault.add_credential("anthropic", "sk-v2-second", "api_key", alias="primary"))
    os.environ["HERMES_VAULT_CRYPTO_VERSION"] = CRYPTO_VERSION
    try:
        v1_rows.append(vault.add_credential("github", "gh-v1", "token", alias="work"))
        v1_rows.append(vault.add_credential("google", "gmail-v1", "app_password", alias="personal"))
    finally:
        os.environ.pop("HERMES_VAULT_CRYPTO_VERSION", None)
    return vault, v1_rows, v2_rows


def _all_readable(vault: Vault, expected: dict[str, str]) -> None:
    for service, secret in expected.items():
        got = vault.get_secret(service)
        assert got is not None, f"{service} did not decrypt"
        assert got.secret == secret


# ── Mixed v1/v2 store reads correctly ───────────────────────────────────


def test_mixed_v1_v2_store_reads_per_row(tmp_path: Path) -> None:
    vault, v1_rows, v2_rows = _mixed_vault(tmp_path)
    assert all(r.crypto_version == CRYPTO_VERSION for r in v1_rows)
    assert all(r.crypto_version == CRYPTO_VERSION_V2 for r in v2_rows)
    _all_readable(
        vault,
        {"openai": "sk-v2", "anthropic": "sk-v2-second", "github": "gh-v1", "google": "gmail-v1"},
    )


# ── Migration success ───────────────────────────────────────────────────


def test_migrate_crypto_reencrypts_v1_and_verifies_every_row(tmp_path: Path) -> None:
    vault, v1_rows, v2_rows = _mixed_vault(tmp_path)

    result = vault.migrate_crypto()

    assert result["migrated"] == 2
    assert result["already_v2"] == 2
    assert result["verified"] == 4

    after = {r.id: r for r in vault.list_credentials()}
    for rec in v1_rows:
        assert after[rec.id].crypto_version == CRYPTO_VERSION_V2
    for rec in v2_rows:
        assert after[rec.id].crypto_version == CRYPTO_VERSION_V2
        assert after[rec.id].encrypted_payload == rec.encrypted_payload  # v2 rows untouched

    _all_readable(
        vault,
        {"openai": "sk-v2", "anthropic": "sk-v2-second", "github": "gh-v1", "google": "gmail-v1"},
    )


def test_migrate_crypto_empty_vault(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", PASSPHRASE)
    result = vault.migrate_crypto()
    assert result == {"migrated": 0, "already_v2": 0, "verified": 0}


def test_migrate_crypto_all_v2_vault_is_noop(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", PASSPHRASE)
    rec = vault.add_credential("openai", "sk-v2", "api_key")
    result = vault.migrate_crypto()
    assert result["migrated"] == 0
    assert result["already_v2"] == 1
    got = vault.get_secret(rec.id)
    assert got is not None and got.secret == "sk-v2"


# ── Idempotence ─────────────────────────────────────────────────────────


def test_migrate_crypto_idempotent(tmp_path: Path) -> None:
    vault, v1_rows, _ = _mixed_vault(tmp_path)

    first = vault.migrate_crypto()
    assert first["migrated"] == 2
    snapshot = {r.id: r.encrypted_payload for r in vault.list_credentials()}

    second = vault.migrate_crypto()
    assert second["migrated"] == 0
    assert second["already_v2"] == 4
    assert second["verified"] == 4

    # Second run changed nothing on disk.
    after = {r.id: r.encrypted_payload for r in vault.list_credentials()}
    assert after == snapshot
    _all_readable(
        vault,
        {"openai": "sk-v2", "anthropic": "sk-v2-second", "github": "gh-v1", "google": "gmail-v1"},
    )


# ── Refusal on corruption ───────────────────────────────────────────────


def test_migrate_crypto_refuses_on_corrupt_v1_row_and_leaves_vault_unchanged(
    tmp_path: Path,
) -> None:
    vault, v1_rows, _ = _mixed_vault(tmp_path)
    corrupt = v1_rows[0]
    with sqlite3.connect(vault.db_path) as conn:
        conn.execute(
            "UPDATE credentials SET encrypted_payload = ? WHERE id = ?",
            ("bm90LXZhbGlkLWNpcGhlcnRleHQ=", corrupt.id),
        )
        conn.commit()

    before = {r.id: (r.encrypted_payload, r.crypto_version) for r in vault.list_credentials()}

    with pytest.raises(CryptoMigrationError, match="does not decrypt"):
        vault.migrate_crypto()

    after = {r.id: (r.encrypted_payload, r.crypto_version) for r in vault.list_credentials()}
    assert after == before  # all-or-nothing: nothing changed
    # The untouched v1 row still reads; the corrupted one was already broken.
    intact = vault.get_secret(v1_rows[1].id)
    assert intact is not None and intact.secret == "gmail-v1"


def test_migrate_crypto_refuses_on_wrong_passphrase(tmp_path: Path) -> None:
    vault, _, _ = _mixed_vault(tmp_path)
    # Open a second vault instance with a wrong passphrase: fresh salt would
    # normally be created, so instead simulate the wrong-key case directly by
    # corrupting the in-memory key of the existing vault.
    vault.key = b"\x00" * 32
    with pytest.raises(CryptoMigrationError, match="does not decrypt"):
        vault.migrate_crypto()


def test_migrate_crypto_refuses_unknown_version_label(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", PASSPHRASE)
    rec = vault.add_credential("openai", "sk", "api_key")
    with sqlite3.connect(vault.db_path) as conn:
        conn.execute(
            "UPDATE credentials SET crypto_version = ? WHERE id = ?",
            ("aesgcm-v99", rec.id),
        )
        conn.commit()

    with pytest.raises(CryptoMigrationError, match="unsupported crypto_version"):
        vault.migrate_crypto()

    row = vault.get_credential(rec.id)
    assert row is not None and row.crypto_version == "aesgcm-v99"


def test_migrate_crypto_rolls_back_on_post_verification_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure mid-re-encryption must roll the entire transaction back."""
    vault, _, _ = _mixed_vault(tmp_path)
    before = {r.id: (r.encrypted_payload, r.crypto_version) for r in vault.list_credentials()}

    from hermes_vault import vault as vault_mod

    real_encrypt = vault_mod.encrypt_secret_versioned
    calls = {"n": 0}

    def flaky_encrypt(payload, key, version, aad=None):
        calls["n"] += 1
        if calls["n"] == 2:  # blow up on the second v1 re-encryption
            raise RuntimeError("simulated re-encryption failure")
        return real_encrypt(payload, key, version, aad)

    monkeypatch.setattr(vault_mod, "encrypt_secret_versioned", flaky_encrypt)

    with pytest.raises(RuntimeError, match="simulated re-encryption failure"):
        vault.migrate_crypto()

    after = {r.id: (r.encrypted_payload, r.crypto_version) for r in vault.list_credentials()}
    assert after == before  # rollback: no row migrated, no row touched
    _all_readable(vault, {"github": "gh-v1", "google": "gmail-v1", "openai": "sk-v2"})


# ── CLI surface ─────────────────────────────────────────────────────────


def _cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)


def _seed_cli_vault(tmp_path: Path) -> Vault:
    """Seed one v1 row (env downgrade) and one v2 row directly."""
    import os

    vault = Vault(tmp_path / "vault.db", tmp_path / "master_key_salt.bin", PASSPHRASE)
    vault.add_credential("openai", "sk-v2", "api_key", alias="default")
    os.environ["HERMES_VAULT_CRYPTO_VERSION"] = CRYPTO_VERSION
    try:
        vault.add_credential("github", "gh-v1", "token", alias="work")
    finally:
        os.environ.pop("HERMES_VAULT_CRYPTO_VERSION", None)
    return vault


def test_cli_migrate_crypto_dry_run_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _cli_env(tmp_path, monkeypatch)
    vault = _seed_cli_vault(tmp_path)
    before = {r.id: (r.encrypted_payload, r.crypto_version) for r in vault.list_credentials()}

    result = CliRunner().invoke(
        _hermes_group, ["migrate-crypto", "--dry-run"], catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert "1 credential(s) would be re-encrypted" in result.output

    after = {r.id: (r.encrypted_payload, r.crypto_version) for r in vault.list_credentials()}
    assert after == before


def test_cli_migrate_crypto_migrates_and_audits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _cli_env(tmp_path, monkeypatch)
    vault = _seed_cli_vault(tmp_path)

    result = CliRunner().invoke(
        _hermes_group, ["migrate-crypto", "--yes"], catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert "1 credential(s) re-encrypted" in result.output

    rows = {r.id: r for r in vault.list_credentials()}
    assert all(r.crypto_version == CRYPTO_VERSION_V2 for r in rows.values())
    openai_secret = vault.get_secret("openai")
    github_secret = vault.get_secret("github")
    assert openai_secret is not None and openai_secret.secret == "sk-v2"
    assert github_secret is not None and github_secret.secret == "gh-v1"

    from hermes_vault.audit import AuditLogger

    audit = AuditLogger(tmp_path / "vault.db", master_key=vault.key)
    events = audit.list_recent(limit=20, action="migrate_crypto")
    assert events, "expected a migrate_crypto audit event"
    assert events[0]["decision"] == Decision.allow.value
    reason = events[0]["reason"]
    assert isinstance(reason, str) and "1 migrated" in reason


def test_cli_migrate_crypto_refusal_exits_nonzero_and_audits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _cli_env(tmp_path, monkeypatch)
    vault = _seed_cli_vault(tmp_path)
    github_row = vault.resolve_credential("github", alias="work")
    assert github_row is not None
    with sqlite3.connect(vault.db_path) as conn:
        conn.execute(
            "UPDATE credentials SET encrypted_payload = ? WHERE id = ?",
            ("YnJva2Vu", github_row.id),
        )
        conn.commit()

    result = CliRunner().invoke(
        _hermes_group, ["migrate-crypto", "--yes"], catch_exceptions=False,
    )
    assert result.exit_code == 2, result.output
    assert "Migration refused" in result.output

    from hermes_vault.audit import AuditLogger

    audit = AuditLogger(tmp_path / "vault.db", master_key=vault.key)
    events = audit.list_recent(limit=20, action="migrate_crypto")
    assert events
    assert events[0]["decision"] == Decision.deny.value
