"""P1 safe-recovery regression suite (design p1-design.md §7.2, T1–T14).

Scenario A — trap #1 (ops skill "Audit integrity chain break"): raw audit
rows appended past an initialized chain wedge every protected write path;
`audit-checkpoint repair` must recover non-destructively (quarantine +
re-establish) and both bricking outcomes must be impossible afterwards.

Scenario B — trap #2 (ops skill "Backup-rebuild trap"): a salt rotated by
the documented temp-home rebuild playbook; the restore path must block
pre-mutation, and the repair/self-check must name the key-material
mismatch instead of rebuilding over it.
"""

from __future__ import annotations

import json
import os
import sys
import shutil
import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner

from hermes_vault.audit import AuditLogger
from hermes_vault.audit_integrity.models import AuditIntegrityStatus
from hermes_vault.audit_integrity.repair import (
    RepairClass,
    RepairRefusedError,
    classify_repairability,
    run_repair,
)
from hermes_vault.audit_integrity.service import (
    AuditIntegrityError,
    AuditIntegrityService,
)
from hermes_vault.backup import prove_backup_decryptable
from hermes_vault.cli import _hermes_group
from hermes_vault.crypto import MissingKeyMaterialError, load_or_create_master_key
from hermes_vault.models import AccessLogRecord, Decision
from hermes_vault.recovery import (
    ReceiptWriteError,
    RestoreReceipt,
    write_restore_receipt,
)
from hermes_vault.vault import SaltMismatchError, Vault

PASSPHRASE = "test-passphrase"


# ── fixture helpers (design §7.2) ─────────────────────────────────────────


def make_vault(tmp_path: Path, name: str = "vault.db", salt: str = "salt.bin", passphrase: str = PASSPHRASE) -> Vault:
    vault = Vault(tmp_path / name, tmp_path / salt, passphrase)
    return vault


def make_cli_vault(tmp_path: Path, passphrase: str = PASSPHRASE) -> Vault:
    """Vault whose filenames match the CLI settings (vault.db + master_key_salt.bin)."""
    return Vault(tmp_path / "vault.db", tmp_path / "master_key_salt.bin", passphrase)


def wedge_audit(vault: Vault) -> None:
    """Trap #1 state: raw access_logs rows past an initialized chain.

    Appends unprotected rows directly via sqlite (bypassing the integrity
    append), exactly like the documented incident: legacy_count no longer
    equals legacy_prefix + protected → verify() reports
    missing_integrity_record and every protected append raises.
    """
    conn = sqlite3.connect(vault.db_path)
    try:
        for i in range(2):
            conn.execute(
                "INSERT INTO access_logs (id, timestamp, agent_id, service, action, decision, reason, ttl_seconds, verification_result, metadata_json) "
                "VALUES (?, ?, 'raw-agent', 'openai', 'get_env', 'allow', 'raw unprotected row', NULL, NULL, '{}')",
                (f"raw-{i}", f"2026-09-10T00:00:0{i}+00:00"),
            )
        conn.commit()
    finally:
        conn.close()


def _assert_wedged(vault: Vault) -> None:
    service = AuditIntegrityService(vault.db_path, vault.key)
    result = service.verify()
    assert result.status == AuditIntegrityStatus.failed
    assert result.reason_code == "missing_integrity_record"
    with pytest.raises(AuditIntegrityError):
        AuditLogger(vault.db_path, master_key=vault.key).record(
            AccessLogRecord(agent_id="x", service="openai", action="get_env", decision=Decision.allow, reason="probe")
        )


def _set_cli_env(tmp_path: Path, passphrase: str = PASSPHRASE) -> None:
    os.environ["HERMES_VAULT_HOME"] = str(tmp_path)
    os.environ["HERMES_VAULT_PASSPHRASE"] = passphrase


def _seed_chain(vault: Vault) -> None:
    AuditLogger(vault.db_path, master_key=vault.key).record(
        AccessLogRecord(agent_id="seed", service="openai", action="get_env", decision=Decision.allow, reason="seed chain")
    )


def _write_backup_file(path: Path, backup: dict) -> Path:
    path.write_text(json.dumps(backup, indent=2), encoding="utf-8")
    return path


def _restore_event_count(vault: Vault) -> int:
    conn = sqlite3.connect(vault.db_path)
    try:
        row = conn.execute("SELECT COUNT(*) FROM access_logs WHERE action = 'restore'").fetchone()
        return int(row[0])
    finally:
        conn.close()


def _audit_repair_row(vault: Vault) -> sqlite3.Row | None:
    conn = sqlite3.connect(vault.db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM access_logs WHERE action = 'audit_repair' ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()


def _table_names(vault: Vault) -> list[str]:
    conn = sqlite3.connect(vault.db_path)
    try:
        return [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
    finally:
        conn.close()


# ── Scenario A — trap #1 (audit wedge) ────────────────────────────────────


def test_t1_repair_recovers_wedged_chain_end_to_end(tmp_path: Path) -> None:
    """T1: wedge → every write raises → repair --yes → AC2 assertions, via CLI."""
    _set_cli_env(tmp_path)
    vault = make_cli_vault(tmp_path)
    rec = vault.add_credential("openai", "sk-live-1", "api_key")
    _seed_chain(vault)
    wedge_audit(vault)
    _assert_wedged(vault)

    runner = CliRunner()
    result = runner.invoke(
        _hermes_group,
        ["audit-checkpoint", "repair", "--yes", "--reason", "incident wedge test"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert "repaired" in result.output.lower()

    # audit-verify healthy; credential payloads unchanged; writes work again.
    service = AuditIntegrityService(vault.db_path, vault.key)
    assert service.verify().status == AuditIntegrityStatus.healthy
    reopened = Vault(tmp_path / "vault.db", tmp_path / "master_key_salt.bin", PASSPHRASE)
    assert reopened.get_secret(rec.id).secret == "sk-live-1"
    _seed_chain(reopened)  # no AuditIntegrityError

    # Quarantine tables + manifest + safety copy + audit_repair seq-1 event.
    tables = _table_names(vault)
    quarantine_tables = [t for t in tables if t.startswith("quarantine_")]
    assert len(quarantine_tables) >= 6, quarantine_tables
    conn = sqlite3.connect(vault.db_path)
    try:
        manifest = conn.execute("SELECT COUNT(*) FROM audit_quarantine_manifest").fetchone()[0]
        assert manifest == 6
        # Old audit evidence survived inside the quarantine tables.
        preserved = conn.execute(
            'SELECT COUNT(*) FROM "' + [t for t in quarantine_tables if "access_logs" in t][0] + '"'
        ).fetchone()[0]
        assert preserved >= 3  # seed row + 2 raw wedge rows
    finally:
        conn.close()
    assert any(p.name.startswith("vault.db.pre-repair-") for p in tmp_path.iterdir())

    repair_row = _audit_repair_row(vault)
    assert repair_row is not None
    metadata = json.loads(repair_row["metadata_json"])
    assert metadata["prior_verify_reason"] == "missing_integrity_record"
    assert metadata["quarantine_id"]
    # The audit_repair event is part of the NEW chain (verifies healthy).
    assert service.verify().status == AuditIntegrityStatus.healthy


def test_t2_repair_is_transactional(tmp_path: Path, monkeypatch) -> None:
    """T2: a mid-transaction failure rolls back; db byte-identical, no manifest."""
    import types

    import hermes_vault.audit_integrity.repair as repair_module

    vault = make_cli_vault(tmp_path)
    vault.add_credential("openai", "sk-1", "api_key")
    _seed_chain(vault)
    wedge_audit(vault)
    before = (tmp_path / "vault.db").read_bytes()

    class _ExplodingConn:
        """Wraps a real connection; attribute reads AND writes forward to it."""

        def __init__(self, real: sqlite3.Connection) -> None:
            object.__setattr__(self, "_real", real)

        def __getattr__(self, name: str):
            return getattr(self._real, name)

        def __setattr__(self, name: str, value) -> None:
            setattr(self._real, name, value)

        def execute(self, sql, *args, **kwargs):
            if sql.strip().upper().startswith("DELETE FROM ACCESS_LOGS"):
                raise sqlite3.OperationalError("simulated mid-delete crash")
            return self._real.execute(sql, *args, **kwargs)

    fake_sqlite = types.SimpleNamespace(
        connect=lambda *a, **k: _ExplodingConn(sqlite3.connect(*a, **k)),
        Row=sqlite3.Row,
    )
    monkeypatch.setattr(repair_module, "sqlite3", fake_sqlite)
    service = AuditIntegrityService(vault.db_path, vault.key)
    with pytest.raises(sqlite3.OperationalError):
        run_repair(service, vault, reason="crash test")
    monkeypatch.undo()

    after = (tmp_path / "vault.db").read_bytes()
    assert before == after
    conn = sqlite3.connect(vault.db_path)
    try:
        manifest_exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'audit_quarantine_manifest'"
        ).fetchone()
        if manifest_exists:  # rolled-back DDL may remove the table entirely
            assert conn.execute("SELECT COUNT(*) FROM audit_quarantine_manifest").fetchone()[0] == 0
        # The live tables were not purged (rollback restored every row).
        assert conn.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0] >= 3
    finally:
        conn.close()


def test_t3_repair_on_healthy_vault_is_noop(tmp_path: Path) -> None:
    """T3: healthy vault → no-op exit 0, no quarantine tables, no safety copy."""
    _set_cli_env(tmp_path)
    vault = make_cli_vault(tmp_path)
    vault.add_credential("openai", "sk-1", "api_key")
    _seed_chain(vault)

    runner = CliRunner()
    result = runner.invoke(
        _hermes_group,
        ["audit-checkpoint", "repair", "--yes", "--reason", "nothing wrong"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert "nothing to repair" in result.output.lower()
    assert not [t for t in _table_names(vault) if t.startswith("quarantine_")]
    assert not any(p.name.startswith("vault.db.pre-repair-") for p in tmp_path.iterdir())


def test_t4_repair_self_check_is_read_only(tmp_path: Path) -> None:
    """T4: self-check names reason + verdict, byte-identical db + checkpoint."""
    _set_cli_env(tmp_path)
    vault = make_cli_vault(tmp_path)
    vault.add_credential("openai", "sk-1", "api_key")
    _seed_chain(vault)
    wedge_audit(vault)
    before_db = (tmp_path / "vault.db").read_bytes()
    checkpoint = tmp_path / "audit.checkpoint.json"
    before_cp = checkpoint.read_bytes()

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["audit-checkpoint", "repair"], catch_exceptions=False)
    assert result.exit_code == 2, result.output  # REPAIRABLE verdict → exit 2
    assert "missing_integrity_record" in result.output
    assert "REPAIRABLE" in result.output
    assert "Store decryptability: 1/1" in result.output

    assert (tmp_path / "vault.db").read_bytes() == before_db
    assert checkpoint.read_bytes() == before_cp
    assert not [t for t in _table_names(vault) if t.startswith("quarantine_")]


# ── Scenario B — trap #2 (salt rotation brick) ────────────────────────────


def test_t5_restore_blocks_after_documented_salt_swap(tmp_path: Path) -> None:
    """T5: replay the ops-skill backup-rebuild trap; both bricking outcomes impossible.

    Leg 1 — the playbook's rebuild step (restore into a fresh-salt temp
    home) is now IMPOSSIBLE through the product: the preflight blocks it
    pre-mutation with the salt-mismatch error.

    Leg 2 — the post-swap state (fresh salt over the original db, built by
    raw file copies since the product can no longer reach it) is
    caught-and-explained at the first gated surface: restore names the
    key-material mismatch with recovery pointers, and the repair
    self-check refuses to rebuild over it.
    """
    # Vault A: passphrase P, salt S_A, 3 creds, a backup under A's key.
    home_a = tmp_path / "a"
    home_a.mkdir()
    vault_a = make_vault(home_a, salt="master_key_salt.bin")
    for i in range(3):
        vault_a.add_credential("openai", f"sk-a-{i}", "api_key", alias=f"alt{i}")
    backup = vault_a.export_backup()
    backup_path = _write_backup_file(tmp_path / "backup.json", backup)
    runner = CliRunner()

    # ── Leg 1: fresh-salt temp home B — the documented rebuild step blocks.
    home_b = tmp_path / "b"
    home_b.mkdir()
    _set_cli_env(home_b)
    result = runner.invoke(
        _hermes_group, ["restore", "--input", str(backup_path), "--yes"], catch_exceptions=False
    )
    assert result.exit_code == 1, result.output
    assert "decryptable 0/3" in result.output
    assert "NEVER rotates" in result.output
    receipts_b = list((home_b / "recovery").glob("restore-receipt-*.json"))
    assert receipts_b
    payload_b = json.loads(receipts_b[-1].read_text())
    assert payload_b["decision"] == "blocked"
    assert payload_b["blocked_reason"] == "salt_mismatch"
    # Nothing was imported into the temp home.
    conn = sqlite3.connect(home_b / "vault.db")
    try:
        assert conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 0
    finally:
        conn.close()

    # ── Leg 2: post-swap state via raw file copies (§4.3 boundary).
    # Fresh-salt home C, then A's db copied over it: live key K_C cannot
    # decrypt A's K_A payloads — the documented "secret could not be
    # decrypted" brick. A's chain must be seeded so the mismatch surfaces
    # as active_key_mismatch (a bare legacy db would read legacy_only).
    _seed_chain(vault_a)
    home_c = tmp_path / "c"
    home_c.mkdir()
    make_vault(home_c, salt="master_key_salt.bin")  # creates fresh salt S_C + empty db
    shutil.copy(home_a / "vault.db", home_c / "vault.db")
    shutil.copy(home_a / "audit.checkpoint.json", home_c / "audit.checkpoint.json")
    salt_before = (home_c / "master_key_salt.bin").read_bytes()
    db_before = (home_c / "vault.db").read_bytes()

    # (a) restore --yes must block pre-mutation with the salt guidance.
    _set_cli_env(home_c)
    result = runner.invoke(
        _hermes_group, ["restore", "--input", str(backup_path), "--yes"], catch_exceptions=False
    )
    assert result.exit_code == 1, result.output
    assert "decryptable 0/3" in result.output
    assert "master_key_salt.bin" in result.output
    assert "NEVER rotates" in result.output
    # Nothing mutated: salt + db byte-identical.
    assert (home_c / "master_key_salt.bin").read_bytes() == salt_before
    assert (home_c / "vault.db").read_bytes() == db_before
    receipts_c = list((home_c / "recovery").glob("restore-receipt-*.json"))
    assert receipts_c, "no restore receipt written"
    payload_c = json.loads(receipts_c[-1].read_text())
    assert payload_c["decision"] == "blocked"
    assert payload_c["blocked_reason"] == "salt_mismatch"
    assert payload_c["outcome"] == "blocked"

    # (b) the repair self-check names the key-material mismatch and refuses.
    result = runner.invoke(_hermes_group, ["audit-checkpoint", "repair"], catch_exceptions=False)
    assert "active_key_mismatch" in result.output, result.output
    assert "KEY-MATERIAL MISMATCH" in result.output, result.output
    result = runner.invoke(
        _hermes_group,
        ["audit-checkpoint", "repair", "--yes", "--reason", "must refuse"],
        catch_exceptions=False,
    )
    assert result.exit_code == 2, result.output
    assert "refused" in result.output.lower()
    assert not [t for t in _table_names_via(home_c) if t.startswith("quarantine_")]
    # The audit evidence tables are intact (refusal rebuilt nothing).
    conn = sqlite3.connect(home_c / "vault.db")
    try:
        assert conn.execute("SELECT COUNT(*) FROM audit_integrity_records").fetchone()[0] >= 1
    finally:
        conn.close()


def _table_names_via(home: Path) -> list[str]:
    conn = sqlite3.connect(home / "vault.db")
    try:
        return [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
    finally:
        conn.close()


def test_t6_import_backup_salt_mismatch_guards(tmp_path: Path) -> None:
    """T6: library-layer guard — foreign-key backups raise SaltMismatchError."""
    vault_a = make_vault(tmp_path / "a", name="a.db", salt="a_salt.bin")
    vault_a.add_credential("openai", "sk-a", "api_key")
    v1_backup = vault_a.export_backup(include_audit=False)
    v2_backup = vault_a.export_backup(include_audit=True)

    # v1 foreign-key import raises SaltMismatchError, vault unchanged.
    vault_b = make_vault(tmp_path / "a", name="b.db", salt="b_salt.bin")
    with pytest.raises(SaltMismatchError) as excinfo:
        vault_b.import_backup(v1_backup)
    assert "NEVER rotates" in str(excinfo.value)
    assert vault_b.list_credentials() == []

    # Same-key v1 backup imports (positive control).
    shutil.copy(tmp_path / "a" / "a_salt.bin", tmp_path / "a" / "b2_salt.bin")
    vault_b2 = Vault(tmp_path / "a" / "b2.db", tmp_path / "a" / "b2_salt.bin", PASSPHRASE)
    imported = vault_b2.import_backup(v1_backup)
    assert len(imported) == 1

    # v2 foreign-key backup raises with the §4 text (upgraded from bare
    # key_mismatch) — evidence gate fires first.
    vault_c = make_vault(tmp_path / "a", name="c.db", salt="c_salt.bin")
    with pytest.raises(ValueError, match="key_mismatch|do not decrypt"):
        vault_c.import_backup(v2_backup)
    assert vault_c.list_credentials() == []


def test_t7_partial_decrypt_failure_blocks(tmp_path: Path) -> None:
    """T7: one corrupted payload in an otherwise same-key backup → blocked."""
    vault = make_cli_vault(tmp_path)
    vault.add_credential("openai", "sk-1", "api_key", alias="one")
    vault.add_credential("github", "ghp-1", "personal_access_token", alias="two")
    backup = vault.export_backup()
    # Corrupt exactly one payload (same key, garbage bytes) — target by
    # service/alias, not list position (export order is not insertion order).
    target = next(c for c in backup["credentials"] if c["service"] == "openai")
    target["encrypted_payload"] = "garbage-not-a-payload"

    proof = prove_backup_decryptable(backup, vault.key)
    assert proof.ok is False
    assert proof.credential_count == 2
    assert proof.decryptable_count == 1
    assert proof.blocked_reason == "partial_decrypt_failure"
    # Finding names service/alias only — never plaintext or key material.
    assert any("openai/one" in f for f in proof.findings)
    assert not any("sk-1" in f or "ghp-1" in f for f in proof.findings)


def test_t8_empty_backup_proves_vacuously(tmp_path: Path) -> None:
    """T8: zero-credential backup proves vacuously and restores."""
    vault = make_cli_vault(tmp_path)
    backup = vault.export_backup()
    backup["credentials"] = []

    proof = prove_backup_decryptable(backup, vault.key)
    assert proof.ok is True
    assert proof.credential_count == 0
    assert proof.findings == ("empty backup: nothing to prove",)

    imported = vault.import_backup(backup)
    assert imported == []


def test_t9_happy_path_receipt_and_audit_events(tmp_path: Path) -> None:
    """T9: same-key restore → two-phase receipt + restore_preflight allow event."""
    _set_cli_env(tmp_path)
    source = make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "sk-secret", "api_key", alias="primary")
    backup_path = _write_backup_file(tmp_path / "backup.json", source.export_backup())

    shutil.copy(tmp_path / "src_salt.bin", tmp_path / "master_key_salt.bin")
    target = make_vault(tmp_path, salt="master_key_salt.bin")
    _seed_chain(target)

    runner = CliRunner()
    result = runner.invoke(
        _hermes_group, ["restore", "--input", str(backup_path), "--yes"], catch_exceptions=False
    )
    assert result.exit_code == 0, result.output
    assert "Restored 1 credential(s)" in result.output

    receipts = sorted((tmp_path / "recovery").glob("restore-receipt-*.json"))
    assert receipts
    payload = json.loads(receipts[-1].read_text())
    assert payload["version"] == "restore-receipt-v1"
    assert payload["mode"] == "preflight"
    assert payload["outcome"] == "restored"
    assert payload["decision"] == "proceed"
    assert payload["credential_count"] == 1
    assert payload["decryptable_credential_count"] == 1
    assert payload["destination_salt_fingerprint"]
    assert len(payload["backup_sha256"]) == 64

    conn = sqlite3.connect(tmp_path / "vault.db")
    try:
        actions = [r[0] for r in conn.execute("SELECT action FROM access_logs")]
    finally:
        conn.close()
    assert "restore_preflight" in actions
    assert "restore" in actions


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX dir write bits: chmod 0o500 cannot make a dir unwritable on Windows")
def test_t10_unwritable_receipt_dir_blocks_restore(tmp_path: Path) -> None:
    """T10: fail-closed receipt rule — unwritable recovery dir blocks restore."""
    _set_cli_env(tmp_path)
    source = make_vault(tmp_path, name="src.db", salt="src_salt.bin")
    source.add_credential("openai", "sk-secret", "api_key")
    backup_path = _write_backup_file(tmp_path / "backup.json", source.export_backup())
    shutil.copy(tmp_path / "src_salt.bin", tmp_path / "master_key_salt.bin")
    make_vault(tmp_path, salt="master_key_salt.bin")  # target vault shares the key
    db_before = (tmp_path / "vault.db").read_bytes()

    recovery = tmp_path / "recovery"
    recovery.mkdir()
    recovery.chmod(0o500)  # r-x: writable check fails for non-root

    runner = CliRunner()
    result = runner.invoke(
        _hermes_group, ["restore", "--input", str(backup_path), "--yes"], catch_exceptions=False
    )
    recovery.chmod(0o700)
    if os.geteuid() == 0:
        pytest.skip("root ignores directory write bits")
    assert result.exit_code == 1, result.output
    assert "receipt" in result.output.lower()
    assert "NOT performed" in result.output
    assert (tmp_path / "vault.db").read_bytes() == db_before


# ── Guard/interlock units (T11–T14) ───────────────────────────────────────


def test_t11_salt_creation_refused_over_sibling_db(tmp_path: Path) -> None:
    """T11: load_or_create_master_key refuses when vault.db exists next to missing salt."""
    salt_path = tmp_path / "master_key_salt.bin"
    (tmp_path / "vault.db").write_bytes(b"sqlite-bytes")

    with pytest.raises(MissingKeyMaterialError, match="no new salt was written"):
        load_or_create_master_key(salt_path, PASSPHRASE, enable_dpapi=False)
    assert not salt_path.exists(), "salt file was created over a populated db"

    # Positive: fresh dir (no db) still creates.
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    key = load_or_create_master_key(fresh / "master_key_salt.bin", PASSPHRASE, enable_dpapi=False)
    assert isinstance(key, bytes) and len(key) == 32
    assert (fresh / "master_key_salt.bin").exists()


def test_t12_refusal_classes_never_rebuild(tmp_path: Path) -> None:
    """T12: tamper-evidence reasons refuse repair; tables untouched."""
    vault = make_cli_vault(tmp_path)
    vault.add_credential("openai", "sk-1", "api_key")
    _seed_chain(vault)
    vault.add_credential("github", "ghp-1", "personal_access_token")

    # Tamper fixture: mutate a protected row → entry_digest_mismatch.
    conn = sqlite3.connect(vault.db_path)
    conn.execute("UPDATE access_logs SET reason = 'tampered'")
    conn.commit()
    conn.close()

    service = AuditIntegrityService(vault.db_path, vault.key)
    result = service.verify()
    assert result.reason_code == "entry_digest_mismatch"
    assert classify_repairability(result) is RepairClass.refuse_tamper

    before = (tmp_path / "vault.db").read_bytes()
    with pytest.raises(RepairRefusedError, match="tampering"):
        run_repair(service, vault, reason="must refuse")
    assert (tmp_path / "vault.db").read_bytes() == before
    assert not any(p.name.startswith("vault.db.pre-repair-") for p in tmp_path.iterdir())

    # Parameterized set-membership assert over the full refusal mapping.
    from hermes_vault.audit_integrity import repair as repair_module

    for reason in repair_module.REFUSE_TAMPER_REASONS:
        assert reason not in repair_module.REPAIRABLE_REASONS
    for reason in repair_module.REFUSE_KEY_MATERIAL_REASONS:
        assert reason not in repair_module.REPAIRABLE_REASONS
    assert "active_key_mismatch" in repair_module.REFUSE_KEY_MATERIAL_REASONS


def test_t13_recover_no_longer_rebuilds_on_key_mismatch(tmp_path: Path) -> None:
    """T13: recover_checkpoint returns the failed result; rebuild method deleted."""
    from hermes_vault.audit_integrity import service as service_module

    assert not hasattr(service_module.AuditIntegrityService, "_rebuild_integrity_for_key_mismatch")

    vault1 = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "passphrase-a")
    logger1 = AuditLogger(vault1.db_path, master_key=vault1.key)
    logger1.record(AccessLogRecord(agent_id="a", service="openai", action="get_env", decision=Decision.allow, reason="r"))
    vault2 = Vault(vault1.db_path, vault1.salt_path, "passphrase-b")
    service2 = AuditLogger(vault2.db_path, master_key=vault2.key).integrity

    result = service2.verify()
    assert result.status is AuditIntegrityStatus.failed
    assert result.reason_code == "active_key_mismatch"

    recovered = service2.recover_checkpoint()
    assert recovered.status is AuditIntegrityStatus.failed
    assert recovered.reason_code == "active_key_mismatch"

    # The old integrity tables are still present (evidence preserved).
    conn = sqlite3.connect(vault1.db_path)
    try:
        for table in ("audit_integrity_records", "audit_integrity_segments", "audit_integrity_state"):
            exists = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
            ).fetchone()
            assert exists, f"{table} was dropped"
        count = conn.execute("SELECT COUNT(*) FROM audit_integrity_records").fetchone()[0]
        assert count >= 1
    finally:
        conn.close()


def test_t14_deferred_events_folded_into_audit_repair(tmp_path: Path) -> None:
    """T14: a deferred recovery fact recorded while the chain was broken is
    folded into the audit_repair event metadata on the new chain."""
    vault = make_cli_vault(tmp_path)
    vault.add_credential("openai", "sk-1", "api_key")
    _seed_chain(vault)
    wedge_audit(vault)

    deferred = ["restore_preflight denied: salt_mismatch (receipt restore-receipt-20260910-000000.json)"]
    service = AuditIntegrityService(vault.db_path, vault.key)
    report = run_repair(service, vault, reason="deferred-event test", deferred_events=deferred)

    assert report.executed
    row = _audit_repair_row(vault)
    metadata = json.loads(row["metadata_json"])
    assert metadata["deferred_recovery_events"] == deferred


# ── receipt fail-closed unit ──────────────────────────────────────────────


def test_t16_post_commit_failure_exits_three_at_cli(tmp_path: Path, monkeypatch) -> None:
    """T16: a post-commit audit_repair append failure surfaces as exit 3.

    Design §3.3 interlock 9: the quarantine + purge committed and the chain
    verifies healthy — the failure is confined to the audit event append.
    The CLI must report it distinctly (exit 3 with remediation), never as a
    refused or rolled-back repair.
    """
    _set_cli_env(tmp_path)
    vault = make_cli_vault(tmp_path)
    vault.add_credential("openai", "sk-1", "api_key")
    _seed_chain(vault)
    wedge_audit(vault)

    from hermes_vault.audit import AuditLogger as _AL

    def failing_record(self, record, **kwargs):
        raise AuditIntegrityError("simulated append failure post-repair")

    monkeypatch.setattr(_AL, "record", failing_record)
    runner = CliRunner()
    result = runner.invoke(
        _hermes_group,
        ["audit-checkpoint", "repair", "--yes", "--reason", "post-commit test"],
        catch_exceptions=False,
    )
    assert result.exit_code == 3, result.output
    assert "committed" in result.output.lower(), result.output
    assert "safety copy" in result.output.lower() or "quarantine id" in result.output.lower()

    # The repair itself is durable: quarantine tables exist and the chain
    # verifies healthy despite the audit-event failure.
    conn = sqlite3.connect(vault.db_path)
    try:
        quarantine = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'quarantine_%' AND name != 'audit_quarantine_manifest'"
        )]
        assert len(quarantine) == 6
    finally:
        conn.close()
    service = AuditIntegrityService(vault.db_path, vault.key)
    assert service.verify().status == AuditIntegrityStatus.healthy


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX dir write bits: chmod 0o500 cannot make a dir unwritable on Windows")
def test_receipt_write_fail_closed(tmp_path: Path) -> None:
    """The receipt writer itself raises ReceiptWriteError on an unwritable dir."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "recovery").mkdir()
    (home / "recovery").chmod(0o500)
    try:
        with pytest.raises(ReceiptWriteError, match="NOT performed"):
            write_restore_receipt(RestoreReceipt(), vault_home=home)
    finally:
        (home / "recovery").chmod(0o700)
