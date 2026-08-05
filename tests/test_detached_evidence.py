"""Slice D (#59) — detached cryptographic verification of hvbackup-v2 evidence.

These tests are RED against the current classifier (structural-only): a v2
backup with tampered audit evidence is reported ``healthy`` because
``_classify_v2_integrity`` never verifies signatures, digests, continuity, the
checkpoint, access-log bindings, or segment key material. Slice D adds a
detached verifier over the exported evidence (no live-DB reads) and makes
``_classify_v2_integrity`` / recovery drill / ``backup-verify`` fail closed.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from click.testing import CliRunner

from hermes_vault.audit_integrity.checkpoint import signed_checkpoint
from hermes_vault.audit_integrity.service import AuditIntegrityService
from hermes_vault.backup import verify_backup_file
from hermes_vault.cli import _hermes_group
from hermes_vault.models import AccessLogRecord, Decision
from hermes_vault.recovery import run_recovery_drill
from hermes_vault.vault import Vault


# ── helpers ─────────────────────────────────────────────────────────────────


def _make_vault_with_chain(tmp_path: Path, count: int = 5) -> Vault:
    """Vault with credentials plus a healthy protected audit chain."""
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-secret-1234567890", "api_key")
    svc = AuditIntegrityService(vault.db_path, vault.key)
    svc.ensure_initialized()
    for i in range(count):
        svc.append(
            AccessLogRecord(
                id=f"det-{i}-{time.monotonic_ns()}",
                agent_id=f"agent-{i}",
                service="openai",
                action="get_env",
                decision=Decision.allow,
                reason=f"detached test record {i}",
            )
        )
    return vault


def _write_v2(path: Path, vault: Vault) -> dict:
    backup = vault.export_backup(include_audit=True)
    path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")
    return backup


# ── record tampering ────────────────────────────────────────────────────────


def test_v2_tampered_signature_fails_verification(tmp_path: Path) -> None:
    vault = _make_vault_with_chain(tmp_path)
    backup = vault.export_backup(include_audit=True)
    backup["audit_integrity"]["records"][2]["signature"] = "not-a-valid-signature"
    backup_path = tmp_path / "tampered-sig.json"
    backup_path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")

    report = verify_backup_file(backup_path, vault)

    assert report.decryptable is True
    assert report.integrity_status == "failed"
    assert report.integrity_reason == "entry_signature_mismatch"


def test_v2_tampered_entry_digest_fails_verification(tmp_path: Path) -> None:
    vault = _make_vault_with_chain(tmp_path)
    backup = vault.export_backup(include_audit=True)
    backup["audit_integrity"]["records"][2]["entry_digest"] = "0" * 64
    backup_path = tmp_path / "tampered-digest.json"
    backup_path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")

    report = verify_backup_file(backup_path, vault)

    assert report.decryptable is True
    assert report.integrity_status == "failed"
    assert report.integrity_reason == "entry_digest_mismatch"


def test_v2_tampered_previous_digest_fails_verification(tmp_path: Path) -> None:
    vault = _make_vault_with_chain(tmp_path)
    backup = vault.export_backup(include_audit=True)
    backup["audit_integrity"]["records"][3]["previous_digest"] = "0" * 64
    backup_path = tmp_path / "tampered-prev.json"
    backup_path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")

    report = verify_backup_file(backup_path, vault)

    assert report.decryptable is True
    assert report.integrity_status == "failed"
    assert report.integrity_reason == "previous_digest_mismatch"


def test_v2_reordered_records_fail_verification(tmp_path: Path) -> None:
    vault = _make_vault_with_chain(tmp_path)
    backup = vault.export_backup(include_audit=True)
    records = backup["audit_integrity"]["records"]
    records[2]["sequence"], records[3]["sequence"] = records[3]["sequence"], records[2]["sequence"]
    backup_path = tmp_path / "reordered.json"
    backup_path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")

    report = verify_backup_file(backup_path, vault)

    assert report.decryptable is True
    assert report.integrity_status == "failed"
    assert report.integrity_reason in ("previous_digest_mismatch", "entry_signature_mismatch", "sequence_gap")


def test_v2_deleted_record_sequence_gap_fails_verification(tmp_path: Path) -> None:
    vault = _make_vault_with_chain(tmp_path)
    backup = vault.export_backup(include_audit=True)
    del backup["audit_integrity"]["records"][2]
    backup_path = tmp_path / "gap.json"
    backup_path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")

    report = verify_backup_file(backup_path, vault)

    assert report.decryptable is True
    assert report.integrity_status == "failed"
    assert report.integrity_reason == "sequence_gap"


# ── checkpoint tampering ────────────────────────────────────────────────────


def test_v2_tampered_checkpoint_signature_fails(tmp_path: Path) -> None:
    vault = _make_vault_with_chain(tmp_path)
    backup = vault.export_backup(include_audit=True)
    backup["audit_integrity"]["checkpoint"]["signature"] = "tampered-signature"
    backup_path = tmp_path / "tampered-cp-sig.json"
    backup_path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")

    report = verify_backup_file(backup_path, vault)

    assert report.decryptable is True
    assert report.integrity_status == "failed"
    assert report.integrity_reason == "checkpoint_invalid_signature"


def test_v2_tampered_checkpoint_tip_fails(tmp_path: Path) -> None:
    vault = _make_vault_with_chain(tmp_path)
    backup = vault.export_backup(include_audit=True)
    # Re-sign a checkpoint whose tip no longer matches the last verified record.
    cp = backup["audit_integrity"]["checkpoint"]
    cp.pop("signature", None)
    cp["latest_entry_digest"] = "0" * 64
    backup["audit_integrity"]["checkpoint"] = signed_checkpoint(cp, vault.key)
    backup_path = tmp_path / "tampered-cp-tip.json"
    backup_path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")

    report = verify_backup_file(backup_path, vault)

    assert report.decryptable is True
    assert report.integrity_status != "healthy"
    assert report.integrity_reason in ("checkpoint_stale", "checkpoint_ahead", "checkpoint_invalid_signature")


# ── access-log bindings ─────────────────────────────────────────────────────


def test_v2_tampered_access_log_field_fails(tmp_path: Path) -> None:
    vault = _make_vault_with_chain(tmp_path)
    backup = vault.export_backup(include_audit=True)
    backup["audit_integrity"]["access_logs"][2]["reason"] = "tampered reason"
    backup_path = tmp_path / "tampered-access-log.json"
    backup_path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")

    report = verify_backup_file(backup_path, vault)

    assert report.decryptable is True
    assert report.integrity_status == "failed"
    assert report.integrity_reason == "entry_digest_mismatch"


def test_v2_missing_access_log_row_fails(tmp_path: Path) -> None:
    vault = _make_vault_with_chain(tmp_path)
    backup = vault.export_backup(include_audit=True)
    removed = backup["audit_integrity"]["records"][2]["access_log_id"]
    backup["audit_integrity"]["access_logs"] = [
        row for row in backup["audit_integrity"]["access_logs"] if row["id"] != removed
    ]
    backup_path = tmp_path / "missing-access-log.json"
    backup_path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")

    report = verify_backup_file(backup_path, vault)

    assert report.decryptable is True
    assert report.integrity_status == "failed"
    assert report.integrity_reason == "missing_access_log"


# ── segment key material ────────────────────────────────────────────────────


def test_v2_tampered_segment_public_key_fails(tmp_path: Path) -> None:
    vault = _make_vault_with_chain(tmp_path, count=3)
    vault.rotate_master_key("test-passphrase", "new-passphrase")
    reopened = Vault(vault.db_path, vault.salt_path, "new-passphrase")
    svc = AuditIntegrityService(reopened.db_path, reopened.key)
    svc.append(
        AccessLogRecord(
            id=f"det-post-rotation-{time.monotonic_ns()}",
            agent_id="agent-post",
            service="openai",
            action="get_env",
            decision=Decision.allow,
            reason="post-rotation record",
        )
    )
    backup = reopened.export_backup(include_audit=True)
    # Tamper key material on the CLOSED (first) segment. The active segment key
    # still matches and record signatures are unaffected (records in segment 1
    # are signed with entry_public_key), so only a registry digest check over
    # the exported segment registry can catch this.
    for seg in backup["audit_integrity"]["segments"]:
        if seg["segment_number"] == 1:
            seg["checkpoint_public_key"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    backup_path = tmp_path / "tampered-segment-key.json"
    backup_path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")

    report = verify_backup_file(backup_path, reopened)

    assert report.decryptable is True
    assert report.integrity_status == "failed"
    assert report.integrity_reason == "segment_registry_mismatch"


# ── valid detached verification ─────────────────────────────────────────────


def test_v2_valid_backup_verifies_detached(tmp_path: Path) -> None:
    vault = _make_vault_with_chain(tmp_path)
    backup = vault.export_backup(include_audit=True)
    evidence = backup["audit_integrity"]

    from hermes_vault.audit_integrity.detached import verify_detached_evidence

    status, reason = verify_detached_evidence(evidence, vault.key)
    assert status == "healthy"
    assert reason is None

    # No live-DB dependency: wipe the database and checkpoint, then verify
    # again using only the exported evidence plus the master key.
    vault.db_path.unlink()
    (tmp_path / "audit.checkpoint.json").unlink()
    status2, reason2 = verify_detached_evidence(evidence, vault.key)
    assert status2 == "healthy"
    assert reason2 is None


def test_v2_missing_evidence_stays_legacy(tmp_path: Path) -> None:
    vault = _make_vault_with_chain(tmp_path)
    backup = vault.export_backup(include_audit=True)
    backup.pop("audit_integrity", None)
    backup_path = tmp_path / "no-evidence.json"
    backup_path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")

    report = verify_backup_file(backup_path, vault)

    assert report.decryptable is True
    assert report.integrity_available is False
    assert report.integrity_status == "legacy"


# ── CLI exit code ───────────────────────────────────────────────────────────


def test_backup_verify_exit_nonzero_on_invalid_evidence(monkeypatch, tmp_path: Path) -> None:
    vault = _make_vault_with_chain(tmp_path)
    backup = vault.export_backup(include_audit=True)
    backup["audit_integrity"]["records"][1]["signature"] = "tampered"
    backup_path = tmp_path / "tampered-v2.json"
    backup_path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")

    def fake_build_services(prompt: bool = False):
        return vault, object(), object(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build_services)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["backup-verify", "--input", str(backup_path), "--format", "json"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["integrity_status"] == "failed"


# ── recovery drill health ───────────────────────────────────────────────────


def test_recovery_drill_not_healthy_on_invalid_evidence(tmp_path: Path) -> None:
    vault = _make_vault_with_chain(tmp_path)
    backup = vault.export_backup(include_audit=True)
    backup["audit_integrity"]["records"][0]["signature"] = "tampered"
    backup_path = tmp_path / "tampered-v2.json"
    backup_path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")

    report = run_recovery_drill(backup_path=backup_path, vault=vault)

    assert report.healthy is False
    assert report.backup_verify["integrity_status"] == "failed"
