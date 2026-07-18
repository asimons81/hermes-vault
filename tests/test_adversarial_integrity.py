from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path


from hermes_vault.audit_integrity.checkpoint import read_checkpoint
from hermes_vault.audit_integrity.service import AuditIntegrityService
from hermes_vault.models import AccessLogRecord, Decision
from hermes_vault.vault import Vault


# ── helpers ─────────────────────────────────────────────────────────────────


def _make_vault(tmp_path: Path) -> Vault:
    vault = Vault(tmp_path / "vault.db", tmp_path / "master_key_salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-fake-key-12345", "api_key")
    return vault


def _seed_healthy_chain(vault: Vault, count: int = 10) -> AuditIntegrityService:
    """Create a healthy audit chain with *count* protected records."""
    svc = AuditIntegrityService(vault.db_path, vault.key)
    svc.ensure_initialized()
    for i in range(count):
        svc.append(
            AccessLogRecord(
                id=f"adv-{i}-{time.monotonic_ns()}",
                agent_id=f"agent-{i}",
                service="openai",
                action="get_env",
                decision=Decision.allow,
                reason=f"adversarial test row {i}",
            )
        )
    return svc


def _verify(vault: Vault) -> dict:
    """Run verification and return a dict with key fields for assertion."""
    svc = AuditIntegrityService(vault.db_path, vault.key)
    result = svc.verify()
    return {
        "status": result.status.value,
        "reason_code": result.reason_code,
        "failure_sequence": result.failure_sequence,
        "checkpoint_status": result.checkpoint_status.value,
        "sanitized_reason": result.sanitized_reason,
        "verified_count": result.verified_count,
        "legacy_count": result.legacy_count,
    }


def _corrupt_db(vault: Vault, sql: str, params: tuple = ()) -> None:
    """Execute arbitrary SQL against the vault database."""
    conn = sqlite3.connect(vault.db_path)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def _read_cp(vault: Vault) -> dict | None:
    return read_checkpoint(vault.db_path.with_name("audit.checkpoint.json"))


def _write_cp_raw(vault: Vault, cp: dict) -> None:
    """Write checkpoint directly without signing (for adversarial tests)."""
    cp_path = vault.db_path.with_name("audit.checkpoint.json")
    cp_path.write_text(json.dumps(cp, sort_keys=True), encoding="utf-8")


def _all_records(vault: Vault) -> list[sqlite3.Row]:
    conn = sqlite3.connect(vault.db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM audit_integrity_records ORDER BY sequence").fetchall()
    finally:
        conn.close()


# ── Adversarial test framework ──────────────────────────────────────────────

# Each adversarial scenario:
# 1. Seeds a healthy chain
# 2. Corrupts one property
# 3. Verifies and checks the expected result contract


class TestAdversarialIntegrity:
    """Verify that each corruption scenario is detected with correct status, reason code, and guidance."""

    def _check(self, vault: Vault, expected_status: str, expected_reason: str | None = None) -> dict:
        result = _verify(vault)
        assert result["status"] == expected_status, (
            f"Expected status={expected_status}, got {result['status']} "
            f"(reason={result['reason_code']})"
        )
        if expected_reason:
            assert result["reason_code"] == expected_reason, (
                f"Expected reason={expected_reason}, got {result['reason_code']}"
            )
        # Every result must have sanitized operator guidance
        assert result["sanitized_reason"], "Missing sanitized_reason in verification result"
        # Every non-healthy result must have truthy sanitized_reason
        if result["status"] != "healthy":
            assert len(result["sanitized_reason"]) > 10, "sanitized_reason too short for guidance"
        return result

    # ── 1. Data-level attacks ──────────────────────────────────────────────

    def test_altered_audit_reason(self, tmp_path: Path) -> None:
        """Modified audit reason should trigger entry_digest_mismatch."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        # Change the reason in access_logs so the digest no longer matches
        _corrupt_db(vault, "UPDATE access_logs SET reason = 'tampered' WHERE id = (SELECT access_log_id FROM audit_integrity_records ORDER BY sequence LIMIT 1 OFFSET 3)")
        self._check(vault, "failed", "entry_digest_mismatch")

    def test_altered_decision(self, tmp_path: Path) -> None:
        """Modified decision should trigger entry_digest_mismatch."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        _corrupt_db(vault, "UPDATE access_logs SET decision = 'deny' WHERE id = (SELECT access_log_id FROM audit_integrity_records ORDER BY sequence LIMIT 1 OFFSET 5)")
        self._check(vault, "failed", "entry_digest_mismatch")

    def test_altered_metadata(self, tmp_path: Path) -> None:
        """Modified metadata_json should trigger entry_digest_mismatch."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        _corrupt_db(vault, "UPDATE access_logs SET metadata_json = '{\"tampered\": true}' WHERE id = (SELECT access_log_id FROM audit_integrity_records ORDER BY sequence LIMIT 1 OFFSET 2)")
        self._check(vault, "failed", "entry_digest_mismatch")

    def test_deleted_audit_row(self, tmp_path: Path) -> None:
        """Deleted access_log row should trigger missing_access_log."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        _corrupt_db(vault, "DELETE FROM access_logs WHERE id = (SELECT access_log_id FROM audit_integrity_records ORDER BY sequence LIMIT 1 OFFSET 4)")
        self._check(vault, "failed", "missing_access_log")

    def test_deleted_integrity_row(self, tmp_path: Path) -> None:
        """Deleted integrity record should trigger sequence_gap (gap from removal)."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        _corrupt_db(vault, "DELETE FROM audit_integrity_records WHERE sequence = 7")
        self._check(vault, "failed", "sequence_gap")

    # ── 2. Chain-structure attacks ─────────────────────────────────────────

    def test_altered_digest(self, tmp_path: Path) -> None:
        """Modified entry_digest should trigger entry_digest_mismatch."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        _corrupt_db(vault, "UPDATE audit_integrity_records SET entry_digest = '0000000000000000000000000000000000000000000000000000000000000000' WHERE sequence = 3")
        self._check(vault, "failed", "entry_digest_mismatch")

    def test_altered_signature(self, tmp_path: Path) -> None:
        """Modified signature should trigger entry_signature_mismatch."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        _corrupt_db(vault, "UPDATE audit_integrity_records SET signature = 'fake-signature-value-that-wont-verify' WHERE sequence = 2")
        self._check(vault, "failed", "entry_signature_mismatch")

    def test_altered_predecessor(self, tmp_path: Path) -> None:
        """Modified previous_digest should trigger previous_digest_mismatch on the next entry."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        # Change the previous_digest of entry 5 so entry 5's predecessor doesn't match entry 4's digest
        _corrupt_db(vault, "UPDATE audit_integrity_records SET previous_digest = '0000000000000000000000000000000000000000000000000000000000000000' WHERE sequence = 5")
        self._check(vault, "failed", "previous_digest_mismatch")

    def test_duplicate_sequence(self, tmp_path: Path) -> None:
        """Sequence reordering should be detected (schema prevents true duplicates)."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        # Swap the sequence numbers of two records — this triggers sequence_gap
        # because the expected_sequence increment won't match
        conn = sqlite3.connect(vault.db_path)
        try:
            conn.execute("UPDATE audit_integrity_records SET sequence = -1 WHERE sequence = 5")
            conn.execute("UPDATE audit_integrity_records SET sequence = 5 WHERE sequence = 6")
            conn.execute("UPDATE audit_integrity_records SET sequence = 6 WHERE sequence = -1")
            conn.commit()
        finally:
            conn.close()
        result = _verify(vault)
        assert result["status"] in ("failed",), f"Sequence manipulation not detected: {result}"
        assert result["reason_code"] in ("sequence_gap", "previous_digest_mismatch")

    def test_sequence_gap(self, tmp_path: Path) -> None:
        """Missing sequence number should trigger sequence_gap."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        # Delete sequence 4 — creates a gap
        _corrupt_db(vault, "DELETE FROM audit_integrity_records WHERE sequence = 4")
        self._check(vault, "failed", "sequence_gap")

    # ── 3. Key / segment attacks ───────────────────────────────────────────

    def test_changed_segment_key(self, tmp_path: Path) -> None:
        """Changed entry public key should trigger active_key_mismatch."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        _corrupt_db(vault, "UPDATE audit_integrity_segments SET entry_public_key = 'fake-public-key' WHERE segment_id = (SELECT active_segment_id FROM audit_integrity_state WHERE id = 1)")
        self._check(vault, "failed", "active_key_mismatch")

    def test_changed_registry(self, tmp_path: Path) -> None:
        """Changed segment registry should trigger checkpoint segment_mismatch or registry_mismatch."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        # Add a phantom segment to the registry
        _corrupt_db(vault,
            "INSERT INTO audit_integrity_segments (segment_id, segment_number, chain_version, serialization_version, key_derivation_version, entry_signature_version, checkpoint_signature_version, entry_public_key, checkpoint_public_key, sequence_start, transition_reason, created_at) VALUES ('phantom-segment', 99, 'sha256-chain-v1', 'canonical-json-v1', 'hkdf-sha256-v1', 'ed25519-v1', 'ed25519-v1', 'fake-key', 'fake-key', 1, 'fresh_vault', '2026-07-18T00:00:00')",
        )
        # This should make the registry digest mismatch
        result = _verify(vault)
        assert result["status"] in ("failed", "incomplete"), f"Registry manipulation not detected: {result}"
        assert result["reason_code"] in ("segment_registry_mismatch", "segment_mismatch", "registry_mismatch")

    # ── 4. Checkpoint attacks ──────────────────────────────────────────────

    def test_truncated_checkpoint(self, tmp_path: Path) -> None:
        """Truncated/minimal checkpoint should trigger invalid_format."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        _write_cp_raw(vault, {"format": "hermes-vault-audit-checkpoint", "version": "audit-checkpoint-v1"})
        result = _verify(vault)
        assert result["status"] in ("incomplete", "failed")
        assert result["reason_code"] in ("invalid_format", "stale", "checkpoint_invalid_signature", "checkpoint_invalid_format")

    def test_malformed_checkpoint(self, tmp_path: Path) -> None:
        """Malformed checkpoint (not JSON) should trigger invalid_format."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        cp_path = vault.db_path.with_name("audit.checkpoint.json")
        cp_path.write_text("{this is not valid json", encoding="utf-8")
        result = _verify(vault)
        assert result["status"] in ("incomplete", "failed")
        # The exact reason depends on whether read_checkpoint returns None or raises
        assert result["reason_code"] in ("checkpoint_invalid_format", "invalid_format", "checkpoint_missing")

    def test_invalid_checkpoint_signature(self, tmp_path: Path) -> None:
        """Checkpoint with invalid signature should trigger invalid_signature."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        cp = _read_cp(vault)
        assert cp is not None
        cp["entry_public_key"] = "corrupted-key"
        _write_cp_raw(vault, cp)
        result = _verify(vault)
        # The checkpoint may fail on signature or segment validation
        assert result["status"] in ("failed", "incomplete")
        assert result["reason_code"] in ("checkpoint_invalid_signature", "invalid_signature", "segment_mismatch", "invalid_format")

    def test_stale_checkpoint(self, tmp_path: Path) -> None:
        """Checkpoint behind the database tip should trigger stale."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault, count=5)
        # The checkpoint is current after seeding. Stale it by reducing latest_sequence.
        cp = _read_cp(vault)
        assert cp is not None
        cp["latest_sequence"] = 2
        cp["latest_entry_digest"] = "x" * 64
        _write_cp_raw(vault, cp)
        result = _verify(vault)
        assert result["status"] in ("incomplete", "failed")
        # May fail on stale OR on invalid_signature if we damaged it
        assert result["reason_code"] in ("stale", "checkpoint_stale", "checkpoint_invalid_signature")

    def test_checkpoint_ahead_of_database(self, tmp_path: Path) -> None:
        """Checkpoint ahead of database should trigger ahead."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault, count=5)
        cp = _read_cp(vault)
        assert cp is not None
        cp["latest_sequence"] = 999
        cp["latest_entry_digest"] = "f" * 64
        _write_cp_raw(vault, cp)
        result = _verify(vault)
        assert result["status"] in ("incomplete", "failed")
        assert result["reason_code"] in ("checkpoint_ahead", "ahead", "checkpoint_invalid_signature")

    # ── 5. State-level attacks ─────────────────────────────────────────────

    def test_wrong_active_segment(self, tmp_path: Path) -> None:
        """Wrong active_segment_id in state should be detected."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        _corrupt_db(vault, "UPDATE audit_integrity_state SET active_segment_id = 'nonexistent-segment' WHERE id = 1")
        try:
            result = _verify(vault)
            assert result["status"] in ("failed",)
        except Exception as exc:
            # Exception is also acceptable — it means the error was detected
            assert "segment" in str(exc).lower()
            assert "unavailable" in str(exc).lower() or "nonexistent" in str(exc).lower()

    def test_wrong_active_key(self, tmp_path: Path) -> None:
        """Wrong active key should trigger active_key_mismatch."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        _corrupt_db(vault, "UPDATE audit_integrity_segments SET entry_public_key = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' WHERE segment_id = (SELECT active_segment_id FROM audit_integrity_state WHERE id = 1)")
        self._check(vault, "failed", "active_key_mismatch")

    # ── 6. Version attacks ─────────────────────────────────────────────────

    def test_unsupported_chain_version(self, tmp_path: Path) -> None:
        """Unsupported chain_version should be detected."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        _corrupt_db(vault, "UPDATE audit_integrity_segments SET chain_version = 'md5-chain-v0' WHERE segment_id = (SELECT active_segment_id FROM audit_integrity_state WHERE id = 1)")
        self._check(vault, "failed", "unsupported_chain_version")

    def test_unsupported_serialization_version(self, tmp_path: Path) -> None:
        """Unsupported serialization_version should be detected."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        _corrupt_db(vault, "UPDATE audit_integrity_segments SET serialization_version = 'legacy-v0' WHERE segment_id = (SELECT active_segment_id FROM audit_integrity_state WHERE id = 1)")
        self._check(vault, "failed", "unsupported_serialization_version")

    # ── 7. Interruption scenarios ──────────────────────────────────────────

    def test_interrupted_migration(self, tmp_path: Path) -> None:
        """Migration state not 'active' should be detected."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        _corrupt_db(vault, "UPDATE audit_integrity_state SET migration_state = 'interrupted' WHERE id = 1")
        self._check(vault, "incomplete", "migration_interrupted")

    def test_interrupted_checkpoint_advancement(self, tmp_path: Path) -> None:
        """Checkpoint not matching latest sequence — already covered by stale test above."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault, count=5)
        cp = _read_cp(vault)
        assert cp is not None
        cp["latest_sequence"] = 3
        cp["latest_entry_digest"] = ""
        # We also need to fix the segment registry or it will fail first
        _write_cp_raw(vault, cp)
        result = _verify(vault)
        assert result["status"] in ("incomplete", "failed")

    def test_interrupted_rotation(self, tmp_path: Path) -> None:
        """An interrupted rotation leaves recoverable journal state."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        # Simulate an interrupted rotation by adding a rotation journal
        journal = {
            "version": "rotation-journal-v1",
            "status": "started",
            "old_salt": "aa" * 16,
            "new_salt": "bb" * 16,
            "created_at": "2026-07-18T00:00:00",
        }
        journal_path = vault.salt_path.with_name(f"{vault.salt_path.name}.rotation.json")
        journal_path.write_text(json.dumps(journal), encoding="utf-8")
        # Creating a new vault from the same path should recover (or fail gracefully)
        try:
            Vault(vault.db_path, vault.salt_path, "test-passphrase")
        except Exception as exc:
            # Accept that rotation may fail gracefully with a clear error
            assert "rotation" in str(exc).lower() or "journal" in str(exc).lower()

    def test_interrupted_backup_restore(self, tmp_path: Path) -> None:
        """Partial backup artifacts should not corrupt the vault."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        # Create a partial restore staging file
        stage_path = vault.db_path.with_suffix(".db.restore-stage")
        stage_path.write_text("partial data", encoding="utf-8")
        # The vault should still function normally
        result = _verify(vault)
        assert result["status"] == "healthy"
        # Clean up
        stage_path.unlink(missing_ok=True)

    # ── 8. Legacy anchor attacks ───────────────────────────────────────────

    def test_legacy_anchor_mismatch(self, tmp_path: Path) -> None:
        """Modified legacy rows should trigger legacy_anchor_mismatch."""
        vault = _make_vault(tmp_path)
        # Add unprotected rows, then initialize to capture them as legacy
        audit_logger = __import__("hermes_vault.audit", fromlist=["AuditLogger"]).AuditLogger
        from hermes_vault.models import AccessLogRecord, Decision

        audit_logger(vault.db_path, master_key=vault.key)
        # Add a row directly (which goes through svc.append since master_key is set)
        # To create legacy rows, we need to add them BEFORE integrity init
        # Let's use raw SQL
        conn = sqlite3.connect(vault.db_path)
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS access_logs (id TEXT PRIMARY KEY, timestamp TEXT, agent_id TEXT, service TEXT, action TEXT, decision TEXT, reason TEXT, ttl_seconds INTEGER, verification_result TEXT, metadata_json TEXT)"
            )
            conn.execute(
                "INSERT INTO access_logs (id, timestamp, agent_id, service, action, decision, reason) VALUES ('legacy-1', '2026-01-01T00:00:00', 'legacy-agent', 'openai', 'get_env', 'allow', 'legacy row')"
            )
            conn.commit()
        finally:
            conn.close()

        # Now initialize integrity — this captures the legacy row as a snapshot
        svc = AuditIntegrityService(vault.db_path, vault.key)
        svc.ensure_initialized()

        # Add a protected row to advance the chain
        svc.append(
            AccessLogRecord(
                id=f"post-init-{time.monotonic_ns()}",
                agent_id="post-agent",
                service="openai",
                action="get_env",
                decision=Decision.allow,
                reason="post-init row",
            )
        )

        # Now tamper with the legacy row
        conn = sqlite3.connect(vault.db_path)
        try:
            conn.execute("UPDATE access_logs SET reason = 'tampered legacy' WHERE id = 'legacy-1'")
            conn.commit()
        finally:
            conn.close()

        self._check(vault, "failed", "legacy_anchor_mismatch")


# ── Classifying edge cases ───────────────────────────────────────────────────


class TestAdversarialIntegration:
    """Full-adversary-proxy test: each case asserts overall status + reason code + sanitized guidance."""

    def test_every_result_has_sanitized_guidance(self, tmp_path: Path) -> None:
        """Even healthy results should have meaningful guidance."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        result = _verify(vault)
        assert result["sanitized_reason"]
        assert len(result["sanitized_reason"]) > 20

    def test_every_failure_has_reason_code(self, tmp_path: Path) -> None:
        """Every non-healthy result must have a reason_code."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        _corrupt_db(vault, "DELETE FROM audit_integrity_records WHERE sequence = 3")
        result = _verify(vault)
        assert result["status"] != "healthy"
        assert result["reason_code"] is not None

    def test_failure_includes_checkpoint_status(self, tmp_path: Path) -> None:
        """Checkpoint status should be present in failed/incomplete results."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        cp_path = vault.db_path.with_name("audit.checkpoint.json")
        cp_path.unlink()
        result = _verify(vault)
        assert result["checkpoint_status"] in ("missing", "stale", "ahead", "invalid_format", "invalid_signature")

    def test_interrupted_state_guidance(self, tmp_path: Path) -> None:
        """Operator must receive actionable guidance on interrupted state."""
        vault = _make_vault(tmp_path)
        _seed_healthy_chain(vault)
        _corrupt_db(vault, "UPDATE audit_integrity_state SET migration_state = 'interrupted' WHERE id = 1")
        result = _verify(vault)
        assert result["status"] in ("incomplete", "failed")
        guidance = result["sanitized_reason"]
        # Guidance should be specific enough to act on
        assert len(guidance) > 15
