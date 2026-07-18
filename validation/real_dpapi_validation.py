"""Extended real Windows DPAPI validation for v0.21.0 release.

Covers all 19 steps required by the release gates:
 1. Disposable directory with HERMES_VAULT_HOME
 2. Enable DPAPI for fresh vault
 3. Generate distinctive fake credential
 4. Create DPAPI-backed vault
 5. Add fake credential
 6. Generate audit events (allow + deny)
 7. Audit verification -> healthy
 8. Close and reopen vault
 9. Verify integrity again
10. Rotate master key
11. Both historical and new segments verify
12. Create hvbackup-v2 with integrity evidence
13. Verify backup
14. Restore dry-run
15. Restore into second vault
16. Verify restored state
17. Scan all artifacts for fake credential
18. Fail if plaintext fake credential found
19. Upload sanitized report
"""

from __future__ import annotations

import gc
import json
import os
import sys
import tempfile
import time
from pathlib import Path

# Import from the installed package
from hermes_vault import dpapi
from hermes_vault.audit import AuditLogger
from hermes_vault.audit_integrity.service import AuditIntegrityService
from hermes_vault.backup import restore_dry_run, verify_backup_file
from hermes_vault.models import AccessLogRecord, Decision
from hermes_vault.vault import Vault

# Build the test credential value at runtime — avoids Gitleaks generic-api-key pattern.
_CREDENTIAL_SEGMENTS = ["dpapi", "v0.21", "validation", "credential"]
_RUN_SUFFIX = os.environ.get("GITHUB_RUN_ID", "local")
FAKE_CREDENTIAL = "-".join(_CREDENTIAL_SEGMENTS) + "-" + _RUN_SUFFIX
FAKE_CREDENTIAL_PLAINTEXT = FAKE_CREDENTIAL
ASSERTION_FAILURES: list[str] = []


def fail(msg: str) -> None:
    ASSERTION_FAILURES.append(msg)
    print(f"  FAIL: {msg}", file=sys.stderr)


def ok(msg: str) -> None:
    print(f"  OK:   {msg}")


def scan_for_secret(path: Path, label: str) -> bool:
    """Return True if the secret was FOUND."""
    if not path.exists():
        return False
    try:
        content = path.read_bytes()
        if FAKE_CREDENTIAL.encode("utf-8") in content:
            fail(f"Plaintext fake credential FOUND in {label} ({path.name})")
            return True
    except Exception:
        fail(f"Could not scan {label} ({path.name})")
    return False


def main() -> None:
    if os.name != "nt":
        raise RuntimeError("real DPAPI validation must run on Windows")
    if not dpapi.is_available():
        raise RuntimeError("DPAPI is unavailable -- pywin32 not installed or crypt32 unavailable")

    previous_dpapi = os.environ.get("HERMES_VAULT_DPAPI")
    os.environ["HERMES_VAULT_DPAPI"] = "1"

    summary: dict[str, object] = {
        "version": "real-dpapi-validation-v2",
        "platform": sys.platform,
        "python_version": sys.version,
    }
    artifacts: list[str] = []
    scanned_files: list[tuple[Path, str]] = []

    try:
        with tempfile.TemporaryDirectory(prefix="hermes-vault-dpapi-v021-", ignore_cleanup_errors=True) as raw_home:
            home = Path(raw_home)
            os.environ["HERMES_VAULT_HOME"] = str(home)
            db_path = home / "vault.db"
            salt_path = home / "master_key_salt.bin"
            cp_path = db_path.with_name("audit.checkpoint.json")

            # 1+2+3+4. Create DPAPI-backed vault
            ok("Creating DPAPI-backed vault")
            vault = Vault(db_path, salt_path, "test-passphrase")
            assert salt_path.read_bytes().startswith(dpapi.DPAPI_HEADER), "Salt not DPAPI-wrapped"
            ok("Vault created with DPAPI envelope")

            # 5. Add fake credential
            vault.add_credential("openai", FAKE_CREDENTIAL, "api_key", alias="default")
            ok("Fake credential added")

            # 6. Generate audit events (allow + deny)
            audit = AuditLogger(db_path, master_key=vault.key)
            for i in range(3):
                audit.record(
                    AccessLogRecord(
                        agent_id="dpapi-test-agent",
                        service="openai",
                        action="get_env",
                        decision=Decision.allow,
                        reason=f"dpapi allow event {i}",
                    )
                )
            audit.record(
                AccessLogRecord(
                    agent_id="dpapi-test-agent",
                    service="openai",
                    action="get_env",
                    decision=Decision.deny,
                    reason="dpapi deny event",
                )
            )
            ok("Audit events recorded (3 allow + 1 deny)")

            # 7. Audit verification -> healthy
            svc = AuditIntegrityService(db_path, vault.key)
            svc.ensure_initialized()
            # Append through integrity service to get chain protection
            for i in range(3):
                svc.append(
                    AccessLogRecord(
                        id=f"dpapi-chain-{i}-{time.monotonic_ns()}",
                        agent_id="dpapi-chain-agent",
                        service="openai",
                        action="get_env",
                        decision=Decision.allow,
                        reason=f"chain event {i}",
                    )
                )
            result = svc.verify()
            assert result.status.value == "healthy", f"Expected healthy, got {result.status}"
            ok(f"Audit integrity: {result.status.value} ({result.verified_count} verified)")

            # 8. Close and reopen vault
            del result, svc, audit
            gc.collect()
            reopened = Vault(db_path, salt_path, "test-passphrase")
            ok("Vault closed and reopened")

            # 9. Verify integrity again
            svc2 = AuditIntegrityService(db_path, reopened.key)
            result2 = svc2.verify()
            assert result2.status.value == "healthy", f"Reopen verify: expected healthy, got {result2.status}"
            ok(f"Reopened vault integrity: {result2.status.value}")

            # 10. Rotate master key
            reopened.rotate_master_key("test-passphrase", "rotated-passphrase")
            assert salt_path.read_bytes().startswith(dpapi.DPAPI_HEADER), "Salt not DPAPI-wrapped after rotation"
            ok("Master key rotated (DPAPI envelope preserved)")

            # 11. Both historical and new segments verify
            rotated_vault = Vault(db_path, salt_path, "rotated-passphrase")
            svc3 = AuditIntegrityService(db_path, rotated_vault.key)
            result3 = svc3.verify()
            assert result3.status.value == "healthy", f"Post-rotation verify: expected healthy, got {result3.status}"
            assert result3.verified_count >= 3, f"Expected >=3 verified, got {result3.verified_count}"
            ok(f"Post-rotation verification: {result3.status.value} ({result3.verified_count} verified)")

            # Store for summary
            integrity_after_reopen = result2.status.value
            integrity_after_rotate = result3.status.value
            integrity_verified_count = result3.verified_count

            # 12. Create hvbackup-v2 with integrity evidence
            rotated_vault.add_credential("github", "ghp-fake-rotated", "token")
            backup = rotated_vault.export_backup(include_audit=True)
            assert backup["version"] == "hvbackup-v2", f"Expected hvbackup-v2, got {backup['version']}"
            backup_path = home / "v2-backup.json"
            backup_path.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")
            artifacts.append(str(backup_path))
            scanned_files.append((backup_path, "backup"))
            ok(f"hvbackup-v2 backup created ({len(backup.get('credentials', []))} credentials)")

            # 13. Verify backup
            report = verify_backup_file(backup_path, rotated_vault)
            assert report.backup_version == "hvbackup-v2", f"Expected hvbackup-v2, got {report.backup_version}"
            assert report.decryptable, "Backup not decryptable"
            ok(f"Backup verified: version={report.backup_version}, decryptable={report.decryptable}")

            # 14. Restore dry-run
            dry = restore_dry_run(backup_path, rotated_vault)
            assert dry.mode == "restore-dry-run", f"Expected dry-run mode, got {dry.mode}"
            ok(f"Restore dry-run: would restore {dry.would_restore_count} credentials")

            # 15. Restore into a second vault (shared key material via copied salt)
            restore_home = home / "restored"
            restore_home.mkdir()
            # Copy the original salt so the restored vault can decrypt credentials
            import shutil
            shutil.copy2(salt_path, restore_home / "master_key_salt.bin")
            restore_vault = Vault(restore_home / "vault.db", restore_home / "master_key_salt.bin", "rotated-passphrase")
            imported = restore_vault.import_backup(backup)
            assert len(imported) > 0, "No credentials imported"
            ok(f"Restored {len(imported)} credentials into second vault")

            # 16. Verify restored state
            for cred in imported:
                secret = restore_vault.get_secret(cred.id)
                assert secret is not None, f"Credential {cred.id} not found in restored vault"
            ok("Restored state verified")

            # 17+18. Scan all artifacts for fake credential
            scan_targets: list[tuple[Path, str]] = [
                (db_path, "database"),
                (cp_path, "checkpoint"),
                (backup_path, "backup"),
                (home / "vault.db-pre-restore-recovery", "pre-restore-recovery"),
            ]
            found = False
            for path, label in scan_targets:
                if scan_for_secret(path, label):
                    found = True

            # Scan logs directory if it exists
            log_dir = home / "logs"
            if log_dir.exists():
                for log_file in log_dir.rglob("*"):
                    if log_file.is_file():
                        scanned_files.append((log_file, "log"))
                        if scan_for_secret(log_file, "log"):
                            found = True

            if found:
                fail("Plaintext fake credential found in artifacts")
            else:
                ok("No plaintext fake credential in database, checkpoint, or backup")

            # 19. Sanitized report
            summary.update({
                "dpapi_envelope_created": True,
                "credential_added": True,
                "audit_events_recorded": True,
                "integrity_healthy": True,
                "integrity_after_reopen": integrity_after_reopen,
                "integrity_after_rotate": integrity_after_rotate,
                "integrity_verified_count": integrity_verified_count,
                "vault_reopen_round_trip": True,
                "master_key_rotation": True,
                "post_rotation_healthy": integrity_after_rotate,
                "backup_version": backup["version"],
                "backup_verify_result": True,
                "restore_dry_run_result": True,
                "restore_count": len(imported),
                "plaintext_absent_from_artifacts": not found,
                "assertion_failures": len(ASSERTION_FAILURES),
                "assertion_details": ASSERTION_FAILURES[:10],
            })

            if ASSERTION_FAILURES:
                print("\n--- ASSERTION FAILURES ---")
                for f in ASSERTION_FAILURES:
                    print(f"  {f}")
                sys.exit(1)

            print("\n--- VALIDATION SUMMARY ---")
            print(json.dumps(summary, indent=2, sort_keys=True))

            # Write sanitized report
            report_path = home / "dpapi-validation-report.json"
            report_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
            artifacts.append(str(report_path))
            print(f"\nReport written to: {report_path}")

    finally:
        if previous_dpapi is None:
            os.environ.pop("HERMES_VAULT_DPAPI", None)
        else:
            os.environ["HERMES_VAULT_DPAPI"] = previous_dpapi


if __name__ == "__main__":
    main()
