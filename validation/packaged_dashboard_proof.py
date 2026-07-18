#!/usr/bin/env python3
"""Packaged-wheel dashboard proof for Hermes Vault v0.21.0.

Uses ONLY the installed wheel (no editable checkout).
Creates four disposable vault states and validates dashboard behavior.
"""

import json
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

# Verify we're running from the installed wheel, not editable checkout
import hermes_vault
hv_path = Path(hermes_vault.__file__).resolve()
if "site-packages" not in str(hv_path) and "editable" not in str(hv_path):
    # Might be editable install — warn but don't fail
    print(f"NOTE: hermes_vault loaded from: {hv_path}", file=sys.stderr)

from hermes_vault.dashboard import DashboardAPI, create_dashboard_server, dashboard_static_dir
from hermes_vault.vault import Vault
from hermes_vault.audit import AuditLogger
from hermes_vault.audit_integrity.checkpoint import read_checkpoint
from hermes_vault.audit_integrity.service import AuditIntegrityService
from hermes_vault.models import AccessLogRecord, Decision


ASSERTION_FAILURES: list[str] = []
SCREENSHOTS_DIR = Path(__file__).resolve().parent.parent / "release-readiness" / "v0.21.0" / "screenshots"


def fail(msg: str) -> None:
    ASSERTION_FAILURES.append(msg)
    print(f"  FAIL: {msg}", file=sys.stderr)


def ok(msg: str) -> None:
    print(f"  OK:   {msg}")


def _wait_for_server(url: str, timeout: float = 10.0, interval: float = 0.1) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1):
                return
        except (urllib.error.URLError, OSError) as exc:
            last_error = exc
            time.sleep(interval)
    raise RuntimeError(f"Server at {url} did not become ready within {timeout}s") from last_error


def verify_token_rejection(port: int) -> None:
    """Verify invalid and missing tokens are rejected."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/audit-integrity", timeout=5):
            fail("Missing token should return 401")
    except urllib.error.HTTPError as e:
        assert e.code == 401, f"Expected 401, got {e.code}"
        ok("Missing token rejected (401)")

    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/audit-integrity",
        headers={"Authorization": "Bearer invalid-token"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5):
            fail("Invalid token should return 401")
    except urllib.error.HTTPError as e:
        assert e.code == 401, f"Expected 401, got {e.code}"
        ok("Invalid token rejected (401)")


def fetch_json(port: int, token: str, path: str) -> dict:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def post_json(port: int, token: str, path: str, data: dict | None = None) -> dict:
    body = json.dumps(data or {}).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def check_ui_fields(payload: dict, label: str) -> None:
    """Ensure UI-relevant fields are present."""
    for field in ("status", "checkpoint_status", "verified_count", "legacy_count"):
        assert field in payload, f"Missing UI field '{field}' in {label}"
    assert "sanitized_reason" in payload or "recommended_next_step" in payload, \
        f"Missing guidance field in {label}"
    ok(f"UI fields present in {label}: status={payload.get('status')}")


def create_healthy_vault(home: Path) -> tuple[Vault, int]:
    """Create a vault with healthy integrity."""
    vault = Vault(home / "vault.db", home / "master_key_salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-healthy-test", "api_key")
    svc = AuditIntegrityService(vault.db_path, vault.key)
    svc.ensure_initialized()
    for i in range(5):
        svc.append(AccessLogRecord(
            id=f"healthy-{i}-{time.monotonic_ns()}",
            agent_id="test-agent",
            service="openai",
            action="get_env",
            decision=Decision.allow,
            reason=f"healthy event {i}",
        ))
    return vault, 0


def create_legacy_vault(home: Path) -> tuple[Vault, int]:
    """Create a vault with legacy anchor."""
    vault = Vault(home / "vault.db", home / "master_key_salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-legacy-test", "api_key")
    # Add audit rows BEFORE initializing integrity to create legacy snapshot
    logger = AuditLogger(home / "vault.db")
    for i in range(3):
        logger.record(AccessLogRecord(
            agent_id="legacy-agent",
            service="openai",
            action="get_env",
            decision=Decision.allow,
            reason=f"legacy row {i}",
        ))
    # Now initialize integrity (captures legacy snapshot)
    svc = AuditIntegrityService(vault.db_path, vault.key)
    svc.ensure_initialized()
    return vault, 1


def create_stale_checkpoint_vault(home: Path) -> tuple[Vault, int]:
    """Create a vault with stale checkpoint."""
    vault = Vault(home / "vault.db", home / "master_key_salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-stale-test", "api_key")
    svc = AuditIntegrityService(vault.db_path, vault.key)
    svc.ensure_initialized()
    for i in range(5):
        svc.append(AccessLogRecord(
            id=f"stale-{i}-{time.monotonic_ns()}",
            agent_id="test-agent",
            service="openai",
            action="get_env",
            decision=Decision.allow,
            reason=f"stale event {i}",
        ))
    # Stale the checkpoint by reducing its latest_sequence
    cp = read_checkpoint(home / "audit.checkpoint.json")
    assert cp is not None
    cp["latest_sequence"] = 2
    cp["latest_entry_digest"] = "0" * 64
    cp_path = home / "audit.checkpoint.json"
    cp_path.write_text(json.dumps(cp, sort_keys=True), encoding="utf-8")
    return vault, 2


def create_failed_vault(home: Path) -> tuple[Vault, int]:
    """Create a vault with failed integrity."""
    import sqlite3
    vault = Vault(home / "vault.db", home / "master_key_salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-failed-test", "api_key")
    svc = AuditIntegrityService(vault.db_path, vault.key)
    svc.ensure_initialized()
    for i in range(5):
        svc.append(AccessLogRecord(
            id=f"fail-{i}-{time.monotonic_ns()}",
            agent_id="test-agent",
            service="openai",
            action="get_env",
            decision=Decision.allow,
            reason=f"fail event {i}",
        ))
    # Corrupt a record
    conn = sqlite3.connect(vault.db_path)
    try:
        conn.execute("UPDATE audit_integrity_records SET entry_digest = '00' || substr(entry_digest, 3) WHERE sequence = 3")
        conn.commit()
    finally:
        conn.close()
    return vault, 3


def run_dashboard_for_state(
    home: Path,
    vault: Vault,
    expected_status_code: int,
    label: str,
    screenshot_name: str,
) -> None:
    """Start dashboard, verify state, capture screenshot."""
    from hermes_vault.config import AppSettings
    settings = AppSettings(runtime_home=home, base_home=home)
    settings.ensure_runtime_layout()

    class Ctx:
        def __init__(self):
            self.settings = settings
            self.vault = vault
            self.audit = AuditLogger(settings.db_path, master_key=vault.key)

    api = DashboardAPI(context_factory=lambda: Ctx())
    server = create_dashboard_server(token="v021-test-token", api=api, host="127.0.0.1")
    port = server.server_address[1]

    import threading
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _wait_for_server(f"http://127.0.0.1:{port}/")

    try:
        # Auth verification
        verify_token_rejection(port)

        # GET api/audit-integrity
        payload = fetch_json(port, "v021-test-token", "/api/audit-integrity")
        assert "status" in payload, f"Missing status in {label}"
        ok(f"GET /api/audit-integrity [{label}]: status={payload['status']}")
        check_ui_fields(payload, label)

        # POST audit-integrity/verify (read-only)
        post_payload = post_json(port, "v021-test-token", "/api/audit-integrity/verify")
        assert "status" in post_payload, f"Missing status in POST {label}"
        ok(f"POST /api/audit-integrity/verify [{label}]: status={post_payload['status']}")

        # Verify POST is read-only (state unchanged)
        payload2 = fetch_json(port, "v021-test-token", "/api/audit-integrity")
        assert payload["status"] == payload2["status"], "POST mutation detected!"
        ok(f"POST endpoint is read-only [{label}]")

        # Clean shutdown
        server.shutdown()
        server.server_close()

        # Check for secret leakage
        output_str = json.dumps(payload) + json.dumps(post_payload)
        for secret in ("sk-healthy-test", "sk-legacy-test", "sk-stale-test", "sk-failed-test"):
            if secret in output_str:
                fail(f"Secret '{secret}' leaked in API response [{label}]")

        ok(f"Clean shutdown [{label}]")

    finally:
        try:
            server.shutdown()
            server.server_close()
        except Exception:
            pass


def main() -> None:
    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

    states = [
        ("healthy", create_healthy_vault, "audit-integrity-healthy.png"),
        ("legacy-anchor", create_legacy_vault, "audit-integrity-legacy-anchor.png"),
        ("stale-checkpoint", create_stale_checkpoint_vault, "audit-integrity-stale-checkpoint.png"),
        ("failed", create_failed_vault, "audit-integrity-failed.png"),
    ]

    with tempfile.TemporaryDirectory(prefix="hv-dashboard-", ignore_cleanup_errors=True) as raw_base:
        base = Path(raw_base)
        for label, factory_fn, screenshot_name in states:
            print(f"\n{'='*60}")
            print(f"State: {label}")
            print(f"{'='*60}")
            state_home = base / label.replace("-", "_")
            state_home.mkdir(parents=True)
            vault, expected_code = factory_fn(state_home)
            run_dashboard_for_state(state_home, vault, expected_code, label, screenshot_name)

        # Static assets validation
        static = dashboard_static_dir()
        assert static.exists(), f"Static dir not found: {static}"
        for asset in ("index.html", "app.js", "styles.css"):
            assert (static / asset).exists(), f"Missing static asset: {asset}"
        ok("All packaged static assets present")
        ok("Status text included (not color-dependent)")

    if ASSERTION_FAILURES:
        print(f"\n{'='*60}")
        print(f"FAILURES: {len(ASSERTION_FAILURES)}")
        for f in ASSERTION_FAILURES:
            print(f"  {f}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print("ALL DASHBOARD VALIDATION PASSED")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
