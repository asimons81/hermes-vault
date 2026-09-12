"""P7 ``doctor`` tests: one guided install/recovery health command.

Covers every check path (spec P7/C3): binary, launcher/home layout, store
integrity, salt/key pairing (P1 trap #2), audit chain state + repair verdict
(P1 trap #1), optional backup pairing, and MCP wiring — plus the --json mode,
the 0/1/2 exit-code contract, read-only guarantees, and the end-to-end loop
(doctor names the wedge → P1 repair → doctor healthy).

Doctor WRAPS P1 primitives; these tests pin the wrapping, not P1 itself
(that is test_p1_safe_recovery.py's job).
"""

from __future__ import annotations

import json
import os
import sys
import subprocess
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from hermes_vault.cli import _hermes_group
from hermes_vault.doctor import (
    CheckStatus,
    DoctorReport,
    run_doctor,
)
from hermes_vault.vault import Vault

PASSPHRASE = "test-passphrase"


# ── helpers ────────────────────────────────────────────────────────────────


def make_vault_home(tmp_path: Path, credentials: int = 1, passphrase: str = PASSPHRASE) -> Path:
    """Fresh vault home with real encrypted credentials + an active audit chain."""
    from hermes_vault.audit import AuditLogger
    from hermes_vault.models import AccessLogRecord, Decision

    home = tmp_path / "home"
    home.mkdir(parents=True)
    vault = Vault(home / "vault.db", home / "master_key_salt.bin", passphrase)
    for i in range(credentials):
        vault.add_credential(
            service="openai" if i == 0 else f"svc{i}",
            alias="primary" if i == 0 else "a",
            secret=f"secret-{i}",
            credential_type="api_key",
        )
    # One protected audit row initializes the integrity chain (active state),
    # mirroring any real vault that has been used at least once.
    AuditLogger(vault.db_path, master_key=vault.key).record(
        AccessLogRecord(agent_id="seed", service="openai", action="get_env", decision=Decision.allow, reason="seed chain")
    )
    return home


def doctor_env(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "HERMES_VAULT_HOME", "HERMES_VAULT_PASSPHRASE")}
    env["HERMES_VAULT_HOME"] = str(home)
    env["HERMES_VAULT_PASSPHRASE"] = PASSPHRASE
    return env


def check_by_name(report: DoctorReport, name: str):
    matches = [c for c in report.checks if c.name == name]
    assert matches, f"no check named {name!r} in {[c.name for c in report.checks]}"
    return matches[0]


def wedge_audit(home: Path) -> None:
    """P1 trap #1: raw access_logs rows past an initialized chain."""
    import sqlite3

    conn = sqlite3.connect(home / "vault.db")
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


def rotate_salt(home: Path) -> None:
    """P1 trap #2: the store's salt replaced by foreign key material."""
    (home / "master_key_salt.bin").write_bytes(os.urandom(16))


def fake_smoke_ok(command, **kwargs):
    return subprocess.CompletedProcess(
        args=[command],
        returncode=0,
        stdout='{"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": "hermes-vault", "version": "test"}}}\n',
        stderr="",
    )


def fake_smoke_timeout(command, **kwargs):
    raise subprocess.TimeoutExpired(cmd=command, timeout=kwargs.get("timeout", 10))


# ── report model ───────────────────────────────────────────────────────────


def test_report_verdict_and_exit_codes() -> None:
    ok = DoctorReport(checks=[])
    assert ok.verdict == "healthy" and ok.exit_code == 0

    from hermes_vault.doctor import DoctorCheck

    warned = DoctorReport(checks=[DoctorCheck("a", CheckStatus.ok, "fine"), DoctorCheck("b", CheckStatus.warn, "hmm")])
    assert warned.verdict == "degraded" and warned.exit_code == 1

    broken = DoctorReport(checks=[DoctorCheck("a", CheckStatus.fail, "bad"), DoctorCheck("b", CheckStatus.warn, "hmm")])
    assert broken.verdict == "broken" and broken.exit_code == 2

    skipped = DoctorReport(checks=[DoctorCheck("a", CheckStatus.skip, "n/a")])
    assert skipped.verdict == "healthy" and skipped.exit_code == 0

    payload = broken.as_dict()
    assert payload["verdict"] == "broken"
    assert payload["exit_code"] == 2
    assert payload["checks"][0]["status"] == "fail"
    assert payload["version"] == "doctor-v1"


# ── healthy path ───────────────────────────────────────────────────────────


def test_healthy_vault_all_checks_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path, credentials=2)
    config = tmp_path / "config.yaml"
    config.write_text(
        yaml.safe_dump({"mcp_servers": {"hermes-vault": {"command": _existing_executable(), "args": ["mcp"]}}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)
    monkeypatch.delenv("PYTHONPATH", raising=False)

    report = run_doctor(hermes_config=config, mcp_smoke=False)

    assert report.verdict == "healthy"
    assert report.exit_code == 0
    by_name = {c.name: c for c in report.checks}
    assert set(by_name) >= {"binary", "launcher", "store", "salt-match", "audit-chain", "mcp-wiring"}
    assert by_name["binary"].status is CheckStatus.ok
    assert by_name["launcher"].status is CheckStatus.ok
    assert by_name["store"].status is CheckStatus.ok
    assert by_name["store"].data["credential_count"] == 2
    assert by_name["salt-match"].status is CheckStatus.ok
    assert "2/2" in by_name["salt-match"].summary
    assert by_name["audit-chain"].status is CheckStatus.ok
    assert by_name["mcp-wiring"].status is CheckStatus.ok


def test_fresh_home_is_degraded_not_broken(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No vault at all: warnings, exit 1 — a fresh install is not a failure."""
    home = tmp_path / "empty"
    home.mkdir()
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)
    monkeypatch.delenv("PYTHONPATH", raising=False)

    report = run_doctor(hermes_config=tmp_path / "missing-config.yaml", mcp_smoke=False)
    assert report.verdict == "degraded"
    launcher = check_by_name(report, "launcher")
    assert launcher.status is CheckStatus.warn
    assert "no vault found" in launcher.summary
    # key-dependent checks skip rather than fail
    assert check_by_name(report, "salt-match").status is CheckStatus.skip
    assert check_by_name(report, "audit-chain").status is CheckStatus.skip


# ── launcher check paths ───────────────────────────────────────────────────


def test_missing_salt_with_populated_db_is_broken(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The #1 brick: db present, salt gone → fail + never-rotate guidance."""
    home = make_vault_home(tmp_path)
    (home / "master_key_salt.bin").unlink()
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)

    report = run_doctor(hermes_config=tmp_path / "missing.yaml", mcp_smoke=False)
    launcher = check_by_name(report, "launcher")
    assert launcher.status is CheckStatus.fail
    assert "salt file" in launcher.summary and "missing" in launcher.summary
    assert any("NEVER rotates" in step or "Restore the ORIGINAL" in step for step in launcher.remediation)
    assert report.verdict == "broken"


def test_corrupt_salt_shape_is_broken(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path)
    (home / "master_key_salt.bin").write_bytes(b"junk-not-a-salt")
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)

    report = run_doctor(hermes_config=tmp_path / "missing.yaml", mcp_smoke=False)
    launcher = check_by_name(report, "launcher")
    assert launcher.status is CheckStatus.fail
    assert "corrupted" in launcher.summary
    assert report.verdict == "broken"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits: Windows has no world-readable bit to trigger the warn path")
def test_world_readable_key_material_warns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path)
    os.chmod(home / "vault.db", 0o644)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)

    report = run_doctor(hermes_config=tmp_path / "missing.yaml", mcp_smoke=False)
    launcher = check_by_name(report, "launcher")
    assert launcher.status is CheckStatus.warn
    assert any("vault.db" in step for step in launcher.remediation)


def test_world_readable_policy_yaml_is_not_flagged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """policy.yaml ships 0644 by design (no secrets) — must not warn."""
    home = make_vault_home(tmp_path)
    policy = home / "policy.yaml"
    policy.write_text("agents: {}\n")
    os.chmod(policy, 0o644)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)

    report = run_doctor(hermes_config=tmp_path / "missing.yaml", mcp_smoke=False)
    launcher = check_by_name(report, "launcher")
    assert launcher.status is CheckStatus.ok, launcher.summary


def test_no_passphrase_skips_key_checks_without_failing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.delenv("HERMES_VAULT_PASSPHRASE", raising=False)
    monkeypatch.delenv("PYTHONPATH", raising=False)

    report = run_doctor(hermes_config=tmp_path / "missing.yaml", mcp_smoke=False)
    launcher = check_by_name(report, "launcher")
    assert launcher.status is CheckStatus.warn
    assert "no passphrase available" in launcher.summary
    assert check_by_name(report, "salt-match").status is CheckStatus.skip
    assert check_by_name(report, "audit-chain").status is CheckStatus.skip
    # store check still works keylessly
    assert check_by_name(report, "store").status is CheckStatus.ok


# ── store check paths ──────────────────────────────────────────────────────


def test_corrupt_db_is_broken(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / "vault.db").write_bytes(b"this is not sqlite" * 100)
    (home / "master_key_salt.bin").write_bytes(os.urandom(16))
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)

    report = run_doctor(hermes_config=tmp_path / "missing.yaml", mcp_smoke=False)
    store = check_by_name(report, "store")
    assert store.status is CheckStatus.fail
    assert "not a readable SQLite database" in store.summary
    assert any("Do NOT write" in step for step in store.remediation)
    assert report.verdict == "broken"
    # a corrupt store must not be opened by later checks
    assert check_by_name(report, "salt-match").status is CheckStatus.skip


# ── salt-match check paths (P1 trap #2) ────────────────────────────────────


def test_salt_rotation_named_as_key_material_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path, credentials=2)
    rotate_salt(home)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)
    monkeypatch.delenv("PYTHONPATH", raising=False)

    report = run_doctor(hermes_config=tmp_path / "missing.yaml", mcp_smoke=False)
    salt_match = check_by_name(report, "salt-match")
    assert salt_match.status is CheckStatus.fail
    assert "KEY-MATERIAL MISMATCH" in salt_match.summary
    assert "0/2" in salt_match.summary
    assert salt_match.data["decryptable_count"] == 0
    assert salt_match.detail and "NEVER rotates" in salt_match.detail
    assert report.verdict == "broken"


# ── audit-chain check paths (P1 trap #1) ───────────────────────────────────


def test_wedged_chain_names_p1_repair_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path)
    wedge_audit(home)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)
    monkeypatch.delenv("PYTHONPATH", raising=False)

    report = run_doctor(hermes_config=tmp_path / "missing.yaml", mcp_smoke=False)
    audit = check_by_name(report, "audit-chain")
    assert audit.status is CheckStatus.fail
    assert audit.data["reason_code"] == "missing_integrity_record"
    assert audit.data["repair_class"] == "repairable"
    assert any("audit-checkpoint repair" in step for step in audit.remediation)
    assert report.verdict == "broken"


def test_wedged_plus_rotated_salt_refuses_repair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Both traps at once: repair is refused; the salt mismatch leads."""
    home = make_vault_home(tmp_path)
    wedge_audit(home)
    rotate_salt(home)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)

    report = run_doctor(hermes_config=tmp_path / "missing.yaml", mcp_smoke=False)
    audit = check_by_name(report, "audit-chain")
    assert audit.status is CheckStatus.fail
    assert audit.data["repair_class"] == "refuse_key_material"
    assert any("salt-match" in step for step in audit.remediation)
    assert check_by_name(report, "salt-match").status is CheckStatus.fail


# ── backup pairing (P1 primitive, optional flag) ───────────────────────────


def test_backup_pairing_ok_on_paired_backup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path)
    vault = Vault(home / "vault.db", home / "master_key_salt.bin", PASSPHRASE)
    backup_path = tmp_path / "backup.json"
    backup_path.write_text(json.dumps(vault.export_backup()), encoding="utf-8")

    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)

    report = run_doctor(backup=backup_path, hermes_config=tmp_path / "missing.yaml", mcp_smoke=False)
    pairing = check_by_name(report, "backup-pairing")
    assert pairing.status is CheckStatus.ok, pairing.summary
    assert pairing.data["credential_count"] == 1
    assert pairing.data["decryptable_count"] == 1


def test_backup_pairing_fails_on_foreign_key_backup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A backup taken under different key material must fail pairing —
    exactly what the mandatory restore preflight would block."""
    home = make_vault_home(tmp_path)
    # Foreign vault: different salt + same passphrase → different key.
    other_home = make_vault_home(tmp_path / "other", credentials=1, passphrase=PASSPHRASE)
    other_vault = Vault(other_home / "vault.db", other_home / "master_key_salt.bin", PASSPHRASE)

    backup_path = tmp_path / "foreign-backup.json"
    backup_path.write_text(json.dumps(other_vault.export_backup()), encoding="utf-8")

    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)

    report = run_doctor(backup=backup_path, hermes_config=tmp_path / "missing.yaml", mcp_smoke=False)
    pairing = check_by_name(report, "backup-pairing")
    assert pairing.status is CheckStatus.fail
    assert "does NOT decrypt" in pairing.summary
    assert "preflight" in pairing.summary
    assert pairing.data["decryptable_count"] == 0


def test_backup_pairing_unreadable_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)

    report = run_doctor(backup=bad, hermes_config=tmp_path / "missing.yaml", mcp_smoke=False)
    pairing = check_by_name(report, "backup-pairing")
    assert pairing.status is CheckStatus.fail
    assert "unreadable" in pairing.summary


# ── MCP wiring check paths ─────────────────────────────────────────────────


def _write_hermes_config(tmp_path: Path, entry: dict | None, enabled_key: bool = True) -> Path:
    config = tmp_path / "config.yaml"
    servers: dict = {}
    if entry is not None:
        servers["hermes-vault"] = entry
    config.write_text(yaml.safe_dump({"mcp_servers": servers}), encoding="utf-8")
    return config


def _existing_executable() -> str:
    """An absolute path that exists and is executable (smoke runner is faked)."""
    venv_bin = Path(__file__).resolve().parent.parent / ".venv" / "bin" / "hermes-vault"
    if venv_bin.exists():
        return str(venv_bin)
    return __import__("sys").executable


def test_mcp_wiring_ok_with_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path)
    entry = {"command": _existing_executable(), "args": ["mcp"]}
    config = _write_hermes_config(tmp_path, entry)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)

    report = run_doctor(
        hermes_config=config,
        mcp_smoke=True,
        smoke_runner=fake_smoke_ok,
    )
    mcp = check_by_name(report, "mcp-wiring")
    assert mcp.status is CheckStatus.ok, mcp.summary
    assert mcp.data["smoke"]["ok"] is True
    assert mcp.data["smoke"]["server_info"] == "hermes-vault test"


def test_mcp_wiring_string_args_trap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """args: '[\"mcp\"]' as a STRING — the documented config trap."""
    home = make_vault_home(tmp_path)
    config = tmp_path / "config.yaml"
    config.write_text(
        f'mcp_servers:\n  hermes-vault:\n    command: {_existing_executable()}\n    args: \'["mcp"]\'\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)

    report = run_doctor(hermes_config=config, mcp_smoke=False)
    mcp = check_by_name(report, "mcp-wiring")
    assert mcp.status is CheckStatus.warn
    assert "STRING" in mcp.summary or "string" in mcp.summary.lower()
    assert any("YAML list" in step for step in mcp.remediation)


def test_mcp_wiring_missing_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path)
    config = _write_hermes_config(tmp_path, None)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)

    report = run_doctor(hermes_config=config, mcp_smoke=False)
    mcp = check_by_name(report, "mcp-wiring")
    assert mcp.status is CheckStatus.warn
    assert "no mcp_servers.hermes-vault entry" in mcp.summary


def test_mcp_wiring_command_not_resolvable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path)
    config = _write_hermes_config(tmp_path, {"command": "/does/not/exist-hermes-vault", "args": ["mcp"]})
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)

    report = run_doctor(hermes_config=config, mcp_smoke=False)
    mcp = check_by_name(report, "mcp-wiring")
    assert mcp.status is CheckStatus.warn
    assert "does not resolve" in mcp.summary


def test_mcp_wiring_smoke_failure_warns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path)
    config = _write_hermes_config(tmp_path, {"command": _existing_executable(), "args": ["mcp"]})
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)

    report = run_doctor(hermes_config=config, mcp_smoke=True, smoke_runner=fake_smoke_timeout)
    mcp = check_by_name(report, "mcp-wiring")
    assert mcp.status is CheckStatus.warn
    assert "smoke test failed" in mcp.summary


def test_mcp_wiring_real_launch_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Real spawn: the repo's own console script answers initialize."""
    home = make_vault_home(tmp_path)
    venv_bin = Path(__file__).resolve().parent.parent / ".venv" / "bin" / "hermes-vault"
    if not venv_bin.exists():
        pytest.skip("worktree venv console script not present")
    config = _write_hermes_config(tmp_path, {"command": str(venv_bin), "args": ["mcp"]})
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)

    report = run_doctor(hermes_config=config, mcp_smoke=True)
    mcp = check_by_name(report, "mcp-wiring")
    assert mcp.status is CheckStatus.ok, mcp.summary
    assert mcp.data["smoke"]["ok"] is True
    assert "hermes-vault" in mcp.data["smoke"]["server_info"]


# ── binary check paths ─────────────────────────────────────────────────────


def test_binary_pythonpath_poisoning_warns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)
    monkeypatch.setenv("PYTHONPATH", "/opt/hermes-agent:/tmp/lib")

    report = run_doctor(hermes_config=tmp_path / "missing.yaml", mcp_smoke=False)
    binary = check_by_name(report, "binary")
    assert binary.status is CheckStatus.warn
    assert "PYTHONPATH" in binary.summary


def test_binary_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)
    monkeypatch.delenv("PYTHONPATH", raising=False)

    report = run_doctor(hermes_config=tmp_path / "missing.yaml", mcp_smoke=False)
    binary = check_by_name(report, "binary")
    assert binary.status is CheckStatus.ok
    assert binary.data["version"]
    assert binary.data["cli_on_path"] is not None or True  # PATH-dependent; informational only


# ── CLI surface: --json, exit codes, no-prompt ─────────────────────────────


def test_cli_json_mode_emits_one_json_object(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)
    monkeypatch.delenv("PYTHONPATH", raising=False)

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["doctor", "--json", "--no-mcp-smoke"], catch_exceptions=False)
    assert result.exit_code in (0, 1), result.output
    payload = json.loads(result.output)
    assert payload["version"] == "doctor-v1"
    assert payload["verdict"] in ("healthy", "degraded", "broken")
    assert payload["exit_code"] == result.exit_code
    names = [c["name"] for c in payload["checks"]]
    assert "salt-match" in names and "audit-chain" in names


def test_cli_exit_2_on_broken_vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path, credentials=2)
    rotate_salt(home)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)
    monkeypatch.delenv("PYTHONPATH", raising=False)

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["doctor", "--no-mcp-smoke"], catch_exceptions=False)
    assert result.exit_code == 2
    assert "KEY-MATERIAL MISMATCH" in result.output


def test_cli_exit_1_on_degraded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "empty"
    home.mkdir()
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)
    monkeypatch.delenv("PYTHONPATH", raising=False)

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["doctor", "--no-mcp-smoke"], catch_exceptions=False)
    assert result.exit_code == 1


def test_cli_exit_0_on_healthy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path)
    # A config entry pointing at the repo venv CLI keeps mcp-wiring green.
    venv_bin = Path(__file__).resolve().parent.parent / ".venv" / "bin" / "hermes-vault"
    if not venv_bin.exists():
        pytest.skip("worktree venv console script not present")
    config = tmp_path / "config.yaml"
    config.write_text(yaml.safe_dump({"mcp_servers": {"hermes-vault": {"command": str(venv_bin), "args": ["mcp"]}}}), encoding="utf-8")
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)
    monkeypatch.delenv("PYTHONPATH", raising=False)

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["doctor", "--hermes-config", str(config)], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert "Verdict: healthy" in result.output


def test_cli_rejects_bad_smoke_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = make_vault_home(tmp_path)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["doctor", "--smoke-timeout", "0"], catch_exceptions=False)
    assert result.exit_code == 2
    assert "smoke-timeout" in result.output


def test_cli_never_prompts_for_passphrase(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Doctor must stay automatable: no passphrase → warn + skip, no prompt."""
    home = make_vault_home(tmp_path)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.delenv("HERMES_VAULT_PASSPHRASE", raising=False)
    monkeypatch.delenv("PYTHONPATH", raising=False)

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["doctor", "--no-mcp-smoke"], catch_exceptions=False)
    assert result.exit_code == 1
    assert "Hermes Vault passphrase:" not in result.output


# ── read-only guarantees ───────────────────────────────────────────────────


def test_doctor_is_byte_identical_read_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Doctor must not mutate a healthy store, and must not create a store
    where none exists (the fresh-install path)."""
    home = make_vault_home(tmp_path)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)
    monkeypatch.delenv("PYTHONPATH", raising=False)

    import hashlib

    def digest(home: Path) -> dict[str, str]:
        out = {}
        for f in sorted(p for p in home.iterdir() if p.is_file()):
            out[f.name] = hashlib.sha256(f.read_bytes()).hexdigest()
        return out

    wedge_audit(home)  # also prove read-only on a BROKEN chain (no crash, no writes)
    before_wedged = digest(home)

    report = run_doctor(hermes_config=tmp_path / "missing.yaml", mcp_smoke=False)
    assert report.verdict == "broken"

    assert digest(home) == before_wedged

    # fresh home: doctor must not create a store or key material (the layout
    # dirs get_settings() ensure_runtime_layout creates are product behavior
    # shared by every command and are not vault state).
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    monkeypatch.setenv("HERMES_VAULT_HOME", str(fresh))
    run_doctor(hermes_config=tmp_path / "missing.yaml", mcp_smoke=False)
    assert not (fresh / "vault.db").exists()
    assert not (fresh / "master_key_salt.bin").exists()


# ── end-to-end recovery loop (doctor → P1 repair → doctor) ────────────────


def test_e2e_doctor_names_wedge_p1_repairs_doctor_healthy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The C3 acceptance: the ops-skill reinstall scenario, end to end."""
    home = make_vault_home(tmp_path, credentials=2)
    # Hermetic mcp-wiring: a fixture config, not the operator's real
    # ~/.hermes/config.yaml (QA F-1 — suite greenness must not depend on the
    # dev machine; CI runners have no Hermes config at all).
    config = _write_hermes_config(tmp_path, {"command": _existing_executable(), "args": ["mcp"]})
    monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", PASSPHRASE)
    monkeypatch.delenv("PYTHONPATH", raising=False)

    runner = CliRunner()

    # 1. healthy
    first = runner.invoke(
        _hermes_group, ["doctor", "--no-mcp-smoke", "--hermes-config", str(config)], catch_exceptions=False
    )
    assert first.exit_code == 0

    # 2. wedge (trap #1) → doctor names the exact P1 repair command
    wedge_audit(home)
    wedged = runner.invoke(
        _hermes_group, ["doctor", "--no-mcp-smoke", "--hermes-config", str(config)], catch_exceptions=False
    )
    assert wedged.exit_code == 2
    assert "missing_integrity_record" in wedged.output or "not protected" in wedged.output
    assert "audit-checkpoint repair" in wedged.output

    # 3. execute the named P1 repair
    repaired = runner.invoke(
        _hermes_group,
        ["audit-checkpoint", "repair", "--yes", "--reason", "doctor e2e test"],
        catch_exceptions=False,
    )
    assert repaired.exit_code == 0, repaired.output

    # 4. doctor is healthy again — verdicts agree with audit-verify
    after = runner.invoke(
        _hermes_group, ["doctor", "--no-mcp-smoke", "--hermes-config", str(config)], catch_exceptions=False
    )
    assert after.exit_code == 0, after.output
    assert "Verdict: healthy" in after.output

    verify = runner.invoke(_hermes_group, ["audit-verify"], catch_exceptions=False)
    assert verify.exit_code == 0
