"""P7 ``doctor``: one guided install/recovery health command.

Doctor WRAPS the P1 safe-recovery primitives — ``store_decryptability``,
``classify_repairability``, ``prove_backup_decryptable``, the salt
fingerprints — plus read-only inspection of the install, the launcher
environment, the store files, the audit chain, and the MCP wiring. It owns
NO recovery logic of its own: every repair path it names is an existing P1
command (``audit-checkpoint repair``, the restore preflight, the salt
guidance).

Doctor is read-only by construction:

* it never opens the vault with a creating constructor unless the store
  already passed a SQLite integrity check,
* it never writes audit rows (a wedged chain must not crash the doctor),
* the optional MCP smoke test performs only the JSON-RPC ``initialize``
  handshake — the lazy broker (P4) means no unlock happens.

Exit codes: 0 healthy / 1 degraded / 2 broken.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

import yaml
from rich.console import Console
from rich.table import Table

from hermes_vault.config import AppSettings, get_settings

if TYPE_CHECKING:
    from hermes_vault.vault import Vault

DOCTOR_REPORT_VERSION = "doctor-v1"

EXIT_HEALTHY = 0
EXIT_DEGRADED = 1
EXIT_BROKEN = 2

DEFAULT_HERMES_CONFIG = Path("~/.hermes/config.yaml")
MCP_SERVER_KEY = "hermes-vault"
SMOKE_TIMEOUT_DEFAULT = 10.0

# The JSON-RPC initialize handshake (lazy broker: no unlock, no credentials).
_SMOKE_INITIALIZE = (
    '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": '
    '{"protocolVersion": "2025-06-18", "capabilities": {}, '
    '"clientInfo": {"name": "hv-doctor", "version": "doctor"}}}\n'
)


class CheckStatus(StrEnum):
    ok = "ok"
    warn = "warn"
    fail = "fail"
    skip = "skip"


@dataclass
class DoctorCheck:
    name: str
    status: CheckStatus
    summary: str
    detail: str | None = None
    remediation: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class DoctorReport:
    version: str = DOCTOR_REPORT_VERSION
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    vault_home: str | None = None
    hermes_vault_version: str | None = None
    checks: list[DoctorCheck] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        statuses = {check.status for check in self.checks}
        if CheckStatus.fail in statuses:
            return "broken"
        if CheckStatus.warn in statuses:
            return "degraded"
        return "healthy"

    @property
    def exit_code(self) -> int:
        return {"healthy": EXIT_HEALTHY, "degraded": EXIT_DEGRADED, "broken": EXIT_BROKEN}[self.verdict]

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "generated_at": self.generated_at.isoformat(),
            "verdict": self.verdict,
            "exit_code": self.exit_code,
            "vault_home": self.vault_home,
            "hermes_vault_version": self.hermes_vault_version,
            "checks": [
                {
                    "name": check.name,
                    "status": check.status.value,
                    "summary": check.summary,
                    "detail": check.detail,
                    "remediation": list(check.remediation),
                    "data": check.data,
                }
                for check in self.checks
            ],
        }


# ── Check: binary ──────────────────────────────────────────────────────────


def _check_binary() -> DoctorCheck:
    """The installed package imports, its version is readable, and the
    environment does not show the documented PYTHONPATH-poisoning pattern."""
    from hermes_vault import update as hv_update

    data: dict[str, Any] = {"python": sys.executable}

    try:
        version = hv_update.get_current_version()
    except Exception as exc:  # pragma: no cover - defensive: CLI is running, so import worked
        return DoctorCheck(
            name="binary",
            status=CheckStatus.warn,
            summary=f"installed hermes-vault version could not be determined ({exc})",
            remediation=["Reinstall with: uv tool install --force git+<released tag>"],
            data=data,
        )

    import hermes_vault

    data["version"] = version
    data["module"] = str(Path(hermes_vault.__file__).parent)
    data["cli_on_path"] = shutil.which("hermes-vault")

    pythonpath = os.environ.get("PYTHONPATH", "")
    data["pythonpath"] = pythonpath or None
    if pythonpath and ("hermes-agent" in pythonpath or "hermes_agent" in pythonpath):
        return DoctorCheck(
            name="binary",
            status=CheckStatus.warn,
            summary=(
                "PYTHONPATH contains hermes-agent entries — the documented "
                "dependency-poisoning friction (pydantic/cryptography mismatches)"
            ),
            detail=f"PYTHONPATH={pythonpath}",
            remediation=[
                'Run via a clean environment (env -u PYTHONPATH ...) or the canonical launcher (export PYTHONPATH="").',
            ],
            data=data,
        )

    return DoctorCheck(
        name="binary",
        status=CheckStatus.ok,
        summary=f"hermes-vault {version} imports cleanly",
        data=data,
    )


# ── Check: launcher / environment layout ───────────────────────────────────


def _check_launcher(settings: AppSettings, passphrase: str | None, passphrase_source: str | None) -> DoctorCheck:
    """Vault home layout, db/salt file pairing, permissions, passphrase source."""
    home = settings.runtime_home
    db = settings.db_path
    salt = settings.salt_path
    data: dict[str, Any] = {
        "vault_home": str(home),
        "hermes_vault_home_env": os.environ.get("HERMES_VAULT_HOME"),
        "db_path": str(db),
        "salt_path": str(salt),
        "policy_path": str(settings.effective_policy_path),
        "passphrase_source": passphrase_source,
    }
    warnings: list[str] = []
    remediation: list[str] = []

    if not db.exists() and not salt.exists():
        return DoctorCheck(
            name="launcher",
            status=CheckStatus.warn,
            summary=f"no vault found at {home} — fresh install (nothing to recover, nothing proven)",
            remediation=[
                "Add the first credential (hermes-vault add <service>) or restore a verified backup.",
            ],
            data=data,
        )

    # Trap guard: a populated store without its paired salt is the #1 brick.
    if db.exists() and not salt.exists():
        return DoctorCheck(
            name="launcher",
            status=CheckStatus.fail,
            summary=f"vault database exists at {db} but the salt file {salt} is missing",
            detail=(
                "The master key cannot be re-derived: hermes-vault never rotates "
                "master_key_salt.bin automatically, and a new salt would NOT open the store."
            ),
            remediation=[
                "Restore the ORIGINAL master_key_salt.bin that pairs with this database (check *.bak-* / pre-repair safety copies).",
                "Never delete vault.db to 'fix' this — see docs/safe-recovery.md.",
            ],
            data=data,
        )
    if salt.exists() and not db.exists():
        warnings.append(f"salt file present at {salt} but no vault database at {db}")

    # Salt file shape (read-only pre-check; Vault re-validates on open).
    if salt.exists():
        from hermes_vault.crypto import DPAPI_HEADER, SALT_SIZE

        raw = salt.read_bytes()
        if len(raw) != SALT_SIZE and not raw.startswith(DPAPI_HEADER):
            return DoctorCheck(
                name="launcher",
                status=CheckStatus.fail,
                summary=f"salt file {salt} is corrupted (size {len(raw)}; expected {SALT_SIZE} bytes or a DPAPI envelope)",
                remediation=[
                    "Restore the paired salt file from safety copies; the store cannot be opened with wrong key material.",
                ],
                data=data,
            )
        data["salt_fingerprint"] = _salt_fingerprint(salt)

    # File/directory permissions (POSIX only). Only the key-material files
    # are checked: the product itself writes policy.yaml 0644 (it holds no
    # secrets), so warning there would flag every healthy install.
    if os.name == "posix":
        from hermes_vault.permissions import mode_is_insecure

        for path in [db, salt]:
            if path.exists() and mode_is_insecure(path):
                warnings.append(f"{path} has group/other permissions (expected owner-only 0600)")
                remediation.append(f"chmod 600 {path}")
        if home.exists() and mode_is_insecure(home):
            warnings.append(f"{home} has group/other permissions (expected 0700)")
            remediation.append(f"chmod 700 {home}")

    if passphrase is None:
        warnings.append(
            "no passphrase available (HERMES_VAULT_PASSPHRASE unset) — key-dependent checks are skipped"
        )
        remediation.append(
            "Run doctor from the canonical launcher (reads $VAULT_HOME/.passphrase) "
            "or export HERMES_VAULT_PASSPHRASE."
        )

    status = CheckStatus.warn if warnings else CheckStatus.ok
    summary = "; ".join(warnings) if warnings else f"vault home layout intact at {home}"
    return DoctorCheck(name="launcher", status=status, summary=summary, remediation=remediation, data=data)


def _salt_fingerprint(salt_path: Path) -> str | None:
    from hermes_vault.backup import destination_salt_fingerprint

    try:
        return destination_salt_fingerprint(salt_path)
    except OSError:
        return None


# ── Check: store (container integrity, no key needed) ──────────────────────


def _check_store(settings: AppSettings) -> tuple[DoctorCheck, bool]:
    """Read-only SQLite integrity of vault.db. Never opens the vault."""
    db = settings.db_path
    if not db.exists():
        return (
            DoctorCheck(
                name="store",
                status=CheckStatus.skip,
                summary="no vault database to inspect",
            ),
            False,
        )

    uri = f"file:{db}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        return (_store_fail(db, f"cannot open {db}: {exc}"), False)
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("PRAGMA quick_integrity_check").fetchall()
        results = [row[0] for row in rows]
        credentials = int(conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0])
        leases = int(conn.execute("SELECT COUNT(*) FROM leases").fetchone()[0])
    except sqlite3.DatabaseError as exc:
        return (_store_fail(db, f"{db} is not a readable SQLite database: {exc}"), False)
    finally:
        conn.close()

    data = {"db_path": str(db), "integrity_check": results, "credential_count": credentials, "lease_count": leases}
    if any(result != "ok" for result in results):
        return (
            DoctorCheck(
                name="store",
                status=CheckStatus.fail,
                summary=f"SQLite integrity check failed for {db}",
                detail="; ".join(results),
                remediation=[
                    "Do NOT write to this store. Restore vault.db from a verified backup or a *.bak-* / pre-repair safety copy.",
                ],
                data=data,
            ),
            False,
        )
    return (
        DoctorCheck(
            name="store",
            status=CheckStatus.ok,
            summary=f"vault.db passes SQLite integrity check ({credentials} credential(s), {leases} lease(s))",
            data=data,
        ),
        True,
    )


def _store_fail(db: Path, message: str) -> DoctorCheck:
    return DoctorCheck(
        name="store",
        status=CheckStatus.fail,
        summary=message,
        remediation=[
            "Do NOT write to this store. Restore vault.db from a verified backup or a *.bak-* / pre-repair safety copy.",
        ],
        data={"db_path": str(db)},
    )


# ── Check: salt match / key-material pairing (P1 trap #2 catcher) ──────────


def _check_salt_match(
    settings: AppSettings,
    vault: "Vault | None",
    vault_error: str | None,
) -> DoctorCheck:
    from hermes_vault.audit_integrity.repair import store_decryptability
    from hermes_vault.vault import _salt_fingerprint_or_none, _salt_mismatch_message

    if vault is None:
        if vault_error:
            return DoctorCheck(
                name="salt-match",
                status=CheckStatus.fail,
                summary="the vault cannot be opened under the current key material",
                detail=vault_error,
            )
        return DoctorCheck(
            name="salt-match",
            status=CheckStatus.skip,
            summary="key-material check skipped (no unlocked vault: see the launcher/store checks)",
        )

    fp = _salt_fingerprint_or_none(settings.salt_path)
    decrypt = store_decryptability(vault)
    data = {
        "salt_fingerprint": fp,
        "credential_count": decrypt.credential_count,
        "decryptable_count": decrypt.decryptable_count,
    }
    if decrypt.ok:
        return DoctorCheck(
            name="salt-match",
            status=CheckStatus.ok,
            summary=decrypt.summary_line(salt_fingerprint=fp),
            data=data,
        )
    return DoctorCheck(
        name="salt-match",
        status=CheckStatus.fail,
        summary=decrypt.summary_line(salt_fingerprint=fp),
        detail=_salt_mismatch_message(
            decryptable_count=decrypt.decryptable_count,
            credential_count=decrypt.credential_count,
            salt_fingerprint=fp,
            subject="store",
        ),
        data=data,
    )


# ── Check: audit chain state (P1 trap #1 catcher) ──────────────────────────


def _check_audit_chain(settings: AppSettings, vault: "Vault | None", vault_error: str | None) -> DoctorCheck:
    from hermes_vault.audit_integrity.models import AuditIntegrityStatus
    from hermes_vault.audit_integrity.repair import RepairClass, classify_repairability
    from hermes_vault.audit_integrity.service import AuditIntegrityService

    if vault is None:
        return DoctorCheck(
            name="audit-chain",
            status=CheckStatus.skip,
            summary="audit chain check skipped (no unlocked vault: see the launcher/store checks)"
            + (f" — {vault_error}" if vault_error else ""),
        )

    service = AuditIntegrityService(settings.db_path, vault.key)
    result = service.verify()
    data: dict[str, Any] = {
        "status": result.status.value,
        "reason_code": result.reason_code,
        "checkpoint_status": getattr(result.checkpoint_status, "value", str(result.checkpoint_status)),
    }
    detail = getattr(result, "sanitized_reason", None) or result.reason_code
    recommended = getattr(result, "recommended_next_step", None)

    if result.status == AuditIntegrityStatus.healthy:
        return DoctorCheck(
            name="audit-chain",
            status=CheckStatus.ok,
            summary=f"audit chain healthy ({detail or 'verified'})",
            data=data,
        )

    repair_class = classify_repairability(result)
    data["repair_class"] = repair_class.value

    if result.status in (AuditIntegrityStatus.legacy, AuditIntegrityStatus.incomplete):
        remediation = [recommended] if recommended else ["hermes-vault audit-checkpoint establish --yes"]
        return DoctorCheck(
            name="audit-chain",
            status=CheckStatus.warn,
            summary=f"audit chain {result.status.value} ({detail})",
            remediation=remediation,
            data=data,
        )

    # status == failed
    guidance: dict[RepairClass, tuple[str, list[str]]] = {
        RepairClass.repairable: (
            f"audit chain failed ({detail}) — non-destructively repairable",
            [
                'Run: hermes-vault audit-checkpoint repair --yes --reason "<incident text>"',
                "The repair quarantines the old integrity tables (nothing is dropped) and re-establishes a fresh checkpoint.",
            ],
        ),
        RepairClass.refuse_tamper: (
            f"audit chain shows tamper evidence ({detail}) — repair is refused",
            [
                "Inspect the evidence: hermes-vault audit-export --with-integrity",
                "Preserve the evidence and restore from a verified backup instead of repairing.",
            ],
        ),
        RepairClass.refuse_key_material: (
            f"audit chain signed under different key material ({detail}) — repair is refused",
            ["Fix the salt/key pairing first (see the salt-match check); repairing would hide the real failure."],
        ),
        RepairClass.refuse_unsupported: (
            f"audit chain state unsupported/unreadable ({detail})",
            ["This is an upgrade-path or database-level diagnosis — see docs/safe-recovery.md; do not attempt repair."],
        ),
    }
    summary, remediation = guidance.get(repair_class, guidance[RepairClass.refuse_unsupported])
    if recommended and recommended not in remediation:
        remediation = [*remediation, recommended]
    return DoctorCheck(
        name="audit-chain",
        status=CheckStatus.fail,
        summary=summary,
        remediation=remediation,
        data=data,
    )


# ── Check: backup pairing (optional, P1 primitive) ─────────────────────────


def _check_backup_pairing(path: Path, vault: "Vault | None") -> DoctorCheck:
    from hermes_vault.backup import backup_key_fingerprint, prove_backup_decryptable
    from hermes_vault.vault import _salt_mismatch_message, _salt_fingerprint_or_none

    data: dict[str, Any] = {"backup_path": str(path)}
    if vault is None:
        return DoctorCheck(
            name="backup-pairing",
            status=CheckStatus.skip,
            summary="backup pairing skipped (no unlocked vault)",
            data=data,
        )

    try:
        backup = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return DoctorCheck(
            name="backup-pairing",
            status=CheckStatus.fail,
            summary=f"backup file unreadable: {exc}",
            data=data,
        )

    proof = prove_backup_decryptable(backup, vault.key)
    data["credential_count"] = proof.credential_count
    data["decryptable_count"] = proof.decryptable_count
    data["backup_key_fingerprint"] = backup_key_fingerprint(backup)
    salt_fp = _salt_fingerprint_or_none(Path(getattr(vault, "salt_path", Path())))
    data["destination_salt_fingerprint"] = salt_fp

    if proof.ok:
        return DoctorCheck(
            name="backup-pairing",
            status=CheckStatus.ok,
            summary=f"backup restores under this vault's master key ({proof.decryptable_count}/{proof.credential_count} decryptable)",
            detail="; ".join(proof.findings) or None,
            data=data,
        )
    return DoctorCheck(
        name="backup-pairing",
        status=CheckStatus.fail,
        summary=(
            f"backup does NOT decrypt under this vault's master key "
            f"({proof.decryptable_count}/{proof.credential_count}) — a restore would be blocked by the mandatory preflight"
        ),
        detail=_salt_mismatch_message(
            decryptable_count=proof.decryptable_count,
            credential_count=proof.credential_count,
            salt_fingerprint=salt_fp,
            subject="backup",
        ),
        data=data,
    )


# ── Check: MCP wiring ──────────────────────────────────────────────────────


def _check_mcp_wiring(
    config_path: Path,
    *,
    smoke: bool = True,
    smoke_timeout: float = SMOKE_TIMEOUT_DEFAULT,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> DoctorCheck:
    config_path = config_path.expanduser()
    data: dict[str, Any] = {"hermes_config": str(config_path)}

    if not config_path.exists():
        return DoctorCheck(
            name="mcp-wiring",
            status=CheckStatus.warn,
            summary=f"no Hermes config at {config_path} — MCP wiring not configured",
            remediation=[
                f"Add to {config_path}:\n  mcp_servers:\n    {MCP_SERVER_KEY}:\n      command: /absolute/path/hermes-vault\n      args: [\"mcp\"]",
            ],
            data=data,
        )
    try:
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return DoctorCheck(
            name="mcp-wiring",
            status=CheckStatus.warn,
            summary=f"Hermes config unreadable: {exc}",
            data=data,
        )
    if not isinstance(loaded, dict):
        loaded = {}
    servers = loaded.get("mcp_servers")
    entry = servers.get(MCP_SERVER_KEY) if isinstance(servers, dict) else None
    data["configured"] = entry is not None
    if not isinstance(entry, dict):
        return DoctorCheck(
            name="mcp-wiring",
            status=CheckStatus.warn,
            summary=f"no mcp_servers.{MCP_SERVER_KEY} entry in {config_path}",
            remediation=[
                f"Add under mcp_servers:\n    {MCP_SERVER_KEY}:\n      command: /absolute/path/hermes-vault-canonical\n      args: [\"mcp\"]",
            ],
            data=data,
        )

    warnings: list[str] = []
    remediation: list[str] = []

    if entry.get("enabled") is False:
        warnings.append("entry is disabled (enabled: false)")
        remediation.append(f"Set enabled: true under mcp_servers.{MCP_SERVER_KEY}, or remove the key entirely.")

    command = entry.get("command")
    args = entry.get("args", [])
    data["command"] = command
    data["args"] = args

    if not isinstance(command, str) or not command.strip():
        return DoctorCheck(
            name="mcp-wiring",
            status=CheckStatus.warn,
            summary=f"mcp_servers.{MCP_SERVER_KEY}.command is missing or empty",
            data=data,
        )
    if isinstance(args, str):
        warnings.append(
            f'args is the STRING {args!r} — YAML must be a real list (["mcp"]), the documented config trap'
        )
        remediation.append('Fix: args: ["mcp"] (a YAML list, not a quoted string).')
        args = []

    resolved = command if Path(command).is_absolute() else shutil.which(command)
    data["resolved_command"] = resolved
    if resolved is None or not Path(resolved).exists():
        warnings.append(f"command {command!r} does not resolve to an executable on this host")
        remediation.append("Point command at an absolute path that exists (e.g. ~/.local/bin/hermes-vault-canonical).")
        return DoctorCheck(
            name="mcp-wiring",
            status=CheckStatus.warn,
            summary="; ".join(warnings),
            remediation=remediation,
            data=data,
        )

    if smoke:
        smoke_result = _mcp_smoke(resolved, args if isinstance(args, list) else [], timeout=smoke_timeout, runner=runner)
        data["smoke"] = smoke_result
        if not smoke_result["ok"]:
            warnings.append(f"MCP stdio smoke test failed: {smoke_result['detail']}")
            remediation.append(
                "Run the configured command by hand and send it a JSON-RPC initialize request; "
                "check PYTHONPATH/passphrase wiring in the launcher."
            )

    if warnings:
        return DoctorCheck(
            name="mcp-wiring",
            status=CheckStatus.warn,
            summary="; ".join(warnings),
            remediation=remediation,
            data=data,
        )
    server_info = ((data.get("smoke") or {}).get("server_info") or None) if smoke else None
    suffix = f" (smoke: {server_info})" if server_info else ""
    return DoctorCheck(
        name="mcp-wiring",
        status=CheckStatus.ok,
        summary=f"MCP wiring intact: {resolved} {' '.join(map(str, args))}".rstrip() + suffix,
        data=data,
    )


def _mcp_smoke(
    command: str,
    args: list[Any],
    *,
    timeout: float,
    runner: Callable[..., subprocess.CompletedProcess],
) -> dict[str, Any]:
    """Spawn the configured server and perform the initialize handshake."""
    cmd = [command, *map(str, args)]
    try:
        completed = runner(cmd, input=_SMOKE_INITIALIZE, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "detail": f"no initialize response within {timeout:.0f}s"}
    except OSError as exc:
        return {"ok": False, "detail": f"could not spawn {command}: {exc}"}

    for line in (completed.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        result = payload.get("result") if isinstance(payload, dict) else None
        if isinstance(result, dict) and isinstance(result.get("serverInfo"), dict):
            info = result["serverInfo"]
            return {
                "ok": True,
                "detail": "initialize handshake answered",
                "server_info": f"{info.get('name', '?')} {info.get('version', '?')}".strip(),
            }
        if isinstance(payload, dict) and payload.get("error"):
            return {"ok": False, "detail": f"initialize returned an error: {payload['error']}"}
    stderr = (completed.stderr or "").strip().splitlines()
    return {
        "ok": False,
        "detail": f"no JSON-RPC initialize result on stdout (exit {completed.returncode}"
        + (f"; last stderr: {stderr[-1][:200]}" if stderr else "")
        + ")",
    }


# ── Orchestration ──────────────────────────────────────────────────────────


def run_doctor(
    *,
    settings: AppSettings | None = None,
    hermes_config: Path | None = None,
    mcp_smoke: bool = True,
    backup: Path | None = None,
    smoke_timeout: float = SMOKE_TIMEOUT_DEFAULT,
    smoke_runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> DoctorReport:
    """Run every doctor check and aggregate into one report.

    Read-only: doctor never mutates the vault, never writes audit rows, and
    never creates vault files (the Vault constructor is only invoked when the
    store already exists and passed the integrity check).
    """
    settings = settings or get_settings()
    report = DoctorReport(vault_home=str(settings.runtime_home))

    # Passphrase (never prompt — doctor must stay automatable).
    from hermes_vault.crypto import MissingPassphraseError, resolve_passphrase_with_source

    try:
        passphrase_result = resolve_passphrase_with_source(prompt=False, profile_name=settings.profile_name)
        passphrase: str | None = passphrase_result.passphrase
        passphrase_source: str | None = passphrase_result.source
    except MissingPassphraseError:
        passphrase = None
        passphrase_source = None

    # 1. binary
    binary = _check_binary()
    report.checks.append(binary)
    report.hermes_vault_version = binary.data.get("version")

    # 2. launcher / layout
    report.checks.append(_check_launcher(settings, passphrase, passphrase_source))

    # 3. store container
    store_check, store_ok = _check_store(settings)
    report.checks.append(store_check)

    # Open the vault only when it can be done safely (existing + intact store).
    vault: Vault | None = None
    vault_error: str | None = None
    if store_ok and passphrase is not None and settings.db_path.exists() and settings.salt_path.exists():
        from hermes_vault.vault import Vault

        try:
            vault = Vault(settings.db_path, settings.salt_path, passphrase)
        except Exception as exc:  # typed key-material errors carry P1 guidance text
            vault_error = str(exc)

    # 4. salt match / key-material pairing
    report.checks.append(_check_salt_match(settings, vault, vault_error))

    # 5. audit chain
    report.checks.append(_check_audit_chain(settings, vault, vault_error))

    # 6. backup pairing (optional)
    if backup is not None:
        report.checks.append(_check_backup_pairing(backup, vault))

    # 7. MCP wiring
    report.checks.append(
        _check_mcp_wiring(
            hermes_config or DEFAULT_HERMES_CONFIG,
            smoke=mcp_smoke,
            smoke_timeout=smoke_timeout,
            runner=smoke_runner,
        )
    )

    return report


# ── Rendering ──────────────────────────────────────────────────────────────


_STATUS_GLYPH = {
    CheckStatus.ok: ("✓", "green"),
    CheckStatus.warn: ("!", "yellow"),
    CheckStatus.fail: ("✗", "red"),
    CheckStatus.skip: ("−", "dim"),
}
_VERDICT_STYLE = {"healthy": "green", "degraded": "yellow", "broken": "red"}


def render_doctor_report(console: Console, report: DoctorReport) -> None:
    table = Table(title="Hermes Vault Doctor", show_lines=False)
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Finding", overflow="fold")
    for check in report.checks:
        glyph, style = _STATUS_GLYPH[check.status]
        table.add_row(check.name, f"[{style}]{glyph} {check.status.value}[/{style}]", check.summary)
    console.print(table)

    for check in report.checks:
        if check.status not in (CheckStatus.warn, CheckStatus.fail):
            continue
        console.print(f"[bold]{check.name}[/bold] — {check.summary}")
        if check.detail:
            console.print(check.detail)
        for step in check.remediation:
            console.print(f"  → {step}")

    verdict = report.verdict
    style = _VERDICT_STYLE[verdict]
    console.print(f"\nVerdict: [bold {style}]{verdict}[/bold {style}] (exit {report.exit_code})")
