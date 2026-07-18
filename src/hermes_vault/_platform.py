"""Platform abstraction for Hermes Vault.

Centralizes all OS-dependent behavior so the rest of the codebase does not
need raw os.name / sys.platform checks. Linux/macOS (POSIX) behavior is
preserved unchanged. Windows behavior provides safe fallbacks where the
POSIX equivalent does not exist.
"""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import webbrowser
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hermes_vault.models import FindingRecord


class PlatformKind(StrEnum):
    WINDOWS = "windows"
    POSIX = "posix"


def current_platform() -> PlatformKind:
    return PlatformKind.WINDOWS if os.name == "nt" else PlatformKind.POSIX


def _is_windows() -> bool:
    return current_platform() == PlatformKind.WINDOWS


def default_vault_home() -> Path:
    """Default vault data directory.

    POSIX: ~/.hermes/hermes-vault-data (existing default).
    Windows: %LOCALAPPDATA%/HermesVault.
    """
    if _is_windows():
        appdata = os.environ.get("LOCALAPPDATA")
        if appdata:
            return Path(appdata) / "HermesVault"
        return Path.home() / "AppData" / "Local" / "HermesVault"
    return Path("~/.hermes/hermes-vault-data").expanduser()


def default_scan_roots() -> list[Path]:
    """Default scan root paths.

    POSIX: Hermes config dirs and shell profile files.
    Windows: Hermes config dir under LOCALAPPDATA; no bash/zsh dotfiles.
    """
    if _is_windows():
        appdata = os.environ.get("LOCALAPPDATA")
        if appdata:
            return [Path(appdata) / "Hermes"]
        return []
    return [
        Path("~/.hermes").expanduser(),
        Path("~/.config/hermes").expanduser(),
        Path("~/.bashrc").expanduser(),
        Path("~/.zshrc").expanduser(),
        Path("~/.profile").expanduser(),
    ]


def secure_file(path: Path) -> None:
    """Restrict a file to owner-only access where possible.

    POSIX: chmod(0o600). Windows: best-effort.
    """
    if not path.exists():
        return
    if not _is_windows():
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


def secure_directory(path: Path) -> None:
    """Restrict a directory to owner-only access where possible.

    POSIX: chmod(0o700). Windows: best-effort.
    """
    if not path.exists():
        return
    if not _is_windows():
        try:
            os.chmod(path, stat.S_IRWXU)
        except OSError:
            pass


def set_owner_only(path: Path) -> None:
    """Set owner-only permissions on a file (POSIX: chmod 0600, Windows: no-op)."""
    if not _is_windows():
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


def mode_is_insecure(path: Path) -> bool:
    """Check if file permissions allow group/other access.

    POSIX: checks st_mode. Windows: returns False (needs pywin32).
    """
    if _is_windows():
        return False
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        return bool(mode & (stat.S_IRWXG | stat.S_IRWXO))
    except OSError:
        return False


def permission_finding(path: Path) -> "FindingRecord | None":
    """Return a finding dict for an insecure file, or None."""
    from hermes_vault.models import FindingRecord, FindingSeverity

    if _is_windows():
        if not path.exists():
            return None
        try:
            ok = _check_windows_file_ownership(path)
            if not ok:
                return FindingRecord(
                    severity=FindingSeverity.high,
                    kind="insecure_permissions",
                    path=str(path),
                    recommendation=(
                        "Restrict the file to your user account "
                        "using File Properties > Security."
                    ),
                    detail="File may be readable by non-owner users.",
                )
        except OSError:
            pass
        return None

    try:
        if not path.exists():
            return None
        if mode_is_insecure(path):
            return FindingRecord(
                severity=FindingSeverity.high,
                kind="insecure_permissions",
                path=str(path),
                recommendation="Restrict the file to owner-only access, mode 600.",
                detail=f"Mode is {oct(stat.S_IMODE(path.stat().st_mode))}",
            )
    except OSError:
        return None
    return None


def _check_windows_file_ownership(path: Path) -> bool:
    """Best-effort Windows file ownership check. Returns True if safe."""
    try:
        import win32security  # noqa: F401
    except ImportError:
        return True
    try:
        sd = win32security.GetFileSecurity(
            str(path),
            win32security.OWNER_SECURITY_INFORMATION
            | win32security.DACL_SECURITY_INFORMATION,
        )
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            return True
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            ace_sid = ace[2]
            if ace_sid in (
                win32security.ConvertStringSidToSid("S-1-1-0"),
                win32security.ConvertStringSidToSid("S-1-5-32-545"),
                win32security.ConvertStringSidToSid("S-1-5-11"),
            ):
                if ace[1] & (
                    win32security.GENERIC_ALL
                    | win32security.GENERIC_WRITE
                    | win32security.GENERIC_READ
                ):
                    return False
        return True
    except Exception:
        return True


def dpapi_available() -> bool:
    """True iff DPAPI is usable on this process (Windows + pywin32 importable).

    Single source of truth for the DPAPI availability rule. Used by
    :mod:`hermes_vault.dpapi` so the rule lives in one place. The
    ``import win32crypt`` is deferred and guarded so the import error
    is swallowed here without leaking into callers.
    """
    if not _is_windows():
        return False
    try:
        import win32crypt  # noqa: F401
    except ImportError:
        return False
    return True


def write_bytes_durable(path: Path, content: bytes) -> None:
    """Write bytes durably, with platform-appropriate permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(content)
        handle.flush()
        if not _is_windows():
            os.fsync(handle.fileno())
    secure_file(path)


def replace_bytes_durable(path: Path, content: bytes) -> None:
    """Atomically replace *path* with durable, owner-only bytes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".pending", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            if not _is_windows():
                os.fsync(handle.fileno())
        secure_file(temporary)
        os.replace(temporary, path)
        secure_file(path)
        fsync_directory(path.parent)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def write_text_durable(path: Path, content: str) -> None:
    """Write text durably."""
    write_bytes_durable(path, content.encode("utf-8"))


def fsync_directory(path: Path) -> None:
    """Sync parent directory metadata.

    POSIX: opens and fsyncs the directory. Windows: no-op.
    """
    if _is_windows():
        return
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def temp_path_check(path: Path) -> bool:
    """Check if a path is inside a temp directory."""
    if _is_windows():
        try:
            resolved = path.resolve()
            candidates: list[Path] = []
            for var in ("TEMP", "TMP"):
                val = os.environ.get(var)
                if val:
                    candidates.append(Path(val).resolve())
            try:
                candidates.append(Path(tempfile.gettempdir()).resolve())
            except OSError:
                pass
            for td in candidates:
                try:
                    resolved.relative_to(td)
                    return True
                except ValueError:
                    continue
            return False
        except OSError:
            return False
    try:
        resolved = path.resolve()
        return resolved.is_relative_to(Path("/tmp").resolve())
    except OSError:
        return str(path).startswith("/tmp/")


def format_command(parts: tuple[str, ...] | list[str]) -> str:
    """Format a command tuple as a shell string.

    POSIX: shlex.join. Windows: subprocess.list2cmdline.
    """
    if _is_windows():
        return subprocess.list2cmdline(list(parts))
    import shlex
    return shlex.join(list(parts))


def shell_safe_quote(s: str) -> str:
    """Quote a string for the current platform shell.

    POSIX: shlex.quote. Windows: double-quote with escape.
    """
    if _is_windows():
        escaped = s.replace('"', '\\"')
        return f'"{escaped}"'
    import shlex
    return shlex.quote(s)


def open_browser(url: str) -> bool:
    """Open a URL in the default browser."""
    return webbrowser.open(url, new=2)


def render_task_scheduler_template(
    command: str = "hermes-vault",
    args: str = "--no-banner maintain --format json",
    task_name: str = "HermesVaultMaintenance",
    interval_minutes: int = 15,
) -> str:
    """Render Windows Task Scheduler creation instructions."""
    full_cmd = command + " " + args
    lines = []
    lines.append(":: Windows Task Scheduler -- Scheduled Maintenance for Hermes Vault")
    lines.append("::")
    lines.append(":: Run in PowerShell as Administrator or your user account:")
    lines.append("::")
    sch_line = (
        "schtasks /Create /SC MINUTE /MO "
        + str(interval_minutes)
        + ' /TN "' + task_name + '" /TR "' + full_cmd + '" /IT /DELAY 0005:00 /F'
    )
    lines.append("::   " + sch_line)
    lines.append("")
    lines.append("# PowerShell equivalent using ScheduledTasks module:")
    act_line = (
        '$Action = New-ScheduledTaskAction -Execute '
        + '"' + command + '" -Argument "' + args + '"'
    )
    lines.append(act_line)
    tri_line = (
        "$Trigger = New-ScheduledTaskTrigger -RepetitionInterval "
        + "(New-TimeSpan -Minutes " + str(interval_minutes) + ") -AtStartup"
    )
    lines.append(tri_line)
    backslash = chr(92)
    user = "$env:USERDOMAIN" + backslash + "$env:USERNAME"
    pri_line = (
        '$Principal = New-ScheduledTaskPrincipal -UserId "'
        + user + '" -RunLevel Limited'
    )
    lines.append(pri_line)
    reg_line = (
        'Register-ScheduledTask -TaskName "' + task_name
        + '" -Action $Action -Trigger $Trigger -Principal $Principal -Force'
    )
    lines.append(reg_line)
    lines.append("")
    lines.append('Write-Host "Created scheduled task: ' + task_name + '"')
    lines.append('Write-Host "  Command: ' + full_cmd + '"')
    lines.append('Write-Host "  Interval: Every ' + str(interval_minutes) + ' minutes"')
    return "\n".join(lines)
