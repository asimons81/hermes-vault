from __future__ import annotations

import stat
from pathlib import Path

from hermes_vault import _platform

from hermes_vault.models import FindingRecord, FindingSeverity


def mode_is_insecure(path: Path) -> bool:
    return _platform.mode_is_insecure(path)


def permission_finding(path: Path) -> FindingRecord | None:
    if _platform.current_platform() == "windows":
        return _platform.permission_finding(path)
    try:
        if not path.exists():
            return None
        if mode_is_insecure(path):
            return FindingRecord(
                severity=FindingSeverity.high,
                kind="insecure_permissions",
                path=str(path),
                recommendation="Restrict the file to owner-only access, ideally mode 600.",
                detail=f"Mode is {oct(stat.S_IMODE(path.stat().st_mode))}",
            )
    except OSError:
        return None
    return None


def set_owner_only(path: Path) -> None:
    _platform.set_owner_only(path)

