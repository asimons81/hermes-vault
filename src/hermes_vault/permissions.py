from __future__ import annotations

import os
import stat
from pathlib import Path

from hermes_vault.models import FindingRecord, FindingSeverity


def mode_is_insecure(path: Path) -> bool:
    mode = stat.S_IMODE(path.stat().st_mode)
    return bool(mode & (stat.S_IRWXG | stat.S_IRWXO))


def permission_finding(path: Path) -> FindingRecord | None:
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
    os.chmod(path, 0o600)

