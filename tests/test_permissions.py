from __future__ import annotations

from pathlib import Path

import pytest

from hermes_vault import _platform
from hermes_vault.permissions import mode_is_insecure, permission_finding


def test_permission_finding_flags_world_readable_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: False)
    secret_file = tmp_path / "secret.env"
    secret_file.write_text("OPENAI_API_KEY=sk-tes...7890\n", encoding="utf-8")
    secret_file.chmod(0o644)

    finding = permission_finding(secret_file)

    assert mode_is_insecure(secret_file) is True
    assert finding is not None
    assert finding.kind == "insecure_permissions"

