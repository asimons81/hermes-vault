from __future__ import annotations

from pathlib import Path

from hermes_vault.permissions import mode_is_insecure, permission_finding


def test_permission_finding_flags_world_readable_file(tmp_path: Path) -> None:
    secret_file = tmp_path / "secret.env"
    secret_file.write_text("OPENAI_API_KEY=sk-testsecretvalue1234567890\n", encoding="utf-8")
    secret_file.chmod(0o644)

    finding = permission_finding(secret_file)

    assert mode_is_insecure(secret_file) is True
    assert finding is not None
    assert finding.kind == "insecure_permissions"

