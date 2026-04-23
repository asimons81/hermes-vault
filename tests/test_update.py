from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from urllib.error import URLError

from click.testing import CliRunner

from hermes_vault.cli import _hermes_group
from hermes_vault.update import (
    InstallMethod,
    InstallationState,
    ReleaseInfo,
    UpdateError,
    UpdatePlan,
    detect_installation_state,
    fetch_latest_release,
    perform_update,
)


class FakeDistribution:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values

    def read_text(self, name: str) -> str | None:
        return self.values.get(name)


def _plan(
    *,
    current_version: str = "0.1.0",
    latest_tag: str = "v0.2.0",
    method: InstallMethod = InstallMethod.UV_TOOL,
    auto_update_supported: bool = True,
    auto_update_command: tuple[str, ...] | None = ("uv", "tool", "install", "git+https://github.com/asimons81/hermes-vault.git@v0.2.0"),
    manual_command: str = "python -m pip install --upgrade https://example.invalid/v0.2.0.tar.gz",
) -> UpdatePlan:
    release = ReleaseInfo(
        tag=latest_tag,
        version=latest_tag.removeprefix("v"),
        url="https://github.com/asimons81/hermes-vault/releases/tag/v0.2.0",
        archive_url="https://github.com/asimons81/hermes-vault/archive/refs/tags/v0.2.0.tar.gz",
    )
    installation = InstallationState(
        method=method,
        detail=f"Detected {method.value}.",
        auto_update_supported=auto_update_supported,
        auto_update_command=auto_update_command,
        manual_command=manual_command,
    )
    return UpdatePlan(
        current_version=current_version,
        latest_release=release,
        installation=installation,
    )


def test_detect_installation_state_for_editable_install(tmp_path: Path) -> None:
    repo_path = tmp_path / "hermes-vault"
    repo_path.mkdir()
    (repo_path / ".git").mkdir()
    direct_url = json.dumps(
        {
            "url": repo_path.as_uri(),
            "dir_info": {"editable": True},
        }
    )
    distribution = FakeDistribution(
        {
            "direct_url.json": direct_url,
            "INSTALLER": "pip\n",
        }
    )
    release = ReleaseInfo(
        tag="v0.2.0",
        version="0.2.0",
        url="https://github.com/asimons81/hermes-vault/releases/tag/v0.2.0",
        archive_url="https://github.com/asimons81/hermes-vault/archive/refs/tags/v0.2.0.tar.gz",
    )

    state = detect_installation_state(
        release,
        distribution=distribution,
        sys_prefix=str(tmp_path / "venv"),
        sys_executable=str(tmp_path / "venv" / "bin" / "python"),
    )

    assert state.method == InstallMethod.EDITABLE_DEV
    assert state.auto_update_supported is False
    assert "git -C" in state.manual_command
    assert str(repo_path) in state.manual_command


def test_fetch_latest_release_wraps_network_failures() -> None:
    def failing_opener(*args, **kwargs):
        raise URLError("offline")

    try:
        fetch_latest_release(opener=failing_opener)
    except UpdateError as exc:
        assert "Failed to reach the Hermes Vault release source" in str(exc)
    else:
        raise AssertionError("expected UpdateError")


def test_update_check_is_read_only(monkeypatch) -> None:
    plan = _plan()
    monkeypatch.setattr("hermes_vault.cli.resolve_update_plan", lambda: plan)

    def should_not_run(*args, **kwargs):
        raise AssertionError("perform_update should not run during --check")

    monkeypatch.setattr("hermes_vault.cli.perform_update", should_not_run)

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["update", "--check"])

    assert result.exit_code == 0
    assert "Current version" in result.output
    assert "Latest version" in result.output
    assert "Read-only check complete" in result.output


def test_update_help_lists_check_flag() -> None:
    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["update", "--help"])

    assert result.exit_code == 0
    assert "--check" in result.output


def test_update_runs_supported_install_method(monkeypatch) -> None:
    plan = _plan()
    monkeypatch.setattr("hermes_vault.cli.resolve_update_plan", lambda: plan)
    monkeypatch.setattr("hermes_vault.cli.perform_update", lambda plan: "0.2.0")

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["update"])

    assert result.exit_code == 0
    assert "Running: uv tool install" in result.output
    assert "updated successfully to 0.2.0" in result.output


def test_update_refuses_unsupported_install_method(monkeypatch) -> None:
    plan = _plan(
        method=InstallMethod.PIP,
        auto_update_supported=False,
        auto_update_command=None,
        manual_command=f"{sys.executable} -m pip install --upgrade https://github.com/asimons81/hermes-vault/archive/refs/tags/v0.2.0.tar.gz",
    )
    monkeypatch.setattr("hermes_vault.cli.resolve_update_plan", lambda: plan)

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["update"])

    assert result.exit_code == 1
    assert "Auto-update is not supported" in result.output
    assert "Manual command:" in result.output


def test_update_reports_release_lookup_failure(monkeypatch) -> None:
    monkeypatch.setattr(
        "hermes_vault.cli.resolve_update_plan",
        lambda: (_ for _ in ()).throw(UpdateError("Failed to reach the Hermes Vault release source: offline")),
    )

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["update", "--check"])

    assert result.exit_code == 1
    assert "Failed to reach the Hermes Vault release source" in result.output


def test_update_reports_post_update_verification_failure(monkeypatch) -> None:
    plan = _plan()
    monkeypatch.setattr("hermes_vault.cli.resolve_update_plan", lambda: plan)
    monkeypatch.setattr(
        "hermes_vault.cli.perform_update",
        lambda plan: (_ for _ in ()).throw(
            UpdateError("Update completed, but post-update verification reported 0.1.0 instead of 0.2.0.")
        ),
    )

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["update"])

    assert result.exit_code == 1
    assert "post-update verification reported 0.1.0 instead of 0.2.0" in result.output


def test_perform_update_detects_version_mismatch() -> None:
    plan = _plan()

    def fake_runner(command, capture_output=False, text=False, check=False):
        if command[:2] == [sys.executable, "-c"]:
            return subprocess.CompletedProcess(command, 0, stdout="0.1.0\n", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    try:
        perform_update(plan, runner=fake_runner)
    except UpdateError as exc:
        assert "post-update verification reported 0.1.0 instead of 0.2.0" in str(exc)
    else:
        raise AssertionError("expected UpdateError")
