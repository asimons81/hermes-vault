"""P3 CLI truth pack: --version flag.

v0.25.1 probe: `hermes-vault --version` -> click exit 2 ("No such option").
Scripting/cron recipes had to grep dist-info METADATA instead.
"""

from __future__ import annotations

import subprocess
import sys

from click.testing import CliRunner

import hermes_vault
from hermes_vault.cli import _hermes_group, app


def test_version_flag_prints_version_and_exits_zero() -> None:
    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["--version"])
    assert result.exit_code == 0, result.output
    assert result.output.strip() == f"hermes-vault {hermes_vault.__version__}"


def test_version_flag_with_no_banner_composes() -> None:
    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["--no-banner", "--version"])
    assert result.exit_code == 0, result.output
    assert hermes_vault.__version__ in result.output


def test_version_flag_before_subcommand_still_versions() -> None:
    """--version is eager: it wins even if other tokens follow."""
    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["--version", "health"])
    assert result.exit_code == 0, result.output
    assert hermes_vault.__version__ in result.output


def test_version_entrypoint_path_root_argv(monkeypatch) -> None:
    """The app() proxy short-circuits root-only --version (console script path)."""
    monkeypatch.setattr("sys.argv", ["hermes-vault", "--version"])
    # Capture stdout via click.echo -> use CliRunner on the proxy.
    from click.testing import CliRunner as _CR

    class _Cap:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def __call__(self, message: str = "", **kwargs) -> None:
            self.lines.append(message)

    cap = _Cap()
    monkeypatch.setattr("hermes_vault.cli.click.echo", cap)
    rc = app()
    assert rc == 0
    assert cap.lines == [f"hermes-vault {hermes_vault.__version__}"]


def test_version_subprocess_console_script_equivalent() -> None:
    """End-to-end through the same entry the console script calls."""
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys\n"
                "from hermes_vault.cli import app\n"
                "sys.argv = ['hermes-vault', '--version']\n"
                "rc = app()\n"
                "sys.exit(rc)\n"
            ),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == f"hermes-vault {hermes_vault.__version__}"
