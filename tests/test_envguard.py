"""Tests for the CLI PYTHONPATH self-guard (hermes_vault._envguard).

The guard applies the v0.23.0 conftest pattern to the shipped tool: hermes-agent
venv leakage on ``sys.path``/``PYTHONPATH`` is stripped at the CLI entrypoint so
the installed console script works from any agent/cron shell without an
``env -u PYTHONPATH`` prefix.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from hermes_vault._envguard import sanitize_poisoned_sys_path

MARKER = "hermes-agent"


# ── unit: clean environment is a strict no-op ──────────────────────────────


def test_clean_environment_is_noop(monkeypatch) -> None:
    monkeypatch.delenv("PYTHONPATH", raising=False)
    before = list(sys.path)
    assert sanitize_poisoned_sys_path(__file__) == 0
    assert sys.path == before


# ── unit: poisoned entries are stripped ────────────────────────────────────


def test_poisoned_sys_path_entries_are_removed(monkeypatch, tmp_path: Path) -> None:
    poison = tmp_path / f"venv-{MARKER}" / "site-packages"
    poison.mkdir(parents=True)
    monkeypatch.setenv("PYTHONPATH", str(poison))
    # Simulate interpreter startup folding PYTHONPATH into sys.path.
    monkeypatch.syspath_prepend(str(poison))
    try:
        removed = sanitize_poisoned_sys_path(__file__)
    finally:
        # sanitize() already removed the entry; drop it from PYTHONPATH monkeypatching
        pass
    assert removed == 1
    assert str(poison) not in sys.path
    assert "PYTHONPATH" not in os.environ


def test_unrelated_paths_are_never_touched(monkeypatch, tmp_path: Path) -> None:
    unrelated = tmp_path / "some-other-venv" / "site-packages"
    unrelated.mkdir(parents=True)
    poison = tmp_path / f"{MARKER}" / "site-packages"
    poison.mkdir(parents=True)
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join([str(unrelated), str(poison)]))
    monkeypatch.syspath_prepend(str(unrelated))
    monkeypatch.syspath_prepend(str(poison))
    removed = sanitize_poisoned_sys_path(__file__)
    assert removed == 1
    assert str(unrelated) in sys.path
    assert str(poison) not in sys.path
    # Legit PYTHONPATH entries survive for child processes.
    assert os.environ["PYTHONPATH"] == str(unrelated)


# ── unit: dev/editable install protection ──────────────────────────────────


def test_dev_install_ancestor_with_marker_survives(tmp_path: Path) -> None:
    """A checkout whose path merely CONTAINS the marker must keep working.

    Simulates an editable/dev install at e.g. ~/hermes-agent/hermes-vault/src:
    the sys.path entry is an ancestor of the running package.
    """
    src = tmp_path / MARKER / "hermes-vault" / "src"
    pkg = src / "hermes_vault"
    pkg.mkdir(parents=True)
    entry_file = pkg / "cli.py"
    entry_file.write_text("", encoding="utf-8")

    poison_elsewhere = tmp_path / f"other-{MARKER}-venv" / "site-packages"
    poison_elsewhere.mkdir(parents=True)

    original = list(sys.path)
    try:
        sys.path.insert(0, str(src))
        sys.path.insert(0, str(poison_elsewhere))
        os.environ["PYTHONPATH"] = os.pathsep.join([str(src), str(poison_elsewhere)])
        removed = sanitize_poisoned_sys_path(str(entry_file))
        assert removed == 1  # only the unrelated hermes-agent entry
        assert str(src) in sys.path
        assert str(poison_elsewhere) not in sys.path
    finally:
        sys.path[:] = original


# ── integration: the installed CLI survives a poisoned environment ────────


@pytest.fixture
def poison_env(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    """A fake hermes-agent venv whose pydantic crashes on import."""
    site_packages = tmp_path / f"agent-{MARKER}" / "venv" / "site-packages"
    broken = site_packages / "pydantic"
    broken.mkdir(parents=True)
    (broken / "__init__.py").write_text(
        "raise ImportError('poisoned pydantic from hermes-agent venv')\n",
        encoding="utf-8",
    )
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = str(site_packages)
    return site_packages, env


def test_poison_fixture_really_breaks_unprotected_imports(poison_env) -> None:
    """Control: without the guard, the poison shadows pydantic and crashes."""
    _, env = poison_env
    probe = subprocess.run(
        [sys.executable, "-c", "import pydantic"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert probe.returncode != 0
    assert "poisoned pydantic" in probe.stderr


def test_cli_import_survives_poisoned_pythonpath(poison_env) -> None:
    """The CLI entrypoint scrubs the poison before its third-party imports."""
    _, env = poison_env
    probe = subprocess.run(
        [sys.executable, "-c", "from hermes_vault.cli import app; print('cli-import-ok')"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert probe.returncode == 0, probe.stderr
    assert "cli-import-ok" in probe.stdout


def test_console_script_surface_survives_poisoned_pythonpath(poison_env) -> None:
    """End-to-end: --help through the entrypoint function, poison in env."""
    _, env = poison_env
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            textwrap.dedent(
                """
                import sys
                from hermes_vault.cli import app
                sys.argv = ["hermes-vault", "--help"]
                try:
                    app()
                except SystemExit as exc:
                    sys.exit(exc.code)
                """
            ),
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert probe.returncode == 0, probe.stderr
    assert "Usage" in probe.stdout
