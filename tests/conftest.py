"""Root conftest — guards against PYTHONPATH pollution from the Hermes agent venv.

Without this guard, the Hermes agent's Python 3.11 pydantic leaks into uv's
Python 3.12 process and every test file fails to collect with:
    ModuleNotFoundError: No module named 'pydantic_core._pydantic_core'

This conftest runs before test collection — safe to mutate sys.path here.
"""

import os
import sys
from pathlib import Path

import pytest


def pytest_configure(config):
    _guard_pythonpath()


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Give every test an isolated HOME (empty per-test dir).

    Class-killer for the QA F-1 defect class: any code path that resolves
    ``~`` (doctor's DEFAULT_HERMES_CONFIG, expanduser defaults, shell-dotfile
    detection) silently reads the operator's real home, so suite greenness
    depends on the dev machine's ``~/.hermes/config.yaml`` and diverges on CI
    runners, which have no such file. With this fixture a forgotten
    ``--hermes-config``/HOME fixture fails the same way on every machine
    instead of passing only where the operator happens to be wired.
    """
    home = tmp_path / "isolated-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))  # Windows expanduser base


def _guard_pythonpath():
    cleaned = 0
    keep = []
    for p in sys.path:
        if "hermes-agent" in p:
            cleaned += 1
            continue
        keep.append(p)

    if cleaned:
        sys.path[:] = keep
        os.environ.pop("PYTHONPATH", None)
