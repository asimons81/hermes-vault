"""Root conftest — guards against PYTHONPATH pollution from the Hermes agent venv.

Without this guard, the Hermes agent's Python 3.11 pydantic leaks into uv's
Python 3.12 process and every test file fails to collect with:
    ModuleNotFoundError: No module named 'pydantic_core._pydantic_core'

This conftest runs before test collection — safe to mutate sys.path here.
"""

import os
import sys


def pytest_configure(config):
    _guard_pythonpath()


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
