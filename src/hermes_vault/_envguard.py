"""Runtime guard against PYTHONPATH poisoning from the Hermes agent venv.

The Hermes agent host exports a global ``PYTHONPATH`` pointing into its own
virtualenv (``.../hermes-agent/...``). When the installed ``hermes-vault``
console script runs inside such a shell, Python injects those directories at
the front of ``sys.path`` ahead of the tool's own dependencies, and the agent
venv's incompatible binary wheels (for example a ``pydantic_core`` built for
a different interpreter) crash the CLI at import time with::

    ModuleNotFoundError: No module named 'pydantic_core._pydantic_core'

This is the single most-documented fleet friction for the shipped tool
(every cron/launcher recipe carries an ``env -u PYTHONPATH`` prefix to paper
over it). This module applies, at the CLI entrypoint, the same scrub the
test-suite conftest has performed since v0.23.0: drop ``sys.path`` entries
located inside a ``hermes-agent`` checkout and remove the inherited
``PYTHONPATH`` so child processes inherit a clean environment too.

The guard is deliberately narrow:

* Only paths containing the ``hermes-agent`` marker are removed — unrelated
  developer paths are never touched.
* A path that is the running ``hermes_vault`` package itself or one of its
  ancestors always survives, so an editable dev install whose checkout path
  merely *contains* the marker keeps working.
* It is a strict no-op in a clean environment.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

#: Path marker identifying the Hermes agent venv whose dependencies poison
#: the installed tool. Matches the v0.23.0 conftest guard exactly.
_MARKER = "hermes-agent"


def sanitize_poisoned_sys_path(entry_file: str) -> int:
    """Strip hermes-agent venv leakage from ``sys.path``/``PYTHONPATH``.

    ``entry_file`` is the ``__file__`` of the calling module (the CLI
    entrypoint); it locates the running package so an editable install that
    contains the marker is never stripped.

    Returns the number of ``sys.path`` entries removed (0 in a clean
    environment, in which case nothing is mutated).
    """
    pythonpath = os.environ.get("PYTHONPATH", "")
    if _MARKER not in pythonpath and not any(_MARKER in p for p in sys.path):
        return 0

    try:
        package_root = Path(entry_file).resolve().parent
    except OSError:  # pragma: no cover - pathological filesystem state
        package_root = None

    def _is_dev_install_path(path: str) -> bool:
        # Ancestor-or-self of the running package: an editable/dev install.
        if package_root is None or not path:
            return False
        try:
            candidate = Path(path).resolve()
        except OSError:
            return False
        return candidate == package_root or candidate in package_root.parents

    keep: list[str] = []
    removed: list[str] = []
    for path in sys.path:
        if _MARKER in path and not _is_dev_install_path(path):
            removed.append(path)
            continue
        keep.append(path)

    if removed:
        sys.path[:] = keep
        # Child processes (uv/pip spawned by `update`, bridges) must not
        # re-inherit the poisoned search path. Keep unrelated PYTHONPATH
        # entries intact so legitimate developer paths survive.
        surviving = [
            entry
            for entry in os.environ.get("PYTHONPATH", "").split(os.pathsep)
            if entry and _MARKER not in entry
        ]
        if surviving:
            os.environ["PYTHONPATH"] = os.pathsep.join(surviving)
        else:
            os.environ.pop("PYTHONPATH", None)
    return len(removed)
