from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
HERMES_AGENT_ROOT = Path(os.environ["HERMES_AGENT_ROOT"]).resolve()


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_conformance = _load_module(
    "upstream_hermes_secret_source_conformance",
    HERMES_AGENT_ROOT / "tests" / "secret_sources" / "conformance.py",
)
_plugin = _load_module(
    "hermes_vault_secret_source_plugin_upstream_validation",
    REPO_ROOT / "plugins" / "hermes-vault-secret-source" / "__init__.py",
)


class TestHermesVaultUpstreamConformance(_conformance.SecretSourceConformance):
    @pytest.fixture
    def source(self):
        return _plugin.HermesVaultSource()
