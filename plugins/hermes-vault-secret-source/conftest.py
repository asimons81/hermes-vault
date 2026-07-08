from __future__ import annotations

import sys
import types
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class ErrorKind(str, Enum):
    NOT_CONFIGURED = "not_configured"
    BINARY_MISSING = "binary_missing"
    AUTH_FAILED = "auth_failed"
    AUTH_EXPIRED = "auth_expired"
    REF_INVALID = "ref_invalid"
    NETWORK = "network"
    EMPTY_VALUE = "empty_value"
    TIMEOUT = "timeout"
    INTERNAL = "internal"


@dataclass
class FetchResult:
    secrets: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    error_kind: ErrorKind | None = None
    binary_path: Path | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


class SecretSource:
    api_version = 1

    def is_enabled(self, cfg):
        return bool(isinstance(cfg, dict) and cfg.get("enabled"))

    def override_existing(self, cfg):
        return bool(isinstance(cfg, dict) and cfg.get("override_existing", False))

    def protected_env_vars(self, cfg):
        return frozenset()

    def fetch_timeout_seconds(self, cfg):
        return 120


def is_valid_env_name(name: str) -> bool:
    return bool(name) and (name[0].isalpha() or name[0] == "_") and all(ch.isalnum() or ch == "_" for ch in name)


def _run_secret_cli(*args, **kwargs):
    raise RuntimeError("run_secret_cli stub was not patched by the test")


agent = types.ModuleType("agent")
secret_sources = types.ModuleType("agent.secret_sources")
base = types.ModuleType("agent.secret_sources.base")
base.ErrorKind = ErrorKind
base.FetchResult = FetchResult
base.SecretSource = SecretSource
base.is_valid_env_name = is_valid_env_name
base.run_secret_cli = _run_secret_cli
sys.modules.setdefault("agent", agent)
sys.modules.setdefault("agent.secret_sources", secret_sources)
sys.modules.setdefault("agent.secret_sources.base", base)
