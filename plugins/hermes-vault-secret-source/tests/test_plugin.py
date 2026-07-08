from __future__ import annotations

import importlib.util
import json
import sys
import types
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


PLUGIN_PATH = Path(__file__).resolve().parents[1] / "__init__.py"


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


def _valid_env(name: str) -> bool:
    return bool(name) and (name[0].isalpha() or name[0] == "_") and all(ch.isalnum() or ch == "_" for ch in name)


def _install_agent_stubs() -> None:
    agent = types.ModuleType("agent")
    secret_sources = types.ModuleType("agent.secret_sources")
    base = types.ModuleType("agent.secret_sources.base")
    base.ErrorKind = ErrorKind
    base.FetchResult = FetchResult
    base.SecretSource = SecretSource
    base.is_valid_env_name = _valid_env
    base.run_secret_cli = lambda *args, **kwargs: None
    sys.modules["agent"] = agent
    sys.modules["agent.secret_sources"] = secret_sources
    sys.modules["agent.secret_sources.base"] = base


def _load_plugin():
    _install_agent_stubs()
    spec = importlib.util.spec_from_file_location("hermes_vault_secret_source_plugin", PLUGIN_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Proc:
    def __init__(self, stdout: str, returncode: int = 0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


def test_plugin_fetch_success_uses_run_secret_cli(monkeypatch, tmp_path: Path) -> None:
    plugin = _load_plugin()
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return Proc(json.dumps({"ok": True, "secrets": {"OPENAI_API_KEY": "sk-test"}, "warnings": {}, "errors": {}}))

    monkeypatch.setattr(plugin, "run_secret_cli", fake_run)
    result = plugin.HermesVaultSource().fetch(
        {"enabled": True, "env": {"OPENAI_API_KEY": "hv://openai"}, "binary": "hermes-vault"},
        tmp_path,
    )

    assert result.ok is True
    assert result.secrets == {"OPENAI_API_KEY": "sk-test"}
    assert "--" in captured["argv"]
    assert captured["argv"][-1] == "OPENAI_API_KEY=hv://openai"


def test_plugin_partial_success_keeps_ok_and_warnings(monkeypatch, tmp_path: Path) -> None:
    plugin = _load_plugin()

    def fake_run(argv, **kwargs):
        return Proc(json.dumps({
            "ok": True,
            "secrets": {"OPENAI_API_KEY": "sk-test"},
            "warnings": {"GITHUB_TOKEN": {"kind": "EMPTY_VALUE", "message": "empty"}},
            "errors": {},
        }))

    monkeypatch.setattr(plugin, "run_secret_cli", fake_run)
    result = plugin.HermesVaultSource().fetch(
        {"enabled": True, "env": {"OPENAI_API_KEY": "hv://openai", "GITHUB_TOKEN": "hv://github"}},
        tmp_path,
    )

    assert result.ok is True
    assert result.error is None
    assert result.error_kind is None
    assert result.secrets == {"OPENAI_API_KEY": "sk-test"}
    assert any("GITHUB_TOKEN" in warning for warning in result.warnings)


def test_plugin_zero_usable_sets_error_kind(monkeypatch, tmp_path: Path) -> None:
    plugin = _load_plugin()

    def fake_run(argv, **kwargs):
        return Proc(json.dumps({
            "ok": False,
            "secrets": {},
            "warnings": {},
            "errors": {"OPENAI_API_KEY": {"kind": "EMPTY_VALUE", "message": "empty"}},
        }), returncode=1)

    monkeypatch.setattr(plugin, "run_secret_cli", fake_run)
    result = plugin.HermesVaultSource().fetch(
        {"enabled": True, "env": {"OPENAI_API_KEY": "hv://openai"}},
        tmp_path,
    )

    assert result.ok is False
    assert result.error_kind == ErrorKind.EMPTY_VALUE


def test_plugin_omits_empty_secrets(monkeypatch, tmp_path: Path) -> None:
    plugin = _load_plugin()

    def fake_run(argv, **kwargs):
        return Proc(json.dumps({"ok": True, "secrets": {"OPENAI_API_KEY": ""}, "warnings": {}, "errors": {}}))

    monkeypatch.setattr(plugin, "run_secret_cli", fake_run)
    result = plugin.HermesVaultSource().fetch(
        {"enabled": True, "env": {"OPENAI_API_KEY": "hv://openai"}},
        tmp_path,
    )

    assert result.secrets == {}
    assert result.error_kind == ErrorKind.INTERNAL


def test_plugin_allow_env_excludes_path(monkeypatch, tmp_path: Path) -> None:
    plugin = _load_plugin()
    captured = {}

    def fake_run(argv, **kwargs):
        captured.update(kwargs)
        return Proc(json.dumps({"ok": True, "secrets": {"OPENAI_API_KEY": "sk-test"}, "warnings": {}, "errors": {}}))

    monkeypatch.setattr(plugin, "run_secret_cli", fake_run)
    plugin.HermesVaultSource().fetch(
        {"enabled": True, "profile": "work", "env": {"OPENAI_API_KEY": "hv://openai"}},
        tmp_path,
    )

    assert "PATH" not in captured["allow_env"]
    assert "HERMES_VAULT_PASSPHRASE" in captured["allow_env"]
    assert "HERMES_VAULT_PASSPHRASE_WORK" in captured["allow_env"]


def test_plugin_does_not_mutate_os_environ(monkeypatch, tmp_path: Path) -> None:
    plugin = _load_plugin()
    before = dict(plugin.os.environ)

    def fake_run(argv, **kwargs):
        return Proc(json.dumps({"ok": True, "secrets": {"OPENAI_API_KEY": "sk-test"}, "warnings": {}, "errors": {}}))

    monkeypatch.setattr(plugin, "run_secret_cli", fake_run)
    plugin.HermesVaultSource().fetch(
        {"enabled": True, "env": {"OPENAI_API_KEY": "hv://openai"}},
        tmp_path,
    )

    assert dict(plugin.os.environ) == before
