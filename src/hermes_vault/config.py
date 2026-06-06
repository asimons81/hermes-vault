from __future__ import annotations

import os
import re
from contextvars import ContextVar, Token
from dataclasses import dataclass
from pathlib import Path

from hermes_vault import _platform
from typing import Literal

from pydantic import BaseModel, Field, model_validator


_PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_active_profile: ContextVar[str | None] = ContextVar("hermes_vault_profile", default=None)


@dataclass(frozen=True)
class VaultProfile:
    name: str
    base_home: Path
    profile_home: Path
    source: Literal["explicit", "cli", "env", "default"]
    home_source: Literal["env", "default"]
    is_default: bool


@dataclass(frozen=True)
class VaultRuntime:
    profile: VaultProfile
    settings: "AppSettings"
    passphrase_source: str | None = None


def _parse_csv_env(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def _parse_optional_env(name: str) -> str | None:
    raw = os.environ.get(name)
    if raw is None:
        return None
    value = raw.strip()
    return value or None


def _base_home() -> tuple[Path, Literal["env", "default"]]:
    raw_home = os.environ.get("HERMES_VAULT_HOME")
    source: Literal["env", "default"] = "env" if raw_home else "default"
    return Path(raw_home).expanduser() if raw_home else _platform.default_vault_home(), source


def validate_profile_name(name: str) -> str:
    value = (name or "").strip()
    if not value:
        raise ValueError("Hermes Vault profile name cannot be empty")
    if value == "profiles":
        raise ValueError("'profiles' is reserved and cannot be used as a Hermes Vault profile name")
    if value.startswith(".") or ".." in value or "/" in value or "\\" in value:
        raise ValueError(f"Invalid Hermes Vault profile name: {name!r}")
    if not _PROFILE_RE.match(value):
        raise ValueError(f"Invalid Hermes Vault profile name: {name!r}")
    return value


def set_active_profile(name: str | None) -> Token[str | None]:
    return _active_profile.set(validate_profile_name(name) if name else None)


def reset_active_profile(token: Token[str | None]) -> None:
    _active_profile.reset(token)


def current_active_profile() -> str | None:
    return _active_profile.get()


def resolve_profile_name(explicit: str | None = None) -> tuple[str, Literal["explicit", "cli", "env", "default"]]:
    if explicit:
        return validate_profile_name(explicit), "explicit"
    cli_profile = current_active_profile()
    if cli_profile:
        return validate_profile_name(cli_profile), "cli"
    env_profile = os.environ.get("HERMES_VAULT_PROFILE")
    if env_profile and env_profile.strip():
        return validate_profile_name(env_profile), "env"
    return "default", "default"


def resolve_profile(explicit: str | None = None) -> VaultProfile:
    name, source = resolve_profile_name(explicit)
    base_home, home_source = _base_home()
    if name == "default":
        profile_home = base_home
    else:
        profile_home = base_home / "profiles" / name
    return VaultProfile(
        name=name,
        base_home=base_home,
        profile_home=profile_home,
        source=source,
        home_source=home_source,
        is_default=name == "default",
    )


def list_profiles(base_home: Path | None = None) -> list[VaultProfile]:
    root = (base_home.expanduser() if base_home is not None else _base_home()[0])
    profiles = [
        VaultProfile(
            name="default",
            base_home=root,
            profile_home=root,
            source="default",
            home_source="env" if os.environ.get("HERMES_VAULT_HOME") else "default",
            is_default=True,
        )
    ]
    profile_root = root / "profiles"
    if profile_root.is_dir():
        for child in sorted(profile_root.iterdir(), key=lambda p: p.name):
            if not child.is_dir():
                continue
            try:
                name = validate_profile_name(child.name)
            except ValueError:
                continue
            if name == "default":
                continue
            profiles.append(
                VaultProfile(
                    name=name,
                    base_home=root,
                    profile_home=child,
                    source="default",
                    home_source="env" if os.environ.get("HERMES_VAULT_HOME") else "default",
                    is_default=False,
                )
            )
    return profiles


class AppSettings(BaseModel):
    app_name: str = "hermes-vault"
    runtime_home: Path = Field(default_factory=lambda: _base_home()[0])
    base_home: Path = Field(default_factory=lambda: _base_home()[0])
    profile_name: str = "default"
    profile_source: str = "default"
    profile_home_source: str = "default"
    policy_source: str = "profile"
    policy_path: Path | None = Field(
        default_factory=lambda: (
            Path(os.environ["HERMES_VAULT_POLICY"]).expanduser()
            if os.environ.get("HERMES_VAULT_POLICY")
            else None
        )
    )
    db_filename: str = "vault.db"
    ignore_filename: str = "scan.ignore"
    salt_filename: str = "master_key_salt.bin"
    default_scan_roots: list[Path] = Field(
        default_factory=lambda: _platform.default_scan_roots()
    )
    expiry_warning_days: int = Field(
        default_factory=lambda: int(os.environ.get("HERMES_VAULT_EXPIRY_WARNING_DAYS", "7"))
    )
    backup_reminder_days: int = Field(
        default_factory=lambda: int(os.environ.get("HERMES_VAULT_BACKUP_REMINDER_DAYS", "30"))
    )
    governance_warnings_enabled: bool = Field(
        default_factory=lambda: os.environ.get("HERMES_VAULT_GOVERNANCE_WARNINGS", "0") == "1"
    )
    mcp_allowed_agents: list[str] = Field(
        default_factory=lambda: _parse_csv_env("HERMES_VAULT_MCP_ALLOWED_AGENTS")
    )
    mcp_default_agent: str | None = Field(
        default_factory=lambda: _parse_optional_env("HERMES_VAULT_MCP_DEFAULT_AGENT")
    )

    @property
    def db_path(self) -> Path:
        return self.runtime_home / self.db_filename

    @property
    def effective_policy_path(self) -> Path:
        return self.policy_path or (self.runtime_home / "policy.yaml")

    @property
    def ignore_path(self) -> Path:
        return self.runtime_home / self.ignore_filename

    @property
    def salt_path(self) -> Path:
        return self.runtime_home / self.salt_filename

    @property
    def generated_skills_dir(self) -> Path:
        return self.runtime_home / "generated-skills"

    @property
    def verifier_plugin_dir(self) -> Path:
        return self.runtime_home / "verifiers"

    @property
    def mcp_binding_enabled(self) -> bool:
        return bool(self.mcp_allowed_agents)

    @model_validator(mode="after")
    def _validate_mcp_binding(self) -> "AppSettings":
        if self.mcp_allowed_agents and self.mcp_default_agent:
            if self.mcp_default_agent not in self.mcp_allowed_agents:
                raise ValueError(
                    "HERMES_VAULT_MCP_DEFAULT_AGENT must be one of HERMES_VAULT_MCP_ALLOWED_AGENTS"
                )
        return self

    def ensure_runtime_layout(self) -> None:
        self.runtime_home.mkdir(parents=True, exist_ok=True)
        self.generated_skills_dir.mkdir(parents=True, exist_ok=True)
        self.verifier_plugin_dir.mkdir(parents=True, exist_ok=True)
        self._secure_directory(self.runtime_home)
        self._secure_directory(self.generated_skills_dir)
        self._secure_directory(self.verifier_plugin_dir)

    def secure_file(self, path: Path, mode: int = 0o600) -> None:
        _platform.secure_file(path)

    def _secure_directory(self, path: Path) -> None:
        _platform.secure_directory(path)


def get_settings(profile: str | None = None) -> AppSettings:
    resolved = resolve_profile(profile)
    env_policy = os.environ.get("HERMES_VAULT_POLICY")
    settings = AppSettings(
        runtime_home=resolved.profile_home,
        base_home=resolved.base_home,
        profile_name=resolved.name,
        profile_source=resolved.source,
        profile_home_source=resolved.home_source,
        policy_source="env" if env_policy else "profile",
        policy_path=Path(env_policy).expanduser() if env_policy else None,
    )
    settings.ensure_runtime_layout()
    return settings
