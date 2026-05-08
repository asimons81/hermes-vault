from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field, model_validator


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


class AppSettings(BaseModel):
    app_name: str = "hermes-vault"
    runtime_home: Path = Field(
        default_factory=lambda: Path(
            os.environ.get("HERMES_VAULT_HOME", "~/.hermes/hermes-vault-data")
        ).expanduser()
    )
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
        default_factory=lambda: [
            Path("~/.hermes").expanduser(),
            Path("~/.config/hermes").expanduser(),
            Path("~/.bashrc").expanduser(),
            Path("~/.zshrc").expanduser(),
            Path("~/.profile").expanduser(),
        ]
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
        self._secure_directory(self.runtime_home)
        self._secure_directory(self.generated_skills_dir)

    def secure_file(self, path: Path, mode: int = 0o600) -> None:
        if path.exists():
            try:
                os.chmod(path, mode)
            except OSError:
                pass

    def _secure_directory(self, path: Path) -> None:
        if path.exists():
            try:
                os.chmod(path, 0o700)
            except OSError:
                pass


def get_settings() -> AppSettings:
    settings = AppSettings()
    settings.ensure_runtime_layout()
    return settings
