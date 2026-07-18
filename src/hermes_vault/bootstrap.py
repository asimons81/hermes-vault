"""First Safe Agent bootstrap orchestration for Hermes Vault."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hermes_vault import _platform
from hermes_vault.config import AppSettings, get_settings, resolve_profile
from hermes_vault.detectors import EnvImportDecision, classify_env_name, parse_env_map
from hermes_vault.policy import PolicyEngine
from hermes_vault.policy_doctor import run_policy_doctor
from hermes_vault.service_ids import normalize

REPORT_VERSION = "first-safe-agent-bootstrap-v1"


@dataclass(frozen=True)
class EnvPreviewEntry:
    line: int
    env_name: str
    service: str
    credential_type: str
    source: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "line": self.line,
            "env_name": self.env_name,
            "service": self.service,
            "credential_type": self.credential_type,
            "source": self.source,
        }


@dataclass(frozen=True)
class EnvSkippedEntry:
    line: int
    env_name: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "line": self.line,
            "env_name": self.env_name,
            "reason": self.reason,
        }


@dataclass
class BootstrapReport:
    agent: str
    profile: str
    dry_run: bool
    source: str | None
    runtime_home: str
    policy_path: str
    generated_skills_dir: str
    importable: list[EnvPreviewEntry] = field(default_factory=list)
    skipped: list[EnvSkippedEntry] = field(default_factory=list)
    imported: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    policy_doctor: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": REPORT_VERSION,
            "agent": self.agent,
            "profile": self.profile,
            "dry_run": self.dry_run,
            "source": self.source,
            "runtime_home": self.runtime_home,
            "policy_path": self.policy_path,
            "generated_skills_dir": self.generated_skills_dir,
            "import_preview": {
                "importable_count": len(self.importable),
                "skipped_count": len(self.skipped),
                "importable": [entry.as_dict() for entry in self.importable],
                "skipped": [entry.as_dict() for entry in self.skipped],
            },
            "import_result": {
                "imported_count": len(self.imported),
                "updated_count": len(self.updated),
                "unchanged_count": len(self.unchanged),
                "imported_env_names": self.imported,
                "updated_env_names": self.updated,
                "unchanged_env_names": self.unchanged,
            },
            "verification_summary": {
                "status": "next_step",
                "command": "hermes-vault verify --all",
                "note": "Run live provider verification after approving imported credentials.",
            },
            "policy_doctor_summary": self.policy_doctor,
            "skill_contract": {
                "status": "next_step",
                "command": f"hermes-vault generate-skill --agent {self.agent}",
                "generated_path": f"{self.generated_skills_dir}/{self.agent}/SKILL.md",
                "note": "Generated skills are review artifacts until the operator explicitly installs them.",
            },
            "mcp_config_snippet": {
                "mcp_servers": {
                    "hermes-vault": {
                        "command": "hermes-vault",
                        "args": ["mcp"],
                        "env": {
                            "HERMES_VAULT_HOME": self.runtime_home,
                            "HERMES_VAULT_POLICY": self.policy_path,
                            "HERMES_VAULT_PASSPHRASE": "<set outside repo>",
                        },
                    }
                }
            },
            "next_steps": self.next_steps,
            "warnings": self.warnings,
        }


def parse_env_preview(path: Path, env_map: list[str] | None = None) -> tuple[list[tuple[int, str, str, EnvImportDecision]], list[EnvSkippedEntry]]:
    overrides: dict[str, tuple[str, str]] = {}
    for mapping in env_map or []:
        env_name, service, credential_type = parse_env_map(mapping)
        overrides[env_name] = (normalize(service), credential_type)

    importable: list[tuple[int, str, str, EnvImportDecision]] = []
    skipped: list[EnvSkippedEntry] = []
    for index, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines()):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            continue
        raw_name, raw_value = line.split("=", 1)
        env_name = raw_name.strip()
        decision = classify_env_name(env_name, overrides)
        if decision.action == "import" and decision.service and decision.credential_type:
            importable.append((index, env_name, raw_value.strip().strip("'\""), decision))
        else:
            skipped.append(EnvSkippedEntry(index + 1, env_name, decision.reason))
    return importable, skipped


def _dry_run_settings() -> AppSettings:
    """Resolve settings without creating runtime directories or files."""
    resolved = resolve_profile()
    env_policy = os.environ.get("HERMES_VAULT_POLICY")
    return AppSettings(
        runtime_home=resolved.profile_home,
        base_home=resolved.base_home,
        profile_name=resolved.name,
        profile_source=resolved.source,
        profile_home_source=resolved.home_source,
        policy_source="env" if env_policy else "profile",
        policy_path=Path(env_policy).expanduser() if env_policy else None,
    )


def run_bootstrap(
    *,
    from_env: Path | None,
    agent: str,
    dry_run: bool,
    env_map: list[str] | None = None,
    redact_source: bool = False,
) -> BootstrapReport:
    """Run a local-first First Safe Agent bootstrap pass.

    The report intentionally never includes raw secret values.
    """
    settings = _dry_run_settings() if dry_run else get_settings()
    policy = PolicyEngine.from_yaml(settings.effective_policy_path)
    if not dry_run:
        policy.write_default(settings.effective_policy_path)

    report = BootstrapReport(
        agent=agent,
        profile=settings.profile_name,
        dry_run=dry_run,
        source=str(from_env) if from_env else None,
        runtime_home=str(settings.runtime_home),
        policy_path=str(settings.effective_policy_path),
        generated_skills_dir=str(settings.generated_skills_dir),
    )

    if from_env is not None:
        env_entries, skipped = parse_env_preview(from_env, env_map=env_map)
        report.importable = [
            EnvPreviewEntry(
                line=index + 1,
                env_name=name,
                service=decision.service or "",
                credential_type=decision.credential_type or "",
                source=decision.source,
            )
            for index, name, _secret, decision in env_entries
        ]
        report.skipped = skipped

        if not dry_run and env_entries:
            from hermes_vault.audit import AuditLogger
            from hermes_vault.crypto import resolve_passphrase
            from hermes_vault.models import CredentialSecret
            from hermes_vault.mutations import OPERATOR_AGENT_ID, VaultMutations
            from hermes_vault.vault import Vault

            passphrase = resolve_passphrase(prompt=True, profile_name=settings.profile_name)
            vault = Vault(settings.db_path, settings.salt_path, passphrase)
            mutations = VaultMutations(vault=vault, policy=policy, audit=AuditLogger(settings.db_path, master_key=vault.key))
            redacted_lines: set[int] = set()
            for index, env_name, secret, decision in env_entries:
                alias = env_name.lower()
                existing = None
                existing_secret = None
                try:
                    existing = vault.resolve_credential(decision.service or "", alias=alias)
                    secret_obj: CredentialSecret | None = vault.get_secret(existing.id)
                    existing_secret = secret_obj.secret if secret_obj else None
                except Exception:
                    existing = None
                if existing is not None and existing_secret == secret:
                    report.unchanged.append(env_name)
                    redacted_lines.add(index)
                    continue
                result = mutations.add_credential(
                    agent_id=OPERATOR_AGENT_ID,
                    service=decision.service or "",
                    secret=secret,
                    credential_type=decision.credential_type or "api_key",
                    alias=alias,
                    imported_from=str(from_env),
                    replace_existing=existing is not None,
                )
                if not result.allowed:
                    report.warnings.append(f"Denied importing {env_name}: {result.reason}")
                    continue
                if existing is not None:
                    report.updated.append(env_name)
                else:
                    report.imported.append(env_name)
                redacted_lines.add(index)

            if redact_source and redacted_lines:
                source_lines = from_env.read_text(encoding="utf-8", errors="ignore").splitlines()
                rewritten = [
                    f"# REDACTED by hermes-vault bootstrap: {line}" if idx in redacted_lines else line
                    for idx, line in enumerate(source_lines)
                ]
                from_env.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
                _platform.secure_file(from_env)
    elif redact_source:
        report.warnings.append("--redact-source only applies when --from-env is provided.")

    doctor = run_policy_doctor(
        settings.effective_policy_path,
        generated_skills_dir=settings.generated_skills_dir,
        strict=False,
    )
    report.policy_doctor = {
        "finding_count": doctor.finding_count,
        "severity_counts": doctor.severity_counts,
        "strict_violation": doctor.strict_violation,
    }
    report.next_steps = [
        "Review the import preview before mutating a real .env file." if dry_run else "Review and remove any remaining plaintext source secrets.",
        f"Run `hermes-vault generate-skill --agent {agent}` and review the generated skill contract.",
        f"Run `hermes-vault broker env <service> --agent {agent} --ttl 900` for task-scoped credentials.",
        "Use `hermes-vault oauth device-login <provider>` or `hermes-vault oauth login <provider> --headless` for browserless first login on supported providers.",
    ]
    return report
