from __future__ import annotations

import json
import os
import platform
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from hermes_vault import __version__
from hermes_vault.audit import AuditLogger
from hermes_vault.config import AppSettings
from hermes_vault.health import run_health
from hermes_vault.models import utc_now
from hermes_vault.policy import PolicyEngine
from hermes_vault.vault import Vault


INCIDENT_BUNDLE_VERSION = "incident-bundle-v1"


@dataclass
class IncidentBundleReport:
    version: str = INCIDENT_BUNDLE_VERSION
    generated_at: str = field(default_factory=lambda: utc_now().isoformat())
    output_path: str = ""
    dry_run: bool = False
    file_count: int = 0
    files: list[str] = field(default_factory=list)
    redaction_boundary: str = (
        "metadata-only; excludes vault databases, salts, encrypted payloads, raw secrets, provider responses, and env files"
    )

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "generated_at": self.generated_at,
            "output_path": self.output_path,
            "dry_run": self.dry_run,
            "file_count": self.file_count,
            "files": list(self.files),
            "redaction_boundary": self.redaction_boundary,
        }


def _write_json(base: Path, name: str, data: dict[str, Any]) -> Path:
    path = base / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def _sanitize_audit(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized = []
    for entry in entries:
        item = dict(entry)
        metadata = item.get("metadata")
        if isinstance(metadata, dict):
            metadata = {
                key: value
                for key, value in metadata.items()
                if key not in {"backup", "env", "secret", "encrypted_payload"}
            }
        item["metadata"] = metadata or {}
        sanitized.append(item)
    return sanitized


def _parse_since(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("h") and text[:-1].isdigit():
        return datetime.now(timezone.utc) - timedelta(hours=int(text[:-1]))
    if text.endswith("d") and text[:-1].isdigit():
        return datetime.now(timezone.utc) - timedelta(days=int(text[:-1]))
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("since must be an ISO timestamp or a relative value like 24h or 7d") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _zip_directory(source: Path, output: Path) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in source.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(source))
    try:
        output.chmod(0o600)
    except OSError:
        pass


def build_incident_bundle(
    *,
    output_path: str | Path,
    settings: AppSettings,
    vault: Vault,
    policy: PolicyEngine,
    audit: AuditLogger,
    since: str | None = None,
    agent: str | None = None,
    service: str | None = None,
    dry_run: bool = False,
) -> IncidentBundleReport:
    output = Path(output_path)
    files = [
        "manifest.json",
        "audit.json",
        "policy-summary.json",
        "health.json",
        "leases.json",
        "requests.json",
        "runtime.json",
    ]
    report = IncidentBundleReport(
        output_path=str(output),
        dry_run=dry_run,
        file_count=len(files),
        files=files,
    )
    if dry_run:
        return report

    work_dir = output.with_suffix("")
    work_dir.mkdir(parents=True, exist_ok=True)

    audit_entries = audit.list_recent(
        limit=5000,
        agent_id=agent,
        service=service,
        since=_parse_since(since),
    )
    health = run_health(vault, audit=audit).as_dict(exclude_none=False)
    agent_policies = {
        agent_id: policy_value.model_dump(mode="json")
        for agent_id, policy_value in policy.config.agents.items()
    }
    if agent:
        agent_policies = {
            agent_id: data for agent_id, data in agent_policies.items() if agent_id == agent
        }

    payloads = {
        "manifest.json": report.as_dict(),
        "audit.json": {"version": "incident-audit-v1", "entries": _sanitize_audit(audit_entries)},
        "policy-summary.json": {
            "version": "incident-policy-summary-v1",
            "policy_hash": policy.compute_policy_hash(),
            "agents": agent_policies,
        },
        "health.json": health,
        "leases.json": {
            "version": "incident-leases-v1",
            "leases": [
                lease.model_dump(mode="json")
                for lease in vault.list_leases(agent_id=agent, service=service)
            ],
        },
        "requests.json": {
            "version": "incident-requests-v1",
            "requests": [
                request.model_dump(mode="json")
                for request in vault.list_access_requests(agent_id=agent, service=service)
            ],
        },
        "runtime.json": {
            "version": "incident-runtime-v1",
            "hermes_vault_version": __version__,
            "python": platform.python_version(),
            "platform": platform.platform(),
            "profile": settings.profile_name,
            "runtime_home": str(settings.runtime_home),
            "policy_path": str(settings.effective_policy_path),
            "mcp_binding_enabled": settings.mcp_binding_enabled,
            "mcp_allowed_agents": list(settings.mcp_allowed_agents),
            "environment": {
                "HERMES_VAULT_HOME_set": bool(os.environ.get("HERMES_VAULT_HOME")),
                "HERMES_VAULT_POLICY_set": bool(os.environ.get("HERMES_VAULT_POLICY")),
                "HERMES_VAULT_PROFILE_set": bool(os.environ.get("HERMES_VAULT_PROFILE")),
            },
        },
    }

    written = []
    for name, data in payloads.items():
        written.append(_write_json(work_dir, name, data))
    _zip_directory(work_dir, output)
    report.file_count = len(written)
    return report
