from __future__ import annotations

import json
import mimetypes
import secrets
import sqlite3
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from hermes_vault import _platform
from hermes_vault.agent_context import build_agent_context
from hermes_vault.audit import AuditLogger
from hermes_vault.backup import restore_dry_run, verify_backup_file
from hermes_vault.broker import Broker
from hermes_vault.bootstrap import run_bootstrap
from hermes_vault.config import AppSettings, get_settings, list_profiles, validate_profile_name
from hermes_vault.crypto import MissingPassphraseError, resolve_passphrase_with_source
from hermes_vault.diff import diff_backups
from hermes_vault.health import run_health
from hermes_vault.maintenance import run_maintenance
from hermes_vault.models import CredentialRecord, LeaseRecord
from hermes_vault.oauth.oauth_refresh import RefreshEngine
from hermes_vault.oauth.providers import OAuthProviderRegistry
from hermes_vault.policy import PolicyEngine
from hermes_vault.policy_doctor import run_policy_doctor
from hermes_vault.service_ids import normalize
from hermes_vault.verifier import Verifier
from hermes_vault.vault import Vault


DASHBOARD_VERSION = "dashboard-v1"
DEFAULT_HOST = "127.0.0.1"
SAFE_ACTIONS = {
    "health",
    "policy_doctor",
    "verify",
    "oauth_refresh",
    "backup_verify",
    "restore_dry_run",
    "backup_diff",
    "onboarding_preview",
    "maintenance",
    "policy_explain",
    "request_access",
    "request_approve",
    "request_deny",
    "recovery_drill",
}
DASHBOARD_DRY_RUN_ONLY_ACTIONS = {
    "oauth_refresh",
    "maintenance",
    "onboarding_preview",
}
SECRET_REQUIRED_ACTIONS = {
    "verify",
    "oauth_refresh",
    "backup_verify",
    "restore_dry_run",
    "backup_diff",
    "maintenance",
    "request_approve",
    "recovery_drill",
}
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Resource-Policy": "same-origin",
}


@dataclass
class DashboardContext:
    settings: AppSettings
    vault: Vault
    policy: PolicyEngine
    broker: Broker
    audit: AuditLogger
    passphrase_source: str | None = None


def build_dashboard_context(*, prompt: bool = True, profile: str | None = None) -> DashboardContext:
    settings = get_settings(profile=profile)
    policy = PolicyEngine.from_yaml(settings.effective_policy_path)
    policy.write_default(settings.effective_policy_path)
    passphrase_result = resolve_passphrase_with_source(prompt=prompt, profile_name=settings.profile_name)
    vault = Vault(settings.db_path, settings.salt_path, passphrase_result.passphrase)
    audit = AuditLogger(settings.db_path, master_key=vault.key)
    broker = Broker(
        vault=vault,
        policy=policy,
        verifier=Verifier(plugin_dir=settings.verifier_plugin_dir),
        audit=audit,
    )
    return DashboardContext(
        settings=settings,
        vault=vault,
        policy=policy,
        broker=broker,
        audit=audit,
        passphrase_source=passphrase_result.source,
    )


class DashboardState:
    def __init__(self, initial_profile: str | None = None, prompt: bool = True) -> None:
        self._lock = threading.RLock()
        self._prompt = prompt
        self._context = build_dashboard_context(prompt=prompt, profile=initial_profile)

    def current_context(self) -> DashboardContext:
        with self._lock:
            return self._context

    def switch_profile(self, profile: str) -> DashboardContext:
        name = validate_profile_name(profile)
        new_context = build_dashboard_context(prompt=False, profile=name)
        key_validation = validate_vault_key(new_context)
        if key_validation.get("ok") is False:
            raise ValueError(key_validation.get("reason") or "Vault key material is not valid for selected profile")
        with self._lock:
            self._context = new_context
            return self._context


def dashboard_static_dir() -> Path:
    return Path(__file__).with_name("dashboard_static")


def generate_session_token() -> str:
    return secrets.token_urlsafe(32)


def sanitize_credential(record: CredentialRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "service": record.service,
        "alias": record.alias,
        "credential_type": record.credential_type,
        "status": record.status.value,
        "scopes": list(record.scopes),
        "tags": list(record.tags),
        "notes": record.notes,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "last_verified_at": record.last_verified_at.isoformat() if record.last_verified_at else None,
        "imported_from": record.imported_from,
        "expiry": record.expiry.isoformat() if record.expiry else None,
        "crypto_version": record.crypto_version,
    }


def sanitize_lease(record: LeaseRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "service": record.service,
        "alias": record.alias,
        "credential_id": record.credential_id,
        "credential_type": record.credential_type,
        "agent_id": record.agent_id,
        "issued_by": record.issued_by,
        "purpose": record.purpose,
        "status": record.status.value,
        "ttl_seconds": record.ttl_seconds,
        "issued_at": record.issued_at.isoformat(),
        "expires_at": record.expires_at.isoformat(),
        "revoked_at": record.revoked_at.isoformat() if record.revoked_at else None,
        "renewed_at": record.renewed_at.isoformat() if record.renewed_at else None,
        "renew_count": record.renew_count,
        "reason": record.reason,
        "scopes": list(record.scopes),
        "metadata_keys": sorted(record.metadata.keys()),
        "has_metadata": bool(record.metadata),
    }


def validate_vault_key(ctx: DashboardContext, max_checks: int | None = None) -> dict[str, Any]:
    records = ctx.vault.list_credentials()
    if not records:
        return {
            "status": "empty_vault",
            "ok": True,
            "credential_count": 0,
            "checked_count": 0,
            "reason": "Vault contains no credentials to validate.",
        }

    if max_checks is None:
        checked = records
        validation_scope = "all"
    else:
        checked = records[:max(1, max_checks)]
        validation_scope = "sample"
    failures = []
    decrypted_count = 0
    for record in checked:
        try:
            secret = ctx.vault.get_secret(record.id)
        except Exception:
            secret = None
        if secret is None:
            failures.append({"service": record.service, "alias": record.alias})
        else:
            decrypted_count += 1

    if decrypted_count == 0:
        return {
            "status": "invalid",
            "ok": False,
            "credential_count": len(records),
            "checked_count": len(checked),
            "decrypted_count": 0,
            "failed_count": len(failures),
            "validation_scope": validation_scope,
            "failures": failures[:5],
            "reason": "Vault key material could not decrypt credential data.",
        }

    if failures:
        return {
            "status": "degraded",
            "ok": True,
            "credential_count": len(records),
            "checked_count": len(checked),
            "decrypted_count": decrypted_count,
            "failed_count": len(failures),
            "validation_scope": validation_scope,
            "failures": failures[:5],
            "reason": "Vault key material is valid, but some credential records could not be decrypted.",
        }

    return {
        "status": "valid",
        "ok": True,
        "credential_count": len(records),
        "checked_count": len(checked),
        "decrypted_count": decrypted_count,
        "failed_count": 0,
        "validation_scope": validation_scope,
        "reason": "Vault key material decrypted credential data successfully.",
    }


def runtime_metadata(ctx: DashboardContext) -> dict[str, Any]:
    credentials = ctx.vault.list_credentials()
    return {
        "runtime_home": str(ctx.settings.runtime_home),
        "db_path": str(ctx.settings.db_path),
        "db_exists": ctx.settings.db_path.exists(),
        "policy_path": str(ctx.settings.effective_policy_path),
        "policy_exists": ctx.settings.effective_policy_path.exists(),
        "salt_path": str(ctx.settings.salt_path),
        "salt_exists": ctx.settings.salt_path.exists(),
        "credential_count": len(credentials),
        "key_validation": validate_vault_key(ctx),
        "passphrase_source": ctx.passphrase_source or "unknown",
        "home_source": ctx.settings.profile_home_source,
        "is_temp_runtime": _platform.temp_path_check(ctx.settings.runtime_home) if hasattr(_platform, 'temp_path_check') else False,
        "profile": ctx.settings.profile_name,
        "profile_source": ctx.settings.profile_source,
        "profile_home": str(ctx.settings.runtime_home),
        "base_home": str(ctx.settings.base_home),
        "profile_is_default": ctx.settings.profile_name == "default",
        "policy_source": ctx.settings.policy_source,
    }


class DashboardAPI:
    def __init__(
        self,
        context_factory: Callable[[], DashboardContext] = build_dashboard_context,
        profile_switcher: Callable[[str], DashboardContext] | None = None,
    ) -> None:
        self._context_factory = context_factory
        self._profile_switcher = profile_switcher

    def overview(self) -> dict[str, Any]:
        ctx = self._context_factory()
        records = ctx.vault.list_credentials()
        leases = ctx.vault.list_leases()
        health = run_health(ctx.vault, audit=ctx.audit)
        policy_report = run_policy_doctor(
            ctx.settings.effective_policy_path,
            generated_skills_dir=ctx.settings.generated_skills_dir,
            strict=False,
        )
        recent_audit = ctx.audit.list_recent(limit=12)
        return {
            "version": DASHBOARD_VERSION,
            "runtime": runtime_metadata(ctx),
            "runtime_home": str(ctx.settings.runtime_home),
            "policy_path": str(ctx.settings.effective_policy_path),
            "credential_count": len(records),
            "lease_count": len(leases),
            "active_lease_count": sum(1 for lease in leases if lease.status.value == "active"),
            "services": sorted({record.service for record in records}),
            "health": health.as_dict(exclude_none=False),
            "policy_doctor": policy_report.as_dict(exclude_none=False),
            "recent_audit": recent_audit,
            "mcp": self.mcp_status(ctx),
        }

    def credentials(self) -> dict[str, Any]:
        ctx = self._context_factory()
        return {
            "version": DASHBOARD_VERSION,
            "runtime": runtime_metadata(ctx),
            "credentials": [sanitize_credential(record) for record in ctx.vault.list_credentials()],
        }

    def leases(self) -> dict[str, Any]:
        ctx = self._context_factory()
        return {
            "version": DASHBOARD_VERSION,
            "runtime": runtime_metadata(ctx),
            "leases": [sanitize_lease(record) for record in ctx.vault.list_leases()],
        }

    def policy(self) -> dict[str, Any]:
        ctx = self._context_factory()
        report = run_policy_doctor(
            ctx.settings.effective_policy_path,
            generated_skills_dir=ctx.settings.generated_skills_dir,
            strict=False,
        )
        return {
            "version": DASHBOARD_VERSION,
            "runtime": runtime_metadata(ctx),
            "policy_path": str(ctx.settings.effective_policy_path),
            "doctor": report.as_dict(exclude_none=False),
            "agents": _policy_agent_summary(ctx.policy),
        }

    def agent_context(self, agent_id: str) -> dict[str, Any]:
        ctx = self._context_factory()
        return build_agent_context(agent_id=agent_id, vault=ctx.vault, policy=ctx.policy)

    def requests(self, agent_id: str | None = None) -> dict[str, Any]:
        ctx = self._context_factory()
        decision = ctx.broker.list_access_requests(agent_id=agent_id)
        return {
            "version": DASHBOARD_VERSION,
            "runtime": runtime_metadata(ctx),
            "requests": decision.metadata.get("requests", []),
        }

    def audit(self, limit: int = 50) -> dict[str, Any]:
        ctx = self._context_factory()
        bounded_limit = max(1, min(limit, 250))
        return {
            "version": DASHBOARD_VERSION,
            "entries": ctx.audit.list_recent(limit=bounded_limit),
        }

    def mcp_status(self, ctx: DashboardContext | None = None) -> dict[str, Any]:
        ctx = ctx or self._context_factory()
        return {
            "binding_enabled": ctx.settings.mcp_binding_enabled,
            "allowed_agents": list(ctx.settings.mcp_allowed_agents),
            "default_agent": ctx.settings.mcp_default_agent,
        }

    def audit_integrity(self) -> dict[str, Any]:
        """Return read-only audit integrity status for the dashboard."""
        try:
            ctx = self._context_factory()
            from hermes_vault.audit_integrity.service import AuditIntegrityService
            service = AuditIntegrityService(ctx.settings.db_path, ctx.vault.key)
            service.ensure_initialized()
            result = service.verify()
            return {
                "version": "audit-integrity-dashboard-v1",
                "status": result.status.value,
                "reason_code": result.reason_code,
                "chain_version": result.chain_version,
                "active_segment_id": result.active_segment_id,
                "active_segment_number": result.active_segment_number,
                "verified_count": result.verified_count,
                "legacy_count": result.legacy_count,
                "first_verified_sequence": result.first_verified_sequence,
                "last_verified_sequence": result.last_verified_sequence,
                "checkpoint_status": result.checkpoint_status.value,
                "last_verification_time": result.verified_at.isoformat() if result.verified_at else None,
                "sanitized_reason": result.sanitized_reason,
                "recommended_next_step": result.recommended_next_step,
            }
        except Exception as exc:
            return {
                "version": "audit-integrity-dashboard-v1",
                "status": "error",
                "error": str(exc),
            }

    def profiles(self) -> dict[str, Any]:
        ctx = self._context_factory()
        active = ctx.settings.profile_name
        profiles = []
        for profile in list_profiles(ctx.settings.base_home):
            db_path = profile.profile_home / "vault.db"
            policy_path = profile.profile_home / "policy.yaml"
            credential_count: int | None = None
            if db_path.exists():
                try:
                    with sqlite3.connect(db_path) as conn:
                        row = conn.execute("SELECT COUNT(*) FROM credentials").fetchone()
                    credential_count = int(row[0]) if row else 0
                except Exception:
                    credential_count = None
            profiles.append(
                {
                    "name": profile.name,
                    "profile_home": str(profile.profile_home),
                    "base_home": str(profile.base_home),
                    "is_default": profile.is_default,
                    "active": profile.name == active,
                    "db_exists": db_path.exists(),
                    "policy_exists": policy_path.exists(),
                    "credential_count": credential_count,
                }
            )
        return {"version": DASHBOARD_VERSION, "active_profile": active, "profiles": profiles}

    def select_profile(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        switcher = getattr(self, "_profile_switcher", None)
        if switcher is None:
            return 409, {"error": "Dashboard profile switching is not enabled for this server."}
        profile = str(payload.get("profile") or "").strip()
        if not profile:
            return 400, {"error": "profile is required"}
        try:
            ctx = switcher(profile)
        except ValueError as exc:
            return 422, {"error": str(exc), "profile": profile}
        except MissingPassphraseError as exc:
            relaunch = f"hermes-vault --profile {profile} dashboard"
            return 409, {
                "error": str(exc),
                "profile": profile,
                "requires_passphrase": True,
                "relaunch_command": relaunch,
            }
        except Exception as exc:
            return 500, {"error": str(exc), "profile": profile}
        return 200, {"version": DASHBOARD_VERSION, "selected_profile": ctx.settings.profile_name, "runtime": runtime_metadata(ctx)}

    def session(self, server: "DashboardServer") -> dict[str, Any]:
        ctx = self._context_factory()
        return {
            "version": DASHBOARD_VERSION,
            "local_only": True,
            "host": server.server_address[0],
            "port": server.server_address[1],
            "expires_at_epoch": int(server.expires_at),
            "seconds_remaining": max(0, int(server.expires_at - time.time())),
            "safe_actions": sorted(SAFE_ACTIONS),
            "dry_run_only_actions": sorted(DASHBOARD_DRY_RUN_ONLY_ACTIONS),
            "runtime": runtime_metadata(ctx),
        }

    def action(self, action: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if action not in SAFE_ACTIONS:
            return 404, {"error": f"unknown dashboard action: {action}"}
        ctx = self._context_factory()
        key_validation = validate_vault_key(ctx)
        if action in SECRET_REQUIRED_ACTIONS and not key_validation["ok"]:
            return 423, {
                "error": "Vault key material is not valid for secret-backed dashboard actions.",
                "action": action,
                "key_validation": key_validation,
            }
        try:
            if action == "health":
                return 200, self._action_health(payload, ctx)
            if action == "policy_doctor":
                return 200, self._action_policy_doctor(payload, ctx)
            if action == "verify":
                return 200, self._action_verify(payload, ctx)
            if action == "oauth_refresh":
                return 200, self._action_oauth_refresh(payload, ctx)
            if action == "backup_verify":
                return self._action_backup_verify(payload, ctx)
            if action == "restore_dry_run":
                return self._action_restore_dry_run(payload, ctx)
            if action == "backup_diff":
                return self._action_backup_diff(payload, ctx)
            if action == "onboarding_preview":
                return self._action_onboarding_preview(payload, ctx)
            if action == "maintenance":
                return 200, self._action_maintenance(payload, ctx)
            if action == "policy_explain":
                return 200, self._action_policy_explain(payload, ctx)
            if action == "request_access":
                return 200, self._action_request_access(payload, ctx)
            if action == "request_approve":
                return 200, self._action_request_approve(payload, ctx)
            if action == "request_deny":
                return 200, self._action_request_deny(payload, ctx)
            if action == "recovery_drill":
                return 200, self._action_recovery_drill(payload, ctx)
        except Exception as exc:
            return 500, {"error": str(exc), "action": action}
        return 404, {"error": f"unknown dashboard action: {action}"}

    def _action_health(self, payload: dict[str, Any], ctx: DashboardContext) -> dict[str, Any]:
        report = run_health(
            ctx.vault,
            audit=ctx.audit,
            stale_days=int(payload.get("stale_days") or 30),
            expiring_days=int(payload.get("expiring_days") or 7),
            backup_days=int(payload.get("backup_days") or 30),
        )
        return report.as_dict(exclude_none=False)

    def _action_policy_doctor(self, payload: dict[str, Any], ctx: DashboardContext) -> dict[str, Any]:
        report = run_policy_doctor(
            ctx.settings.effective_policy_path,
            generated_skills_dir=ctx.settings.generated_skills_dir,
            strict=bool(payload.get("strict", False)),
        )
        return report.as_dict(exclude_none=False)

    def _action_policy_explain(self, payload: dict[str, Any], ctx: DashboardContext) -> dict[str, Any]:
        agent_id = str(payload.get("agent_id") or "").strip()
        service = str(payload.get("service") or "").strip()
        action = str(payload.get("action") or "get_env").strip()
        ttl = payload.get("ttl_seconds")
        if not agent_id or not service:
            raise ValueError("agent_id and service are required")
        requested_ttl = int(str(ttl)) if ttl not in (None, "") else None
        return ctx.policy.explain(
            agent_id,
            service,
            action,
            requested_ttl=requested_ttl,
        )

    def _action_request_access(self, payload: dict[str, Any], ctx: DashboardContext) -> dict[str, Any]:
        agent_id = str(payload.get("agent_id") or "").strip()
        service = str(payload.get("service") or "").strip()
        purpose = str(payload.get("purpose") or "").strip()
        if not agent_id or not service or not purpose:
            raise ValueError("agent_id, service, and purpose are required")
        decision = ctx.broker.request_access(
            agent_id=agent_id,
            service=service,
            alias=str(payload.get("alias") or "default"),
            action=str(payload.get("action") or "get_env"),
            purpose=purpose,
            requested_ttl_seconds=int(payload["ttl_seconds"]) if payload.get("ttl_seconds") not in (None, "") else None,
        )
        return decision.model_dump(mode="json")

    def _action_request_approve(self, payload: dict[str, Any], ctx: DashboardContext) -> dict[str, Any]:
        request_id = str(payload.get("request_id") or "").strip()
        if not request_id:
            raise ValueError("request_id is required")
        decision = ctx.broker.approve_access_request(
            request_id,
            reason=payload.get("reason"),
            issue_lease=bool(payload.get("issue_lease", False)),
            ttl_seconds=int(payload["ttl_seconds"]) if payload.get("ttl_seconds") not in (None, "") else None,
        )
        return decision.model_dump(mode="json")

    def _action_request_deny(self, payload: dict[str, Any], ctx: DashboardContext) -> dict[str, Any]:
        request_id = str(payload.get("request_id") or "").strip()
        if not request_id:
            raise ValueError("request_id is required")
        decision = ctx.broker.deny_access_request(
            request_id,
            reason=payload.get("reason"),
        )
        return decision.model_dump(mode="json")

    def _action_recovery_drill(self, payload: dict[str, Any], ctx: DashboardContext) -> dict[str, Any]:
        backup_path = str(payload.get("path") or payload.get("backup_path") or "").strip()
        if not backup_path:
            raise ValueError("backup path is required")
        from hermes_vault.recovery import run_recovery_drill

        report = run_recovery_drill(backup_path=backup_path, vault=ctx.vault, policy=ctx.policy)
        return report.as_dict(exclude_none=False)

    def _action_verify(self, payload: dict[str, Any], ctx: DashboardContext) -> dict[str, Any]:
        targets: list[tuple[str, str | None]]
        if payload.get("all"):
            targets = [(record.service, record.alias) for record in ctx.vault.list_credentials()]
        else:
            service = str(payload.get("service") or "").strip()
            if not service:
                raise ValueError("service is required unless all=true")
            targets = [(service, payload.get("alias") or None)]

        results = []
        for service, alias in targets:
            try:
                decision = ctx.broker.verify_credential(service, alias=alias)
                results.append(decision.model_dump(mode="json"))
            except Exception:
                results.append(_safe_verification_error(service, alias))
        return {"version": DASHBOARD_VERSION, "results": results}

    def _action_oauth_refresh(self, payload: dict[str, Any], ctx: DashboardContext) -> dict[str, Any]:
        registry = OAuthProviderRegistry(ctx.settings.runtime_home / "oauth-providers.yaml")
        engine = RefreshEngine(
            vault=ctx.vault,
            registry=registry,
            proactive_margin_seconds=int(payload.get("margin") or 300),
        )
        engine.set_audit(ctx.audit)
        dry_run = True
        if payload.get("all"):
            attempts = engine.refresh_all(dry_run=dry_run)
        else:
            service = str(payload.get("service") or "").strip()
            if not service:
                raise ValueError("service is required unless all=true")
            attempts = [
                engine.refresh(
                    normalize(service),
                    alias=str(payload.get("alias") or "default"),
                    dry_run=dry_run,
                )
            ]
        return {
            "version": DASHBOARD_VERSION,
            "dry_run": dry_run,
            "dashboard_boundary": "dry_run_only",
            "results": [_safe_refresh_attempt_dict(attempt) for attempt in attempts],
        }

    def _action_backup_verify(self, payload: dict[str, Any], ctx: DashboardContext) -> tuple[int, dict[str, Any]]:
        input_path = str(payload.get("input") or "").strip()
        if not input_path:
            return 400, {"error": "input path is required"}
        report = verify_backup_file(input_path, ctx.vault)
        return (200 if report.decryptable else 422), report.as_dict(exclude_none=False)

    def _action_restore_dry_run(self, payload: dict[str, Any], ctx: DashboardContext) -> tuple[int, dict[str, Any]]:
        input_path = str(payload.get("input") or "").strip()
        if not input_path:
            return 400, {"error": "input path is required"}
        report = restore_dry_run(input_path, ctx.vault)
        return (200 if report.decryptable else 422), report.as_dict(exclude_none=False)

    def _action_backup_diff(self, payload: dict[str, Any], ctx: DashboardContext) -> tuple[int, dict[str, Any]]:
        input_path = str(payload.get("input") or "").strip()
        if not input_path:
            return 400, {"error": "input path is required"}
        try:
            compare = json.loads(Path(input_path).read_text(encoding="utf-8"))
        except Exception as exc:
            return 422, {"error": f"Failed to read backup file: {exc}"}
        current = ctx.vault.export_backup(metadata_only=True)
        entries = [entry.as_dict() for entry in diff_backups(current, compare)]
        summary: dict[str, int] = {"added": 0, "changed": 0, "removed": 0}
        resource_summary: dict[str, int] = {"credential": 0, "lease": 0}
        for entry in entries:
            kind = str(entry["kind"])
            summary[kind] = summary.get(kind, 0) + 1
            resource_type = str(entry.get("resource_type", "credential"))
            resource_summary[resource_type] = resource_summary.get(resource_type, 0) + 1
        return 200, {
            "version": DASHBOARD_VERSION,
            "mode": "backup-diff",
            "backup_path": input_path,
            "count": len(entries),
            "summary": summary,
            "resource_summary": resource_summary,
            "entries": entries,
        }

    def _action_onboarding_preview(self, payload: dict[str, Any], ctx: DashboardContext) -> tuple[int, dict[str, Any]]:
        input_path = str(payload.get("from_env") or payload.get("input") or "").strip()
        if not input_path:
            return 400, {"error": "from_env path is required"}
        env_map = payload.get("map") or payload.get("env_map") or []
        if isinstance(env_map, str):
            env_map = [item.strip() for item in env_map.split(",") if item.strip()]
        if not isinstance(env_map, list):
            return 400, {"error": "map must be a list or comma-separated string"}
        try:
            report = run_bootstrap(
                from_env=Path(input_path),
                agent=str(payload.get("agent") or "hermes"),
                dry_run=True,
                env_map=[str(item) for item in env_map],
                redact_source=False,
            )
        except Exception as exc:
            return 422, {"error": str(exc), "mode": "onboarding-preview"}
        data = report.as_dict()
        data["dashboard_boundary"] = "dry_run_only"
        data["raw_values_returned"] = False
        data["source_mutated"] = False
        data["active_profile"] = ctx.settings.profile_name
        return 200, data

    def _action_maintenance(self, payload: dict[str, Any], ctx: DashboardContext) -> dict[str, Any]:
        report = run_maintenance(
            ctx.vault,
            audit=ctx.audit,
            dry_run=True,
            margin=int(payload.get("margin") or 300),
            stale_days=int(payload.get("stale_days") or 30),
            expiring_days=int(payload.get("expiring_days") or 7),
            backup_days=int(payload.get("backup_days") or 30),
        )
        return _sanitize_maintenance_for_dashboard(report.as_dict(exclude_none=False))


def _safe_refresh_attempt_dict(attempt) -> dict[str, Any]:
    """Serialize a refresh attempt for the dashboard without leaking tokens."""
    return {
        "service": attempt.service,
        "alias": attempt.alias,
        "success": attempt.success,
        "reason": attempt.reason,
        "expires_in": attempt.expires_in,
        "scopes": list(attempt.scopes) if attempt.scopes else [],
        "retry_count": attempt.retry_count,
    }


def _sanitize_maintenance_for_dashboard(report: dict[str, Any]) -> dict[str, Any]:
    """Strip raw token material from a maintenance report before browser exposure."""
    report = dict(report)
    refresh_results = report.get("refresh_results", [])
    if isinstance(refresh_results, list):
        report["refresh_results"] = [
            {
                k: v
                for k, v in result.items()
                if k not in {"new_access_token", "new_refresh_token"}
            }
            for result in refresh_results
        ]
    return report


def _policy_agent_summary(policy: PolicyEngine) -> list[dict[str, Any]]:
    summary = []
    for agent_id, agent_policy in policy.config.agents.items():
        summary.append(
            {
                "agent_id": agent_id,
                "services": {
                    service: {
                        "actions": [action.value for action in entry.actions],
                        "max_ttl_seconds": entry.max_ttl_seconds,
                    }
                    for service, entry in agent_policy.service_actions.items()
                },
                "capabilities": [capability.value for capability in agent_policy.capabilities],
                "raw_secret_access": agent_policy.raw_secret_access,
                "ephemeral_env_only": agent_policy.ephemeral_env_only,
                "max_ttl_seconds": agent_policy.max_ttl_seconds,
            }
        )
    return summary


def _safe_verification_error(service: str, alias: str | None) -> dict[str, Any]:
    reason = (
        "Verification failed before provider check. "
        "Review vault key material and credential metadata."
    )
    return {
        "allowed": False,
        "service": normalize(service),
        "agent_id": "hermes-vault",
        "reason": reason,
        "ttl_seconds": None,
        "env": {},
        "metadata": {
            "alias": alias or "default",
            "record_service": service,
            "error_kind": "dashboard_verify_exception",
            "verification_result": {
                "service": normalize(service),
                "category": "unknown",
                "success": False,
                "reason": reason,
                "status_code": None,
            },
        },
    }


class DashboardServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        token: str,
        api: DashboardAPI,
        static_dir: Path | None = None,
        ttl_seconds: int = 3600,
        dev_origin: str | None = None,
    ) -> None:
        self.token = token
        self.api = api
        self.static_dir = static_dir or dashboard_static_dir()
        self.expires_at = time.time() + ttl_seconds
        self.dev_origin = dev_origin
        super().__init__(server_address, DashboardRequestHandler)


class DashboardRequestHandler(BaseHTTPRequestHandler):
    server: DashboardServer

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/api/"):
            if not self._authorized(parsed):
                self._write_json({"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_api_get(parsed)
            return
        self._serve_static(parsed.path)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        if not self._authorized(parsed):
            self._write_json({"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
            return
        # Read-only audit integrity verification endpoint.
        if parsed.path == "/api/audit-integrity/verify":
            result = self.server.api.audit_integrity()
            self._write_json(result)
            return
        try:
            payload = self._read_json()
        except ValueError as exc:
            self._write_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return
        if parsed.path == "/api/profile/select":
            status, response = self.server.api.select_profile(payload)
            self._write_json(response, status=status)
            return
        if not parsed.path.startswith("/api/actions/"):
            self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        action = parsed.path.rsplit("/", 1)[-1]
        status, response = self.server.api.action(action, payload)
        self._write_json(response, status=status)

    def do_OPTIONS(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if not parsed.path.startswith("/api/") or not self.server.dev_origin:
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_cors_headers()
        self._send_security_headers()
        self.end_headers()

    def _authorized(self, parsed: urllib.parse.ParseResult) -> bool:
        if time.time() > self.server.expires_at:
            return False
        expected = self.server.token
        auth = self.headers.get("Authorization", "")
        if auth == f"Bearer {expected}":
            return True
        query = urllib.parse.parse_qs(parsed.query)
        return query.get("token", [""])[0] == expected

    def _handle_api_get(self, parsed: urllib.parse.ParseResult) -> None:
        query = urllib.parse.parse_qs(parsed.query)
        path = parsed.path
        if path == "/api/overview":
            self._write_json(self.server.api.overview())
        elif path == "/api/credentials":
            self._write_json(self.server.api.credentials())
        elif path == "/api/policy":
            self._write_json(self.server.api.policy())
        elif path == "/api/agent-context":
            agent_id = query.get("agent_id", [""])[0]
            if not agent_id:
                self._write_json({"error": "agent_id is required"}, status=HTTPStatus.BAD_REQUEST)
                return
            self._write_json(self.server.api.agent_context(agent_id))
        elif path == "/api/requests":
            agent_values = query.get("agent_id")
            request_agent_id = agent_values[0] if agent_values else None
            self._write_json(self.server.api.requests(agent_id=request_agent_id))
        elif path == "/api/leases":
            self._write_json(self.server.api.leases())
        elif path == "/api/audit":
            try:
                limit = int(query.get("limit", ["50"])[0] or 50)
            except ValueError:
                self._write_json({"error": "limit must be an integer"}, status=HTTPStatus.BAD_REQUEST)
                return
            self._write_json(self.server.api.audit(limit=limit))
        elif path == "/api/mcp":
            self._write_json(self.server.api.mcp_status())
        elif path == "/api/audit-integrity":
            self._write_json(self.server.api.audit_integrity())
        elif path == "/api/profiles":
            self._write_json(self.server.api.profiles())
        elif path == "/api/session":
            self._write_json(self.server.api.session(self.server))
        else:
            self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def _serve_static(self, path: str) -> None:
        clean_path = "index.html" if path in {"", "/"} else path.lstrip("/")
        candidate = (self.server.static_dir / clean_path).resolve()
        static_root = self.server.static_dir.resolve()
        try:
            candidate.relative_to(static_root)
            inside_static_root = True
        except ValueError:
            inside_static_root = False
        if not inside_static_root or not candidate.exists() or candidate.is_dir():
            if self._is_asset_path(clean_path):
                self._write_static_not_found()
                return
            candidate = static_root / "index.html"
        content_type = mimetypes.guess_type(str(candidate))[0] or "application/octet-stream"
        data = candidate.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store" if candidate.name == "index.html" else "private, max-age=3600")
        self._send_cors_headers()
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return {}
        data = self.rfile.read(int(raw_length))
        if not data:
            return {}
        try:
            parsed = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("request body must be valid JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("request body must be a JSON object")
        return parsed

    def _write_json(self, payload: dict[str, Any], status: int | HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._send_cors_headers()
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_security_headers(self) -> None:
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)

    def _send_cors_headers(self) -> None:
        if not self.server.dev_origin:
            return
        self.send_header("Access-Control-Allow-Origin", self.server.dev_origin)
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Vary", "Origin")

    def _is_asset_path(self, path: str) -> bool:
        return path.startswith("assets/") or Path(path).suffix in {".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".webp"}

    def _write_static_not_found(self) -> None:
        body = b"Not found"
        self.send_response(HTTPStatus.NOT_FOUND)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(body)


def create_dashboard_server(
    *,
    host: str = DEFAULT_HOST,
    port: int = 0,
    token: str | None = None,
    api: DashboardAPI | None = None,
    static_dir: Path | None = None,
    ttl_seconds: int = 3600,
    dev_origin: str | None = None,
) -> DashboardServer:
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("Hermes Vault dashboard only supports local host binding")
    return DashboardServer(
        (host, port),
        token or generate_session_token(),
        api or DashboardAPI(),
        static_dir=static_dir,
        ttl_seconds=ttl_seconds,
        dev_origin=dev_origin,
    )


def run_dashboard(
    *,
    host: str = DEFAULT_HOST,
    port: int = 0,
    open_browser: bool = True,
    dev_assets: str | None = None,
    no_intro: bool = False,
    ttl_seconds: int = 3600,
) -> tuple[str, DashboardServer]:
    state = DashboardState(prompt=True)
    dev_origin = None
    if dev_assets:
        parsed_dev_assets = urllib.parse.urlparse(dev_assets)
        if parsed_dev_assets.scheme and parsed_dev_assets.netloc:
            dev_origin = f"{parsed_dev_assets.scheme}://{parsed_dev_assets.netloc}"
    server = create_dashboard_server(
        host=host,
        port=port,
        api=DashboardAPI(context_factory=state.current_context, profile_switcher=state.switch_profile),
        ttl_seconds=ttl_seconds,
        dev_origin=dev_origin,
    )
    actual_host = server.server_name
    actual_port = server.server_port
    api_base = f"http://{actual_host}:{actual_port}"
    base_url = dev_assets.rstrip("/") if dev_assets else api_base
    query = {"token": server.token}
    if dev_assets:
        query["api_base"] = api_base
    if no_intro:
        query["no_intro"] = "1"
    url = f"{base_url}/?{urllib.parse.urlencode(query)}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    if open_browser:
        webbrowser.open(url, new=2)
    return url, server
