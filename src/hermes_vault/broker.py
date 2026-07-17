from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any

from hermes_vault.audit import AuditLogger
from hermes_vault.models import (
    AccessLogRecord,
    AccessRequestStatus,
    AgentCapability,
    BrokerDecision,
    CredentialStatus,
    Decision,
    LeaseStatus,
    MutationResult,
    ServiceAction,
    VerificationCategory,
    VerificationResult,
)
from hermes_vault.mutations import VaultMutations
from hermes_vault.oauth.errors import (
    OAuthNetworkError,
    OAuthProviderError,
    sanitize_oauth_error_detail,
)
from hermes_vault.oauth.oauth_refresh import (
    RefreshTokenExpiredError,
    RefreshTokenMissingError,
)
from hermes_vault.policy import PolicyEngine
from hermes_vault.service_ids import get_env_var_map, normalize
from hermes_vault.verifier import Verifier
from hermes_vault.vault import AmbiguousTargetError, Vault

OAUTH_REFRESH_MARGIN_SECONDS = 300  # 5 minutes
OAUTH_REFRESH_COOLDOWN_SECONDS = 30  # seconds between refresh attempts


def _verification_is_unsupported(result: VerificationResult) -> bool:
    return (
        result.category is VerificationCategory.unknown
        and result.reason == "No provider-specific verifier is configured for this service."
    )


class Broker:
    def __init__(
        self,
        vault: Vault,
        policy: PolicyEngine,
        verifier: Verifier,
        audit: AuditLogger,
        scanner: Any = None,
        refresh_engine: Any = None,
    ) -> None:
        self.vault = vault
        self.policy = policy
        self.verifier = verifier
        self.audit = audit
        self.scanner = scanner
        self._refresh_engine = refresh_engine
        self._refresh_cooldowns: dict[str, float] = {}
        self._mutations = VaultMutations(vault=vault, policy=policy, audit=audit)

    @property
    def refresh_engine(self):
        if self._refresh_engine is None:
            from hermes_vault.oauth.oauth_refresh import RefreshEngine
            self._refresh_engine = RefreshEngine(vault=self.vault)
        return self._refresh_engine

    def get_credential(self, service: str, purpose: str, agent_id: str) -> BrokerDecision:
        service = normalize(service)
        allowed, reason = self.policy.allow_raw_secret_access(agent_id, service)
        if not allowed:
            return self._deny(agent_id, service, "get_credential", reason)
        record = self.vault.get_credential(service)
        if not record:
            return self._deny(agent_id, service, "get_credential", "credential not found in vault")
        return self._allow(
            agent_id,
            service,
            "get_credential",
            f"raw secret access allowed for purpose '{purpose}'",
            metadata={
                "credential_id": record.id,
                "service": record.service,
                "alias": record.alias,
                "credential_type": record.credential_type,
            },
        )

    def get_ephemeral_env(self, service: str, agent_id: str, ttl: int, alias: str | None = None) -> BrokerDecision:
        canonical = normalize(service)
        allowed, reason = self.policy.can(agent_id, canonical, ServiceAction.get_env)
        if not allowed:
            return self._deny(agent_id, canonical, "get_ephemeral_env", reason, ttl_seconds=ttl)
        ttl_ok, ttl_reason, effective_ttl = self.policy.enforce_ttl(agent_id, ttl, service=canonical)
        if not ttl_ok:
            return self._deny(agent_id, canonical, "get_ephemeral_env", ttl_reason, ttl_seconds=ttl)
        try:
            record = self.vault.resolve_credential(canonical, alias=alias)
        except (AmbiguousTargetError, KeyError) as exc:
            return self._deny(agent_id, canonical, "get_ephemeral_env", str(exc), ttl_seconds=effective_ttl)
        lease_metadata: dict[str, object] = {}
        if self.policy.require_lease_for_env(agent_id, canonical):
            lease = self.vault.find_active_lease(
                agent_id=agent_id,
                service=record.service,
                alias=record.alias,
            )
            if lease is None:
                return self._deny(
                    agent_id,
                    canonical,
                    "get_ephemeral_env",
                    "policy requires an active lease before env handoff",
                    ttl_seconds=effective_ttl,
                    metadata={"lease_required": True, "alias": record.alias},
                )
            remaining = int((lease.expires_at - datetime.now(timezone.utc)).total_seconds())
            if remaining <= 0:
                return self._deny(
                    agent_id,
                    canonical,
                    "get_ephemeral_env",
                    "lease expired before env handoff",
                    ttl_seconds=effective_ttl,
                    metadata={"lease_required": True, "lease_id": lease.id},
                )
            effective_ttl = min(effective_ttl, remaining)
            lease_metadata = {
                "lease_required": True,
                "lease_id": lease.id,
                "lease_expires_at": lease.expires_at.isoformat(),
                "lease_purpose": lease.purpose,
            }
        secret = self.vault.get_secret(record.id)
        if not secret:
            return self._deny(agent_id, canonical, "get_ephemeral_env", "credential not found in vault", ttl_seconds=effective_ttl)
        # ── OAuth freshness check ────────────────────────────────────────
        freshness_result = self._ensure_oauth_freshness(
            record, canonical, alias, agent_id,
        )
        if freshness_result.get("decision") == "deny":
            deny_meta: dict[str, object] = {}
            oauth_meta = freshness_result.get("oauth_refresh")
            if oauth_meta is not None:
                deny_meta["oauth_refresh"] = oauth_meta
            raw_reason = freshness_result.get("reason")
            deny_reason = raw_reason if isinstance(raw_reason, str) else "OAuth refresh failed"
            return self._deny(
                agent_id, canonical, "get_ephemeral_env",
                deny_reason,
                ttl_seconds=effective_ttl,
                metadata=deny_meta,
            )
        if freshness_result.get("re_resolve"):
            record = self.vault.resolve_credential(canonical, alias=alias)
            secret = self.vault.get_secret(record.id)
            if not secret:
                return self._deny(agent_id, canonical, "get_ephemeral_env", "credential not found after OAuth refresh", ttl_seconds=effective_ttl)
        env_template = get_env_var_map(canonical)
        env = {key: value.format(secret=secret.secret) for key, value in env_template.items()}
        warnings = self._governance_warnings(canonical, alias)
        metadata: dict[str, object] = {}
        if warnings:
            metadata["warnings"] = warnings
        oauth_meta = freshness_result.get("oauth_refresh")
        if oauth_meta is not None:
            metadata["oauth_refresh"] = oauth_meta
        metadata.update(lease_metadata)
        return self._allow(
            agent_id,
            canonical,
            "get_ephemeral_env",
            "ephemeral environment materialization approved",
            ttl_seconds=effective_ttl,
            env=env,
            metadata=metadata,
        )

    def _ensure_oauth_freshness(
        self,
        record,
        service: str,
        alias: str | None,
        agent_id: str,
    ) -> dict[str, object]:
        """Check whether an OAuth access token needs refreshing and do it.

        Returns a dict with keys:
          - decision: "pass" | "deny"
          - re_resolve: bool (if True, caller must re-fetch record + secret)
          - oauth_refresh: dict with refresh metadata (or None for non-OAuth)
          - reason: str (for deny cases)
        """
        # 1. Non-OAuth credentials pass through untouched
        if record.credential_type != "oauth_access_token":
            return {"decision": "pass", "oauth_refresh": None}

        # 2. Token with no expiry — can't determine staleness
        if record.expiry is None:
            return {"decision": "pass", "oauth_refresh": {"refreshed": None}}

        # 3. Check if token is near expiry or already expired
        is_near_expiry = self.refresh_engine.is_expired(
            record, margin_seconds=OAUTH_REFRESH_MARGIN_SECONDS,
        )

        if not is_near_expiry:
            # 4. Token still has plenty of life
            return {"decision": "pass", "oauth_refresh": {"refreshed": False}}

        # 5. Token is near/at expiry — check rotate permission
        can_rotate, rotate_reason = self.policy.can(
            agent_id, service, ServiceAction.rotate,
        )
        cooldown_key = f"{service}:{alias or 'default'}"

        if not can_rotate:
            hard_expired = self.refresh_engine.is_expired(record, margin_seconds=0)
            self.audit.record(
                AccessLogRecord(
                    agent_id=agent_id,
                    service=service,
                    action="broker_env_oauth_refresh",
                    decision=Decision.deny if hard_expired else Decision.allow,
                    reason=f"OAuth refresh skipped: {rotate_reason}",
                )
            )
            if hard_expired:
                return {
                    "decision": "deny",
                    "reason": f"OAuth refresh denied: {rotate_reason}",
                    "oauth_refresh": {"refreshed": False, "error": rotate_reason},
                }
            return {
                "decision": "pass",
                "oauth_refresh": {"refreshed": False, "warning": rotate_reason},
            }

        # 6. Check cooldown
        last_attempt = self._refresh_cooldowns.get(cooldown_key, 0.0)
        if time.time() - last_attempt < OAUTH_REFRESH_COOLDOWN_SECONDS:
            return {
                "decision": "pass",
                "oauth_refresh": {"refreshed": False, "cooldown": True},
            }

        # 7. Attempt live refresh
        try:
            self.refresh_engine.refresh(service, alias=alias or "default", dry_run=False)
            self._refresh_cooldowns[cooldown_key] = time.time()
            self.audit.record(
                AccessLogRecord(
                    agent_id=agent_id,
                    service=service,
                    action="broker_env_oauth_refresh",
                    decision=Decision.allow,
                    reason="Token refreshed successfully by broker",
                )
            )
            return {
                "decision": "pass",
                "re_resolve": True,
                "oauth_refresh": {"refreshed": True},
            }
        except RefreshTokenMissingError as exc:
            return self._oauth_refresh_error(
                record, exc, agent_id, service, cooldown_key,
            )
        except RefreshTokenExpiredError as exc:
            return self._oauth_refresh_error(
                record, exc, agent_id, service, cooldown_key,
            )
        except OAuthProviderError as exc:
            return self._oauth_refresh_error(
                record, exc, agent_id, service, cooldown_key,
            )
        except OAuthNetworkError as exc:
            return self._oauth_refresh_error(
                record, exc, agent_id, service, cooldown_key,
            )
        except Exception as exc:
            return self._oauth_refresh_error(
                record, exc, agent_id, service, cooldown_key,
            )

    def _oauth_refresh_error(
        self,
        record,
        exc: Exception,
        agent_id: str,
        service: str,
        cooldown_key: str,
    ) -> dict[str, object]:
        """Handle a refresh error: audit, cooldown, and decide pass/deny."""
        sanitized = sanitize_oauth_error_detail(exc)
        self._refresh_cooldowns[cooldown_key] = time.time()
        hard_expired = self.refresh_engine.is_expired(record, margin_seconds=0)
        self.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service=service,
                action="broker_env_oauth_refresh",
                decision=Decision.deny if hard_expired else Decision.allow,
                reason=sanitized,
            )
        )
        if hard_expired:
            return {
                "decision": "deny",
                "reason": sanitized,
                "oauth_refresh": {"refreshed": False, "error": sanitized},
            }
        return {
            "decision": "pass",
            "oauth_refresh": {"refreshed": False, "error": sanitized},
        }

    def _governance_warnings(self, service: str, alias: str | None = None) -> list[dict[str, str]]:
        """Build structured governance warnings for a credential request."""
        warnings: list[dict[str, str]] = []
        now = datetime.now(timezone.utc)

        # ── expiry warnings ──────────────────────────────────────────
        expiry_warning_days = int(os.environ.get("HERMES_VAULT_EXPIRY_WARNING_DAYS", "7"))
        record = None
        try:
            if alias is not None:
                record = self.vault.resolve_credential(service, alias=alias)
            else:
                record = self.vault.get_credential(service)
        except Exception:
            record = None
        if record and record.expiry:
            expiry = record.expiry.replace(tzinfo=timezone.utc) if record.expiry.tzinfo is None else record.expiry
            days_until = (expiry - now).days
            if days_until < 0:
                warnings.append({
                    "kind": "credential_expired",
                    "service": record.service,
                    "alias": record.alias,
                    "detail": f"credential expired {abs(days_until)} day(s) ago",
                    "days_until_expiry": str(days_until),
                })
            elif days_until <= expiry_warning_days:
                warnings.append({
                    "kind": "credential_expiring_soon",
                    "service": record.service,
                    "alias": record.alias,
                    "detail": f"credential expires in {days_until} day(s)",
                    "days_until_expiry": str(days_until),
                })

        # ── backup reminder ──────────────────────────────────────────
        backup_days = int(os.environ.get("HERMES_VAULT_BACKUP_REMINDER_DAYS", "30"))
        entries = self.audit.list_recent(limit=500, action="export_backup")
        last_backup: datetime | None = None
        for entry in entries:
            ts_str = entry.get("timestamp")
            if ts_str and isinstance(ts_str, str):
                try:
                    last_backup = datetime.fromisoformat(ts_str)
                    break
                except ValueError:
                    continue
        if last_backup is None:
            entries = self.audit.list_recent(limit=500, action="backup")
            for entry in entries:
                ts_str = entry.get("timestamp")
                if ts_str and isinstance(ts_str, str):
                    try:
                        last_backup = datetime.fromisoformat(ts_str)
                        break
                    except ValueError:
                        continue

        if last_backup is not None:
            days_since = (now - last_backup.replace(tzinfo=timezone.utc)).days
            if days_since > backup_days:
                warnings.append({
                    "kind": "backup_overdue",
                    "service": "*",
                    "alias": "*",
                    "detail": f"last backup was {days_since} day(s) ago (reminder: {backup_days}d)",
                    "days_since_backup": str(days_since),
                })
        else:
            warnings.append({
                "kind": "no_backup",
                "service": "*",
                "alias": "*",
                "detail": "no backup has been recorded",
            })

        return warnings

    def verify_credential(self, service: str, alias: str | None = None) -> BrokerDecision:
        requested_service = service
        service = normalize(service)
        try:
            record = self.vault.resolve_credential(requested_service, alias=alias)
        except KeyError:
            return BrokerDecision(
                allowed=False,
                service=service,
                agent_id="hermes-vault",
                reason="credential not found in vault",
            )
        except Exception as exc:
            return BrokerDecision(
                allowed=False,
                service=service,
                agent_id="hermes-vault",
                reason=str(exc),
            )
        try:
            secret = self.vault.get_secret(record.id)
        except Exception:
            reason = "Credential secret could not be decrypted. Verify the vault passphrase and key material."
            result = VerificationResult(
                service=service,
                category=VerificationCategory.unknown,
                success=False,
                reason=reason,
            )
            return BrokerDecision(
                allowed=False,
                service=service,
                agent_id="hermes-vault",
                reason=reason,
                metadata={
                    "credential_id": record.id,
                    "alias": record.alias,
                    "record_service": record.service,
                    "error_kind": "secret_decrypt_failed",
                    "verification_result": result.model_dump(mode="json"),
                },
            )
        if secret is None:
            reason = "Credential secret was not found in vault."
            result = VerificationResult(
                service=service,
                category=VerificationCategory.unknown,
                success=False,
                reason=reason,
            )
            return BrokerDecision(
                allowed=False,
                service=service,
                agent_id="hermes-vault",
                reason=reason,
                metadata={
                    "credential_id": record.id,
                    "alias": record.alias,
                    "record_service": record.service,
                    "error_kind": "secret_not_found",
                    "verification_result": result.model_dump(mode="json"),
                },
            )
        result = self.verifier.verify(service, secret.secret)
        status = CredentialStatus.active if result.success else (
            CredentialStatus.invalid if result.category.value == "invalid_or_expired" else CredentialStatus.unknown
        )
        verified_at = None if _verification_is_unsupported(result) else result.checked_at.isoformat()
        self.vault.update_status(record.id, status=status, verified_at=verified_at)
        self.audit.record(
            AccessLogRecord(
                agent_id="hermes-vault",
                service=service,
                action="verify_credential",
                decision=Decision.allow,
                reason=result.reason,
                verification_result=result.category,
            )
        )
        return BrokerDecision(
            allowed=result.success,
            service=service,
            agent_id="hermes-vault",
            reason=result.reason,
            metadata={
                "credential_id": record.id,
                "alias": record.alias,
                "record_service": record.service,
                "verification_result": result.model_dump(mode="json"),
            },
        )

    def list_available_credentials(self, agent_id: str) -> list[dict[str, str]]:
        # Gate on agent-level capability (non-service-scoped action).
        cap_ok, cap_reason = self.policy.can_capability(agent_id, AgentCapability.list_credentials)
        if not cap_ok:
            self._deny(agent_id, "n/a", "list_available_credentials", cap_reason)
            return []
        agent_policy = self.policy.get_agent_policy(agent_id)
        if not agent_policy:
            self._deny(agent_id, "n/a", "list_available_credentials", "agent is not defined in policy")
            return []
        allowed_services = set(agent_policy.services)
        records = self.vault.list_credentials()
        visible = [
            {
                "service": record.service,
                "alias": record.alias,
                "credential_type": record.credential_type,
                "status": record.status.value,
            }
            for record in records
            if record.service in allowed_services
        ]
        self.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service="*",
                action="list_available_credentials",
                decision=Decision.allow,
                reason="returned policy-filtered credential metadata",
            )
        )  # audit allow
        return visible

    def scan_secrets(self, agent_id: str, paths: list | None = None) -> BrokerDecision:
        """Scan filesystem for plaintext secrets.  Gated on ``scan_secrets`` capability."""
        cap_ok, cap_reason = self.policy.can_capability(agent_id, AgentCapability.scan_secrets)
        if not cap_ok:
            return self._deny(agent_id, "n/a", "scan_secrets", cap_reason)
        if self.scanner is None:
            return self._deny(agent_id, "n/a", "scan_secrets", "scanner not available in broker")
        findings = self.scanner.scan(paths=paths)
        self.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service="*",
                action="scan_secrets",
                decision=Decision.allow,
                reason=f"scan completed, {len(findings)} finding(s)",
            )
        )
        return BrokerDecision(
            allowed=True,
            service="*",
            agent_id=agent_id,
            reason=f"scan completed, {len(findings)} finding(s)",
            metadata={
                "finding_count": len(findings),
                "findings": [f.model_dump(mode="json") for f in findings],
            },
        )

    def export_backup(self, agent_id: str) -> BrokerDecision:
        """Export encrypted vault backup.  Gated on ``export_backup`` capability."""
        cap_ok, cap_reason = self.policy.can_capability(agent_id, AgentCapability.export_backup)
        if not cap_ok:
            return self._deny(agent_id, "n/a", "export_backup", cap_reason)
        backup = self.vault.export_backup()
        cred_count = len(backup.get("credentials", []))
        self.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service="*",
                action="export_backup",
                decision=Decision.allow,
                reason=f"backup exported, {cred_count} credential(s)",
            )
        )
        return BrokerDecision(
            allowed=True,
            service="*",
            agent_id=agent_id,
            reason=f"backup exported, {cred_count} credential(s)",
            metadata={"backup": backup},
        )

    def import_credentials(self, agent_id: str, backup: dict, replace: bool = True) -> BrokerDecision:
        """Import credentials from a backup dict.  Gated on ``import_credentials`` capability."""
        cap_ok, cap_reason = self.policy.can_capability(agent_id, AgentCapability.import_credentials)
        if not cap_ok:
            return self._deny(agent_id, "n/a", "import_credentials", cap_reason)
        imported = self.vault.import_backup(backup, replace=replace)
        self.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service="*",
                action="import_credentials",
                decision=Decision.allow,
                reason=f"imported {len(imported)} credential(s)",
            )
        )
        return BrokerDecision(
            allowed=True,
            service="*",
            agent_id=agent_id,
            reason=f"imported {len(imported)} credential(s)",
            metadata={
                "imported_count": len(imported),
                "imported_ids": [r.id for r in imported],
            },
        )

    # ── mutation paths (policy-checked, audited) ──────────────────────────

    def add_credential(
        self,
        agent_id: str,
        service: str,
        secret: str,
        credential_type: str = "api_key",
        alias: str = "default",
        imported_from: str | None = None,
        scopes: list[str] | None = None,
        replace_existing: bool = False,
    ) -> MutationResult:
        """Add a credential through the centralized mutation path."""
        return self._mutations.add_credential(
            agent_id=agent_id,
            service=service,
            secret=secret,
            credential_type=credential_type,
            alias=alias,
            imported_from=imported_from,
            scopes=scopes,
            replace_existing=replace_existing,
        )

    def rotate_credential(
        self,
        agent_id: str,
        service_or_id: str,
        new_secret: str,
        alias: str | None = None,
    ) -> MutationResult:
        """Rotate a credential through the centralized mutation path."""
        return self._mutations.rotate_credential(
            agent_id=agent_id,
            service_or_id=service_or_id,
            new_secret=new_secret,
            alias=alias,
        )

    def delete_credential(
        self,
        agent_id: str,
        service_or_id: str,
        alias: str | None = None,
    ) -> MutationResult:
        """Delete a credential through the centralized mutation path."""
        return self._mutations.delete_credential(
            agent_id=agent_id,
            service_or_id=service_or_id,
            alias=alias,
        )

    def get_metadata(
        self,
        agent_id: str,
        service_or_id: str,
        alias: str | None = None,
    ) -> MutationResult:
        """Fetch credential metadata through the centralized mutation path."""
        return self._mutations.get_metadata(
            agent_id=agent_id,
            service_or_id=service_or_id,
            alias=alias,
        )

    def issue_lease(
        self,
        agent_id: str,
        service_or_id: str,
        ttl_seconds: int,
        alias: str | None = None,
        purpose: str = "task",
        reason: str | None = None,
    ) -> BrokerDecision:
        try:
            record = self.vault.resolve_credential(service_or_id, alias=alias)
        except Exception as exc:
            return self._deny(agent_id, normalize(service_or_id), "issue_lease", str(exc), ttl_seconds=ttl_seconds)

        allowed, policy_reason = self.policy.can(agent_id, record.service, ServiceAction.issue_lease)
        if not allowed:
            return self._deny(agent_id, record.service, "issue_lease", policy_reason, ttl_seconds=ttl_seconds)
        if self.policy.require_lease_purpose(agent_id, record.service) and purpose.strip().lower() in {"", "task", "default"}:
            return self._deny(
                agent_id,
                record.service,
                "issue_lease",
                "policy requires a specific lease purpose",
                ttl_seconds=ttl_seconds,
            )

        ttl_ok, ttl_reason, effective_ttl = self.policy.enforce_ttl(agent_id, ttl_seconds, record.service)
        if not ttl_ok:
            return self._deny(agent_id, record.service, "issue_lease", ttl_reason, ttl_seconds=ttl_seconds)

        lease = self.vault.issue_lease(
            service_or_id=record.id,
            agent_id=agent_id,
            ttl_seconds=effective_ttl,
            purpose=purpose,
            issued_by=agent_id,
            reason=reason,
        )
        metadata = lease.model_dump(mode="json")
        self.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service=lease.service,
                action="issue_lease",
                decision=Decision.allow,
                reason="lease issued",
                ttl_seconds=lease.ttl_seconds,
                metadata={"lease_id": lease.id, "status": lease.status.value, "expires_at": lease.expires_at.isoformat()},
            )
        )
        return BrokerDecision(
            allowed=True,
            service=lease.service,
            agent_id=agent_id,
            reason="lease issued",
            ttl_seconds=lease.ttl_seconds,
            metadata={"lease": metadata},
        )

    def lease_checkout(
        self,
        *,
        agent_id: str,
        service: str,
        ttl_seconds: int,
        alias: str | None = None,
        purpose: str = "task",
    ) -> BrokerDecision:
        canonical = normalize(service)
        try:
            record = self.vault.resolve_credential(canonical, alias=alias)
        except Exception as exc:
            return self._deny(agent_id, canonical, "lease_checkout", str(exc), ttl_seconds=ttl_seconds)
        lease = self.vault.find_active_lease(
            agent_id=agent_id,
            service=record.service,
            alias=record.alias,
        )
        lease_issued = False
        if lease is None:
            issued = self.issue_lease(
                agent_id=agent_id,
                service_or_id=record.service,
                ttl_seconds=ttl_seconds,
                alias=record.alias,
                purpose=purpose,
            )
            if not issued.allowed:
                return issued
            lease = self.vault.get_lease(issued.metadata["lease"]["id"])
            lease_issued = True
        if lease is None:
            return self._deny(agent_id, canonical, "lease_checkout", "lease could not be resolved", ttl_seconds=ttl_seconds)
        env_decision = self.get_ephemeral_env(
            service=record.service,
            agent_id=agent_id,
            ttl=ttl_seconds,
            alias=record.alias,
        )
        env_decision.metadata["lease_checkout"] = {
            "lease_id": lease.id,
            "lease_issued": lease_issued,
            "purpose": lease.purpose,
        }
        return env_decision

    def request_access(
        self,
        *,
        agent_id: str,
        service: str,
        action: str,
        purpose: str,
        alias: str = "default",
        requested_ttl_seconds: int | None = None,
    ) -> BrokerDecision:
        canonical = normalize(service)
        explanation = self.policy.explain(agent_id, canonical, action, requested_ttl_seconds)
        request = self.vault.create_access_request(
            agent_id=agent_id,
            service=canonical,
            alias=alias,
            action=action,
            purpose=purpose,
            requested_ttl_seconds=requested_ttl_seconds,
            metadata={"policy_explain": explanation},
        )
        self.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service=canonical,
                action="request_access",
                decision=Decision.allow,
                reason="access request created",
                ttl_seconds=requested_ttl_seconds,
                metadata={"request_id": request.id, "requested_action": action, "alias": alias},
            )
        )
        return BrokerDecision(
            allowed=True,
            service=canonical,
            agent_id=agent_id,
            reason="access request created; no credential material was returned",
            ttl_seconds=requested_ttl_seconds,
            metadata={"request": request.model_dump(mode="json")},
        )

    def list_access_requests(
        self,
        *,
        agent_id: str | None = None,
        service: str | None = None,
        status: str | None = None,
    ) -> BrokerDecision:
        requests = self.vault.list_access_requests(agent_id=agent_id, service=service, status=status)
        return BrokerDecision(
            allowed=True,
            service=normalize(service) if service else "*",
            agent_id=agent_id or "operator",
            reason=f"returned {len(requests)} access request(s)",
            metadata={"requests": [request.model_dump(mode="json") for request in requests]},
        )

    def show_access_request(self, request_id: str) -> BrokerDecision:
        request = self.vault.get_access_request(request_id)
        if request is None:
            return self._deny("operator", "*", "show_access_request", f"access request '{request_id}' not found")
        return BrokerDecision(
            allowed=True,
            service=request.service,
            agent_id=request.agent_id,
            reason=f"returned access request {request.id}",
            metadata={"request": request.model_dump(mode="json")},
        )

    def approve_access_request(
        self,
        request_id: str,
        *,
        decided_by: str = "operator",
        reason: str | None = None,
        issue_lease: bool = False,
        ttl_seconds: int | None = None,
    ) -> BrokerDecision:
        request = self.vault.get_access_request(request_id)
        if request is None:
            return self._deny(decided_by, "*", "approve_access_request", f"access request '{request_id}' not found")
        lease_id = None
        if issue_lease:
            lease_decision = self.issue_lease(
                agent_id=request.agent_id,
                service_or_id=request.service,
                ttl_seconds=ttl_seconds or request.requested_ttl_seconds or 900,
                alias=request.alias,
                purpose=request.purpose,
                reason=reason,
            )
            if not lease_decision.allowed:
                return lease_decision
            lease_id = lease_decision.metadata["lease"]["id"]
        try:
            updated = self.vault.decide_access_request(
                request_id,
                status=AccessRequestStatus.approved,
                decided_by=decided_by,
                reason=reason,
                lease_id=lease_id,
            )
        except (KeyError, ValueError) as exc:
            return self._deny(decided_by, request.service, "approve_access_request", str(exc))
        self.audit.record(
            AccessLogRecord(
                agent_id=decided_by,
                service=updated.service,
                action="approve_access_request",
                decision=Decision.allow,
                reason=reason or "access request approved",
                metadata={"request_id": updated.id, "lease_id": lease_id},
            )
        )
        return BrokerDecision(
            allowed=True,
            service=updated.service,
            agent_id=updated.agent_id,
            reason="access request approved",
            metadata={"request": updated.model_dump(mode="json")},
        )

    def deny_access_request(
        self,
        request_id: str,
        *,
        decided_by: str = "operator",
        reason: str | None = None,
    ) -> BrokerDecision:
        request = self.vault.get_access_request(request_id)
        service = request.service if request else "*"
        try:
            updated = self.vault.decide_access_request(
                request_id,
                status=AccessRequestStatus.denied,
                decided_by=decided_by,
                reason=reason,
            )
        except (KeyError, ValueError) as exc:
            return self._deny(decided_by, service, "deny_access_request", str(exc))
        self.audit.record(
            AccessLogRecord(
                agent_id=decided_by,
                service=updated.service,
                action="deny_access_request",
                decision=Decision.deny,
                reason=reason or "access request denied",
                metadata={"request_id": updated.id},
            )
        )
        return BrokerDecision(
            allowed=True,
            service=updated.service,
            agent_id=updated.agent_id,
            reason="access request denied",
            metadata={"request": updated.model_dump(mode="json")},
        )

    def list_leases(
        self,
        agent_id: str,
        service: str | None = None,
        status: str | LeaseStatus | None = None,
    ) -> BrokerDecision:
        leases = self.vault.list_leases(service=service, status=status)
        visible = []
        for lease in leases:
            allowed, policy_reason = self.policy.can(agent_id, lease.service, ServiceAction.list_leases)
            if not allowed:
                continue
            visible.append(lease.model_dump(mode="json"))
        if service is not None and not visible:
            return self._deny(agent_id, normalize(service), "list_leases", "no visible leases for this service")
        self.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service=service or "*",
                action="list_leases",
                decision=Decision.allow,
                reason=f"returned {len(visible)} lease(s)",
                metadata={"lease_count": len(visible), "filtered_out": len(leases) - len(visible)},
            )
        )
        return BrokerDecision(
            allowed=True,
            service=normalize(service) if service else "*",
            agent_id=agent_id,
            reason=f"returned {len(visible)} lease(s)",
            metadata={"leases": visible},
        )

    def show_lease(self, agent_id: str, lease_id: str) -> BrokerDecision:
        lease = self.vault.get_lease(lease_id)
        if lease is None:
            return self._deny(agent_id, "*", "show_lease", f"lease '{lease_id}' not found")
        allowed, policy_reason = self.policy.can(agent_id, lease.service, ServiceAction.show_lease)
        if not allowed:
            return self._deny(agent_id, lease.service, "show_lease", policy_reason)
        self.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service=lease.service,
                action="show_lease",
                decision=Decision.allow,
                reason=f"returned lease {lease.id}",
                metadata={"lease_id": lease.id, "status": lease.status.value},
            )
        )
        return BrokerDecision(
            allowed=True,
            service=lease.service,
            agent_id=agent_id,
            reason=f"returned lease {lease.id}",
            metadata={"lease": lease.model_dump(mode="json")},
        )

    def renew_lease(
        self,
        agent_id: str,
        lease_id: str,
        ttl_seconds: int,
    ) -> BrokerDecision:
        lease = self.vault.get_lease(lease_id)
        if lease is None:
            return self._deny(agent_id, "*", "renew_lease", f"lease '{lease_id}' not found", ttl_seconds=ttl_seconds)
        allowed, policy_reason = self.policy.can(agent_id, lease.service, ServiceAction.renew_lease)
        if not allowed:
            return self._deny(agent_id, lease.service, "renew_lease", policy_reason, ttl_seconds=ttl_seconds)
        ttl_ok, ttl_reason, effective_ttl = self.policy.enforce_ttl(agent_id, ttl_seconds, lease.service)
        if not ttl_ok:
            return self._deny(agent_id, lease.service, "renew_lease", ttl_reason, ttl_seconds=ttl_seconds)
        try:
            updated = self.vault.renew_lease(lease.id, effective_ttl)
        except ValueError as exc:
            return self._deny(agent_id, lease.service, "renew_lease", str(exc), ttl_seconds=ttl_seconds)
        self.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service=lease.service,
                action="renew_lease",
                decision=Decision.allow,
                reason=f"renewed lease {lease.id}",
                ttl_seconds=updated.ttl_seconds,
                metadata={"lease_id": updated.id, "status": updated.status.value, "expires_at": updated.expires_at.isoformat()},
            )
        )
        return BrokerDecision(
            allowed=True,
            service=lease.service,
            agent_id=agent_id,
            reason=f"renewed lease {lease.id}",
            ttl_seconds=updated.ttl_seconds,
            metadata={"lease": updated.model_dump(mode="json")},
        )

    def revoke_lease(
        self,
        agent_id: str,
        lease_id: str,
        reason: str | None = None,
    ) -> BrokerDecision:
        lease = self.vault.get_lease(lease_id)
        if lease is None:
            return self._deny(agent_id, "*", "revoke_lease", f"lease '{lease_id}' not found")
        allowed, policy_reason = self.policy.can(agent_id, lease.service, ServiceAction.revoke_lease)
        if not allowed:
            return self._deny(agent_id, lease.service, "revoke_lease", policy_reason)
        try:
            updated = self.vault.revoke_lease(lease.id, reason=reason)
        except ValueError as exc:
            return self._deny(agent_id, lease.service, "revoke_lease", str(exc))
        self.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service=lease.service,
                action="revoke_lease",
                decision=Decision.allow,
                reason=f"revoked lease {lease.id}",
                metadata={"lease_id": updated.id, "status": updated.status.value, "revoked_at": updated.revoked_at.isoformat() if updated.revoked_at else None},
            )
        )
        return BrokerDecision(
            allowed=True,
            service=lease.service,
            agent_id=agent_id,
            reason=f"revoked lease {lease.id}",
            metadata={"lease": updated.model_dump(mode="json")},
        )

    # ── internal helpers ──────────────────────────────────────────────────

    def _allow(
        self,
        agent_id: str,
        service: str,
        action: str,
        reason: str,
        ttl_seconds: int | None = None,
        env: dict[str, str] | None = None,
        metadata: dict[str, object] | None = None,
    ) -> BrokerDecision:
        decision = BrokerDecision(
            allowed=True,
            service=service,
            agent_id=agent_id,
            reason=reason,
            ttl_seconds=ttl_seconds,
            env=env or {},
            metadata=metadata or {},
        )
        self.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service=service,
                action=action,
                decision=Decision.allow,
                reason=reason,
                ttl_seconds=ttl_seconds,
            )
        )
        return decision

    def _deny(
        self,
        agent_id: str,
        service: str,
        action: str,
        reason: str,
        ttl_seconds: int | None = None,
        metadata: dict[str, object] | None = None,
    ) -> BrokerDecision:
        self.audit.record(
            AccessLogRecord(
                agent_id=agent_id,
                service=service,
                action=action,
                decision=Decision.deny,
                reason=reason,
                ttl_seconds=ttl_seconds,
            )
        )
        return BrokerDecision(
            allowed=False,
            service=service,
            agent_id=agent_id,
            reason=reason,
            ttl_seconds=ttl_seconds,
            metadata=metadata or {},
        )
