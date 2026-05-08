"""OAuth token auto-refresh engine for Hermes Vault.

Detects expired or nearly-expired access tokens and refreshes them using
stored refresh tokens.  Updates the vault atomically and logs every attempt.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from hermes_vault.models import (
    AccessLogRecord,
    CredentialRecord,
    CredentialSecret,
    CredentialStatus,
    Decision,
    MutationResult,
    utc_now,
)
from hermes_vault.oauth.errors import OAuthNetworkError, OAuthProviderError
from hermes_vault.oauth.providers import OAuthProvider, OAuthProviderRegistry
from hermes_vault.service_ids import normalize
from hermes_vault.vault import Vault


class RefreshTokenMissingError(RuntimeError):
    """Raised when no refresh token exists for a service."""


class RefreshTokenExpiredError(RuntimeError):
    """Raised when the refresh token itself has been revoked or expired."""


def refresh_alias_for(access_alias: str) -> str:
    """Return the deterministic refresh-token alias for an access-token alias."""
    return f"refresh:{access_alias}"


@dataclass
class RefreshAttempt:
    """Result of a single refresh attempt."""

    service: str
    alias: str
    success: bool
    reason: str
    new_access_token: str | None = None
    new_refresh_token: str | None = None
    expires_in: int | None = None
    scopes: list[str] = field(default_factory=list)
    retry_count: int = 0


class RefreshEngine:
    """Proactive and on-demand OAuth token refresh.

    Parameters
    ----------
    vault:
        The encrypted credential vault.
    registry:
        OAuth provider registry.  If ``None``, loaded from the default path.
    proactive_margin_seconds:
        How far *before* expiry to trigger proactive refresh (default 300s).
    max_retries:
        Number of retry attempts on transient failures (default 3).
    base_backoff_seconds:
        Initial backoff between retries (default 2s).
    """

    def __init__(
        self,
        vault: Vault,
        registry: OAuthProviderRegistry | None = None,
        proactive_margin_seconds: int = 300,
        max_retries: int = 3,
        base_backoff_seconds: float = 2.0,
    ) -> None:
        self.vault = vault
        self.registry = registry
        self.proactive_margin_seconds = proactive_margin_seconds
        self.max_retries = max_retries
        self.base_backoff_seconds = base_backoff_seconds
        self._audit = None  # injected by caller if audit is available

    @property
    def audit(self):
        if self._audit is None:
            from hermes_vault.audit import AuditLogger
            self._audit = AuditLogger(self.vault.db_path)
        return self._audit

    def set_audit(self, audit) -> None:
        self._audit = audit

    # ── Detection ─────────────────────────────────────────────────────────

    def is_expired(self, record: CredentialRecord, margin_seconds: int | None = None) -> bool:
        """Return True if the access token is expired or within *margin* of expiry."""
        if record.expiry is None:
            return False
        margin = margin_seconds if margin_seconds is not None else self.proactive_margin_seconds
        now = utc_now()
        expiry = record.expiry.replace(tzinfo=timezone.utc) if record.expiry.tzinfo is None else record.expiry
        return (expiry - now).total_seconds() <= margin

    def list_expired(self, service: str | None = None) -> list[CredentialRecord]:
        """List access tokens that are expired or near expiry.

        If *service* is given, limit to that service.  Otherwise scan all.
        """
        candidates: list[CredentialRecord] = []
        for rec in self.vault.list_credentials():
            if rec.credential_type != "oauth_access_token":
                continue
            if service is not None and rec.service != normalize(service):
                continue
            if self.is_expired(rec):
                candidates.append(rec)
        return candidates

    # ── Refresh core ──────────────────────────────────────────────────────

    def refresh(
        self,
        service: str,
        alias: str = "default",
        dry_run: bool = False,
    ) -> RefreshAttempt:
        """Refresh a single service's access token.

        1. Resolve the access token and its paired refresh token.
        2. POST to the provider's token endpoint with ``grant_type=refresh_token``.
        3. On success, atomically update both tokens in the vault.
        4. Log the attempt (success or failure).

        Raises:
            RefreshTokenMissingError: no refresh token stored for this service.
            OAuthProviderError: provider rejected the refresh request.
            OAuthNetworkError: network failure after retries.
        """
        service = normalize(service)

        access_rec = self._resolve_access_token(service, alias)
        refresh_rec = self._resolve_refresh_token(service, alias)
        if refresh_rec is None:
            raise RefreshTokenMissingError(
                f"No refresh token found for service '{service}'. Re-authentication required."
            )

        refresh_secret = self.vault.get_secret(refresh_rec.id)
        if refresh_secret is None:
            raise RefreshTokenMissingError(
                f"Refresh token for '{service}' exists but cannot be decrypted."
            )

        provider = self._get_provider(service)
        client_id, client_secret = self._get_client_credentials(provider)

        raw_refresh = refresh_secret.secret
        attempt = RefreshAttempt(service=service, alias=alias, success=False, reason="")

        for attempt.retry_count in range(1, self.max_retries + 1):  # type: ignore
            try:
                response = self._do_refresh_post(
                    provider,
                    raw_refresh,
                    client_id=client_id,
                    client_secret=client_secret,
                )
            except (OAuthNetworkError, requests.RequestException) as exc:
                if attempt.retry_count < self.max_retries:
                    backoff = self.base_backoff_seconds * (2 ** (attempt.retry_count - 1))
                    time.sleep(backoff)
                    continue
                attempt.reason = f"Network failure after {self.max_retries} retries: {exc}"
                self._log_refresh(attempt)
                raise OAuthNetworkError(attempt.reason) from exc
            except (OAuthProviderError, RefreshTokenExpiredError) as exc:
                # Provider / token errors are generally not retryable
                attempt.reason = str(exc)
                self._log_refresh(attempt)
                raise

            # Success path
            attempt.success = True
            attempt.new_access_token = response.get("access_token")
            attempt.new_refresh_token = response.get("refresh_token")  # may be absent
            attempt.expires_in = response.get("expires_in")
            attempt.scopes = self._parse_scopes(response.get("scope", ""))
            attempt.reason = "Token refreshed successfully"

            if not dry_run:
                self._update_vault_atomic(
                    access_rec,
                    refresh_rec,
                    attempt,
                    provider=provider,
                )
            else:
                attempt.reason = "Token refresh simulated (dry-run)"

            self._log_refresh(attempt)
            return attempt

        # Unreachable, but keeps mypy happy
        return attempt

    def refresh_all(
        self,
        dry_run: bool = False,
    ) -> list[RefreshAttempt]:
        """Refresh every expired or nearly-expired access token in the vault.

        Returns a list of results, one per candidate credential.
        """
        expired = self.list_expired()
        results: list[RefreshAttempt] = []
        for rec in expired:
            try:
                result = self.refresh(rec.service, alias=rec.alias, dry_run=dry_run)
                results.append(result)
            except Exception as exc:
                results.append(
                    RefreshAttempt(
                        service=rec.service,
                        alias=rec.alias,
                        success=False,
                        reason=str(exc),
                    )
                )
        return results

    # ── Vault helpers ─────────────────────────────────────────────────────

    def _resolve_access_token(self, service: str, alias: str) -> CredentialRecord:
        """Fetch the access token record, ensuring it exists and has the right type."""
        rec = self.vault.resolve_credential(service, alias=alias)
        if rec.credential_type != "oauth_access_token":
            raise ValueError(
                f"Credential for '{service}' alias '{alias}' is not an oauth_access_token "
                f"(got {rec.credential_type})"
            )
        return rec

    def _resolve_refresh_token(self, service: str, alias: str) -> CredentialRecord | None:
        """Fetch the paired refresh token for a service/access-alias pair.

        Prefer the alias-scoped refresh record (``refresh:<alias>``). Fall back
        to the legacy ``refresh`` alias only when it is the only usable record.
        """
        scoped_alias = refresh_alias_for(alias)
        scoped = self.vault._find_by_service_alias(service, scoped_alias)
        if scoped is not None:
            return scoped

        legacy = self.vault._find_by_service_alias(service, "refresh")
        if legacy is None:
            return None

        legacy_secret = self.vault.get_secret(legacy.id)
        legacy_metadata = legacy_secret.metadata if legacy_secret is not None else {}
        if isinstance(legacy_metadata, dict):
            associated_alias = legacy_metadata.get("associated_access_token_alias")
            if associated_alias is not None and associated_alias != alias:
                return None
        return legacy

    def _get_provider(self, service: str) -> OAuthProvider:
        if self.registry is None:
            from hermes_vault.config import get_settings
            settings = get_settings()
            self.registry = OAuthProviderRegistry(
                settings.runtime_home / "oauth-providers.yaml",
            )
        provider = self.registry.get(service)
        if provider is None:
            raise OAuthProviderError(
                f"Unknown OAuth provider '{service}'. Run `hermes-vault oauth providers` to see available providers."
            )
        return provider

    def _get_client_credentials(self, provider: OAuthProvider) -> tuple[str | None, str | None]:
        if self.registry is None:
            return None, None
        return self.registry.get_client_credentials(provider)

    # ── Network helpers ───────────────────────────────────────────────────

    @staticmethod
    def _do_refresh_post(
        provider: OAuthProvider,
        refresh_token: str,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        if client_id is not None:
            payload["client_id"] = client_id
        if client_secret is not None:
            payload["client_secret"] = client_secret

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        try:
            resp = requests.post(
                str(provider.token_endpoint),
                data=payload,
                headers=headers,
                timeout=30,
            )
        except requests.RequestException as exc:
            raise OAuthNetworkError(f"Refresh request failed: {exc}") from exc

        try:
            data = resp.json()
        except Exception:
            from urllib.parse import parse_qs
            parsed = parse_qs(resp.text.strip())
            data = {k: v[0] if len(v) == 1 else " ".join(v) for k, v in parsed.items()}

        if "error" in data:
            error_code = data.get("error", "unknown")
            description = data.get("error_description", "")
            if error_code in ("invalid_grant", "invalid_request"):
                raise RefreshTokenExpiredError(
                    f"Refresh token rejected by provider: {error_code} — {description}"
                )
            raise OAuthProviderError(
                f"Token endpoint error on refresh: {error_code} — {description}"
            )

        if not resp.ok:
            raise OAuthProviderError(
                f"Token endpoint error on refresh: HTTP {resp.status_code} — {resp.text}"
            )

        access_token = data.get("access_token")
        if not access_token:
            raise OAuthProviderError("Refresh response missing access_token")

        return data

    @staticmethod
    def _parse_scopes(scope_str: str | None) -> list[str]:
        if not scope_str:
            return []
        return [s.strip() for s in scope_str.split(" ") if s.strip()]

    # ── Atomic vault update ──────────────────────────────────────────────

    def _update_vault_atomic(
        self,
        access_rec: CredentialRecord,
        refresh_rec: CredentialRecord,
        attempt: RefreshAttempt,
        provider: OAuthProvider,
    ) -> None:
        """Replace old tokens with new ones in a single SQLite transaction."""
        now = utc_now()

        # Build new access token secret + metadata
        access_meta: dict[str, Any] = {
            "token_type": "Bearer",
            "provider": provider.service_id,
            "scopes": attempt.scopes,
            "issued_at": now.isoformat(),
        }
        if attempt.expires_in is not None:
            expires_at = now + timedelta(seconds=attempt.expires_in)
            access_meta["expires_at"] = expires_at.isoformat()
        else:
            expires_at = None

        new_access_secret = CredentialSecret(
            secret=attempt.new_access_token or "",
            metadata=access_meta,
        )
        new_access_payload = new_access_secret.model_dump_json()
        from hermes_vault.crypto import encrypt_secret

        new_access_encrypted = encrypt_secret(new_access_payload, self.vault.key)

        # Build new refresh token secret if rotated
        new_refresh_encrypted: str | None = None
        old_refresh_secret = self.vault.get_secret(refresh_rec.id)
        current_refresh_value = old_refresh_secret.secret if old_refresh_secret is not None else None
        if attempt.new_refresh_token and attempt.new_refresh_token != current_refresh_value:
            # Provider rotated the refresh token — preserve and increment counter
            rotation_counter = 1
            family_id: str | None = None
            if old_refresh_secret and isinstance(old_refresh_secret.metadata, dict):
                old_counter = old_refresh_secret.metadata.get("rotation_counter")
                if isinstance(old_counter, int):
                    rotation_counter = old_counter + 1
                family_id = old_refresh_secret.metadata.get("family_id")

            refresh_metadata: dict[str, Any] = {}
            if old_refresh_secret and isinstance(old_refresh_secret.metadata, dict):
                refresh_metadata.update(old_refresh_secret.metadata)
            refresh_metadata.update(
                {
                    "associated_access_token_alias": access_rec.alias,
                    "provider": provider.service_id,
                    "rotation_counter": rotation_counter,
                }
            )
            refresh_metadata.pop("refresh_token", None)
            refresh_metadata.pop("raw_response", None)
            refresh_meta: dict[str, Any] = dict(refresh_metadata)
            if family_id is not None:
                refresh_meta["family_id"] = family_id

            new_refresh_secret = CredentialSecret(
                secret=attempt.new_refresh_token,
                metadata=refresh_meta,
            )
            new_refresh_payload = new_refresh_secret.model_dump_json()
            new_refresh_encrypted = encrypt_secret(new_refresh_payload, self.vault.key)

        import sqlite3

        with sqlite3.connect(self.vault.db_path) as conn:
            conn.execute("BEGIN EXCLUSIVE")
            try:
                # Update access token
                conn.execute(
                    """
                    UPDATE credentials
                    SET encrypted_payload = ?, status = ?, scopes = ?, updated_at = ?, expiry = ?
                    WHERE id = ?
                    """,
                    (
                        new_access_encrypted,
                        CredentialStatus.active.value,
                        json.dumps(attempt.scopes),
                        now.isoformat(),
                        expires_at.isoformat() if expires_at else None,
                        access_rec.id,
                    ),
                )

                # Update refresh token if rotated
                if new_refresh_encrypted is not None:
                    conn.execute(
                        """
                        UPDATE credentials
                        SET encrypted_payload = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (new_refresh_encrypted, now.isoformat(), refresh_rec.id),
                    )

                conn.commit()
            except Exception:
                conn.rollback()
                raise

    # ── Audit helpers ─────────────────────────────────────────────────────

    def _log_refresh(self, attempt: RefreshAttempt) -> None:
        action = "refresh_token"
        decision = Decision.allow if attempt.success else Decision.deny
        self.audit.record(
            AccessLogRecord(
                agent_id="hermes-vault-refresh",
                service=attempt.service,
                action=action,
                decision=decision,
                reason=attempt.reason,
            )
        )
