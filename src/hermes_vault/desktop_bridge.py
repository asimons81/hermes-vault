"""Versioned NDJSON desktop bridge for the Hermes Vault desktop plugin.

The bridge is a Vault-owned, read-only protocol spoken over stdin/stdout.
Each request is one JSON object per line; each response is one JSON object
per line. Every response is a typed metadata-only envelope: raw credential
values, encrypted payloads, env maps, passphrases, OAuth tokens, absolute
sensitive paths, and child tracebacks never serialize.

Protocol
--------
Request::

    {"id": 1, "method": "hello", "params": {}, "protocol_version": 1}

Response (success)::

    {"id": 1, "ok": true, "protocol_version": 1, "result": {...}}

Response (error)::

    {"id": 1, "ok": false, "protocol_version": 1,
     "error": {"code": "MISSING_PASSPHRASE", "message": "...", "locked": true}}

Supported methods (read-only dispatch):
    hello, overview, credentials, leases, policy, requests, audit, integrity

The bridge never prompts for a passphrase. Credentials come from the
environment (``HERMES_VAULT_PASSPHRASE`` or the per-profile
``HERMES_VAULT_PASSPHRASE_<PROFILE>``); when none is available every
context-backed method returns a ``MISSING_PASSPHRASE`` locked envelope.
"""

from __future__ import annotations

import json
import math
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterator, TextIO
from urllib.parse import quote

from hermes_vault import __version__
from hermes_vault.audit import AuditLogger
from hermes_vault.audit_integrity.service import AuditIntegrityService
from hermes_vault.broker import Broker
from hermes_vault.config import AppSettings, resolve_profile, validate_profile_name
from hermes_vault.crypto import (
    CorruptKeyMaterialError,
    MissingKeyMaterialError,
    MissingPassphraseError,
    load_or_create_master_key,
    resolve_passphrase_with_source,
)
from hermes_vault.dashboard import DashboardAPI, DashboardContext
from hermes_vault.health import run_health
from hermes_vault.logging_redaction import redact_text
from hermes_vault.models import AccessRequestStatus, LeaseStatus, utc_now
from hermes_vault.policy import PolicyEngine
from hermes_vault.policy_doctor import run_policy_doctor
from hermes_vault.service_ids import normalize
from hermes_vault.vault import Vault
from hermes_vault.verifier import Verifier

PROTOCOL_VERSION = 1
BRIDGE_NAME = "hermes-vault-desktop-bridge"
MIN_HERMES_VERSION = "0.20.0"
MIN_VAULT_VERSION = "0.22.0"

# Bounds keep the bridge predictable and cheap to run as a child process.
MAX_REQUEST_BYTES = 64 * 1024  # 64 KiB per request line
MAX_OUTPUT_BYTES = 512 * 1024  # 512 KiB per response line
MAX_AUDIT_LIMIT = 250
MAX_CREDENTIALS = 500
MAX_LEASES = 500
MAX_REQUESTS = 500
MAX_RECENT_AUDIT = 12

ALL_METHODS = (
    "hello",
    "overview",
    "credentials",
    "leases",
    "policy",
    "requests",
    "audit",
    "integrity",
)

# Canonical metadata-only field sets. Serializers below never include
# encrypted payloads, env maps, raw token material, arbitrary operator-entered
# text, or absolute paths. Presence flags below preserve useful UI state without
# turning free-text fields into an accidental secret transport.
CREDENTIAL_FIELDS = (
    "id",
    "service",
    "alias",
    "credential_type",
    "status",
    "scopes",
    "tags",
    "created_at",
    "updated_at",
    "last_verified_at",
    "expiry",
    "crypto_version",
)

LEASE_FIELDS = (
    "id",
    "service",
    "alias",
    "credential_id",
    "credential_type",
    "agent_id",
    "issued_by",
    "status",
    "ttl_seconds",
    "issued_at",
    "expires_at",
    "revoked_at",
    "renewed_at",
    "renew_count",
    "scopes",
)

REQUEST_FIELDS = (
    "id",
    "agent_id",
    "service",
    "alias",
    "action",
    "status",
    "requested_ttl_seconds",
    "created_at",
    "decided_at",
    "decided_by",
    "lease_id",
)

AUDIT_FIELDS = (
    "id",
    "timestamp",
    "agent_id",
    "service",
    "action",
    "decision",
    "ttl_seconds",
    "verification_result",
)


_ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])(?:/[^\s'\"<>]+|[A-Za-z]:[\\/][^\s'\"<>]+)")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}")
_HEX_TOKEN_RE = re.compile(r"\b[0-9A-Fa-f]{32,}\b")


def _safe_text(value: Any) -> str:
    text = redact_text(str(value))
    text = _ABSOLUTE_PATH_RE.sub("[path]", text)
    text = _JWT_RE.sub("[redacted:jwt]", text)
    text = _BEARER_RE.sub("[redacted:bearer]", text)
    text = _HEX_TOKEN_RE.sub("[redacted:hex-token]", text)
    return text[:300]


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _valid_request_id(value: Any) -> Any:
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(value):
        return value
    return None


def _ok(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": request_id,
        "ok": True,
        "protocol_version": PROTOCOL_VERSION,
        "result": result,
    }


def _error(
    request_id: Any,
    code: str,
    message: str,
    *,
    locked: bool = False,
    **extra: Any,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": _safe_text(message)}
    if locked:
        error["locked"] = True
    error.update(extra)
    return {
        "id": request_id,
        "ok": False,
        "protocol_version": PROTOCOL_VERSION,
        "error": error,
    }


def _pick(source: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Typed projection: return exactly the allowed metadata fields."""
    return {field: source.get(field) for field in fields}


def _iso(value: Any) -> Any:
    """Convert datetime-like values to ISO strings for JSON serialization."""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def _credential_metadata(record: Any) -> dict[str, Any]:
    """Metadata-only credential projection (never arbitrary note text)."""
    data = {
        field: _iso(getattr(record, field, None))
        for field in CREDENTIAL_FIELDS
    }
    data["has_notes"] = bool(getattr(record, "notes", None))
    return data


def _lease_metadata(record: Any) -> dict[str, Any]:
    """Metadata-only lease projection; free-text values never serialize."""
    data = {
        field: _iso(getattr(record, field, None))
        for field in LEASE_FIELDS
    }
    data["has_purpose"] = bool(getattr(record, "purpose", None))
    data["has_reason"] = bool(getattr(record, "reason", None))
    data["metadata_keys"] = sorted((record.metadata or {}).keys())
    data["has_metadata"] = bool(record.metadata)
    return data


def _request_metadata(request: dict[str, Any]) -> dict[str, Any]:
    """Metadata-only access-request projection (raw text/nested metadata stripped)."""
    data = _pick(request, REQUEST_FIELDS)
    data["has_purpose"] = bool(request.get("purpose"))
    data["has_decision_reason"] = bool(request.get("decision_reason"))
    return data


def _audit_metadata(entry: dict[str, Any]) -> dict[str, Any]:
    """Metadata-only audit projection; reason and nested values never serialize."""
    data = _pick(entry, AUDIT_FIELDS)
    data["has_reason"] = bool(entry.get("reason"))
    raw_metadata = entry.get("metadata")
    metadata = raw_metadata if isinstance(raw_metadata, dict) else {}
    data["metadata_keys"] = sorted(metadata.keys())
    data["has_metadata"] = bool(metadata)
    return data


def _doctor_metadata(report: Any) -> dict[str, Any]:
    """Policy-doctor projection without paths or arbitrary policy text."""
    data = report.as_dict(exclude_none=False)
    finding_fields = ("kind", "severity", "agent_id", "service", "strict_violation")
    return {
        "version": data.get("version"),
        "generated_at": data.get("generated_at"),
        "policy_hash": data.get("policy_hash"),
        "strict_mode": bool(data.get("strict_mode")),
        "strict_violation": bool(data.get("strict_violation")),
        "finding_count": int(data.get("finding_count") or 0),
        "strict_violation_count": int(data.get("strict_violation_count") or 0),
        "severity_counts": data.get("severity_counts") or {},
        "findings": [
            _pick(finding, finding_fields)
            for finding in data.get("findings", [])
            if isinstance(finding, dict)
        ],
    }


def _policy_agents(policy: PolicyEngine) -> list[dict[str, Any]]:
    """Metadata-only agent policy summary (service/action/capability names only)."""
    summary: list[dict[str, Any]] = []
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


class _ReadOnlyVault(Vault):
    """Vault-shaped metadata reader that never opens SQLite for writing."""

    def __init__(self, db_path: Path, salt_path: Path, key: bytes) -> None:
        self.db_path = db_path
        self.salt_path = salt_path
        self.key = key

    @staticmethod
    def _connect(path: Path) -> sqlite3.Connection:
        if not path.is_file():
            raise MissingKeyMaterialError("Vault database is not initialized")
        uri = f"file:{quote(str(path), safe='/')}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def list_credentials(self) -> list[Any]:
        with self._connect(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM credentials ORDER BY service, alias").fetchall()
        return [self._row_to_record(row) for row in rows]

    def list_leases(
        self,
        agent_id: str | None = None,
        service: str | None = None,
        status: LeaseStatus | str | None = None,
    ) -> list[Any]:
        conditions: list[str] = []
        params: list[Any] = []
        if agent_id is not None:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if service is not None:
            conditions.append("service = ?")
            params.append(normalize(service))
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        with self._connect(self.db_path) as conn:
            rows = conn.execute(
                f"SELECT * FROM leases WHERE {where_clause} ORDER BY issued_at DESC",
                params,
            ).fetchall()
        now = utc_now()
        requested_status = status.value if isinstance(status, LeaseStatus) else str(status) if status is not None else None
        records: list[Any] = []
        for row in rows:
            record = self._row_to_lease_record(row)
            if record.status is LeaseStatus.active and record.expires_at <= now:
                record = record.model_copy(update={"status": LeaseStatus.expired})
            if requested_status is None or record.status.value == requested_status:
                records.append(record)
        return records

    def list_access_requests(
        self,
        *,
        agent_id: str | None = None,
        service: str | None = None,
        status: AccessRequestStatus | str | None = None,
    ) -> list[Any]:
        conditions: list[str] = []
        params: list[Any] = []
        if agent_id is not None:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if service is not None:
            conditions.append("service = ?")
            params.append(normalize(service))
        if status is not None:
            conditions.append("status = ?")
            params.append(status.value if isinstance(status, AccessRequestStatus) else str(status))
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        with self._connect(self.db_path) as conn:
            rows = conn.execute(
                f"SELECT * FROM access_requests WHERE {where_clause} ORDER BY created_at DESC",
                params,
            ).fetchall()
        return [self._row_to_access_request_record(row) for row in rows]


class _ReadOnlyAudit(AuditLogger):
    """Audit reader that does not create or migrate the access-log table."""

    def list_recent(
        self,
        limit: int = 100,
        agent_id: str | None = None,
        service: str | None = None,
        action: str | None = None,
        decision: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, object]]:
        conditions: list[str] = []
        params: list[Any] = []
        for field, value in (
            ("agent_id", agent_id),
            ("service", service),
            ("action", action),
            ("decision", decision),
        ):
            if value is not None:
                conditions.append(f"{field} = ?")
                params.append(value)
        if since is not None:
            conditions.append("timestamp >= ?")
            params.append(since.isoformat())
        if until is not None:
            conditions.append("timestamp <= ?")
            params.append(until.isoformat())
        params.append(max(0, int(limit)))
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        try:
            with _ReadOnlyVault._connect(self.db_path) as conn:
                rows = conn.execute(
                    f"SELECT * FROM access_logs WHERE {where_clause} ORDER BY timestamp DESC LIMIT ?",
                    params,
                ).fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc).lower():
                return []
            raise
        results: list[dict[str, object]] = []
        for row in rows:
            item = dict(row)
            raw = item.get("metadata_json")
            try:
                item["metadata"] = json.loads(raw) if isinstance(raw, str) and raw else {}
            except json.JSONDecodeError:
                item["metadata"] = {"raw": raw}
            item.pop("metadata_json", None)
            results.append(item)
        return results


class _ReadOnlyAuditIntegrityService(AuditIntegrityService):
    """Verify integrity without initializing schema or recording a run."""

    def _connection(self) -> sqlite3.Connection:
        return _ReadOnlyVault._connect(self.db_path)

    def _record_run(self, conn: sqlite3.Connection, result: Any) -> None:
        # The parent verifier records a verification run and commits it. The
        # desktop bridge is explicitly read-only, so that side effect is skipped.
        return None


def _read_only_settings(profile: str | None = None) -> AppSettings:
    resolved = resolve_profile(profile)
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


def _build_read_only_context(*, prompt: bool = False, profile: str | None = None) -> DashboardContext:
    if prompt:
        raise MissingPassphraseError("The desktop bridge never prompts for a passphrase")
    settings = _read_only_settings(profile)
    passphrase_result = resolve_passphrase_with_source(prompt=False, profile_name=settings.profile_name)
    if not settings.db_path.is_file() or not settings.salt_path.is_file():
        raise MissingKeyMaterialError("Vault key material is not initialized")
    key = load_or_create_master_key(settings.salt_path, passphrase_result.passphrase, enable_dpapi=False)
    policy = PolicyEngine.from_yaml(settings.effective_policy_path)
    vault = _ReadOnlyVault(settings.db_path, settings.salt_path, key)
    audit = _ReadOnlyAudit(settings.db_path)
    broker = Broker(
        vault=vault,
        policy=policy,
        verifier=Verifier(
            plugin_dir=settings.verifier_plugin_dir,
            load_file_plugins=False,
            load_entry_points=False,
        ),
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


class DesktopBridge:
    """Stateless, read-only NDJSON bridge dispatcher.

    The default context is a side-effect-free metadata reader: it uses
    environment-only passphrase resolution and read-only SQLite connections.
    Callers may inject a context factory for unit tests or a trusted embedding.
    """

    def __init__(
        self,
        context_factory: Callable[..., DashboardContext] | None = None,
        api_factory: Callable[[DashboardContext], DashboardAPI] | None = None,
    ) -> None:
        self._context_factory = context_factory or _build_read_only_context
        self._api_factory = api_factory

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Dispatch one decoded request object to a response envelope."""
        request_id = _valid_request_id(request.get("id"))
        raw_protocol = request.get("protocol_version")
        try:
            requested_protocol = PROTOCOL_VERSION if raw_protocol is None else raw_protocol
            if isinstance(requested_protocol, bool) or not isinstance(requested_protocol, int):
                raise TypeError
        except TypeError:
            return _error(request_id, "UNSUPPORTED_PROTOCOL", "protocol_version must be an integer")
        if requested_protocol != PROTOCOL_VERSION:
            return _error(request_id, "UNSUPPORTED_PROTOCOL", f"unsupported protocol_version: {requested_protocol}")
        method = request.get("method")
        if not isinstance(method, str) or not method:
            return _error(request_id, "INVALID_PARAMS", "method is required")
        params = request.get("params") if isinstance(request.get("params"), dict) else {}
        handler = getattr(self, f"_method_{method}", None)
        if handler is None:
            return _error(request_id, "UNKNOWN_METHOD", f"unknown method: {method}")
        try:
            result = handler(params)
        except MissingPassphraseError as exc:
            return _error(request_id, "MISSING_PASSPHRASE", str(exc), locked=True)
        except (MissingKeyMaterialError, CorruptKeyMaterialError):
            return _error(request_id, "VAULT_NOT_READY", "Vault key material is unavailable", locked=True)
        except ValueError as exc:
            return _error(request_id, "INVALID_PARAMS", str(exc))
        except Exception as exc:
            # Child exception envelope: sanitized message, never a traceback.
            return _error(request_id, "INTERNAL", _safe_text(exc))
        return _ok(request_id, result)

    def handle_line(self, line: str) -> dict[str, Any]:
        """Parse one request line and return a response envelope."""
        if _utf8_size(line) > MAX_REQUEST_BYTES:
            return _error(None, "OVERSIZED_REQUEST", f"request line exceeds {MAX_REQUEST_BYTES} bytes")
        try:
            request = json.loads(line, parse_constant=_reject_json_constant)
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            return _error(None, "MALFORMED_REQUEST", f"invalid JSON request: {exc}")
        if not isinstance(request, dict):
            return _error(None, "MALFORMED_REQUEST", "request must be a JSON object")
        return self.handle_request(request)

    # ── context helpers ────────────────────────────────────────────────────

    def _ctx(self, profile: Any = None) -> DashboardContext:
        name = str(profile).strip() if profile not in (None, "") else None
        if name:
            try:
                validate_profile_name(name)
            except ValueError:
                raise ValueError("invalid profile name") from None
        return self._context_factory(prompt=False, profile=name)

    # ── methods ────────────────────────────────────────────────────────────

    def _method_hello(self, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "name": BRIDGE_NAME,
            "protocol_version": PROTOCOL_VERSION,
            "version": __version__,
            "min_hermes_version": MIN_HERMES_VERSION,
            "min_vault_version": MIN_VAULT_VERSION,
            "read_only": True,
            "raw_values_returned": False,
            "capabilities": list(ALL_METHODS),
        }

    def _method_overview(self, params: dict[str, Any]) -> dict[str, Any]:
        ctx = self._ctx(params.get("profile"))
        records = ctx.vault.list_credentials()
        leases = ctx.vault.list_leases()
        health = run_health(ctx.vault, audit=ctx.audit)
        doctor = run_policy_doctor(
            ctx.settings.effective_policy_path,
            generated_skills_dir=ctx.settings.generated_skills_dir,
            strict=False,
        )
        return {
            "version": "desktop-bridge-v1",
            "profile": ctx.settings.profile_name,
            "credential_count": len(records),
            "lease_count": len(leases),
            "active_lease_count": sum(1 for lease in leases if lease.status.value == "active"),
            "services": sorted({record.service for record in records}),
            "health": health.as_dict(exclude_none=False),
            "policy_doctor": _doctor_metadata(doctor),
            "recent_audit": [
                _audit_metadata(entry)
                for entry in ctx.audit.list_recent(limit=MAX_RECENT_AUDIT)
            ],
        }

    def _method_credentials(self, params: dict[str, Any]) -> dict[str, Any]:
        ctx = self._ctx(params.get("profile"))
        records = ctx.vault.list_credentials()
        bounded = records[:MAX_CREDENTIALS]
        return {
            "version": "desktop-bridge-v1",
            "profile": ctx.settings.profile_name,
            "credential_count": len(records),
            "truncated": len(records) > MAX_CREDENTIALS,
            "credentials": [_credential_metadata(record) for record in bounded],
        }

    def _method_leases(self, params: dict[str, Any]) -> dict[str, Any]:
        ctx = self._ctx(params.get("profile"))
        leases = ctx.vault.list_leases()
        bounded = leases[:MAX_LEASES]
        return {
            "version": "desktop-bridge-v1",
            "profile": ctx.settings.profile_name,
            "lease_count": len(leases),
            "truncated": len(leases) > MAX_LEASES,
            "leases": [_lease_metadata(record) for record in bounded],
        }

    def _method_policy(self, params: dict[str, Any]) -> dict[str, Any]:
        ctx = self._ctx(params.get("profile"))
        doctor = run_policy_doctor(
            ctx.settings.effective_policy_path,
            generated_skills_dir=ctx.settings.generated_skills_dir,
            strict=False,
        )
        return {
            "version": "desktop-bridge-v1",
            "profile": ctx.settings.profile_name,
            "policy_exists": ctx.settings.effective_policy_path.exists(),
            "doctor": _doctor_metadata(doctor),
            "agents": _policy_agents(ctx.policy),
        }

    def _method_requests(self, params: dict[str, Any]) -> dict[str, Any]:
        ctx = self._ctx(params.get("profile"))
        agent_id = params.get("agent_id") if params.get("agent_id") not in (None, "") else None
        decision = ctx.broker.list_access_requests(agent_id=agent_id)
        raw_requests = decision.metadata.get("requests", [])
        bounded = raw_requests[:MAX_REQUESTS]
        return {
            "version": "desktop-bridge-v1",
            "profile": ctx.settings.profile_name,
            "request_count": len(raw_requests),
            "truncated": len(raw_requests) > MAX_REQUESTS,
            "requests": [_request_metadata(request) for request in bounded],
        }

    def _method_audit(self, params: dict[str, Any]) -> dict[str, Any]:
        ctx = self._ctx(params.get("profile"))
        raw_limit = params.get("limit")
        if raw_limit in (None, ""):
            limit = 50
        elif isinstance(raw_limit, bool) or not isinstance(raw_limit, int):
            raise ValueError("limit must be an integer")
        else:
            limit = raw_limit
        bounded = max(1, min(limit, MAX_AUDIT_LIMIT))
        return {
            "version": "desktop-bridge-v1",
            "profile": ctx.settings.profile_name,
            "limit": bounded,
            "entries": [_audit_metadata(entry) for entry in ctx.audit.list_recent(limit=bounded)],
        }

    def _method_integrity(self, params: dict[str, Any]) -> dict[str, Any]:
        ctx = self._ctx(params.get("profile"))
        if self._api_factory is not None:
            result = dict(self._api_factory(ctx).audit_integrity())
        else:
            service = _ReadOnlyAuditIntegrityService(ctx.settings.db_path, ctx.vault.key)
            verification = service.verify()
            result = {
                "version": "audit-integrity-dashboard-v1",
                "status": verification.status.value,
                "reason_code": verification.reason_code,
                "chain_version": verification.chain_version,
                "active_segment_id": verification.active_segment_id,
                "active_segment_number": verification.active_segment_number,
                "verified_count": verification.verified_count,
                "legacy_count": verification.legacy_count,
                "first_verified_sequence": verification.first_verified_sequence,
                "last_verified_sequence": verification.last_verified_sequence,
                "checkpoint_status": verification.checkpoint_status.value,
                "last_verification_time": verification.verified_at.isoformat()
                if verification.verified_at
                else None,
                "sanitized_reason": verification.sanitized_reason,
                "recommended_next_step": verification.recommended_next_step,
            }
        if isinstance(result.get("error"), str):
            result["error"] = _safe_text(result["error"])
        result["version"] = "desktop-bridge-v1"
        result["profile"] = ctx.settings.profile_name
        return result


def _utf8_size(value: str) -> int:
    return len(value.encode("utf-8", errors="replace"))


def _iter_request_lines(
    stream: TextIO,
    max_bytes: int = MAX_REQUEST_BYTES,
) -> Iterator[tuple[str, bool]]:
    """Yield (line, oversized) pairs with a hard UTF-8 byte bound."""
    parts: list[str] = []
    line_bytes = 0
    oversized = False
    while True:
        chunk = stream.read(4096)
        if not chunk:
            if parts or line_bytes or oversized:
                yield "".join(parts).rstrip("\r"), oversized
            return
        remainder = chunk
        while remainder:
            newline = remainder.find("\n")
            part = remainder if newline < 0 else remainder[:newline]
            if not oversized:
                part_bytes = _utf8_size(part)
                if line_bytes + part_bytes > max_bytes:
                    oversized = True
                    parts.clear()
                else:
                    parts.append(part)
                    line_bytes += part_bytes
            if newline < 0:
                break
            yield "".join(parts).rstrip("\r"), oversized
            parts = []
            line_bytes = 0
            oversized = False
            remainder = remainder[newline + 1 :]


def _render(response: dict[str, Any], max_bytes: int = MAX_OUTPUT_BYTES) -> str:
    """Serialize one response line; hard-cap output so no response is unbounded."""
    text = json.dumps(response, sort_keys=True)
    if _utf8_size(text) > max_bytes:
        response = _error(
            None,
            "OUTPUT_LIMIT",
            f"response exceeds {max_bytes} bytes",
        )
        text = json.dumps(response, sort_keys=True)
    return text + "\n"


def run_desktop_bridge(
    stream_in: TextIO | None = None,
    stream_out: TextIO | None = None,
    bridge: DesktopBridge | None = None,
    *,
    max_request_bytes: int = MAX_REQUEST_BYTES,
) -> int:
    """Serve the NDJSON bridge over the given streams (defaults to stdio)."""
    import sys

    input_stream = stream_in if stream_in is not None else sys.stdin
    output_stream = stream_out if stream_out is not None else sys.stdout
    handler = bridge or DesktopBridge()
    for raw, oversized in _iter_request_lines(input_stream, max_request_bytes):
        if oversized:
            response = _error(None, "OVERSIZED_REQUEST", f"request line exceeds {max_request_bytes} bytes")
        else:
            response = handler.handle_line(raw)
        output_stream.write(_render(response))
        output_stream.flush()
    return 0


__all__ = [
    "PROTOCOL_VERSION",
    "BRIDGE_NAME",
    "MAX_REQUEST_BYTES",
    "MAX_OUTPUT_BYTES",
    "MAX_AUDIT_LIMIT",
    "ALL_METHODS",
    "DesktopBridge",
    "run_desktop_bridge",
]
