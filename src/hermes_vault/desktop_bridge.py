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
from typing import Any, Callable, Iterator, TextIO

from hermes_vault import __version__
from hermes_vault.config import validate_profile_name
from hermes_vault.crypto import MissingPassphraseError
from hermes_vault.dashboard import (
    DashboardAPI,
    DashboardContext,
    build_dashboard_context,
)
from hermes_vault.health import run_health
from hermes_vault.logging_redaction import redact_text
from hermes_vault.policy import PolicyEngine
from hermes_vault.policy_doctor import run_policy_doctor

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
# encrypted payloads, env maps, raw token material, or absolute paths.
CREDENTIAL_FIELDS = (
    "id",
    "service",
    "alias",
    "credential_type",
    "status",
    "scopes",
    "tags",
    "notes",
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
    "purpose",
    "status",
    "ttl_seconds",
    "issued_at",
    "expires_at",
    "revoked_at",
    "renewed_at",
    "renew_count",
    "reason",
    "scopes",
)

REQUEST_FIELDS = (
    "id",
    "agent_id",
    "service",
    "alias",
    "action",
    "purpose",
    "status",
    "requested_ttl_seconds",
    "created_at",
    "decided_at",
    "decided_by",
    "decision_reason",
    "lease_id",
)

AUDIT_FIELDS = (
    "id",
    "timestamp",
    "agent_id",
    "service",
    "action",
    "decision",
    "reason",
    "ttl_seconds",
    "verification_result",
)


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
    error: dict[str, Any] = {"code": code, "message": redact_text(message)}
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
    """Metadata-only credential projection (never the encrypted payload)."""
    return {
        field: _iso(getattr(record, field, None))
        for field in CREDENTIAL_FIELDS
    }


def _lease_metadata(record: Any) -> dict[str, Any]:
    """Metadata-only lease projection; metadata values never serialize."""
    data = {
        field: _iso(getattr(record, field, None))
        for field in LEASE_FIELDS
    }
    data["metadata_keys"] = sorted((record.metadata or {}).keys())
    data["has_metadata"] = bool(record.metadata)
    return data


def _request_metadata(request: dict[str, Any]) -> dict[str, Any]:
    """Metadata-only access-request projection (raw nested metadata stripped)."""
    return _pick(request, REQUEST_FIELDS)


def _audit_metadata(entry: dict[str, Any]) -> dict[str, Any]:
    """Metadata-only audit projection; nested metadata values never serialize."""
    data = _pick(entry, AUDIT_FIELDS)
    if data.get("reason") is not None:
        data["reason"] = redact_text(str(data["reason"]))
    raw_metadata = entry.get("metadata")
    metadata = raw_metadata if isinstance(raw_metadata, dict) else {}
    data["metadata_keys"] = sorted(metadata.keys())
    data["has_metadata"] = bool(metadata)
    return data


def _doctor_metadata(report: Any) -> dict[str, Any]:
    """Policy-doctor projection without absolute path fields."""
    data = report.as_dict(exclude_none=False)
    data.pop("policy_path", None)
    return data


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


class DesktopBridge:
    """Stateless, read-only NDJSON bridge dispatcher.

    The context factory mirrors ``build_dashboard_context``: it is called
    with ``prompt=False`` so the bridge never prompts, and passphrase
    resolution happens through the environment only.
    """

    def __init__(
        self,
        context_factory: Callable[..., DashboardContext] = build_dashboard_context,
        api_factory: Callable[[DashboardContext], DashboardAPI] | None = None,
    ) -> None:
        self._context_factory = context_factory
        self._api_factory = api_factory or (lambda ctx: DashboardAPI(context_factory=lambda: ctx))

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Dispatch one decoded request object to a response envelope."""
        request_id = request.get("id")
        raw_protocol = request.get("protocol_version")
        try:
            requested_protocol = int(raw_protocol) if raw_protocol is not None else PROTOCOL_VERSION
        except (TypeError, ValueError):
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
        except ValueError as exc:
            return _error(request_id, "INVALID_PARAMS", str(exc))
        except Exception as exc:
            # Child exception envelope: sanitized message, never a traceback.
            return _error(request_id, "INTERNAL", redact_text(str(exc))[:300])
        return _ok(request_id, result)

    def handle_line(self, line: str) -> dict[str, Any]:
        """Parse one request line and return a response envelope."""
        if len(line) > MAX_REQUEST_BYTES:
            return _error(None, "OVERSIZED_REQUEST", f"request line exceeds {MAX_REQUEST_BYTES} bytes")
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            return _error(None, "MALFORMED_REQUEST", "request must be valid JSON")
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
        try:
            limit = int(raw_limit) if raw_limit not in (None, "") else 50
        except (TypeError, ValueError):
            raise ValueError("limit must be an integer")
        bounded = max(1, min(limit, MAX_AUDIT_LIMIT))
        return {
            "version": "desktop-bridge-v1",
            "profile": ctx.settings.profile_name,
            "limit": bounded,
            "entries": [_audit_metadata(entry) for entry in ctx.audit.list_recent(limit=bounded)],
        }

    def _method_integrity(self, params: dict[str, Any]) -> dict[str, Any]:
        ctx = self._ctx(params.get("profile"))
        result = dict(self._api_factory(ctx).audit_integrity())
        # The dashboard helper embeds a raw child message on error; keep the
        # envelope metadata-only by redacting any embedded error text.
        if isinstance(result.get("error"), str):
            result["error"] = redact_text(result["error"])[:300]
        result["version"] = "desktop-bridge-v1"
        result["profile"] = ctx.settings.profile_name
        return result


def _iter_request_lines(
    stream: TextIO,
    max_bytes: int = MAX_REQUEST_BYTES,
) -> Iterator[tuple[str, bool]]:
    """Yield (line, oversized) pairs with a hard per-line byte bound.

    Oversized lines are drained (not parsed) so the stream framing stays
    intact; the caller replies with an OVERSIZED_REQUEST envelope.
    """
    while True:
        line = stream.readline(max_bytes + 1)
        if not line:
            return
        oversized = len(line) > max_bytes
        if oversized:
            while not line.endswith("\n"):
                chunk = stream.readline(max_bytes + 1)
                if not chunk:
                    break
                line = chunk
        yield line.rstrip("\r\n"), oversized


def _render(response: dict[str, Any], max_bytes: int = MAX_OUTPUT_BYTES) -> str:
    """Serialize one response line; hard-cap output so no response is unbounded."""
    text = json.dumps(response, sort_keys=True)
    if len(text) > max_bytes:
        response = _error(
            response.get("id"),
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
