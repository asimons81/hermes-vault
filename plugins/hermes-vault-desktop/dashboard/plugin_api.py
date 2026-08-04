"""Hermes Vault desktop dashboard backend adapter.

Mounted at /api/plugins/hermes-vault-desktop/ by the dashboard plugin system.
This layer is intentionally thin: every handler spawns the Vault-owned
``desktop-bridge`` child process for exactly one request, reads exactly one
response line, and maps the result to a validated REST response.

Security model
--------------
- **No in-process Vault code.** This module never imports ``hermes_vault``.
  All Vault access happens in a short-lived child process
  (``hermes-vault --no-banner desktop-bridge``) that speaks a read-only
  NDJSON protocol over stdin/stdout.
- **Stateless, one-request/one-child.** Each HTTP request spawns a fresh
  child, sends one bounded request line, closes stdin (EOF terminates the
  bridge), reads one bounded response line, then tears the child down.
- **Fixed argv.** ``[hermes-vault, --no-banner, desktop-bridge]`` with
  ``shell=False`` — no shell interpolation, no dynamic arguments.
- **Scrubbed environment.** The child receives only safe basics (PATH, HOME,
  locale, temp dirs) plus ``HERMES_VAULT_HOME``, ``HERMES_VAULT_POLICY`` and
  the ``HERMES_VAULT_PASSPHRASE*`` family. Ambient ``PYTHONPATH`` and
  provider keys never reach the child. The passphrase may reach the child,
  but never returns to the parent and is never logged.
- **No secret transport.** Request bodies are never logged, child stderr is
  discarded, and error text is sanitized before it appears in a response.
  Malformed bridge output is reported as a generic error, never echoed.
- **Read-only surface.** Only fixed GET routes exist; unknown paths and
  non-GET verbs are rejected by the router. Query parameters are limited to
  ``profile`` / ``agent_id`` / ``limit`` with explicit bounds.

Auth note
---------
Plugin HTTP routes go through the dashboard's session-token auth middleware
like every other ``/api/plugins/...`` route, so this adapter adds no
additional authentication of its own.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

log = logging.getLogger(__name__)

router = APIRouter()

PROTOCOL_VERSION = 1

# The only bridge methods this adapter may call. Anything else (unknown
# methods, mutation actions, path-taking operations) is not routable here.
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

# Fixed child argv; the binary may be overridden for tests via
# HERMES_VAULT_BINARY, but the argument vector is never dynamic.
BRIDGE_BINARY_DEFAULT = "hermes-vault"
BRIDGE_ARGV = ("--no-banner", "desktop-bridge")

# Bounds mirror the bridge's own NDJSON limits so the parent rejects
# oversized traffic without trusting the child to behave.
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 512 * 1024
DEFAULT_TIMEOUT_SECONDS = 15.0
MAX_TIMEOUT_SECONDS = 120.0

# Query parameters the adapter understands. Unknown keys are rejected.
ALLOWED_QUERY_PARAMS = frozenset({"profile", "agent_id", "limit"})
MAX_PROFILE_LENGTH = 128
MAX_AGENT_ID_LENGTH = 256
MIN_LIMIT = 1
MAX_LIMIT = 250

# Safe basics that may be forwarded to the child. Anything not listed here —
# notably PYTHONPATH and every provider/token key — is dropped.
SAFE_ENV_KEYS = (
    "PATH",
    "HOME",
    "USERPROFILE",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "PATHEXT",
    "COMSPEC",
)

_ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])(?:/[^\s'\"<>]+|[A-Za-z]:[\\/][^\s'\"<>]+)")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}")
_HEX_TOKEN_RE = re.compile(r"\b[0-9A-Fa-f]{32,}\b")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


class BridgeError(Exception):
    """A failed or malformed bridge exchange, mapped to an HTTP status."""

    def __init__(self, code: str, detail: str, http_status_code: int) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail
        self.http_status_code = http_status_code


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-standard JSON constant: {value}")


def _sanitize(text: str, limit: int = 300) -> str:
    """Redact secret-like fragments and control characters from error text."""
    text = _CONTROL_RE.sub(" ", text)
    text = _ABSOLUTE_PATH_RE.sub("[path]", text)
    text = _JWT_RE.sub("[redacted:jwt]", text)
    text = _BEARER_RE.sub("[redacted:bearer]", text)
    text = _HEX_TOKEN_RE.sub("[redacted:hex-token]", text)
    return text[:limit]


def _bridge_binary() -> str:
    """Resolve the child binary; override via env for tests."""
    return os.environ.get("HERMES_VAULT_BINARY", BRIDGE_BINARY_DEFAULT)


def _bridge_timeout() -> float:
    """Resolve the per-request child timeout; override via env for tests."""
    raw = os.environ.get("HERMES_VAULT_BRIDGE_TIMEOUT", "")
    try:
        value = float(raw)
        if 0 < value <= MAX_TIMEOUT_SECONDS:
            return value
    except ValueError:
        pass
    return DEFAULT_TIMEOUT_SECONDS


def _child_env() -> dict[str, str]:
    """Build the scrubbed child environment.

    Safe basics plus the Vault control variables only. Ambient PYTHONPATH,
    provider keys, and everything else are deliberately dropped.
    """
    env: dict[str, str] = {}
    for key in SAFE_ENV_KEYS:
        if key in os.environ:
            env[key] = os.environ[key]
    for key, value in os.environ.items():
        if key == "HERMES_VAULT_HOME" or key == "HERMES_VAULT_POLICY" or key.startswith("HERMES_VAULT_PASSPHRASE"):
            env[key] = value
    return env


def _terminate(proc: subprocess.Popen[Any]) -> None:
    """Terminate a child with a grace period, then kill. Never raises."""
    try:
        proc.terminate()
    except OSError:
        return
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            return
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            pass
    except OSError:
        pass


def _parse_response(stdout: str, request_id: Any) -> dict[str, Any]:
    """Validate and map exactly one bridge response line.

    The response must be a single NDJSON line with a matching id and the
    current protocol version. Anything else is a generic protocol error —
    raw child output is never echoed.
    """
    if len(stdout.encode("utf-8", errors="replace")) > MAX_RESPONSE_BYTES:
        raise BridgeError("BRIDGE_MALFORMED", "vault bridge response exceeded size bound", http_status_code=502)
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise BridgeError(
            "BRIDGE_MALFORMED", "vault bridge returned an unexpected number of lines", http_status_code=502
        )
    try:
        payload = json.loads(lines[0], parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, RecursionError, ValueError):
        raise BridgeError("BRIDGE_MALFORMED", "vault bridge returned a malformed response", http_status_code=502)
    if not isinstance(payload, dict):
        raise BridgeError("BRIDGE_MALFORMED", "vault bridge returned a malformed response", http_status_code=502)
    if payload.get("id") != request_id:
        raise BridgeError("BRIDGE_MALFORMED", "vault bridge response id mismatch", http_status_code=502)
    if payload.get("protocol_version") != PROTOCOL_VERSION:
        raise BridgeError("BRIDGE_MALFORMED", "vault bridge protocol version mismatch", http_status_code=502)
    if payload.get("ok") is True and isinstance(payload.get("result"), dict):
        return payload["result"]
    if payload.get("ok") is False and isinstance(payload.get("error"), dict):
        error = payload["error"]
        code = str(error.get("code", "BRIDGE_ERROR"))
        detail = _sanitize(str(error.get("message", "")))
        locked = bool(error.get("locked"))
        raise BridgeError(code, detail, http_status_code=_error_status(code, locked))
    raise BridgeError("BRIDGE_MALFORMED", "vault bridge returned a malformed response", http_status_code=502)


def _error_status(code: str, locked: bool) -> int:
    """Map bridge error codes to HTTP statuses."""
    if locked or code in ("MISSING_PASSPHRASE", "VAULT_NOT_READY"):
        return 423
    if code in ("UNKNOWN_METHOD", "INVALID_PARAMS", "MALFORMED_REQUEST", "OVERSIZED_REQUEST", "UNSUPPORTED_PROTOCOL"):
        return 400
    return 502


def _run_bridge(method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Spawn one bridge child, exchange one request/response, tear down."""
    request = {"id": 1, "method": method, "params": params, "protocol_version": PROTOCOL_VERSION}
    line = json.dumps(request, sort_keys=True) + "\n"
    if len(line.encode("utf-8", errors="replace")) > MAX_REQUEST_BYTES:
        raise BridgeError("REQUEST_TOO_LARGE", "request exceeds the bridge size bound", http_status_code=400)

    binary = _bridge_binary()
    argv = [binary, *BRIDGE_ARGV]
    env = _child_env()
    try:
        proc = subprocess.Popen(
            argv,
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        raise BridgeError("BRIDGE_UNAVAILABLE", "vault bridge binary not found", http_status_code=503)
    except OSError:
        raise BridgeError("BRIDGE_UNAVAILABLE", "could not launch vault bridge", http_status_code=503)

    try:
        stdout, _stderr = proc.communicate(input=line, timeout=_bridge_timeout())
    except subprocess.TimeoutExpired:
        _terminate(proc)
        raise BridgeError("BRIDGE_TIMEOUT", "vault bridge timed out", http_status_code=504)
    if proc.returncode is None:
        _terminate(proc)
    if stdout is None or stdout == "":
        raise BridgeError("BRIDGE_EOF", "vault bridge closed without a response", http_status_code=502)
    return _parse_response(stdout, request_id=1)


def _call(method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Invoke the bridge and convert failures to HTTP errors.

    Only the stable error code is logged; request bodies, child stderr, and
    unsanitized messages never reach the log or the HTTP response.
    """
    try:
        return _run_bridge(method, params)
    except BridgeError as exc:
        log.warning("vault bridge request failed: code=%s", exc.code)
        raise HTTPException(status_code=exc.http_status_code, detail=exc.detail) from None
    except Exception:
        log.warning("vault bridge request failed: code=%s", "UNEXPECTED")
        raise HTTPException(status_code=502, detail="vault bridge unavailable") from None


# ---------------------------------------------------------------------------
# Query parameter validation
# ---------------------------------------------------------------------------


def _bounded_query(request: Request) -> dict[str, Any]:
    """Validate the only query parameters the adapter accepts."""
    unknown = sorted(set(request.query_params.keys()) - ALLOWED_QUERY_PARAMS)
    if unknown:
        raise HTTPException(status_code=400, detail=f"unknown query parameter(s): {', '.join(unknown)}")
    params: dict[str, Any] = {}
    profile = request.query_params.get("profile")
    if profile is not None:
        if len(profile) > MAX_PROFILE_LENGTH:
            raise HTTPException(status_code=400, detail="profile too long")
        params["profile"] = profile
    agent_id = request.query_params.get("agent_id")
    if agent_id is not None:
        if len(agent_id) > MAX_AGENT_ID_LENGTH:
            raise HTTPException(status_code=400, detail="agent_id too long")
        params["agent_id"] = agent_id
    limit = request.query_params.get("limit")
    if limit is not None:
        try:
            value = int(limit)
        except ValueError:
            raise HTTPException(status_code=400, detail="limit must be an integer")
        if not (MIN_LIMIT <= value <= MAX_LIMIT):
            raise HTTPException(status_code=400, detail="limit out of range")
        params["limit"] = value
    return params


def _no_query(request: Request) -> None:
    """Reject any query parameter on routes that take none."""
    if request.query_params:
        raise HTTPException(status_code=400, detail="this route accepts no query parameters")


# ---------------------------------------------------------------------------
# Routes — fixed GET only, mirroring the bridge ALL_METHODS surface.
# ---------------------------------------------------------------------------


@router.get("/hello")
def hello(_: None = Depends(_no_query)) -> dict[str, Any]:
    """Bridge hello — name, versions, and capability list."""
    return _call("hello", {})


@router.get("/health")
def health(_: None = Depends(_no_query)) -> dict[str, Any]:
    """Liveness check; delegates to the bridge hello method."""
    return _call("hello", {})


@router.get("/overview")
def overview(params: dict[str, Any] = Depends(_bounded_query)) -> dict[str, Any]:
    """High-level vault overview (counts, services, health, recent audit)."""
    return _call("overview", params)


@router.get("/credentials")
def credentials(params: dict[str, Any] = Depends(_bounded_query)) -> dict[str, Any]:
    """Credential metadata list."""
    return _call("credentials", params)


@router.get("/leases")
def leases(params: dict[str, Any] = Depends(_bounded_query)) -> dict[str, Any]:
    """Lease metadata list."""
    return _call("leases", params)


@router.get("/policy")
def policy(params: dict[str, Any] = Depends(_bounded_query)) -> dict[str, Any]:
    """Policy doctor summary and agent policies."""
    return _call("policy", params)


@router.get("/requests")
def requests(params: dict[str, Any] = Depends(_bounded_query)) -> dict[str, Any]:
    """Access-request metadata list (optionally filtered by agent_id)."""
    return _call("requests", params)


@router.get("/audit")
def audit(params: dict[str, Any] = Depends(_bounded_query)) -> dict[str, Any]:
    """Recent audit-log metadata (optionally bounded by limit)."""
    return _call("audit", params)


@router.get("/integrity")
def integrity(params: dict[str, Any] = Depends(_bounded_query)) -> dict[str, Any]:
    """Audit-integrity verification status."""
    return _call("integrity", params)


__all__ = [
    "PROTOCOL_VERSION",
    "ALL_METHODS",
    "BridgeError",
    "router",
    "_child_env",
    "_parse_response",
    "_run_bridge",
    "_sanitize",
]
