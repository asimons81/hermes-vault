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
  ``shell=False`` — no shell interpolation, no dynamic arguments. Mutation
  routes additionally append ``--allow-mutations`` (still a fixed argument).
- **Scrubbed environment.** The child receives only safe basics (PATH, HOME,
  locale, temp dirs) plus ``HERMES_VAULT_HOME``, ``HERMES_VAULT_POLICY`` and
  the ``HERMES_VAULT_PASSPHRASE*`` family. Ambient ``PYTHONPATH`` and
  provider keys never reach the child. The passphrase may reach the child,
  but never returns to the parent and is never logged.
- **No secret transport.** Request bodies are never logged, child stderr is
  discarded, and error text is sanitized before it appears in a response.
  Malformed bridge output is reported as a generic error, never echoed.
- **Read-only surface by default.** Only fixed GET routes exist; unknown
  paths and non-GET verbs are rejected by the router. Query parameters are
  limited to ``profile`` / ``agent_id`` / ``limit`` with explicit bounds.
- **Mutations are opt-in.** POST ``/mutations/{add,rotate,delete}`` are
  registered but return 404 unless ``HERMES_VAULT_DESKTOP_MUTATIONS`` is set
  to a truthy value (``1``/``true``/``yes``/``on``). Mutation routes require
  an ``Authorization`` bearer header (no ``?token=`` fallback), reject query
  params, validate the JSON body and size bounds before spawning the child,
  and pass ``--allow-mutations`` to the bridge child. The caller identity is
  always the operator: renderer-supplied ``agent_id`` is rejected here (and
  the bridge rejects it again).
- **Host-header hardening (R1).** All routes reject a ``Host`` header that
  does not match the loopback/bound host. The hosting web server also
  validates ``Host`` app-wide; this router re-checks so the adapter stays
  safe even when mounted without that middleware.

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


def _mutations_enabled() -> bool:
    """True when the opt-in mutation surface is enabled via env var."""
    return os.environ.get(MUTATIONS_ENV_VAR, "").strip().lower() in _MUTATIONS_TRUTHY


def _host_only(host_header: str) -> str:
    """Return the hostname portion of a Host header (strip port / brackets)."""
    h = host_header.strip()
    if h.startswith("["):
        close = h.find("]")
        if close != -1:
            return h[1:close].lower()
        return h.strip("[]").lower()
    if ":" in h:
        return h.rsplit(":", 1)[0].lower()
    return h.lower()


def _validate_host_header(request: Request) -> None:
    """Reject requests whose Host header is not loopback (R1 hardening).

    DNS rebinding attacks point a victim browser at an attacker-controlled
    hostname that resolves to 127.0.0.1; validating the Host header at the
    app layer rejects any request whose Host isn't one we bound for. The
    hosting web server already enforces this app-wide; this router-level
    dependency keeps the adapter safe even when mounted without it.
    """
    host = request.headers.get("host", "")
    if _host_only(host) in LOOPBACK_HOSTS:
        return
    # If the hosting app recorded an explicit bound host, accept that exact
    # host too (mirrors the web server's host middleware). A wildcard bind
    # (0.0.0.0 / ::) is an operator opt-in to all interfaces; no Host-layer
    # defence can protect that mode, so accept any host to match the host.
    bound_host = getattr(request.app.state, "bound_host", None)
    if bound_host:
        bound = _host_only(str(bound_host))
        if bound in ("0.0.0.0", "::"):
            return
        if host and _host_only(host) == bound:
            return
    raise HTTPException(status_code=400, detail="invalid Host header")


router = APIRouter(dependencies=[Depends(_validate_host_header)])

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

# Mutation methods are dispatched only when the child was launched with
# ``--allow-mutations``. The adapter appends that flag to the child argv
# ONLY on the three mutation routes below; GET routes never pass it.
MUTATION_METHODS = ("add", "rotate", "delete")

# Opt-in gate: mutation routes exist but return 404 unless this env var is
# set to a truthy value. Keeps the installed adapter read-only until the
# mutation surface ships and passes review (project gate #4).
MUTATIONS_ENV_VAR = "HERMES_VAULT_DESKTOP_MUTATIONS"
_MUTATIONS_TRUTHY = frozenset({"1", "true", "yes", "on"})

# Fixed child argv; the binary may be overridden for tests via
# HERMES_VAULT_BINARY, but the argument vector is never dynamic.
BRIDGE_BINARY_DEFAULT = "hermes-vault-canonical"
BRIDGE_ARGV = ("--no-banner", "desktop-bridge")
ALLOW_MUTATIONS_FLAG = "--allow-mutations"

# Bounds mirror the bridge's own NDJSON limits so the parent rejects
# oversized traffic without trusting the child to behave.
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 512 * 1024
DEFAULT_TIMEOUT_SECONDS = 15.0
MAX_TIMEOUT_SECONDS = 120.0

# Mutation body field bounds (mirror the bridge's own limits).
MAX_SERVICE_LENGTH = 256
MAX_ALIAS_LENGTH = 256
MAX_CREDENTIAL_TYPE_LENGTH = 128
MAX_TARGET_LENGTH = 512  # service_or_id may be a service name or UUID
MAX_CONFIRMATION_LENGTH = 512
MAX_SECRET_LENGTH = 32 * 1024  # secrets are the largest payload, bounded by body cap
MAX_TAGS_COUNT = 32
MAX_TAG_LENGTH = 128
MAX_NOTES_LENGTH = 4096
MAX_REQUEST_ID_LENGTH = 64

# Allowed mutation body fields per route. Any other field (including
# renderer-supplied ``agent_id``) is rejected with 400 before the child
# spawns. ``agent_id`` is deliberately absent: the adapter stamps the
# operator identity and the bridge rejects it again (defense in depth).
MUTATION_ALLOWED_FIELDS: dict[str, frozenset[str]] = {
    "add": frozenset(
        {"service", "alias", "credential_type", "secret", "tags", "notes", "request_id"}
    ),
    "rotate": frozenset({"service_or_id", "alias", "new_secret", "request_id"}),
    "delete": frozenset({"service_or_id", "alias", "confirmation", "request_id"}),
}

MUTATION_REQUIRED_FIELDS: dict[str, frozenset[str]] = {
    "add": frozenset({"service", "secret"}),
    "rotate": frozenset({"service_or_id", "new_secret"}),
    "delete": frozenset({"service_or_id", "confirmation"}),
}

# Query parameters the adapter understands. Unknown keys are rejected.
ALLOWED_QUERY_PARAMS = frozenset({"profile", "agent_id", "limit"})
MAX_PROFILE_LENGTH = 128
MAX_AGENT_ID_LENGTH = 256
MIN_LIMIT = 1
MAX_LIMIT = 250

# Accepted Host header values. The adapter is a local-only desktop plugin;
# DNS rebinding is blocked by rejecting any Host that is not the loopback
# (or the bound host recorded by the hosting web server). ``testserver`` /
# ``testclient`` are FastAPI TestClient aliases used by the test suite.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "testserver", "testclient"})

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
    if code == "CONFIRMATION_MISMATCH":
        return 403
    if code in ("AUDIT_INTEGRITY", "DUPLICATE"):
        return 409
    if code == "MUTATIONS_DISABLED":
        return 503
    if code in ("UNKNOWN_METHOD", "INVALID_PARAMS", "MALFORMED_REQUEST", "OVERSIZED_REQUEST", "UNSUPPORTED_PROTOCOL"):
        return 400
    return 502


def _run_bridge(method: str, params: dict[str, Any], *, allow_mutations: bool = False) -> dict[str, Any]:
    """Spawn one bridge child, exchange one request/response, tear down."""
    request = {"id": 1, "method": method, "params": params, "protocol_version": PROTOCOL_VERSION}
    line = json.dumps(request, sort_keys=True) + "\n"
    if len(line.encode("utf-8", errors="replace")) > MAX_REQUEST_BYTES:
        raise BridgeError("REQUEST_TOO_LARGE", "request exceeds the bridge size bound", http_status_code=400)

    binary = _bridge_binary()
    argv = [binary, *BRIDGE_ARGV]
    if allow_mutations:
        argv.append(ALLOW_MUTATIONS_FLAG)
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


def _call(method: str, params: dict[str, Any], *, allow_mutations: bool = False) -> dict[str, Any]:
    """Invoke the bridge and convert failures to HTTP errors.

    Only the stable error code is logged; request bodies, child stderr, and
    unsanitized messages never reach the log or the HTTP response.
    """
    try:
        return _run_bridge(method, params, allow_mutations=allow_mutations)
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
# Mutation route support: body validation happens BEFORE the child spawns.
# ---------------------------------------------------------------------------


def _require_bearer(request: Request) -> None:
    """Require an Authorization: Bearer <token> header on mutation routes.

    Mutations never accept a ``?token=`` query fallback; the session token
    rides the Authorization header only. (The hosting dashboard auth gate
    validates the token value; this check enforces the transport contract.)
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or not auth[len("Bearer "):].strip():
        raise HTTPException(status_code=401, detail="mutation routes require Authorization: Bearer <token>")


def _require_bounded_str(
    value: Any,
    *,
    field: str,
    required: bool,
    max_len: int,
    allow_empty: bool = False,
) -> str:
    """Validate a string field; returns the normalized value or raises 400."""
    if not isinstance(value, str):
        raise HTTPException(status_code=400, detail=f"{field} must be a string")
    if not allow_empty and not value.strip():
        if required:
            raise HTTPException(status_code=400, detail=f"{field} is required")
        raise HTTPException(status_code=400, detail=f"{field} must not be empty")
    if len(value) > max_len:
        raise HTTPException(status_code=400, detail=f"{field} too long")
    return value


def _validate_request_id(value: Any) -> str | None:
    """Validate optional request_id: alphanumeric plus '-'/'_', ≤64 chars."""
    if value is None or value == "":
        return None
    if not isinstance(value, str) or len(value) > MAX_REQUEST_ID_LENGTH:
        raise HTTPException(status_code=400, detail="request_id must be a short alphanumeric string (≤64 chars)")
    if not all(ch.isalnum() or ch in "-_" for ch in value):
        raise HTTPException(status_code=400, detail="request_id must be alphanumeric")
    return value


def _validate_mutation_body(kind: str, body: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize a mutation request body.

    Returns the bridge ``params`` dict (metadata-only). Raises HTTPException
    400 for malformed/oversized/unknown bodies BEFORE any child spawn.
    """
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="request body must be a JSON object")
    unknown = sorted(set(body) - MUTATION_ALLOWED_FIELDS[kind])
    if unknown:
        raise HTTPException(status_code=400, detail=f"unknown field(s): {', '.join(unknown)}")
    missing = sorted(MUTATION_REQUIRED_FIELDS[kind] - set(body))
    if missing:
        raise HTTPException(status_code=400, detail=f"missing required field(s): {', '.join(missing)}")

    params: dict[str, Any] = {}
    if kind == "add":
        params["service"] = _require_bounded_str(body["service"], field="service", required=True, max_len=MAX_SERVICE_LENGTH)
        params["secret"] = _require_bounded_str(body["secret"], field="secret", required=True, max_len=MAX_SECRET_LENGTH)
        if "alias" in body and body["alias"] not in (None, ""):
            params["alias"] = _require_bounded_str(body["alias"], field="alias", required=False, max_len=MAX_ALIAS_LENGTH)
        if "credential_type" in body and body["credential_type"] not in (None, ""):
            params["credential_type"] = _require_bounded_str(
                body["credential_type"], field="credential_type", required=False, max_len=MAX_CREDENTIAL_TYPE_LENGTH
            )
        if "tags" in body and body["tags"] not in (None, []):
            tags = body["tags"]
            if not isinstance(tags, list) or len(tags) > MAX_TAGS_COUNT:
                raise HTTPException(status_code=400, detail="tags must be a list (max 32)")
            clean_tags: list[str] = []
            for tag in tags:
                clean_tags.append(_require_bounded_str(tag, field="tag", required=False, max_len=MAX_TAG_LENGTH))
            params["tags"] = clean_tags
        if "notes" in body and body["notes"] not in (None, ""):
            params["notes"] = _require_bounded_str(body["notes"], field="notes", required=False, max_len=MAX_NOTES_LENGTH)
    elif kind == "rotate":
        params["service_or_id"] = _require_bounded_str(
            body["service_or_id"], field="service_or_id", required=True, max_len=MAX_TARGET_LENGTH
        )
        params["new_secret"] = _require_bounded_str(body["new_secret"], field="new_secret", required=True, max_len=MAX_SECRET_LENGTH)
        if "alias" in body and body["alias"] not in (None, ""):
            params["alias"] = _require_bounded_str(body["alias"], field="alias", required=False, max_len=MAX_ALIAS_LENGTH)
    elif kind == "delete":
        params["service_or_id"] = _require_bounded_str(
            body["service_or_id"], field="service_or_id", required=True, max_len=MAX_TARGET_LENGTH
        )
        params["confirmation"] = _require_bounded_str(
            body["confirmation"], field="confirmation", required=True, max_len=MAX_CONFIRMATION_LENGTH
        )
        if "alias" in body and body["alias"] not in (None, ""):
            params["alias"] = _require_bounded_str(body["alias"], field="alias", required=False, max_len=MAX_ALIAS_LENGTH)

    request_id = _validate_request_id(body.get("request_id"))
    if request_id is not None:
        params["request_id"] = request_id
    return params


def _require_mutations_enabled() -> None:
    """Gate the mutation routes behind the opt-in env flag."""
    if not _mutations_enabled():
        raise HTTPException(status_code=404, detail="mutation routes are not enabled")


# ---------------------------------------------------------------------------
# Routes — fixed GET only, mirroring the bridge ALL_METHODS surface.
# ---------------------------------------------------------------------------


@router.get("/hello")
def hello(params: dict[str, Any] = Depends(_bounded_query)) -> dict[str, Any]:
    """Bridge hello — name, versions, and capability list.

    Accepts the same bounded query params as the other read routes
    (release/v0.24.0 behavior — the renderer version-gates via hello).
    When the mutation surface is enabled the adapter advertises the mutation
    methods and ``mutations: true`` so the renderer can version-gate. The
    child is still launched WITHOUT ``--allow-mutations`` on this GET route;
    the advertisement is an adapter-level overlay only.
    """
    result = _call("hello", params)
    if _mutations_enabled():
        capabilities = set(result.get("capabilities") or [])
        capabilities.update(MUTATION_METHODS)
        result["capabilities"] = sorted(capabilities)
        result["mutations"] = True
        result["read_only"] = False
    return result


@router.get("/health")
def health(params: dict[str, Any] = Depends(_bounded_query)) -> dict[str, Any]:
    """Liveness check; delegates to the bridge hello method."""
    return _call("hello", params)


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


# ---------------------------------------------------------------------------
# Mutation routes — POST only, opt-in, Bearer-only, body-validated first.
# ---------------------------------------------------------------------------


@router.post("/mutations/add")
async def mutations_add(
    request: Request,
    _enabled: None = Depends(_require_mutations_enabled),
    _query: None = Depends(_no_query),
    _bearer: None = Depends(_require_bearer),
) -> dict[str, Any]:
    """Add a credential (operator-only, audited via the bridge)."""
    body = await _read_mutation_body(request)
    params = _validate_mutation_body("add", body)
    return _call("add", params, allow_mutations=True)


@router.post("/mutations/rotate")
async def mutations_rotate(
    request: Request,
    _enabled: None = Depends(_require_mutations_enabled),
    _query: None = Depends(_no_query),
    _bearer: None = Depends(_require_bearer),
) -> dict[str, Any]:
    """Rotate a credential's secret (operator-only, audited via the bridge)."""
    body = await _read_mutation_body(request)
    params = _validate_mutation_body("rotate", body)
    return _call("rotate", params, allow_mutations=True)


@router.post("/mutations/delete")
async def mutations_delete(
    request: Request,
    _enabled: None = Depends(_require_mutations_enabled),
    _query: None = Depends(_no_query),
    _bearer: None = Depends(_require_bearer),
) -> dict[str, Any]:
    """Delete a credential — deny-by-default, confirmation required.

    The adapter rejects a missing/empty ``confirmation`` with 403 BEFORE any
    child spawn; the bridge independently enforces the exact-match check.
    """
    body = await _read_mutation_body(request)
    confirmation = body.get("confirmation")
    if not isinstance(confirmation, str) or not confirmation.strip():
        raise HTTPException(
            status_code=403,
            detail="confirmation is required and must match the target credential",
        )
    params = _validate_mutation_body("delete", body)
    return _call("delete", params, allow_mutations=True)


async def _read_mutation_body(request: Request) -> dict[str, Any]:
    """Read and bound the raw request body before any child spawn."""
    raw = await request.body()
    if len(raw) > MAX_REQUEST_BYTES:
        raise HTTPException(status_code=400, detail="request body exceeds the size bound")
    if not raw:
        raise HTTPException(status_code=400, detail="request body is required")
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="request body must be valid JSON")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="request body must be a JSON object")
    return body


__all__ = [
    "PROTOCOL_VERSION",
    "ALL_METHODS",
    "MUTATION_METHODS",
    "BridgeError",
    "router",
    "_child_env",
    "_parse_response",
    "_run_bridge",
    "_sanitize",
]
