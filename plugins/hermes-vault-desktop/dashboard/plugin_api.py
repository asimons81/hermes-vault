"""Read-only Hermes Vault dashboard adapter.

The Hermes dashboard imports this module in the gateway process.  This module
intentionally does not import the ``hermes_vault`` package.  Each route starts
one short-lived ``hermes-vault --no-banner desktop-bridge`` child, sends one
NDJSON request, reads one response, and lets the child exit on stdin EOF.

The bridge owns Vault access and redaction.  This layer adds a second boundary:
fixed GET routes, bounded query parameters, an allowlisted child environment,
bounded request/response framing, timeouts, and sanitized error envelopes.
Successful responses expose the bridge's ``result`` object directly.  Errors
use ``{"ok": false, "error": ...}`` with an HTTP status appropriate to the
failure.
"""

from __future__ import annotations

import json
import os
import re
import selectors
import shutil
import subprocess
import time
from typing import Any, Callable

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()

PROTOCOL_VERSION = 1
REQUEST_ID = 1
BRIDGE_BINARY = "hermes-vault"
BRIDGE_TIMEOUT_SECONDS = 5.0
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 512 * 1024
MAX_PROFILE_LENGTH = 64
MAX_AGENT_ID_LENGTH = 128
MAX_ERROR_MESSAGE_LENGTH = 256
MAX_AUDIT_LIMIT = 250

_METHODS = (
    "hello",
    "overview",
    "credentials",
    "leases",
    "policy",
    "requests",
    "audit",
    "integrity",
)
_METHOD_SET = frozenset(_METHODS)
_ALLOWED_QUERY_KEYS = frozenset({"profile", "agent_id", "limit"})
_PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_ERROR_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,31}$")

_SAFE_ENV_KEYS = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "SYSTEMROOT",
        "SystemRoot",
        "TEMP",
        "TMP",
        "PATHEXT",
    }
)
_VAULT_EXACT_ENV_KEYS = frozenset({"HERMES_VAULT_HOME", "HERMES_VAULT_POLICY"})
_VAULT_PASSPHRASE_PREFIX = "HERMES_VAULT_PASSPHRASE"


def _child_env(source: dict[str, str] | None = None) -> dict[str, str]:
    """Return the minimal environment needed by the Vault CLI.

    Provider credentials, ``PYTHONPATH``, and unrelated ambient variables are
    deliberately excluded.  Passphrase variables are allowed only because the
    read-only bridge resolves them from the child environment; this module
    never logs or serializes the resulting environment.
    """

    source = os.environ if source is None else source
    result: dict[str, str] = {}
    for key, value in source.items():
        if key in _SAFE_ENV_KEYS or key in _VAULT_EXACT_ENV_KEYS or key.startswith(_VAULT_PASSPHRASE_PREFIX):
            result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _sanitize_text(value: Any) -> str:
    """Sanitize an untrusted child error without exposing token-like values."""

    text = str(value)
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "[redacted:bearer]", text)
    text = re.sub(
        r"\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        "[redacted:jwt]",
        text,
    )
    text = re.sub(r"(?i)\b(?:sk|rk|ghp|gho|github_pat|xox[baprs])-[-A-Za-z0-9_]+", "[redacted:key]", text)
    text = re.sub(r"\b[0-9a-fA-F]{32,}\b", "[redacted:hex-token]", text)
    text = re.sub(r"(?:(?:[A-Za-z]:)?[/\\])[^\s'\";,)]{1,240}", "[path]", text)
    text = " ".join(text.split())
    return text[:MAX_ERROR_MESSAGE_LENGTH] or "bridge request failed"


def _error(status: int, code: str, message: str, *, locked: bool = False) -> JSONResponse:
    safe_code = code if _ERROR_CODE_RE.fullmatch(code) else "BRIDGE_ERROR"
    payload: dict[str, Any] = {
        "ok": False,
        "error": {"code": safe_code, "message": _sanitize_text(message)},
    }
    if locked:
        payload["error"]["locked"] = True
    return JSONResponse(status_code=status, content=payload)


def _query_error(message: str) -> JSONResponse:
    return _error(400, "INVALID_PARAMS", message)


def _validate_query(request: Request, method: str) -> tuple[dict[str, Any] | None, JSONResponse | None]:
    """Validate and normalize the small, method-specific query surface."""

    allowed = set()
    if method != "hello":
        allowed.add("profile")
    if method == "requests":
        allowed.add("agent_id")
    if method == "audit":
        allowed.add("limit")

    params: dict[str, Any] = {}
    seen: set[str] = set()
    for key, value in request.query_params.multi_items():
        if key not in _ALLOWED_QUERY_KEYS or key not in allowed:
            return None, _query_error("unsupported query parameter")
        if key in seen:
            return None, _query_error("query parameter must appear once")
        seen.add(key)
        if len(value) > MAX_AGENT_ID_LENGTH:
            return None, _query_error("query parameter is too long")
        if key == "profile":
            if not _PROFILE_RE.fullmatch(value) or value == "profiles" or ".." in value:
                return None, _query_error("invalid profile")
            params[key] = value
        elif key == "agent_id":
            if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
                return None, _query_error("invalid agent_id")
            params[key] = value
        else:
            if not re.fullmatch(r"[0-9]{1,3}", value):
                return None, _query_error("limit must be an integer")
            limit = int(value)
            if not 1 <= limit <= MAX_AUDIT_LIMIT:
                return None, _query_error("limit is out of range")
            params[key] = limit
    return params, None


def _stop_process(process: Any) -> None:
    """Best-effort child cleanup; never expose cleanup exceptions."""

    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=0.5)
            except Exception:
                process.kill()
                try:
                    process.wait(timeout=0.5)
                except Exception:
                    pass
    except Exception:
        pass


class _OutputLimitExceeded(Exception):
    pass


def _read_bounded_child_output(process: Any, request_line: bytes) -> bytes:
    """Write one request and drain a real child stdout pipe with a hard cap."""

    stdin = getattr(process, "stdin", None)
    stdout = getattr(process, "stdout", None)
    if stdin is None or stdout is None or not hasattr(stdout, "fileno"):
        # Unit-test doubles may only implement communicate(). Real Popen objects
        # always expose file-backed stdin/stdout and take the bounded path below.
        output, _ = process.communicate(input=request_line, timeout=BRIDGE_TIMEOUT_SECONDS)
        return output or b""

    stdin.write(request_line)
    stdin.close()
    fd = stdout.fileno()
    os.set_blocking(fd, False)
    selector = selectors.DefaultSelector()
    selector.register(fd, selectors.EVENT_READ)
    chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + BRIDGE_TIMEOUT_SECONDS
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired([BRIDGE_BINARY], BRIDGE_TIMEOUT_SECONDS)
            events = selector.select(min(remaining, 0.05))
            if not events:
                continue
            chunk = os.read(fd, min(64 * 1024, MAX_RESPONSE_BYTES + 1 - total))
            if not chunk:
                return b"".join(chunks)
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise _OutputLimitExceeded
            chunks.append(chunk)
    finally:
        selector.close()


def _malformed_response(message: str = "malformed bridge response") -> JSONResponse:
    return _error(502, "MALFORMED_RESPONSE", message)


def _parse_response(stdout: bytes | str) -> dict[str, Any] | JSONResponse:
    if isinstance(stdout, str):
        raw = stdout.encode("utf-8", errors="replace")
    else:
        raw = stdout
    if not raw:
        return _error(502, "BRIDGE_EOF", "bridge returned no response")
    if len(raw) > MAX_RESPONSE_BYTES:
        return _error(502, "OUTPUT_LIMIT", "bridge response exceeded the output limit")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if not raw or b"\n" in raw or b"\r" in raw:
        return _malformed_response()
    try:
        response = json.loads(raw.decode("utf-8"), parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        return _malformed_response()
    if not isinstance(response, dict):
        return _malformed_response()
    protocol = response.get("protocol_version")
    if isinstance(protocol, bool) or protocol != PROTOCOL_VERSION:
        return _error(502, "PROTOCOL_MISMATCH", "bridge protocol version mismatch")
    if response.get("id") != REQUEST_ID:
        return _malformed_response()
    if not isinstance(response.get("ok"), bool):
        return _malformed_response()
    return response


def _bridge_error_response(response: dict[str, Any]) -> JSONResponse:
    raw_error = response.get("error")
    if not isinstance(raw_error, dict):
        return _malformed_response("bridge error envelope is malformed")
    raw_code = raw_error.get("code")
    code = raw_code if isinstance(raw_code, str) and _ERROR_CODE_RE.fullmatch(raw_code) else "BRIDGE_ERROR"
    locked = bool(raw_error.get("locked")) or code in {"MISSING_PASSPHRASE", "VAULT_NOT_READY"}
    if locked:
        status = 423
    elif code == "INVALID_PARAMS":
        status = 400
    elif code in {"MALFORMED_REQUEST", "OVERSIZED_REQUEST"}:
        status = 400
    else:
        status = 502
    message = raw_error.get("message", "bridge request failed")
    return _error(status, code, message, locked=locked)


def _dispatch(method: str, params: dict[str, Any]) -> JSONResponse:
    if method not in _METHOD_SET:
        return _error(404, "UNKNOWN_METHOD", "unknown bridge method")
    binary = shutil.which(BRIDGE_BINARY)
    if not binary:
        return _error(503, "BINARY_MISSING", "Vault bridge binary is unavailable")
    request = {
        "id": REQUEST_ID,
        "method": method,
        "params": params,
        "protocol_version": PROTOCOL_VERSION,
    }
    try:
        request_line = (json.dumps(request, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    except (TypeError, ValueError):
        return _error(400, "INVALID_PARAMS", "request parameters are not serializable")
    if len(request_line) > MAX_REQUEST_BYTES:
        return _error(400, "OVERSIZED_REQUEST", "bridge request exceeded the input limit")

    process: Any = None
    try:
        process = subprocess.Popen(
            [binary, "--no-banner", "desktop-bridge"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_child_env(),
            shell=False,
        )
        stdout = _read_bounded_child_output(process, request_line)
    except _OutputLimitExceeded:
        return _error(502, "OUTPUT_LIMIT", "bridge response exceeded the output limit")
    except FileNotFoundError:
        return _error(503, "BINARY_MISSING", "Vault bridge binary is unavailable")
    except subprocess.TimeoutExpired:
        return _error(504, "TIMEOUT", "Vault bridge timed out")
    except (BrokenPipeError, OSError):
        return _error(502, "BRIDGE_UNAVAILABLE", "Vault bridge could not be reached")
    finally:
        if process is not None:
            _stop_process(process)

    parsed = _parse_response(stdout if stdout is not None else b"")
    if isinstance(parsed, JSONResponse):
        return parsed
    if parsed.get("ok") is True:
        result = parsed.get("result")
        if not isinstance(result, dict):
            return _malformed_response("bridge success envelope is malformed")
        return JSONResponse(status_code=200, content=result)
    return _bridge_error_response(parsed)


def _make_endpoint(method: str) -> Callable[[Request], Any]:
    async def endpoint(request: Request) -> JSONResponse:
        params, error = _validate_query(request, method)
        if error is not None:
            return error
        return _dispatch(method, params or {})

    endpoint.__name__ = f"get_{method}"
    return endpoint


for _method in _METHODS:
    router.add_api_route(
        f"/{_method}",
        _make_endpoint(_method),
        methods=["GET"],
        response_class=JSONResponse,
        name=f"hermes_vault_desktop_{_method}",
    )

# A health probe is deliberately an alias for the non-contextual hello call.
router.add_api_route(
    "/health",
    _make_endpoint("hello"),
    methods=["GET"],
    response_class=JSONResponse,
    name="hermes_vault_desktop_health",
)

__all__ = [
    "BRIDGE_BINARY",
    "BRIDGE_TIMEOUT_SECONDS",
    "MAX_REQUEST_BYTES",
    "MAX_RESPONSE_BYTES",
    "PROTOCOL_VERSION",
    "router",
    "_child_env",
    "_dispatch",
    "_parse_response",
]
