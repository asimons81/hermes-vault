from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from hermes_vault import _platform
from hermes_vault.audit_integrity.canonical import canonical_bytes
from hermes_vault.audit_integrity.crypto import CHECKPOINT_SIGNING_CONTEXT, sign, verify

CHECKPOINT_FORMAT = "hermes-vault-audit-checkpoint"
CHECKPOINT_VERSION = "audit-checkpoint-v1"


class AuditLockError(RuntimeError):
    pass


@contextmanager
def audit_write_lock(path: Path, timeout_seconds: float = 5.0) -> Iterator[None]:
    deadline = time.monotonic() + timeout_seconds
    payload = json.dumps({"version": "audit-lock-v1", "pid": os.getpid(), "created_at": datetime.now(timezone.utc).isoformat()}, sort_keys=True)
    while True:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
            _platform.secure_file(path)
            break
        except FileExistsError:
            try:
                age = time.time() - path.stat().st_mtime
                if age > timeout_seconds * 12:
                    path.unlink(missing_ok=True)
                    continue
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise AuditLockError("Audit write coordination is unavailable; retry after the other operation finishes.")
            time.sleep(0.05)
    try:
        yield
    finally:
        path.unlink(missing_ok=True)


def signed_checkpoint(payload: dict[str, object], master_key: bytes) -> dict[str, object]:
    unsigned = dict(payload)
    unsigned.pop("signature", None)
    unsigned["format"] = CHECKPOINT_FORMAT
    unsigned["version"] = CHECKPOINT_VERSION
    unsigned["signature"] = sign(master_key, CHECKPOINT_SIGNING_CONTEXT, canonical_bytes(unsigned))
    return unsigned


def write_checkpoint(path: Path, payload: dict[str, object], master_key: bytes) -> dict[str, object]:
    signed = signed_checkpoint(payload, master_key)
    _platform.replace_bytes_durable(path, canonical_bytes(signed) + b"\n")
    return signed


def read_checkpoint(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def checkpoint_signature_valid(payload: dict[str, object], public_key: str) -> bool:
    signature = payload.get("signature")
    unsigned = dict(payload)
    unsigned.pop("signature", None)
    return isinstance(signature, str) and verify(public_key, signature, canonical_bytes(unsigned))