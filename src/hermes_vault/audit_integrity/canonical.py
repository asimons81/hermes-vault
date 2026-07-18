from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from enum import Enum
from typing import Any

CANONICAL_JSON_VERSION = "canonical-json-v1"


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise TypeError("Naive timestamps are not supported in audit evidence")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def normalize(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError("Non-finite floats are not supported in audit evidence")
        return value
    if isinstance(value, datetime):
        return _timestamp(value)
    if isinstance(value, Enum):
        return normalize(value.value)
    if isinstance(value, list) or isinstance(value, tuple):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("Audit evidence dictionary keys must be strings")
        return {key: normalize(item) for key, item in value.items()}
    raise TypeError(f"Unsupported audit evidence value: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def framed(parts: list[bytes]) -> bytes:
    return b"".join(len(part).to_bytes(8, "big") + part for part in parts)