from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import StrEnum


class AuditIntegrityStatus(StrEnum):
    healthy = "healthy"
    legacy = "legacy"
    incomplete = "incomplete"
    failed = "failed"


class AuditCheckpointStatus(StrEnum):
    valid = "valid"
    missing = "missing"
    stale = "stale"
    ahead = "ahead"
    invalid_signature = "invalid_signature"
    invalid_format = "invalid_format"
    segment_mismatch = "segment_mismatch"
    registry_mismatch = "registry_mismatch"
    unsupported_version = "unsupported_version"


@dataclass(frozen=True)
class AuditVerificationResult:
    status: AuditIntegrityStatus
    reason_code: str
    chain_version: str | None
    serialization_version: str | None
    active_segment_id: str | None
    active_segment_number: int | None
    verified_count: int
    legacy_count: int
    first_verified_sequence: int | None
    last_verified_sequence: int | None
    checkpoint_status: AuditCheckpointStatus
    failure_sequence: int | None
    failure_segment_id: str | None
    sanitized_reason: str
    recommended_next_step: str
    verified_at: datetime

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["status"] = self.status.value
        value["checkpoint_status"] = self.checkpoint_status.value
        value["verified_at"] = self.verified_at.astimezone(timezone.utc).isoformat()
        return value