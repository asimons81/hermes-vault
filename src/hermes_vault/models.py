from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CredentialStatus(str, Enum):
    active = "active"
    invalid = "invalid"
    expired = "expired"
    unknown = "unknown"


class Decision(str, Enum):
    allow = "allow"
    deny = "deny"


class FindingSeverity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class VerificationCategory(str, Enum):
    valid = "valid"
    invalid_or_expired = "invalid_or_expired"
    network_failure = "network_failure"
    endpoint_misconfiguration = "endpoint_misconfiguration"
    permission_scope_issue = "permission_scope_issue"
    rate_limit = "rate_limit"
    unknown = "unknown"


class FindingRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    severity: FindingSeverity
    kind: str
    path: str
    service: str | None = None
    fingerprint: str | None = None
    recommendation: str
    line_number: int | None = None
    detail: str | None = None


class CredentialRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    service: str
    alias: str = "default"
    credential_type: str
    encrypted_payload: str
    status: CredentialStatus = CredentialStatus.unknown
    scopes: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    last_verified_at: datetime | None = None
    imported_from: str | None = None
    expiry: datetime | None = None
    tags: list[str] = Field(default_factory=list)
    notes: str | None = None
    crypto_version: str = "aesgcm-v1"


class LeaseStatus(str, Enum):
    active = "active"
    expired = "expired"
    revoked = "revoked"


class LeaseRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    service: str
    alias: str = "default"
    credential_id: str
    credential_type: str
    agent_id: str
    issued_by: str
    purpose: str
    status: LeaseStatus = LeaseStatus.active
    ttl_seconds: int
    issued_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime = Field(default_factory=utc_now)
    revoked_at: datetime | None = None
    renewed_at: datetime | None = None
    renew_count: int = 0
    reason: str | None = None
    scopes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AccessRequestStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    denied = "denied"


class AccessRequestRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    agent_id: str
    service: str
    alias: str = "default"
    action: str
    purpose: str
    status: AccessRequestStatus = AccessRequestStatus.pending
    requested_ttl_seconds: int | None = None
    created_at: datetime = Field(default_factory=utc_now)
    decided_at: datetime | None = None
    decided_by: str | None = None
    decision_reason: str | None = None
    lease_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CredentialSecret(BaseModel):
    secret: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    notes: str | None = None


class AccessLogRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=utc_now)
    agent_id: str
    service: str
    action: str
    decision: Decision
    reason: str
    ttl_seconds: int | None = None
    verification_result: VerificationCategory | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class VerificationResult(BaseModel):
    service: str
    category: VerificationCategory
    success: bool
    reason: str
    checked_at: datetime = Field(default_factory=utc_now)
    status_code: int | None = None


class ServiceAction(str, Enum):
    get_credential = "get_credential"
    get_env = "get_env"
    verify = "verify"
    metadata = "metadata"
    add_credential = "add_credential"
    rotate = "rotate"
    delete = "delete"
    issue_lease = "issue_lease"
    list_leases = "list_leases"
    show_lease = "show_lease"
    renew_lease = "renew_lease"
    revoke_lease = "revoke_lease"


ALL_SERVICE_ACTIONS: list[ServiceAction] = list(ServiceAction)


class AgentCapability(str, Enum):
    """Agent-level capabilities for actions not scoped to a single service."""

    list_credentials = "list_credentials"
    add_credential = "add_credential"
    scan_secrets = "scan_secrets"
    export_backup = "export_backup"
    import_credentials = "import_credentials"


ALL_AGENT_CAPABILITIES: list[AgentCapability] = list(AgentCapability)


class ServicePolicyEntry(BaseModel):
    """Per-service permissions in policy v2."""

    actions: list[ServiceAction]
    max_ttl_seconds: int | None = None
    require_lease_for_env: bool | None = None
    require_lease_purpose: bool | None = None


class AgentPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # v2: per-service action permissions.  Normalized from legacy list or v2 dict.
    service_actions: dict[str, ServicePolicyEntry] = Field(default_factory=dict)
    # Agent-level capabilities for non-service-scoped actions.
    # Empty list = all capabilities allowed (backward compat with pre-v0.2.0 policies).
    capabilities: list[AgentCapability] = Field(default_factory=list)
    # Legacy flat list — kept for backward compat.  Populated in all cases.
    services: list[str] = Field(default_factory=list)
    raw_secret_access: bool = False
    ephemeral_env_only: bool = True
    require_verification_before_reauth: bool = True
    max_ttl_seconds: int = 900
    approval_required_services: list[str] = Field(default_factory=list)
    require_lease_for_env: bool = False
    require_lease_purpose: bool = False


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agents: dict[str, AgentPolicy] = Field(default_factory=dict)
    managed_paths: list[str] = Field(default_factory=lambda: ["~/.hermes", "~/.config/hermes"])
    plaintext_migration_paths: list[str] = Field(default_factory=list)
    plaintext_exempt_paths: list[str] = Field(default_factory=list)
    deny_plaintext_under_managed_paths: bool = True


class BrokerDecision(BaseModel):
    allowed: bool
    service: str
    agent_id: str
    reason: str
    ttl_seconds: int | None = None
    env: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class MutationResult(BaseModel):
    """Standardized result for audited vault mutations."""
    allowed: bool
    service: str
    agent_id: str
    action: str
    reason: str
    record: CredentialRecord | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
