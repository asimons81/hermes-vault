from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


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
    crypto_version: str = "aesgcm-v1"


class CredentialSecret(BaseModel):
    secret: str
    metadata: dict[str, Any] = Field(default_factory=dict)


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
    rotate = "rotate"
    delete = "delete"


ALL_SERVICE_ACTIONS: list[ServiceAction] = list(ServiceAction)


class AgentCapability(str, Enum):
    """Agent-level capabilities for actions not scoped to a single service."""

    list_credentials = "list_credentials"
    scan_secrets = "scan_secrets"
    export_backup = "export_backup"
    import_credentials = "import_credentials"


ALL_AGENT_CAPABILITIES: list[AgentCapability] = list(AgentCapability)


class ServicePolicyEntry(BaseModel):
    """Per-service permissions in policy v2."""

    actions: list[ServiceAction]
    max_ttl_seconds: int | None = None


class AgentPolicy(BaseModel):
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


class PolicyConfig(BaseModel):
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
