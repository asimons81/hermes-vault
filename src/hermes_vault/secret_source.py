from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from hermes_vault.logging_redaction import redact_text
from hermes_vault.models import ServiceAction
from hermes_vault.policy import PolicyEngine
from hermes_vault.service_ids import get_env_var_map, normalize
from hermes_vault.vault import AmbiguousTargetError, Vault


SECRET_SOURCE_RESULT_VERSION = "hermes-vault-secret-source-v1"
VALID_ERROR_KINDS = {
    "NOT_CONFIGURED",
    "BINARY_MISSING",
    "AUTH_FAILED",
    "AUTH_EXPIRED",
    "REF_INVALID",
    "NETWORK",
    "EMPTY_VALUE",
    "TIMEOUT",
    "INTERNAL",
}
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class VaultSecretRef:
    raw: str
    service: str
    alias: str | None = None


@dataclass
class SecretSourceIssue:
    kind: str
    message: str
    ref: str | None = None

    def as_dict(self) -> dict[str, str]:
        payload = {"kind": self.kind, "message": redact_text(self.message)}
        if self.ref is not None:
            payload["ref"] = self.ref
        return payload


@dataclass
class SecretSourceFetchReport:
    secrets: dict[str, str] = field(default_factory=dict)
    warnings: dict[str, SecretSourceIssue] = field(default_factory=dict)
    errors: dict[str, SecretSourceIssue] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return bool(self.secrets)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "version": SECRET_SOURCE_RESULT_VERSION,
            "secrets": self.secrets,
            "warnings": {key: issue.as_dict() for key, issue in self.warnings.items()},
            "errors": {key: issue.as_dict() for key, issue in self.errors.items()},
        }


def parse_binding(binding: str) -> tuple[str, VaultSecretRef]:
    if "=" not in binding:
        raise ValueError("binding must be ENV_VAR=hv://service or ENV_VAR=hv://service?alias=name")
    env_name, raw_ref = binding.split("=", 1)
    env_name = env_name.strip()
    if not env_name:
        raise ValueError("environment variable name cannot be empty")
    if not _ENV_NAME_RE.match(env_name):
        raise ValueError(f"invalid environment variable name: {env_name}")
    return env_name, parse_ref(raw_ref.strip())


def parse_ref(raw_ref: str) -> VaultSecretRef:
    parsed = urlparse(raw_ref)
    if parsed.scheme != "hv":
        raise ValueError("secret reference must use hv:// scheme")
    if parsed.params or parsed.fragment or parsed.username or parsed.password or parsed.port:
        raise ValueError("secret reference contains unsupported URI components")
    service = (parsed.netloc + parsed.path).strip("/")
    if not service:
        raise ValueError("secret reference must include a service name")
    query = parse_qs(parsed.query, keep_blank_values=True)
    unexpected = set(query) - {"alias"}
    if unexpected:
        raise ValueError(f"unsupported query key(s): {', '.join(sorted(unexpected))}")
    alias_values = query.get("alias") or []
    if len(alias_values) > 1:
        raise ValueError("alias may only be supplied once")
    alias = alias_values[0].strip() if alias_values else None
    if alias == "":
        raise ValueError("alias cannot be empty")
    return VaultSecretRef(raw=raw_ref, service=normalize(service), alias=alias)


def fetch_secret_source_bindings(
    *,
    vault: Vault,
    policy: PolicyEngine,
    agent_id: str,
    ttl: int,
    bindings: list[str],
) -> SecretSourceFetchReport:
    report = SecretSourceFetchReport()
    for binding in bindings:
        try:
            env_name, ref = parse_binding(binding)
        except ValueError as exc:
            _record_issue(report, binding, "REF_INVALID", str(exc), partial=False)
            continue
        issue = _resolve_one(
            vault=vault,
            policy=policy,
            agent_id=agent_id,
            ttl=ttl,
            env_name=env_name,
            ref=ref,
            report=report,
        )
        if issue is not None:
            _record_issue(report, env_name, issue.kind, issue.message, ref=issue.ref, partial=False)

    if report.secrets:
        report.warnings.update(report.errors)
        report.errors = {}
    return report


def _resolve_one(
    *,
    vault: Vault,
    policy: PolicyEngine,
    agent_id: str,
    ttl: int,
    env_name: str,
    ref: VaultSecretRef,
    report: SecretSourceFetchReport,
) -> SecretSourceIssue | None:
    allowed, reason = policy.can(agent_id, ref.service, ServiceAction.get_env)
    if not allowed:
        return SecretSourceIssue("AUTH_FAILED", reason, ref.raw)
    ttl_ok, ttl_reason, _effective_ttl = policy.enforce_ttl(agent_id, ttl, service=ref.service)
    if not ttl_ok:
        return SecretSourceIssue("AUTH_FAILED", ttl_reason, ref.raw)
    try:
        record = vault.resolve_credential(ref.service, alias=ref.alias)
    except (AmbiguousTargetError, KeyError) as exc:
        return SecretSourceIssue("REF_INVALID", str(exc), ref.raw)
    if policy.require_lease_for_env(agent_id, ref.service):
        lease = vault.find_active_lease(agent_id=agent_id, service=record.service, alias=record.alias)
        if lease is None:
            return SecretSourceIssue("AUTH_FAILED", "policy requires an active lease before env handoff", ref.raw)
    env_template = get_env_var_map(ref.service)
    if env_name not in env_template:
        return SecretSourceIssue(
            "REF_INVALID",
            f"requested env var {env_name} is not produced by service {ref.service}",
            ref.raw,
        )
    secret = vault.get_secret(record.id)
    if secret is None:
        return SecretSourceIssue("REF_INVALID", "credential secret was not found in vault", ref.raw)
    value = env_template[env_name].format(secret=secret.secret)
    if value == "":
        return SecretSourceIssue("EMPTY_VALUE", "requested env var resolved to an empty value", ref.raw)
    report.secrets[env_name] = value
    return None


def _record_issue(
    report: SecretSourceFetchReport,
    key: str,
    kind: str,
    message: str,
    *,
    ref: str | None = None,
    partial: bool,
) -> None:
    safe_kind = kind if kind in VALID_ERROR_KINDS else "INTERNAL"
    issue = SecretSourceIssue(safe_kind, message, ref)
    if partial:
        report.warnings[key] = issue
    else:
        report.errors[key] = issue
