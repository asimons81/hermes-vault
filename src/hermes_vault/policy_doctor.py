from __future__ import annotations

import copy
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from hermes_vault.models import FindingSeverity, PolicyConfig, ServiceAction
from hermes_vault.policy import PolicyEngine, _preprocess_policy
from hermes_vault.service_ids import CANONICAL_IDS, normalize


REPORT_VERSION = "policy-doctor-v1"
_OAUTH_PROVIDER_IDS = frozenset({"google", "github", "openai"})
_POLICY_HASH_RE = re.compile(r"<!--\s*hv-policy-hash:\s*([a-f0-9]{64})\s*-->")


class PolicyDoctorFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str
    severity: FindingSeverity
    detail: str
    agent_id: str | None = None
    service: str | None = None
    suggestion: str | None = None
    yaml_patch: str | None = None
    strict_violation: bool = False

    def as_dict(self, *, exclude_none: bool = True) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=exclude_none)


class PolicyDoctorReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = REPORT_VERSION
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    policy_path: str | None = None
    policy_hash: str | None = None
    strict_mode: bool = False
    strict_violation: bool = False
    findings: list[PolicyDoctorFinding] = Field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def strict_violation_count(self) -> int:
        return sum(1 for finding in self.findings if finding.strict_violation)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in FindingSeverity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def as_dict(self, *, exclude_none: bool = True) -> dict[str, Any]:
        payload = self.model_dump(mode="json", exclude_none=exclude_none)
        payload["finding_count"] = self.finding_count
        payload["strict_violation_count"] = self.strict_violation_count
        payload["severity_counts"] = self.severity_counts
        return payload


def run_policy_doctor(
    policy_path: Path,
    *,
    generated_skills_dir: Path | None = None,
    strict: bool = False,
) -> PolicyDoctorReport:
    """Inspect a policy file without mutating it."""
    report = PolicyDoctorReport(
        policy_path=str(policy_path),
        strict_mode=strict,
    )

    try:
        raw_text = policy_path.read_text(encoding="utf-8")
    except Exception as exc:
        finding = PolicyDoctorFinding(
            kind="policy_read_error",
            severity=FindingSeverity.critical,
            detail=f"failed to read policy file: {exc}",
            strict_violation=True,
        )
        report.findings.append(finding)
        report.strict_violation = strict and finding.strict_violation
        return report

    try:
        raw_data = yaml.safe_load(raw_text) or {}
    except Exception as exc:
        finding = PolicyDoctorFinding(
            kind="policy_parse_error",
            severity=FindingSeverity.critical,
            detail=f"failed to parse policy YAML: {exc}",
            strict_violation=True,
        )
        report.findings.append(finding)
        report.strict_violation = strict and finding.strict_violation
        return report

    if not isinstance(raw_data, dict):
        finding = PolicyDoctorFinding(
            kind="policy_shape_error",
            severity=FindingSeverity.critical,
            detail="policy root must be a mapping with agents/managed_paths fields",
            strict_violation=True,
        )
        report.findings.append(finding)
        report.strict_violation = strict and finding.strict_violation
        return report

    agent_data = raw_data.get("agents", {})
    if not isinstance(agent_data, dict):
        finding = PolicyDoctorFinding(
            kind="policy_shape_error",
            severity=FindingSeverity.critical,
            detail="policy agents section must be a mapping of agent IDs to policies",
            strict_violation=True,
        )
        report.findings.append(finding)
        report.strict_violation = strict and finding.strict_violation
        return report

    findings = _collect_findings(raw_data)
    report.findings.extend(findings)

    # Only compute the policy hash when the policy can be validated cleanly.
    if not any(f.kind in {"unknown_action", "unknown_capability"} for f in findings):
        try:
            policy_config = PolicyConfig.model_validate(_sanitize_policy_for_hash(raw_data))
            policy = PolicyEngine(policy_config)
            report.policy_hash = policy.compute_policy_hash()
        except Exception:
            report.policy_hash = None

    if generated_skills_dir is not None and report.policy_hash is not None:
        report.findings.extend(
            _collect_skill_drift(
                raw_data,
                generated_skills_dir=generated_skills_dir,
                policy_hash=report.policy_hash,
            )
        )

    report.strict_violation = strict and any(f.strict_violation for f in report.findings)
    return report


def _collect_findings(raw_data: dict[str, Any]) -> list[PolicyDoctorFinding]:
    findings: list[PolicyDoctorFinding] = []
    agents = raw_data.get("agents", {})
    if not isinstance(agents, dict):
        return findings

    for agent_id, agent_raw in agents.items():
        if not isinstance(agent_raw, dict):
            findings.append(
                PolicyDoctorFinding(
                    kind="agent_shape_error",
                    severity=FindingSeverity.critical,
                    agent_id=str(agent_id),
                    detail="agent policy must be a mapping",
                    strict_violation=True,
                )
            )
            continue

        findings.extend(_collect_agent_findings(str(agent_id), agent_raw))

    return findings


def _collect_agent_findings(agent_id: str, agent_raw: dict[str, Any]) -> list[PolicyDoctorFinding]:
    findings: list[PolicyDoctorFinding] = []

    raw_services = agent_raw.get("services")
    capabilities = agent_raw.get("capabilities")
    raw_secret_access = bool(agent_raw.get("raw_secret_access", False))
    service_actions: dict[str, dict[str, Any]] = {}

    if isinstance(raw_services, dict):
        service_actions = {
            str(service): entry
            for service, entry in raw_services.items()
        }
    elif isinstance(raw_services, list):
        for raw_service in raw_services:
            canonical = normalize(str(raw_service))
            if canonical in CANONICAL_IDS and canonical != str(raw_service).strip().lower():
                findings.append(
                    PolicyDoctorFinding(
                        kind="legacy_service_name",
                        severity=FindingSeverity.medium,
                        agent_id=agent_id,
                        service=str(raw_service),
                        detail=(
                            f"service '{raw_service}' normalizes to canonical service '{canonical}'"
                        ),
                        suggestion=f"Use '{canonical}' in policy instead of '{raw_service}'.",
                        yaml_patch=_legacy_service_patch(agent_id, canonical),
                    )
                )
    elif raw_services is not None:
        findings.append(
            PolicyDoctorFinding(
                kind="service_shape_error",
                severity=FindingSeverity.critical,
                agent_id=agent_id,
                detail="services must be either a list or a mapping",
                strict_violation=True,
            )
        )

    if capabilities is None or capabilities == []:
        findings.append(
            PolicyDoctorFinding(
                kind="legacy_implicit_capabilities",
                severity=FindingSeverity.high,
                agent_id=agent_id,
                detail=(
                    "agent omits capabilities and therefore inherits implicit all-capabilities grants"
                ),
                suggestion=(
                    "Add an explicit capabilities list to restrict non-service-scoped actions."
                ),
                yaml_patch=_legacy_capabilities_patch(agent_id),
                strict_violation=True,
            )
        )
    elif not isinstance(capabilities, list):
        findings.append(
            PolicyDoctorFinding(
                kind="capability_shape_error",
                severity=FindingSeverity.critical,
                agent_id=agent_id,
                detail="capabilities must be a list of capability names",
                strict_violation=True,
            )
        )
    else:
        known_capabilities = {c.value for c in _KNOWN_AGENT_CAPABILITIES()}
        for capability in capabilities:
            if isinstance(capability, str) and capability not in known_capabilities:
                findings.append(
                    PolicyDoctorFinding(
                        kind="unknown_capability",
                        severity=FindingSeverity.high,
                        agent_id=agent_id,
                        detail=f"unknown capability '{capability}'",
                        suggestion="Replace it with a supported capability or remove the entry.",
                        yaml_patch=_unknown_capability_patch(agent_id, capability),
                        strict_violation=True,
                    )
                )

    if raw_secret_access:
        findings.append(
            PolicyDoctorFinding(
                kind="raw_secret_access_enabled",
                severity=FindingSeverity.high,
                agent_id=agent_id,
                detail="raw_secret_access is enabled",
                suggestion="Set raw_secret_access to false and prefer ephemeral_env_only.",
                yaml_patch=_raw_secret_access_patch(agent_id),
                strict_violation=True,
            )
        )

    if isinstance(raw_services, dict):
        for service_name, entry in service_actions.items():
            findings.extend(_collect_service_findings(agent_id, service_name, entry))

    # Check for provider-specific OAuth permission gaps only when an agent
    # appears OAuth-capable. We intentionally do not treat arbitrary custom
    # services as errors.
    for service_name, entry in service_actions.items():
        canonical_service = normalize(service_name)
        if canonical_service not in _OAUTH_PROVIDER_IDS:
            continue
        actions_raw = entry.get("actions", [])
        if not isinstance(actions_raw, list):
            continue
        actions = {str(action) for action in actions_raw if isinstance(action, str)}
        if "add_credential" not in actions:
            findings.append(
                PolicyDoctorFinding(
                    kind="oauth_login_permission_gap",
                    severity=FindingSeverity.high,
                    agent_id=agent_id,
                    service=canonical_service,
                    detail=(
                        f"OAuth-capable agent lacks add_credential permission for '{canonical_service}'"
                    ),
                    suggestion=(
                        "Add add_credential to the service actions if this agent should perform OAuth login."
                    ),
                    yaml_patch=_oauth_login_patch(agent_id, canonical_service),
                    strict_violation=True,
                )
            )
        if "rotate" not in actions:
            findings.append(
                PolicyDoctorFinding(
                    kind="oauth_refresh_permission_gap",
                    severity=FindingSeverity.high,
                    agent_id=agent_id,
                    service=canonical_service,
                    detail=(
                        f"OAuth-capable agent lacks rotate permission for '{canonical_service}' refresh"
                    ),
                    suggestion=(
                        "Add rotate to the service actions if this agent should refresh OAuth tokens."
                    ),
                    yaml_patch=_oauth_refresh_patch(agent_id, canonical_service),
                    strict_violation=True,
                )
            )

    return findings


def _collect_service_findings(
    agent_id: str,
    service_name: str,
    entry: dict[str, Any],
) -> list[PolicyDoctorFinding]:
    findings: list[PolicyDoctorFinding] = []
    normalized = normalize(service_name)

    if normalized in CANONICAL_IDS and normalized != service_name.strip().lower():
        findings.append(
            PolicyDoctorFinding(
                kind="legacy_service_name",
                severity=FindingSeverity.medium,
                agent_id=agent_id,
                service=service_name,
                detail=f"service '{service_name}' normalizes to canonical service '{normalized}'",
                suggestion=f"Use '{normalized}' in policy instead of '{service_name}'.",
                yaml_patch=_legacy_service_patch(agent_id, normalized),
            )
        )

    actions_raw = entry.get("actions", [])
    if isinstance(actions_raw, list):
        known_actions = {action.value for action in ServiceAction}
        invalid_actions = [str(action) for action in actions_raw if str(action) not in known_actions]
        if invalid_actions:
            invalid_str = ", ".join(sorted(invalid_actions))
            findings.append(
                PolicyDoctorFinding(
                    kind="unknown_action",
                    severity=FindingSeverity.high,
                    agent_id=agent_id,
                    service=normalized,
                    detail=f"unknown action(s) for '{service_name}': {invalid_str}",
                    suggestion="Remove invalid actions or replace them with supported service actions.",
                    yaml_patch=_unknown_action_patch(agent_id, service_name, invalid_actions),
                    strict_violation=True,
                )
            )
    else:
        findings.append(
            PolicyDoctorFinding(
                kind="service_shape_error",
                severity=FindingSeverity.critical,
                agent_id=agent_id,
                service=normalized,
                detail=f"service entry for '{service_name}' must be a mapping",
                strict_violation=True,
            )
        )

    return findings


def _collect_skill_drift(
    raw_data: dict[str, Any],
    *,
    generated_skills_dir: Path,
    policy_hash: str,
) -> list[PolicyDoctorFinding]:
    findings: list[PolicyDoctorFinding] = []
    agents = raw_data.get("agents", {})
    if not isinstance(agents, dict):
        return findings

    for agent_id in agents.keys():
        skill_path = generated_skills_dir / str(agent_id) / "SKILL.md"
        if not skill_path.exists():
            continue
        try:
            content = skill_path.read_text(encoding="utf-8")
        except Exception as exc:
            findings.append(
                PolicyDoctorFinding(
                    kind="skill_read_error",
                    severity=FindingSeverity.medium,
                    agent_id=str(agent_id),
                    detail=f"failed to read generated skill: {exc}",
                    suggestion="Check the generated skills directory permissions and file integrity.",
                )
            )
            continue

        match = _POLICY_HASH_RE.search(content)
        if match is None:
            findings.append(
                PolicyDoctorFinding(
                    kind="stale_generated_skill",
                    severity=FindingSeverity.medium,
                    agent_id=str(agent_id),
                    detail="generated skill is missing a policy hash marker",
                    suggestion="Regenerate the skill so it embeds the current policy hash.",
                    yaml_patch=_skill_patch(str(agent_id)),
                )
            )
            continue

        skill_hash = match.group(1)
        if skill_hash != policy_hash:
            findings.append(
                PolicyDoctorFinding(
                    kind="stale_generated_skill",
                    severity=FindingSeverity.medium,
                    agent_id=str(agent_id),
                    detail=(
                        f"generated skill hash {skill_hash[:12]}... does not match policy hash {policy_hash[:12]}..."
                    ),
                    suggestion="Regenerate the skill from the current policy.",
                    yaml_patch=_skill_patch(str(agent_id)),
                )
            )

    return findings


def _sanitize_policy_for_hash(raw_data: dict[str, Any]) -> dict[str, Any]:
    """Return a deep-copied raw policy suitable for PolicyEngine validation."""
    return _preprocess_policy(copy.deepcopy(raw_data))


def _legacy_service_patch(agent_id: str, canonical_service: str) -> str:
    return (
        "agents:\n"
        f"  {agent_id}:\n"
        "    services:\n"
        f"      {canonical_service}:\n"
        "        actions: [get_credential, get_env, verify, metadata]\n"
        "        # narrow this list to the minimum required actions\n"
    )


def _legacy_capabilities_patch(agent_id: str) -> str:
    return (
        "agents:\n"
        f"  {agent_id}:\n"
        "    capabilities:\n"
        "      - list_credentials\n"
        "      - scan_secrets\n"
        "      # remove capabilities you do not want this agent to have\n"
    )


def _unknown_action_patch(agent_id: str, service: str, invalid_actions: list[str]) -> str:
    invalid = ", ".join(invalid_actions)
    return (
        "agents:\n"
        f"  {agent_id}:\n"
        "    services:\n"
        f"      {service}:\n"
        "        actions:\n"
        f"          # remove unsupported actions: {invalid}\n"
        "          - get_env\n"
        "          - verify\n"
    )


def _unknown_capability_patch(agent_id: str, capability: str) -> str:
    return (
        "agents:\n"
        f"  {agent_id}:\n"
        "    capabilities:\n"
        f"      # remove unsupported capability: {capability}\n"
        "      - list_credentials\n"
    )


def _raw_secret_access_patch(agent_id: str) -> str:
    return (
        "agents:\n"
        f"  {agent_id}:\n"
        "    raw_secret_access: false\n"
        "    ephemeral_env_only: true\n"
    )


def _oauth_login_patch(agent_id: str, service: str) -> str:
    return (
        "agents:\n"
        f"  {agent_id}:\n"
        "    services:\n"
        f"      {service}:\n"
        "        actions: [add_credential, get_env, verify, metadata]\n"
    )


def _oauth_refresh_patch(agent_id: str, service: str) -> str:
    return (
        "agents:\n"
        f"  {agent_id}:\n"
        "    services:\n"
        f"      {service}:\n"
        "        actions: [rotate, get_env, verify, metadata]\n"
    )


def _skill_patch(agent_id: str) -> str:
    return (
        "skills:\n"
        f"  {agent_id}:\n"
        "    # regenerate the skill so the embedded policy hash matches the policy file\n"
    )


def _KNOWN_AGENT_CAPABILITIES() -> set[Any]:
    # Imported lazily so this module stays focused on diagnostics behavior.
    from hermes_vault.models import ALL_AGENT_CAPABILITIES

    return set(ALL_AGENT_CAPABILITIES)
