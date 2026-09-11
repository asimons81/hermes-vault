"""P8 — ``hermes-vault run``: child-process env injection.

The exact contract CrewAI/LangChain/MCP ``env:`` blocks speak: materialize
vault-backed environment variables for ONE child process, for its lifetime
only. Secrets never appear in argv, never in logs, never in the audit record
(audit rows carry variable NAMES, not values).

Resolution follows the same broker path as ``broker env`` —
``Broker.get_ephemeral_env()`` verbatim — so v0.26.0's authorization
enforcement (lease ownership, expiry at handoff, TTL ceilings) and the
deny-by-default policy model apply unchanged. Operator authority bypass is a
NON-goal: an operator running ``hermes-vault run`` is bound by the same
policy as any agent id they pass.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass, field

from hermes_vault.logging_redaction import redact_text
from hermes_vault.models import AccessLogRecord, Decision, ServiceAction
from hermes_vault.service_ids import normalize

#: Audit action for the run-level record (per-service resolution already
#: writes its own ``get_ephemeral_env`` rows through the broker).
RUN_AUDIT_ACTION = "run_env_inject"

#: Key material is never handed to the child. The passphrase variables are
#: vault-wide master-key material — passing them through would grant the
#: child unrestricted operator access to the whole vault, which is strictly
#: more than the policy-scoped credentials being injected.
_PASSPHRASE_ENV_PATTERN = re.compile(r"^HERMES_VAULT_PASSPHRASE(_[A-Z0-9_]+)?$")

# Exit codes (documented in the CLI help; shell conventions).
EXIT_OK = 0
EXIT_DENIED = 1  # broker denial / no services resolved / env collision
EXIT_USAGE = 2  # structural usage errors (no command, --alias without one service)
EXIT_NOT_EXECUTABLE = 126
EXIT_NOT_FOUND = 127


@dataclass
class RunResolution:
    """Everything needed to spawn the child; never holds secret values."""

    agent_id: str
    services: list[str] = field(default_factory=list)
    env_var_names: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


class RunUsageError(Exception):
    """Structural usage error (exit 2). Message is operator-safe."""


class RunDeniedError(Exception):
    """Broker denial or fail-closed abort (exit 1).

    Carries the per-service denial reasons; reasons come from the broker,
    which never embeds secret values in denial text.
    """

    def __init__(self, message: str, denials: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.denials: dict[str, str] = denials or {}


def _strip_vault_key_material(env: dict[str, str]) -> dict[str, str]:
    """Drop passphrase variables (global and per-profile) from a child env."""
    return {k: v for k, v in env.items() if not _PASSPHRASE_ENV_PATTERN.match(k)}


def resolve_services(
    broker,
    agent_id: str,
    requested: list[str] | None,
) -> list[str]:
    """Expand the service set for a run.

    Explicit requests are normalized and de-duplicated (preserving order).
    When nothing is requested, auto-expand to every service the agent may
    ``get_env`` on that actually has a credential in the vault — deny-by-
    default: policy-invisible services never resolve.
    """
    if requested:
        seen: set[str] = set()
        ordered: list[str] = []
        for raw in requested:
            canonical = normalize(raw)
            if canonical not in seen:
                seen.add(canonical)
                ordered.append(canonical)
        return ordered

    agent_policy = broker.policy.get_agent_policy(agent_id)
    if agent_policy is None:
        # The broker call below will emit the canonical undefined-agent denial.
        return []
    in_vault = {record.service for record in broker.vault.list_credentials()}
    resolved: list[str] = []
    for raw in sorted(agent_policy.services):
        canonical = normalize(raw)
        if canonical not in in_vault:
            continue
        allowed, _ = broker.policy.can(agent_id, canonical, ServiceAction.get_env)
        if allowed and canonical not in resolved:
            resolved.append(canonical)
    return resolved


def materialize_run_env(
    broker,
    agent_id: str,
    services: list[str],
    alias: str | None,
    ttl: int,
) -> RunResolution:
    """Resolve every service through ``get_ephemeral_env`` and merge the env maps.

    All-or-nothing: the FIRST denial aborts before anything is handed off,
    and a target-variable collision between services (different values for
    the same variable) fails closed rather than silently overwriting.
    """
    resolution = RunResolution(agent_id=agent_id, services=list(services))
    for service in services:
        decision = broker.get_ephemeral_env(service=service, agent_id=agent_id, ttl=ttl, alias=alias)
        if not decision.allowed:
            raise RunDeniedError(
                f"service '{service}' denied for agent '{agent_id}': {decision.reason}",
                denials={service: decision.reason},
            )
        for var, value in decision.env.items():
            if var in resolution.env and resolution.env[var] != value:
                raise RunDeniedError(
                    f"environment variable collision on '{var}' between injected services "
                    f"({', '.join(services)}); refusing to silently overwrite — request "
                    "the services separately",
                )
            resolution.env[var] = value
        for var in decision.env:
            if var not in resolution.env_var_names:
                resolution.env_var_names.append(var)
        for warning in decision.metadata.get("warnings", []):
            text = warning.get("message") if isinstance(warning, dict) else str(warning)
            if text:
                resolution.warnings.append(f"{service}: {text}")
    return resolution


def _audit_run(
    broker,
    resolution: RunResolution,
    command: list[str],
    allowed: bool,
    reason: str,
    ttl: int,
    denials: dict[str, str] | None = None,
) -> None:
    """Write the run-level audit row. Values are redacted defensively; the
    row records service and variable NAMES plus the child command name only."""
    metadata: dict[str, object] = {
        "services": list(resolution.services),
        "env_var_names": list(resolution.env_var_names),
        "command": command[0] if command else "",
        "argv_count": len(command),
        "ttl_seconds": ttl,
    }
    if denials:
        metadata["denials"] = {svc: redact_text(reason_text) for svc, reason_text in denials.items()}
    try:
        broker.audit.record(
            AccessLogRecord(
                agent_id=resolution.agent_id,
                service="*",
                action=RUN_AUDIT_ACTION,
                decision=Decision.allow if allowed else Decision.deny,
                reason=redact_text(reason),
                metadata=metadata,
            )
        )
    except Exception:
        # Audit failure must not crash a run that already handed off env, and
        # must not turn a denial into a success. Best-effort, fail open here:
        # the broker's own get_ephemeral_env rows are the primary record.
        pass


def spawn_child(command: list[str], env: dict[str, str]) -> int:
    """Run the child with the injected env; return the process exit code.

    Shell exit conventions: 128+N when the child is killed by signal N,
    127 when the command is not found, 126 when it is not executable.
    """
    try:
        completed = subprocess.run(command, env=env, check=False)
    except FileNotFoundError:
        return EXIT_NOT_FOUND
    except PermissionError:
        return EXIT_NOT_EXECUTABLE
    except KeyboardInterrupt:
        # SIGINT hit the foreground group: the child is already gone
        # (subprocess.run reaps it); report the conventional 130.
        return 130
    if completed.returncode < 0:
        return 128 + (-completed.returncode)
    return completed.returncode


def execute_run(
    broker,
    command: list[str],
    agent_id: str,
    requested_services: list[str] | None,
    alias: str | None,
    ttl: int,
    verbose: bool = False,
) -> int:
    """Entry point behind ``hermes-vault run``.

    Returns the child's exit code, or 1/2 on denial/usage errors (raised as
    ``RunDeniedError`` / ``RunUsageError`` for the CLI wrapper to report).
    """
    if not command:
        raise RunUsageError("no command given — pass it after '--', e.g. hermes-vault run -- printenv OPENAI_API_KEY")
    if alias is not None and (requested_services is None or len(requested_services) != 1):
        raise RunUsageError("--alias requires exactly one --service")
    if not agent_id:
        raise RunUsageError(
            "no agent id: pass --agent or set HERMES_VAULT_MCP_DEFAULT_AGENT"
        )

    services = resolve_services(broker, agent_id, requested_services)
    if not services:
        # Auto-mode only: policy grants get_env on no service that has a
        # stored credential. Explicit requests always resolve to a non-empty
        # list here (normalized, never deduplicated away), so their denials
        # surface inside materialize_run_env with the canonical reason.
        raise RunDeniedError(
            f"no authorized services with credentials in the vault for agent '{agent_id}' "
            "(policy grants get_env on no service that has a stored credential)"
        )

    resolution = materialize_run_env(broker, agent_id, services, alias, ttl)

    _audit_run(
        broker,
        resolution,
        command,
        allowed=True,
        reason=(
            f"injected {len(resolution.env_var_names)} env var(s) from "
            f"{len(resolution.services)} service(s) into child process"
        ),
        ttl=ttl,
    )
    if verbose or resolution.warnings:
        print(
            f"hermes-vault run: agent '{agent_id}' services [{', '.join(resolution.services)}] "
            f"vars [{', '.join(resolution.env_var_names)}]",
            file=sys.stderr,
        )
        for warning in resolution.warnings:
            print(f"warning: {warning}", file=sys.stderr)

    child_env = _strip_vault_key_material(dict(os.environ))
    child_env.update(resolution.env)
    return spawn_child(command, child_env)


def execute_run_and_report(
    broker,
    command: list[str],
    agent_id: str,
    requested_services: list[str] | None,
    alias: str | None,
    ttl: int,
    verbose: bool = False,
) -> int:
    """``execute_run`` with denial/usage reporting and run-level audit rows."""
    resolution = RunResolution(agent_id=agent_id)
    try:
        return execute_run(
            broker,
            command,
            agent_id,
            requested_services,
            alias,
            ttl,
            verbose,
        )
    except RunDeniedError as exc:
        resolution.services = list(requested_services or [])
        _audit_run(
            broker,
            resolution,
            command,
            allowed=False,
            reason=str(exc),
            ttl=ttl,
            denials=exc.denials,
        )
        print(f"hermes-vault run: {exc}", file=sys.stderr)
        return EXIT_DENIED
    except RunUsageError as exc:
        print(f"hermes-vault run: {exc}", file=sys.stderr)
        return EXIT_USAGE
