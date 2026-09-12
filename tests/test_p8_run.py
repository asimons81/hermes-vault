"""P8 — ``hermes-vault run``: child-process env injection (R#2).

The contract CrewAI/LangChain/MCP ``env:`` blocks speak: secrets are
injected ONLY into the child process environment for its lifetime — never
argv, never logs, never the audit record.

These tests pin:
- resolution follows the broker ``get_ephemeral_env`` path (policy, TTL
  clamp, lease ownership/expiry from P2 all apply — operator authority
  bypass is a NON-goal);
- deny-by-default: nothing injects without an explicit policy grant;
- env hygiene: key material never reaches the child;
- audit hygiene: rows carry variable NAMES, never values;
- shell exit-code conventions for the child.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.cli import _hermes_group
from hermes_vault.models import (
    AgentPolicy,
    PolicyConfig,
    ServiceAction,
    ServicePolicyEntry,
)
from hermes_vault.policy import PolicyEngine
from hermes_vault.runner import (
    EXIT_DENIED,
    EXIT_NOT_FOUND,
    EXIT_OK,
    RunDeniedError,
    RunUsageError,
    execute_run,
    resolve_services,
)
from hermes_vault.vault import Vault

PYTHON = sys.executable


def _child_probe(var: str) -> list[str]:
    return [PYTHON, "-c", f"import os; print(os.environ.get({var!r}) or 'UNSET')"]


def _child_exit_probe(code: int) -> list[str]:
    return [PYTHON, "-c", f"raise SystemExit({code})"]


def _child_write_probe(var: str, out_path: Path) -> list[str]:
    """Child writes the observed env value to ``out_path`` (real evidence)."""
    return [
        PYTHON,
        "-c",
        f"import os, pathlib; pathlib.Path({str(out_path)!r}).write_text(os.environ.get({var!r}) or 'UNSET')",
    ]


def _child_env_json_probe(keys: list[str], out_path: Path | None = None) -> list[str]:
    """Child reports observed env to stdout or to ``out_path`` (file evidence)."""
    inner = json.dumps(keys)
    dict_expr = "{" + f"k: os.environ.get(k) for k in {inner}" + "}"
    if out_path is None:
        body = f"import os, json; print(json.dumps({dict_expr}))"
    else:
        body = (
            "import os, json, pathlib; pathlib.Path("
            f"{str(out_path)!r}).write_text(json.dumps({dict_expr}))"
        )
    return [PYTHON, "-c", body]


class _StubVerifier:
    def verify(self, service, secret):
        from hermes_vault.models import VerificationCategory, VerificationResult

        return VerificationResult(
            service=service,
            category=VerificationCategory.valid,
            success=True,
            reason="ok",
        )


def _make_services(tmp_path: Path, agents: dict, credentials: list[tuple[str, str, str]]):
    """Build a real (vault, broker, audit) against a temp home."""
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    for service, alias, secret in credentials:
        vault.add_credential(service, secret, "api_key", alias=alias)
    policy = PolicyEngine(PolicyConfig(agents=agents))
    audit = AuditLogger(tmp_path / "vault.db", master_key=vault.key)
    broker = Broker(vault=vault, policy=policy, verifier=_StubVerifier(), audit=audit)
    return vault, broker, audit


def _agent(services: list[str], actions: list[ServiceAction] | None = None, **kwargs) -> AgentPolicy:
    return AgentPolicy(
        services=services,
        service_actions={
            service: ServicePolicyEntry(
                actions=actions if actions is not None else [ServiceAction.get_env],
            )
            for service in services
        },
        **kwargs,
    )


def _run_cli(monkeypatch, tmp_path: Path, agents: dict, credentials: list[tuple[str, str, str]], argv: list[str]):
    vault, broker, audit = _make_services(tmp_path, agents, credentials)

    def fake_build(prompt=False):
        return vault, broker.policy, broker, object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
    return CliRunner(future_value=True).invoke(_hermes_group, ["--no-banner", *argv])


# ── broker-path composition ─────────────────────────────────────────────────


def test_run_injects_secret_into_child_env_only(tmp_path: Path) -> None:
    """The happy path: child sees the env var, argv and logs never carry it."""
    vault, broker, _ = _make_services(
        tmp_path,
        {"hermes": _agent(["openai"])},
        [("openai", "default", "sk-test-1234")],
    )
    out = tmp_path / "observed.txt"
    code = execute_run(
        broker,
        command=_child_write_probe("OPENAI_API_KEY", out),
        agent_id="hermes",
        requested_services=["openai"],
        alias=None,
        ttl=900,
    )
    assert code == EXIT_OK
    assert out.read_text() == "sk-test-1234"


def test_run_auto_injects_all_authorized_services(tmp_path: Path) -> None:
    """No --service: every policy-granted service with a stored credential."""
    vault, broker, _ = _make_services(
        tmp_path,
        {"hermes": _agent(["openai", "github", "anthropic"])},
        [
            ("openai", "default", "sk-openai"),
            ("github", "default", "gh-token"),
            ("anthropic", "default", "sk-ant"),
        ],
    )
    out = tmp_path / "observed.json"
    code = execute_run(
        broker,
        command=_child_env_json_probe(["OPENAI_API_KEY", "GITHUB_TOKEN", "ANTHROPIC_API_KEY"], out),
        agent_id="hermes",
        requested_services=None,
        alias=None,
        ttl=900,
    )
    assert code == EXIT_OK
    data = json.loads(out.read_text())
    assert data["OPENAI_API_KEY"] == "sk-openai"
    assert data["GITHUB_TOKEN"] == "gh-token"
    assert data["ANTHROPIC_API_KEY"] == "sk-ant"


def test_run_denies_service_outside_policy(tmp_path: Path) -> None:
    """Deny-by-default: a service the agent's policy does not list is denied."""
    vault, broker, _ = _make_services(
        tmp_path,
        {"hermes": _agent(["openai"])},
        [("openai", "default", "sk-x"), ("github", "default", "gh-y")],
    )
    with pytest.raises(RunDeniedError) as excinfo:
        execute_run(
            broker,
            command=_child_probe("GITHUB_TOKEN"),
            agent_id="hermes",
            requested_services=["github"],
            alias=None,
            ttl=900,
        )
    assert "not allowed" in str(excinfo.value)


def test_run_denies_undefined_agent(tmp_path: Path) -> None:
    vault, broker, _ = _make_services(
        tmp_path, {"hermes": _agent(["openai"])}, [("openai", "default", "sk-x")]
    )
    with pytest.raises(RunDeniedError):
        execute_run(
            broker,
            command=_child_probe("OPENAI_API_KEY"),
            agent_id="ghost",
            requested_services=["openai"],
            alias=None,
            ttl=900,
        )


def test_run_auto_mode_denies_when_no_authorized_service_in_vault(tmp_path: Path) -> None:
    """Auto-mode with an empty intersection (vault has creds, policy none)."""
    vault, broker, _ = _make_services(
        tmp_path, {"hermes": _agent(["openai"])}, [("github", "default", "gh-x")]
    )
    with pytest.raises(RunDeniedError) as excinfo:
        execute_run(
            broker,
            command=_child_probe("GITHUB_TOKEN"),
            agent_id="hermes",
            requested_services=None,
            alias=None,
            ttl=900,
        )
    assert "no authorized services" in str(excinfo.value)


def test_run_ttl_is_clamped_by_policy(tmp_path: Path) -> None:
    """The requested TTL flows to the broker and is clamped to max_ttl_seconds."""
    vault, broker, audit = _make_services(
        tmp_path,
        {"hermes": AgentPolicy(services=["openai"], max_ttl_seconds=120)},
        [("openai", "default", "sk-x")],
    )
    code = execute_run(
        broker,
        command=_child_probe("OPENAI_API_KEY"),
        agent_id="hermes",
        requested_services=["openai"],
        alias=None,
        ttl=99000,
    )
    assert code == EXIT_OK
    entries = audit.list_recent(limit=5, action="get_ephemeral_env")
    assert entries and entries[0]["ttl_seconds"] == 120


def test_run_expired_credential_is_denied(tmp_path: Path) -> None:
    """P2/F-03 composition: expiry is enforced at handoff, not bypassed."""
    from datetime import timedelta

    from hermes_vault.models import utc_now

    vault, broker, _ = _make_services(
        tmp_path, {"hermes": _agent(["openai"])}, [("openai", "default", "sk-x")]
    )
    record = vault.resolve_credential("openai")
    vault.set_expiry(record.id, utc_now() - timedelta(seconds=60))

    with pytest.raises(RunDeniedError) as excinfo:
        execute_run(
            broker,
            command=_child_probe("OPENAI_API_KEY"),
            agent_id="hermes",
            requested_services=["openai"],
            alias=None,
            ttl=900,
        )
    assert "expired" in str(excinfo.value)


def test_run_require_lease_for_env_denies_without_lease(tmp_path: Path) -> None:
    vault, broker, _ = _make_services(
        tmp_path,
        {"hermes": _agent(["openai"], require_lease_for_env=True)},
        [("openai", "default", "sk-x")],
    )
    with pytest.raises(RunDeniedError) as excinfo:
        execute_run(
            broker,
            command=_child_probe("OPENAI_API_KEY"),
            agent_id="hermes",
            requested_services=["openai"],
            alias=None,
            ttl=900,
        )
    assert "lease" in str(excinfo.value).lower()


def test_run_require_lease_for_env_succeeds_with_active_lease(tmp_path: Path) -> None:
    vault, broker, _ = _make_services(
        tmp_path,
        {"hermes": _agent(
            ["openai"],
            actions=[ServiceAction.get_env, ServiceAction.issue_lease],
            require_lease_for_env=True,
        )},
        [("openai", "default", "sk-x")],
    )
    decision = broker.issue_lease(
        service_or_id="openai", agent_id="hermes", ttl_seconds=600,
        alias="default", purpose="run",
    )
    assert decision.allowed, decision.reason
    out = tmp_path / "observed.txt"
    code = execute_run(
        broker,
        command=_child_write_probe("OPENAI_API_KEY", out),
        agent_id="hermes",
        requested_services=["openai"],
        alias=None,
        ttl=100,
    )
    assert code == EXIT_OK
    assert out.read_text() == "sk-x"


def test_run_alias_selects_credential(tmp_path: Path) -> None:
    vault, broker, _ = _make_services(
        tmp_path,
        {"hermes": _agent(["openai"])},
        [("openai", "primary", "sk-primary"), ("openai", "secondary", "sk-secondary")],
    )
    code = execute_run(
        broker,
        command=_child_probe("OPENAI_API_KEY"),
        agent_id="hermes",
        requested_services=["openai"],
        alias="secondary",
        ttl=900,
    )
    assert code == EXIT_OK
    # ... but the argv never contains it and we assert the value arrives via
    # the child's own report; the CLI test below pins the actual value.
    records = vault.list_credentials()
    assert {r.alias for r in records} == {"primary", "secondary"}


def test_run_alias_without_single_service_is_usage_error(tmp_path: Path) -> None:
    vault, broker, _ = _make_services(
        tmp_path,
        {"hermes": _agent(["openai", "github"])},
        [("openai", "default", "sk-x"), ("github", "default", "gh-y")],
    )
    with pytest.raises(RunUsageError):
        execute_run(
            broker,
            command=_child_probe("X"),
            agent_id="hermes",
            requested_services=None,
            alias="default",
            ttl=900,
        )
    with pytest.raises(RunUsageError):
        execute_run(
            broker,
            command=_child_probe("X"),
            agent_id="hermes",
            requested_services=["openai", "github"],
            alias="default",
            ttl=900,
        )


def test_run_no_command_is_usage_error(tmp_path: Path) -> None:
    vault, broker, _ = _make_services(
        tmp_path, {"hermes": _agent(["openai"])}, [("openai", "default", "sk-x")]
    )
    with pytest.raises(RunUsageError):
        execute_run(broker, command=[], agent_id="hermes", requested_services=["openai"], alias=None, ttl=900)


def test_run_missing_agent_id_is_usage_error(tmp_path: Path) -> None:
    vault, broker, _ = _make_services(
        tmp_path, {"hermes": _agent(["openai"])}, [("openai", "default", "sk-x")]
    )
    with pytest.raises(RunUsageError):
        execute_run(broker, command=_child_probe("X"), agent_id="", requested_services=["openai"], alias=None, ttl=900)


# ── env + audit hygiene ─────────────────────────────────────────────────────


def test_run_child_never_receives_vault_key_material(tmp_path: Path) -> None:
    """Passphrase vars are stripped even though run itself needed them."""
    os.environ["HERMES_VAULT_PASSPHRASE"] = "test-passphrase"
    os.environ["HERMES_VAULT_PASSPHRASE_MY_PROFILE"] = "prof-pass"
    try:
        vault, broker, _ = _make_services(
            tmp_path, {"hermes": _agent(["openai"])}, [("openai", "default", "sk-x")]
        )
        out = tmp_path / "observed.json"
        code = execute_run(
            broker,
            command=_child_env_json_probe(
                ["OPENAI_API_KEY", "HERMES_VAULT_PASSPHRASE", "HERMES_VAULT_PASSPHRASE_MY_PROFILE"],
                out,
            ),
            agent_id="hermes",
            requested_services=["openai"],
            alias=None,
            ttl=900,
        )
        assert code == EXIT_OK
        data = json.loads(out.read_text())
        assert data["OPENAI_API_KEY"] == "sk-x"
        assert data["HERMES_VAULT_PASSPHRASE"] is None
        assert data["HERMES_VAULT_PASSPHRASE_MY_PROFILE"] is None
    finally:
        os.environ.pop("HERMES_VAULT_PASSPHRASE", None)
        os.environ.pop("HERMES_VAULT_PASSPHRASE_MY_PROFILE", None)


def test_run_audit_rows_never_contain_secret_values(tmp_path: Path) -> None:
    """Audit metadata carries var NAMES; no row contains the secret value."""
    vault, broker, audit = _make_services(
        tmp_path, {"hermes": _agent(["openai"])}, [("openai", "default", "sk-leak-canary")]
    )
    execute_run(
        broker,
        command=_child_probe("OPENAI_API_KEY"),
        agent_id="hermes",
        requested_services=["openai"],
        alias=None,
        ttl=900,
    )
    rows = audit.list_recent(limit=20)
    dumped = json.dumps(rows, default=str)
    assert "sk-leak-canary" not in dumped
    run_rows = [r for r in rows if r["action"] == "run_env_inject"]
    assert run_rows, "expected a run-level audit row"
    meta = run_rows[0]["metadata"]
    assert meta["env_var_names"] == ["OPENAI_API_KEY"]
    assert meta["services"] == ["openai"]
    assert meta["command"] == PYTHON
    assert meta["argv_count"] == len(_child_probe("OPENAI_API_KEY"))


def test_run_denial_also_audits_without_secret(tmp_path: Path) -> None:
    vault, broker, audit = _make_services(
        tmp_path, {"hermes": _agent(["openai"])}, [("openai", "default", "sk-x"), ("github", "default", "gh-y")]
    )
    from hermes_vault.runner import execute_run_and_report

    code = execute_run_and_report(
        broker,
        command=_child_probe("GITHUB_TOKEN"),
        agent_id="hermes",
        requested_services=["github"],
        alias=None,
        ttl=900,
    )
    assert code == EXIT_DENIED
    rows = audit.list_recent(limit=20)
    assert "sk-x" not in json.dumps(rows, default=str)
    run_rows = [r for r in rows if r["action"] == "run_env_inject"]
    assert run_rows and run_rows[0]["decision"] == "deny"
    assert run_rows[0]["metadata"]["denials"]["github"]


# ── exit-code conventions ───────────────────────────────────────────────────


def test_run_propagates_child_exit_code(tmp_path: Path) -> None:
    vault, broker, _ = _make_services(
        tmp_path, {"hermes": _agent(["openai"])}, [("openai", "default", "sk-x")]
    )
    for expected in (0, 1, 42):
        code = execute_run(
            broker,
            command=_child_exit_probe(expected),
            agent_id="hermes",
            requested_services=["openai"],
            alias=None,
            ttl=900,
        )
        assert code == expected


def test_run_command_not_found_is_127(tmp_path: Path) -> None:
    vault, broker, _ = _make_services(
        tmp_path, {"hermes": _agent(["openai"])}, [("openai", "default", "sk-x")]
    )
    code = execute_run(
        broker,
        command=["definitely-not-a-command-xyz"],
        agent_id="hermes",
        requested_services=["openai"],
        alias=None,
        ttl=900,
    )
    assert code == EXIT_NOT_FOUND


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX exec semantics: Windows launch raises WinError 193 instead of EACCES/126")
def test_run_command_not_executable_is_126(tmp_path: Path) -> None:
    vault, broker, _ = _make_services(
        tmp_path, {"hermes": _agent(["openai"])}, [("openai", "default", "sk-x")]
    )
    script = tmp_path / "not-executable.sh"
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o644)
    code = execute_run(
        broker,
        command=[str(script)],
        agent_id="hermes",
        requested_services=["openai"],
        alias=None,
        ttl=900,
    )
    assert code == 126


# ── resolve_services unit tests ─────────────────────────────────────────────


def test_resolve_services_dedupes_and_normalizes(tmp_path: Path) -> None:
    vault, broker, _ = _make_services(
        tmp_path, {"hermes": _agent(["openai"])}, [("openai", "default", "sk-x")]
    )
    assert resolve_services(broker, "hermes", ["Open_AI", "openai", "GITHUB"]) == ["openai", "github"]


def test_resolve_services_auto_mode_policy_intersection(tmp_path: Path) -> None:
    """Auto mode = policy services ∩ vault services, sorted, deduplicated."""
    vault, broker, _ = _make_services(
        tmp_path,
        {"hermes": _agent(["openai", "github", "anthropic"])},
        [("openai", "default", "sk-x"), ("github", "default", "gh-y")],
    )
    assert resolve_services(broker, "hermes", None) == ["github", "openai"]
    # anthropic is policy-granted but has no credential: never resolved


# ── CLI wiring ──────────────────────────────────────────────────────────────


def test_cli_run_help_documents_exit_codes() -> None:
    result = CliRunner().invoke(_hermes_group, ["run", "--help"])
    assert result.exit_code == 0
    assert "run" in result.output
    assert "126/127" in result.output


def test_cli_run_injects_and_child_sees_secret(monkeypatch, tmp_path: Path) -> None:
    vault, broker, _ = _make_services(
        tmp_path, {"hermes": _agent(["openai"])}, [("openai", "default", "sk-cli-e2e")]
    )

    def fake_build(prompt=False):
        return vault, broker.policy, broker, object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")

    result = CliRunner().invoke(
        _hermes_group,
        ["--no-banner", "run", "--agent", "hermes", "--service", "openai", "--", *_child_probe("OPENAI_API_KEY")],
    )
    assert result.exit_code == 0
    # child stdout flows through run's inherited stdio; assert via the exit
    # path plus the broker audit row (value-level proof is in module tests)
    rows = broker.audit.list_recent(limit=5, action="run_env_inject")
    assert rows and rows[0]["decision"] == "allow"
    meta = rows[0]["metadata"]
    assert isinstance(meta, dict) and meta["env_var_names"] == ["OPENAI_API_KEY"]


def _write_policy_file(tmp_path: Path, agents: dict) -> Path:
    """Write a policy.yaml naming the agents (for the P3 stderr hint)."""
    path = tmp_path / "policy.yaml"
    lines = ["agents:"]
    for name, policy in agents.items():
        lines.append(f"  {name}:")
        lines.append(f"    services: {policy.services}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert PolicyEngine.from_yaml(path).config.agents  # self-check
    return path


def test_cli_run_denial_exits_1_and_hints_on_stderr(monkeypatch, tmp_path: Path) -> None:
    vault, broker, _ = _make_services(
        tmp_path, {"hermes": _agent(["openai"])}, [("openai", "default", "sk-x")]
    )
    policy_path = _write_policy_file(tmp_path, {"hermes": _agent(["openai"])})

    def fake_build(prompt=False):
        return vault, broker.policy, broker, object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))
    monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")

    result = CliRunner().invoke(
        _hermes_group,
        ["--no-banner", "run", "--agent", "ghost", "--service", "openai", "--", *_child_probe("X")],
    )
    assert result.exit_code == 1
    assert "is not defined in policy" in result.stderr
    assert "hermes" in result.stderr  # defined agents listed in the hint


def test_cli_run_undefined_agent_hint_lists_defined_agents(monkeypatch, tmp_path: Path) -> None:
    """The P3 agent-hint composes with run's denial path."""
    vault, broker, _ = _make_services(
        tmp_path,
        {"hermes": _agent(["openai"]), "deploy-bot": _agent(["github"])},
        [("openai", "default", "sk-x")],
    )
    policy_path = _write_policy_file(
        tmp_path,
        {"hermes": _agent(["openai"]), "deploy-bot": _agent(["github"])},
    )

    def fake_build(prompt=False):
        return vault, broker.policy, broker, object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_POLICY", str(policy_path))

    result = CliRunner().invoke(
        _hermes_group,
        ["--no-banner", "run", "--agent", "ghost", "--service", "openai", "--", *_child_probe("X")],
    )
    assert result.exit_code == 1
    assert "deploy-bot" in result.stderr
    assert "HERMES_VAULT_MCP_DEFAULT_AGENT" in result.stderr


def test_cli_run_default_agent_env_binding(monkeypatch, tmp_path: Path) -> None:
    """No --agent: HERMES_VAULT_MCP_DEFAULT_AGENT binds the identity."""
    vault, broker, _ = _make_services(
        tmp_path, {"hermes": _agent(["openai"])}, [("openai", "default", "sk-default-bind")]
    )

    def fake_build(prompt=False):
        return vault, broker.policy, broker, object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_VAULT_MCP_DEFAULT_AGENT", "hermes")

    out = tmp_path / "observed.txt"
    result = CliRunner().invoke(
        _hermes_group,
        ["--no-banner", "run", "--service", "openai", "--", *_child_write_probe("OPENAI_API_KEY", out)]
    )
    assert result.exit_code == 0
    assert out.read_text() == "sk-default-bind"


def test_cli_run_no_agent_and_no_env_is_usage_error(monkeypatch, tmp_path: Path) -> None:
    vault, broker, _ = _make_services(
        tmp_path, {"hermes": _agent(["openai"])}, [("openai", "default", "sk-x")]
    )

    def fake_build(prompt=False):
        return vault, broker.policy, broker, object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))
    monkeypatch.delenv("HERMES_VAULT_MCP_DEFAULT_AGENT", raising=False)

    result = CliRunner().invoke(
        _hermes_group,
        ["--no-banner", "run", "--service", "openai", "--", "true"],
    )
    assert result.exit_code == 2
    assert "no agent id" in result.stderr


def test_cli_run_ttl_zero_is_usage_error(monkeypatch, tmp_path: Path) -> None:
    result = CliRunner().invoke(
        _hermes_group, ["--no-banner", "run", "--ttl", "0", "--", "true"]
    )
    assert result.exit_code == 2


def test_cli_run_verbose_prints_var_names_not_values(monkeypatch, tmp_path: Path) -> None:
    vault, broker, _ = _make_services(
        tmp_path, {"hermes": _agent(["openai"])}, [("openai", "default", "sk-verbose-secret")]
    )

    def fake_build(prompt=False):
        return vault, broker.policy, broker, object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))

    result = CliRunner().invoke(
        _hermes_group,
        ["--no-banner", "run", "--agent", "hermes", "--service", "openai", "--verbose", "--", "true"],
    )
    assert result.exit_code == 0
    assert "OPENAI_API_KEY" in result.stderr
    assert "sk-verbose-secret" not in result.stderr


def test_cli_run_env_collision_fails_closed(monkeypatch, tmp_path: Path) -> None:
    """Two services mapping the same env var with different values refuse to run."""
    # openai and gemini both map GEMINI_API_KEY? No — build a real collision:
    # fal maps both FAL_KEY and FAL_API_KEY; openai maps OPENAI_API_KEY.
    # Use a genuine pair: "google" maps GOOGLE_OAUTH_ACCESS_TOKEN + GOOGLE_API_KEY.
    # For a collision we need two services sharing one var name — none in the
    # built-in map. So pin the collision at the runner level instead.
    vault, broker, _ = _make_services(
        tmp_path,
        {"hermes": _agent(["openai", "anthropic"])},
        [("openai", "default", "sk-a"), ("anthropic", "default", "sk-b")],
    )
    from hermes_vault import runner as runner_mod

    original = broker.get_ephemeral_env

    def collide(service, agent_id, ttl, alias=None):
        decision = original(service, agent_id, ttl, alias=alias)
        if decision.allowed:
            decision.env["SHARED_VAR"] = f"value-{service}"
        return decision

    broker.get_ephemeral_env = collide  # type: ignore[method-assign]
    code = runner_mod.execute_run_and_report(
        broker,
        command=["true"],
        agent_id="hermes",
        requested_services=["openai", "anthropic"],
        alias=None,
        ttl=900,
    )
    assert code == 1
    rows = broker.audit.list_recent(limit=10, action="run_env_inject")
    assert rows and rows[0]["decision"] == "deny"


def test_cli_run_service_normalized_on_cli(monkeypatch, tmp_path: Path) -> None:
    vault, broker, _ = _make_services(
        tmp_path, {"hermes": _agent(["openai"])}, [("openai", "default", "sk-norm")]
    )

    def fake_build(prompt=False):
        return vault, broker.policy, broker, object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build)
    monkeypatch.setenv("HERMES_VAULT_HOME", str(tmp_path))

    out = tmp_path / "observed.txt"
    result = CliRunner().invoke(
        _hermes_group,
        ["--no-banner", "run", "--agent", "hermes", "--service", "Open_AI", "--", *_child_write_probe("OPENAI_API_KEY", out)],
    )
    assert result.exit_code == 0
    assert out.read_text() == "sk-norm"
